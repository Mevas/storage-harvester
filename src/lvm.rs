//! Proxmox thin pools (`type: lvm_thin`): the pool, every guest with a disk in it, and each
//! guest's disks, as one tree.
//!
//! - A disk's size is its *allocated* thin blocks, what the pool spends on it. Its provisioned
//!   size, what the guest sees, rides along as `p`.
//! - A running container's root disk also holds the container's own directories, walked from
//!   the host through `/proc/<pid>/root`. A VM's disks are opaque here; a harvester inside the
//!   VM fills them in on the atlas, matched by SMBIOS UUID and disk serial.
//! - Allocation and I/O are followed live by polling device-mapper every
//!   `live.block_poll_interval`.
//!
//! Everything is read-only:
//! - `lvs` (at each scan): the pool's thin volumes, active or not.
//! - `dmsetup table` / `dmsetup status`: the pool's chunk size and usage, and each active
//!   volume's mapped sectors.
//! - `/sys/block/dm-N/stat`: sectors read and written per volume.
//! - `<pve_config>/storage.cfg`, `qemu-server/*.conf`, `lxc/*.conf`: which storage is this
//!   pool, and which guest each volume belongs to.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use tracing::{info, warn};

use crate::config::{LvmTarget, ReportMode, Target};
use crate::live::{millis, LiveStore, LiveTarget};
use crate::scanner::native::{self, NativeScanner};
use crate::scanner::{ScanResult, Scanner};
use crate::tree::{Delta, DirNode, DirTree, Tally, NONE};

const SECTOR: u64 = 512;
/// dm-thin metadata blocks are 4 KiB.
const META_BLOCK: u64 = 4096;

/// The pool and everything in it as of the last scan, kept current by [`follow`].
#[derive(Debug, Clone)]
pub struct Pool {
    /// The Proxmox storage name (`local-lvm`), or `vg/lv` when no storage names the pool.
    pub storage: String,
    /// The filesystem id `/api/info` gives the pool: `lvm:vg/lv`.
    pub id: String,
    /// device-mapper name of the pool device (`pve-data-tpool`).
    pub dm: String,
    pub chunk: u64,
    pub size: u64,
    pub used: u64,
    pub meta_size: u64,
    pub meta_used: u64,
    /// Sum of the thin volumes' virtual sizes.
    pub provisioned: u64,
    /// Whole disks under the pool.
    pub disks: Vec<String>,
    pub guests: Vec<Guest>,
    /// Tree node → `(guest, disk)` index; `disk` is `None` for the guest's own node.
    by_node: HashMap<u32, (usize, Option<usize>)>,
}

#[derive(Debug, Clone)]
pub struct Guest {
    pub vmid: Option<u32>,
    pub name: String,
    pub kind: GuestKind,
    pub running: bool,
    pub template: bool,
    /// SMBIOS UUID (VMs).
    pub uuid: Option<String>,
    pub node: u32,
    pub disks: Vec<Disk>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestKind {
    Qemu,
    Lxc,
    /// Volumes in the pool that no guest config refers to.
    Unattached,
}

impl GuestKind {
    pub fn as_str(self) -> &'static str {
        match self {
            GuestKind::Qemu => "qemu",
            GuestKind::Lxc => "lxc",
            GuestKind::Unattached => "none",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Disk {
    /// The config key (`scsi0`, `rootfs`, `mp0`, `efidisk0`, `unused0`), or the volume name for
    /// unattached volumes.
    pub key: String,
    pub lv: String,
    /// Its device-mapper name, whether or not it is active now.
    pub dm: String,
    /// The volume is active (mapped) as of the last reading.
    pub active: bool,
    /// Provisioned (virtual) size.
    pub size: u64,
    /// Mapped thin blocks, as last seen; `None` until the volume has been active once (LVM
    /// cannot tell an inactive volume's allocation).
    pub allocated: Option<u64>,
    /// The guest passes TRIM through, so blocks it frees return to the pool.
    pub discard: bool,
    /// Its node holds the container's walked directories.
    pub walked: bool,
    pub node: u32,
    /// Of the node's direct bytes, allocated blocks that no walked file accounts for.
    pub unaccounted: u64,
    /// Bytes read and written since boot, and per second over the last poll.
    pub read: u64,
    pub written: u64,
    pub read_rate: u64,
    pub write_rate: u64,
}

/// Device-mapper name of `vg/lv`: each `-` doubled, joined by `-`.
fn dm_name(vg: &str, lv: &str) -> String {
    format!("{}-{}", vg.replace('-', "--"), lv.replace('-', "--"))
}

/// One volume `lvs` lists in the pool.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ThinVolume {
    lv: String,
    size: u64,
    active: bool,
}

fn parse_lvs(text: &str, pool: &str) -> Result<Vec<ThinVolume>> {
    let report: Value = serde_json::from_str(text).context("lvs did not print JSON")?;
    let rows = report["report"][0]["lv"]
        .as_array()
        .context("lvs JSON has no report[0].lv")?;
    Ok(rows
        .iter()
        .filter(|row| row["pool_lv"].as_str() == Some(pool))
        .filter_map(|row| {
            Some(ThinVolume {
                lv: row["lv_name"].as_str()?.to_string(),
                size: row["lv_size"].as_str()?.parse().ok()?,
                active: row["lv_active"].as_str() == Some("active"),
            })
        })
        .collect())
}

/// `dmsetup table` or `dmsetup status`: device name → its first segment, after the name.
fn parse_dmsetup(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let (name, rest) = line.split_once(": ")?;
            (!name.contains(' ')).then(|| (name.to_string(), rest.trim().to_string()))
        })
        .collect()
}

/// A thin volume's `dmsetup status` (`0 <len> thin <mapped> <highest>`): mapped sectors.
fn thin_mapped(status: &str) -> Option<u64> {
    let fields: Vec<&str> = status.split_whitespace().collect();
    if fields.get(2) != Some(&"thin") {
        return None;
    }
    fields.get(3)?.parse().ok()
}

/// A thin pool's `dmsetup table` (`0 <len> thin-pool <meta> <data> <block sectors> ...`): its
/// chunk size in bytes.
fn pool_chunk(table: &str) -> Option<u64> {
    let fields: Vec<&str> = table.split_whitespace().collect();
    if fields.get(2) != Some(&"thin-pool") {
        return None;
    }
    Some(fields.get(5)?.parse::<u64>().ok()? * SECTOR)
}

/// A thin pool's `dmsetup status`
/// (`0 <len> thin-pool <transaction> <meta used>/<meta total> <data used>/<data total> ...`):
/// `(data used, data size, metadata used, metadata size)` in bytes.
fn pool_usage(status: &str, chunk: u64) -> Option<(u64, u64, u64, u64)> {
    let fields: Vec<&str> = status.split_whitespace().collect();
    if fields.get(2) != Some(&"thin-pool") {
        return None;
    }
    let fraction = |field: &str| -> Option<(u64, u64)> {
        let (used, total) = field.split_once('/')?;
        Some((used.parse().ok()?, total.parse().ok()?))
    };
    let (meta_used, meta_total) = fraction(fields.get(4)?)?;
    let (data_used, data_total) = fraction(fields.get(5)?)?;
    Some((
        data_used * chunk,
        data_total * chunk,
        meta_used * META_BLOCK,
        meta_total * META_BLOCK,
    ))
}

/// A Proxmox storage from `storage.cfg`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Storage {
    id: String,
    kind: String,
    vg: Option<String>,
    thinpool: Option<String>,
}

fn parse_storage_cfg(text: &str) -> Vec<Storage> {
    let mut storages: Vec<Storage> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if !line.starts_with([' ', '\t']) {
            if let Some((kind, id)) = line.split_once(':') {
                storages.push(Storage {
                    id: id.trim().to_string(),
                    kind: kind.trim().to_string(),
                    ..Storage::default()
                });
            }
            continue;
        }
        let Some(storage) = storages.last_mut() else {
            continue;
        };
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some("vgname"), Some(vg)) => storage.vg = Some(vg.to_string()),
            (Some("thinpool"), Some(pool)) => storage.thinpool = Some(pool.to_string()),
            _ => {}
        }
    }
    storages
}

/// What a guest's config says, before its first `[snapshot]` section.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct GuestConfig {
    name: Option<String>,
    uuid: Option<String>,
    template: bool,
    /// `(key, storage, volume, discard)`.
    volumes: Vec<(String, String, String, bool)>,
}

fn is_volume_key(key: &str, kind: GuestKind) -> bool {
    let numbered = |prefix: &str| {
        key.strip_prefix(prefix)
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    };
    match kind {
        GuestKind::Qemu => {
            ["ide", "sata", "scsi", "virtio", "unused"]
                .iter()
                .any(|prefix| numbered(prefix))
                || key == "efidisk0"
                || key == "tpmstate0"
        }
        GuestKind::Lxc => key == "rootfs" || numbered("mp") || numbered("unused"),
        GuestKind::Unattached => false,
    }
}

fn parse_guest_config(text: &str, kind: GuestKind) -> GuestConfig {
    let mut config = GuestConfig::default();
    for line in text.lines() {
        if line.starts_with('[') {
            break;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        match key {
            "name" if kind == GuestKind::Qemu => config.name = Some(value.to_string()),
            "hostname" if kind == GuestKind::Lxc => config.name = Some(value.to_string()),
            "template" => config.template = value == "1",
            "smbios1" => {
                config.uuid = value
                    .split(',')
                    .find_map(|part| part.strip_prefix("uuid="))
                    .map(|uuid| uuid.to_ascii_lowercase());
            }
            key if is_volume_key(key, kind) => {
                let mut parts = value.split(',');
                let first = parts.next().unwrap_or_default();
                // `local-lvm:vm-100-disk-0` (or `volume=local-lvm:...` for mount points);
                // skip bind mounts (`/mnt/x`), `none` and CD-ROMs on other storages.
                let first = first.strip_prefix("volume=").unwrap_or(first);
                let Some((storage, volume)) = first.split_once(':') else {
                    continue;
                };
                if storage.starts_with('/') || volume.is_empty() {
                    continue;
                }
                let options: Vec<&str> = parts.collect();
                let discard = options.contains(&"discard=on")
                    || options
                        .iter()
                        .any(|o| o.starts_with("mountoptions=") && o.contains("discard"));
                config.volumes.push((
                    key.to_string(),
                    storage.to_string(),
                    volume.to_string(),
                    discard,
                ));
            }
            _ => {}
        }
    }
    config
}

/// Guests' configs: `(vmid, kind, config)`, by vmid.
fn read_guests(pve: &Path) -> Vec<(u32, GuestKind, GuestConfig)> {
    let mut guests = Vec::new();
    for (dir, kind) in [("qemu-server", GuestKind::Qemu), ("lxc", GuestKind::Lxc)] {
        let Ok(entries) = fs::read_dir(pve.join(dir)) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(vmid) = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_suffix(".conf"))
                .and_then(|id| id.parse::<u32>().ok())
            else {
                continue;
            };
            if let Ok(text) = fs::read_to_string(&path) {
                guests.push((vmid, kind, parse_guest_config(&text, kind)));
            }
        }
    }
    guests.sort_by_key(|(vmid, _, _)| *vmid);
    guests
}

/// How long `lvs` and `dmsetup` may take: `lvs` can wait on an LVM lock, `dmsetup` on a
/// suspended device.
const COMMAND_DEADLINE: Duration = Duration::from_secs(15);

/// Runs a read-only tool and returns its output, killing it past `deadline`.
fn run(program: &str, args: &[&str], deadline: Duration) -> Result<String> {
    use std::process::Stdio;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to run {program}"))?;
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{program} {} took longer than {deadline:?}", args.join(" "));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout.join().unwrap_or_default();
    if !status.success() {
        let stderr = stderr.join().unwrap_or_default();
        bail!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

/// Reads a child's pipe to its end (at most 16 MiB) on its own thread, so a chatty child never
/// blocks on a full pipe while it is being waited for.
fn drain(pipe: Option<impl std::io::Read + Send + 'static>) -> std::thread::JoinHandle<Vec<u8>> {
    use std::io::Read;
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(pipe) = pipe {
            let _ = pipe.take(16 << 20).read_to_end(&mut bytes);
        }
        bytes
    })
}

/// An active device-mapper device, from sysfs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Device {
    /// `major:minor`.
    dev: String,
    /// Sectors read and written since it was activated.
    read: u64,
    written: u64,
}

/// One reading of device-mapper: each device's status line, and its sysfs entry.
struct Sample {
    status: HashMap<String, String>,
    devices: HashMap<String, Device>,
    at: Instant,
}

fn sample() -> Result<Sample> {
    let status = parse_dmsetup(&run("dmsetup", &["status"], COMMAND_DEADLINE)?);
    Ok(Sample {
        status,
        devices: dm_devices(),
        at: Instant::now(),
    })
}

/// Active device-mapper devices by name (`/sys/block/dm-*`).
fn dm_devices() -> HashMap<String, Device> {
    let Ok(entries) = fs::read_dir("/sys/block") else {
        return HashMap::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let name = fs::read_to_string(path.join("dm/name")).ok()?;
            let dev = fs::read_to_string(path.join("dev")).ok()?;
            let stat = fs::read_to_string(path.join("stat")).ok()?;
            let fields: Vec<u64> = stat
                .split_whitespace()
                .filter_map(|field| field.parse().ok())
                .collect();
            Some((
                name.trim().to_string(),
                Device {
                    dev: dev.trim().to_string(),
                    read: *fields.get(2)?,
                    written: *fields.get(6)?,
                },
            ))
        })
        .collect()
}

fn qemu_running(vmid: u32) -> bool {
    fs::read_to_string(format!("/run/qemu-server/{vmid}.pid"))
        .ok()
        .and_then(|pid| pid.trim().parse::<u32>().ok())
        .is_some_and(|pid| Path::new(&format!("/proc/{pid}")).exists())
}

/// A running container's init process, as the host sees it.
fn lxc_pid(vmid: u32) -> Option<u32> {
    run(
        "lxc-info",
        &["-n", &vmid.to_string(), "-p", "-H"],
        Duration::from_secs(5),
    )
    .ok()?
    .trim()
    .parse()
    .ok()
}

pub struct LvmScanner {
    lvm: LvmTarget,
}

impl LvmScanner {
    pub fn new(target: &Target) -> Result<Self> {
        let Some(lvm) = target.lvm.clone() else {
            bail!("target {} is not an lvm_thin target", target.name);
        };
        Ok(Self { lvm })
    }
}

impl Scanner for LvmScanner {
    fn backend(&self) -> &'static str {
        "lvm"
    }

    fn scan(&self, target: &Target, cancel: &AtomicBool) -> Result<ScanResult> {
        let started = Instant::now();
        let timestamp = SystemTime::now();
        let lvm = &self.lvm;
        let volumes = parse_lvs(
            &run(
                "lvs",
                &[
                    "--reportformat",
                    "json",
                    "--units",
                    "b",
                    "--nosuffix",
                    "-o",
                    "lv_name,pool_lv,lv_size,lv_active",
                    &lvm.vg,
                ],
                COMMAND_DEADLINE,
            )?,
            &lvm.pool,
        )?;
        let tables = parse_dmsetup(&run("dmsetup", &["table"], COMMAND_DEADLINE)?);
        let sample = sample()?;
        let storages = fs::read_to_string(lvm.pve_config.join("storage.cfg"))
            .map(|text| parse_storage_cfg(&text))
            .unwrap_or_default();
        let guests = read_guests(&lvm.pve_config);
        let inputs = Inputs {
            volumes,
            tables,
            sample,
            storages,
            guests,
        };
        let (mut pool, mut tree) = build(target, lvm, &inputs)?;
        let devices = &inputs.sample.devices;
        pool.disks = devices
            .get(&pool.dm)
            .map(|device| crate::fsinfo::disks_of(&device.dev))
            .unwrap_or_default();

        // Running containers: walk their root disks from the host.
        let skeleton = tree.nodes.len() as u64;
        let mut walks = Walks::default();
        for guest_index in 0..pool.guests.len() {
            let guest = &pool.guests[guest_index];
            if guest.kind != GuestKind::Lxc || !guest.running {
                continue;
            }
            let Some(disk_index) = guest.disks.iter().position(|disk| disk.key == "rootfs") else {
                continue;
            };
            let Some(vmid) = guest.vmid else { continue };
            let Some(volume) = devices.get(&guest.disks[disk_index].dm) else {
                continue;
            };
            let Some(pid) = lxc_pid(vmid) else { continue };
            if cancel.load(Ordering::Relaxed) {
                bail!("scan of {} cancelled", target.name);
            }
            let root = match open_container_root(pid, &volume.dev) {
                Ok(root) => root,
                Err(error) => {
                    warn!(target = %target.name, vmid, %error, "container root not walked");
                    continue;
                }
            };
            let display = PathBuf::from(tree.display_path(guest.disks[disk_index].node));
            let budget = target.tree_max_directories.saturating_sub(tree.nodes.len());
            match walk_container(target, &root, display, budget, cancel) {
                Ok(result) => {
                    walks.add(&result);
                    if let Some(walked) = result.tree {
                        let disk = &mut pool.guests[guest_index].disks[disk_index];
                        graft_walk(&mut tree, disk, walked);
                    }
                }
                Err(error) => {
                    warn!(target = %target.name, vmid, %error, "container walk failed")
                }
            }
        }
        pool.reindex();
        tree.pool = Some(Box::new(pool));
        let observations = native::reported(target, &tree);
        Ok(ScanResult {
            backend: self.backend().to_string(),
            observations,
            entries: Vec::new(),
            permission_errors: walks.permission_errors,
            missing_path_races: walks.missing_path_races,
            skipped_cross_device: 0,
            skipped_excluded: 0,
            scanned_files: walks.files,
            scanned_directories: skeleton + walks.dirs,
            scanned_symlinks: walks.symlinks,
            max_observed_depth: tree
                .nodes
                .iter()
                .map(|n| n.depth as usize)
                .max()
                .unwrap_or(0),
            depth_limit_hits: 0,
            duration: started.elapsed(),
            timestamp,
            tree: Some(tree),
        })
    }
}

/// What the container walks of one scan saw, summed.
#[derive(Default)]
struct Walks {
    files: u64,
    dirs: u64,
    symlinks: u64,
    permission_errors: u64,
    missing_path_races: u64,
}

impl Walks {
    fn add(&mut self, result: &ScanResult) {
        self.files += result.scanned_files;
        self.dirs += result.scanned_directories;
        self.symlinks += result.scanned_symlinks;
        self.permission_errors += result.permission_errors;
        self.missing_path_races += result.missing_path_races;
    }
}

/// What one scan reads, gathered first so [`build`] can be tested without a pool.
struct Inputs {
    volumes: Vec<ThinVolume>,
    tables: HashMap<String, String>,
    sample: Sample,
    storages: Vec<Storage>,
    guests: Vec<(u32, GuestKind, GuestConfig)>,
}

fn synthetic(name: &str, parent: u32, depth: u32) -> DirNode {
    DirNode {
        name: name.as_bytes().into(),
        parent,
        depth,
        ino: 0,
        own_blocks: 0,
        own_apparent: 0,
        mtime: 0,
        direct: Tally::default(),
        sub: Tally::default(),
        children: Vec::new(),
        sealed: false,
        pruned: false,
        alive: true,
    }
}

/// The pool's tree without container contents: pool → guests → disks.
fn build(target: &Target, lvm: &LvmTarget, inputs: &Inputs) -> Result<(Pool, DirTree)> {
    let base = dm_name(&lvm.vg, &lvm.pool);
    let (dm, table) = [format!("{base}-tpool"), base.clone()]
        .into_iter()
        .find_map(|name| {
            let table = inputs.tables.get(&name)?;
            pool_chunk(table).map(|_| (name, table.clone()))
        })
        .with_context(|| format!("no active thin pool {}/{}", lvm.vg, lvm.pool))?;
    let chunk = pool_chunk(&table).unwrap_or(64 * 1024);
    let (used, size, meta_used, meta_size) = inputs
        .sample
        .status
        .get(&dm)
        .and_then(|status| pool_usage(status, chunk))
        .with_context(|| format!("no status for thin pool {dm}"))?;
    let storage = inputs
        .storages
        .iter()
        .find(|s| {
            s.kind == "lvmthin"
                && s.vg.as_deref() == Some(&lvm.vg)
                && s.thinpool.as_deref() == Some(&lvm.pool)
        })
        .map(|s| s.id.clone());

    let volumes: HashMap<&str, &ThinVolume> = inputs
        .volumes
        .iter()
        .map(|volume| (volume.lv.as_str(), volume))
        .collect();
    let disk = |key: &str, volume: &ThinVolume, discard: bool| {
        let dm = dm_name(&lvm.vg, &volume.lv);
        let mapped = inputs
            .sample
            .status
            .get(&dm)
            .and_then(|status| thin_mapped(status));
        // Counters as of now, so a scan never publishes a disk at zero.
        let device = inputs.sample.devices.get(&dm).cloned().unwrap_or_default();
        Disk {
            key: key.to_string(),
            lv: volume.lv.clone(),
            dm,
            active: mapped.is_some(),
            size: volume.size,
            allocated: mapped.map(|sectors| sectors * SECTOR),
            discard,
            walked: false,
            node: NONE,
            unaccounted: 0,
            read: device.read * SECTOR,
            written: device.written * SECTOR,
            read_rate: 0,
            write_rate: 0,
        }
    };

    let mut guests = Vec::new();
    let mut claimed = HashSet::new();
    for (vmid, kind, config) in &inputs.guests {
        let disks: Vec<Disk> = config
            .volumes
            .iter()
            .filter(|(_, on, _, _)| Some(on) == storage.as_ref())
            .filter_map(|(key, _, volume, discard)| {
                let volume = volumes.get(volume.as_str())?;
                claimed.insert(volume.lv.clone());
                Some(disk(key, volume, *discard))
            })
            .collect();
        if disks.is_empty() {
            continue;
        }
        let running = match kind {
            GuestKind::Qemu => qemu_running(*vmid),
            // Settled by the walk; `lxc-info` also tells a stopped container.
            GuestKind::Lxc => Path::new(&format!("/sys/fs/cgroup/lxc/{vmid}")).exists(),
            GuestKind::Unattached => false,
        };
        guests.push(Guest {
            vmid: Some(*vmid),
            name: config.name.clone().unwrap_or_else(|| format!("{vmid}")),
            kind: *kind,
            running,
            template: config.template,
            uuid: config.uuid.clone(),
            node: NONE,
            disks,
        });
    }
    let unattached: Vec<Disk> = inputs
        .volumes
        .iter()
        .filter(|volume| !claimed.contains(&volume.lv))
        .map(|volume| disk(&volume.lv, volume, false))
        .collect();
    if !unattached.is_empty() {
        guests.push(Guest {
            vmid: None,
            name: "Unattached".to_string(),
            kind: GuestKind::Unattached,
            running: false,
            template: false,
            uuid: None,
            node: NONE,
            disks: unattached,
        });
    }

    let mut nodes = vec![synthetic("", NONE, 0)];
    for guest in &mut guests {
        guest.node = nodes.len() as u32;
        let label = match guest.vmid {
            Some(vmid) => format!("{} ({vmid})", guest.name),
            None => guest.name.clone(),
        };
        nodes.push(synthetic(&label, 0, 1));
        nodes[0].direct.dirs += 1;
        for disk in &mut guest.disks {
            disk.node = nodes.len() as u32;
            let mut node = synthetic(&disk.key, guest.node, 2);
            let bytes = disk.allocated.unwrap_or(0);
            node.direct.add_size(bytes, bytes);
            disk.unaccounted = bytes;
            nodes.push(node);
            nodes[guest.node as usize].direct.dirs += 1;
        }
    }
    for index in (0..nodes.len()).rev() {
        let direct = nodes[index].direct;
        nodes[index].sub.add(&direct);
        let parent = nodes[index].parent;
        if parent != NONE {
            let sub = nodes[index].sub;
            nodes[parent as usize].sub.add(&sub);
            nodes[parent as usize].children.push(index as u32);
        }
    }
    for index in 0..nodes.len() {
        let mut children = std::mem::take(&mut nodes[index].children);
        children.sort_by(|&a, &b| nodes[a as usize].name.cmp(&nodes[b as usize].name));
        nodes[index].children = children;
    }
    let provisioned = inputs.volumes.iter().map(|volume| volume.size).sum();
    let tree = DirTree {
        display_root: target.display_path.as_os_str().as_encoded_bytes().to_vec(),
        scan_root: b"/".to_vec(),
        root_dev: 0,
        nodes,
        links: HashMap::new(),
        handles: Vec::new(),
        plain: Vec::new(),
        untracked_links: Vec::new(),
        pool: None,
    };
    let mut pool = Pool {
        storage: storage.unwrap_or_else(|| format!("{}/{}", lvm.vg, lvm.pool)),
        id: lvm.fs_id(),
        dm,
        chunk,
        size,
        used,
        meta_size,
        meta_used,
        provisioned,
        disks: Vec::new(),
        guests,
        by_node: HashMap::new(),
    };
    pool.reindex();
    Ok((pool, tree))
}

/// Opens a running container's root directory through its init process, and checks that it
/// is on the container's own volume (`major:minor`). A PID reused by a host process since
/// `lxc-info` answered would give the host's root instead.
#[cfg(target_os = "linux")]
fn open_container_root(pid: u32, volume: &str) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let root = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(format!("/proc/{pid}/root"))?;
    check_root_device(&root, volume)?;
    Ok(root)
}

#[cfg(not(target_os = "linux"))]
fn open_container_root(_pid: u32, _volume: &str) -> Result<fs::File> {
    bail!("walking containers needs Linux")
}

#[cfg(target_os = "linux")]
fn check_root_device(root: &fs::File, volume: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let dev = root.metadata()?.dev();
    let found = format!("{}:{}", libc::major(dev), libc::minor(dev));
    if found != volume {
        bail!("root is on {found}, not the container's volume {volume}");
    }
    Ok(())
}

/// Walks a container's root filesystem through the descriptor `root` holds, so the walk stays
/// on that directory whatever happens to the process. Entries on other devices are skipped,
/// so a symlink swapped in mid-walk leads nowhere.
fn walk_container(
    target: &Target,
    root: &fs::File,
    display: PathBuf,
    budget: usize,
    cancel: &AtomicBool,
) -> Result<ScanResult> {
    use std::os::fd::AsRawFd;
    let mut walk = target.clone();
    walk.lvm = None;
    walk.scanner = "native".to_string();
    // A magic link to the open directory; the trailing slash makes the walk start at it.
    walk.scan_path = PathBuf::from(format!("/proc/self/fd/{}/", root.as_raw_fd()));
    walk.display_path = display;
    walk.report_mode = ReportMode::Tree;
    walk.report_depth = 0;
    walk.no_cross_filesystem = true;
    walk.scan_threads = walk.scan_threads.min(2);
    walk.tree_max_directories = budget;
    walk.collect_handles = false;
    NativeScanner::new(&walk)?.scan(&walk, cancel)
}

/// Puts a container's walked tree in place of its root disk's opaque node, named after the
/// disk, holding the container's directories plus the allocated blocks no file accounts for.
/// The disk's node changes, so the pool needs [`Pool::reindex`] after.
fn graft_walk(tree: &mut DirTree, disk: &mut Disk, mut walked: DirTree) {
    let opaque = disk.node;
    let guest = tree.nodes[opaque as usize].parent;
    let gone = Delta::from(&tree.nodes[opaque as usize].sub).negate();
    tree.detach(opaque);
    tree.propagate(guest, &gone);

    let root = &mut walked.nodes[0];
    root.name = disk.key.as_bytes().into();
    let remainder = disk
        .allocated
        .unwrap_or(0)
        .saturating_sub(root.total_blocks());
    root.direct.add_size(remainder, remainder);
    root.sub.add_size(remainder, remainder);
    let added = Delta::from(&root.sub).plus(Delta {
        blocks: root.own_blocks as i64,
        apparent: root.own_apparent as i64,
        ..Delta::default()
    });
    disk.node = tree.graft(guest, walked);
    tree.propagate(guest, &added);
    disk.walked = true;
    disk.unaccounted = remainder;
}

impl Pool {
    fn reindex(&mut self) {
        self.by_node.clear();
        for (g, guest) in self.guests.iter().enumerate() {
            self.by_node.insert(guest.node, (g, None));
            for (d, disk) in guest.disks.iter().enumerate() {
                self.by_node.insert(disk.node, (g, Some(d)));
            }
        }
    }

    /// The extra `/api/tree` fields for `node`.
    pub fn annotate(&self, node: u32, object: &mut Map<String, Value>) {
        if node == 0 {
            object.insert("v".into(), json!("pool"));
            return;
        }
        let Some(&(g, d)) = self.by_node.get(&node) else {
            return;
        };
        let guest = &self.guests[g];
        match d {
            None => {
                object.insert("v".into(), json!("guest"));
                object.insert("vmid".into(), json!(guest.vmid));
                object.insert("g".into(), json!(guest.kind.as_str()));
                object.insert("on".into(), json!(guest.running));
            }
            Some(d) => {
                let disk = &guest.disks[d];
                object.insert("v".into(), json!("disk"));
                object.insert("key".into(), json!(disk.key));
                object.insert("p".into(), json!(disk.size));
                object.insert("u".into(), json!(disk.unaccounted));
                object.insert("w".into(), json!(disk.write_rate));
                object.insert("rd".into(), json!(disk.read_rate));
                if !disk.active {
                    object.insert("inactive".into(), json!(true));
                }
            }
        }
    }

    /// `/api/info`'s filesystem entry for the pool.
    pub fn filesystem_json(&self) -> Value {
        json!({
            "id": self.id, "type": "lvmthin", "mount": self.storage,
            "size": self.size, "used": self.used, "avail": self.size.saturating_sub(self.used),
            "reserved": 0, "disks": self.disks, "provisioned": self.provisioned,
            "meta": { "size": self.meta_size, "used": self.meta_used },
        })
    }

    /// `/api/info`'s `guests` for the target.
    pub fn guests_json(&self, tree: &DirTree) -> Value {
        Value::Array(
            self.guests
                .iter()
                .map(|guest| {
                    json!({
                        "vmid": guest.vmid, "name": guest.name, "type": guest.kind.as_str(),
                        "running": guest.running, "template": guest.template,
                        "uuid": guest.uuid, "path": tree.display_path(guest.node),
                        "disks": guest.disks.iter().map(|disk| json!({
                            "key": disk.key, "lv": disk.lv, "path": tree.display_path(disk.node),
                            "size": disk.size, "allocated": disk.allocated, "active": disk.active,
                            "discard": disk.discard, "walked": disk.walked,
                            "write_rate": disk.write_rate, "read_rate": disk.read_rate,
                        })).collect::<Vec<_>>(),
                    })
                })
                .collect(),
        )
    }

    /// Every disk with its tree path: for the block I/O counters.
    pub fn disks_with_paths<'a>(
        &'a self,
        tree: &'a DirTree,
    ) -> impl Iterator<Item = (String, &'a Disk)> + 'a {
        self.guests
            .iter()
            .flat_map(|guest| guest.disks.iter())
            .map(move |disk| (tree.display_path(disk.node), disk))
    }
}

/// Moves a disk node to `allocated` bytes. For a walked container root, only the part no file
/// accounts for moves, unless allocation fell below what the walk found (freed and trimmed
/// since): then the directories overstate the disk, and it goes opaque until a scan walks it
/// again. Returns the change to the node's subtree, and whether it went opaque.
fn set_allocated(tree: &mut DirTree, disk: &mut Disk, allocated: u64) -> (Delta, bool) {
    let node = disk.node as usize;
    let files = tree.nodes[node]
        .total_blocks()
        .saturating_sub(disk.unaccounted);
    disk.allocated = Some(allocated);
    if disk.walked && allocated < files {
        let before = tree.nodes[node].sub;
        let own = Delta {
            blocks: tree.nodes[node].own_blocks as i64,
            apparent: tree.nodes[node].own_apparent as i64,
            ..Delta::default()
        };
        for child in std::mem::take(&mut tree.nodes[node].children) {
            tree.detach(child);
        }
        let opaque = Tally {
            blocks: allocated,
            apparent: allocated,
            ..Tally::default()
        };
        let disk_node = &mut tree.nodes[node];
        (disk_node.direct, disk_node.sub) = (opaque, opaque);
        (disk_node.own_blocks, disk_node.own_apparent) = (0, 0);
        let delta = Delta::between(&before, &opaque).plus(own.negate());
        let parent = disk_node.parent;
        tree.propagate(parent, &delta);
        disk.walked = false;
        disk.unaccounted = allocated;
        return (delta, true);
    }
    let unaccounted = if disk.walked {
        allocated - files
    } else {
        allocated
    };
    let change = unaccounted as i64 - disk.unaccounted as i64;
    disk.unaccounted = unaccounted;
    let delta = Delta {
        blocks: change,
        apparent: change,
        ..Delta::default()
    };
    if change != 0 {
        tree.nodes[node].direct.apply(&delta);
        tree.propagate(disk.node, &delta);
    }
    (delta, false)
}

/// The last I/O counters seen per device: `(when, sectors read, sectors written)`.
type Counters = HashMap<String, (Instant, u64, u64)>;

/// Follows allocation and I/O of an `lvm_thin` target until the process exits.
pub fn follow(store: Arc<LiveStore>, lt: Arc<LiveTarget>, interval: Duration) {
    *lt.source.lock().unwrap_or_else(PoisonError::into_inner) = Some("lvm");
    info!(target = %lt.target.name, "following thin pool allocation and I/O");
    std::thread::Builder::new()
        .name("harvester-lvm".to_string())
        .spawn(move || {
            let mut last = Counters::new();
            loop {
                std::thread::sleep(interval);
                if let Err(error) = poll(&store, &lt, &mut last) {
                    warn!(target = %lt.target.name, %error, "thin pool poll failed");
                    std::thread::sleep(interval * 10);
                }
            }
        })
        .expect("spawn an lvm poller");
}

fn poll(store: &LiveStore, lt: &LiveTarget, last: &mut Counters) -> Result<()> {
    let generation = lt
        .state
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .map(|state| state.generation);
    let Some(generation) = generation else {
        return Ok(());
    };
    // Sampled without the lock: `dmsetup` may be slow.
    let sample = sample()?;
    apply(store, lt, generation, &sample, last);
    Ok(())
}

/// Applies a sample to the tree it was taken for. A scan that replaced the tree meanwhile read
/// device-mapper itself, so the sample is dropped rather than written over newer numbers.
/// Events go out under the lock, so they cannot interleave with a scan's.
fn apply(
    store: &LiveStore,
    lt: &LiveTarget,
    generation: u64,
    sample: &Sample,
    last: &mut Counters,
) -> bool {
    let mut guard = lt.state.write().unwrap_or_else(PoisonError::into_inner);
    let Some(state) = guard.as_mut() else {
        return false;
    };
    if state.generation != generation {
        return false;
    }
    let Some(mut pool) = state.tree.pool.take() else {
        return false;
    };
    if let Some((used, size, meta_used, meta_size)) = sample
        .status
        .get(&pool.dm)
        .and_then(|line| pool_usage(line, pool.chunk))
    {
        (pool.used, pool.size, pool.meta_used, pool.meta_size) = (used, size, meta_used, meta_size);
    }
    let mut changes = Vec::new();
    let mut io = Vec::new();
    let mut rescan = false;
    for disk in pool
        .guests
        .iter_mut()
        .flat_map(|guest| guest.disks.iter_mut())
    {
        let mapped = sample
            .status
            .get(&disk.dm)
            .and_then(|line| thin_mapped(line));
        disk.active = mapped.is_some();
        if let Some(sectors) = mapped {
            let allocated = sectors * SECTOR;
            if disk.allocated != Some(allocated) {
                let (delta, opaque) = set_allocated(&mut state.tree, disk, allocated);
                rescan |= opaque;
                if !delta.is_zero() {
                    changes.push((
                        state.tree.display_path(disk.node),
                        delta,
                        state.tree.nodes[disk.node as usize].total_blocks(),
                    ));
                }
            }
        }
        let device = sample.devices.get(&disk.dm).filter(|_| disk.active);
        let Some(device) = device else {
            (disk.read_rate, disk.write_rate) = (0, 0);
            last.remove(&disk.dm);
            continue;
        };
        (disk.read, disk.written) = (device.read * SECTOR, device.written * SECTOR);
        let previous = last.insert(disk.dm.clone(), (sample.at, device.read, device.written));
        if let Some((then, read, written)) = previous {
            let seconds = sample.at.duration_since(then).as_secs_f64().max(0.001);
            let rate = |now: u64, then: u64| {
                (now.saturating_sub(then) as f64 * SECTOR as f64 / seconds) as u64
            };
            disk.read_rate = rate(device.read, read);
            disk.write_rate = rate(device.written, written);
            if disk.read_rate > 0 || disk.write_rate > 0 {
                io.push(json!({
                    "path": state.tree.display_path(disk.node),
                    "w": disk.write_rate, "r": disk.read_rate,
                }));
            }
        }
    }
    last.retain(|name, _| sample.devices.contains_key(name));
    state.tree.pool = Some(pool);
    if rescan {
        lt.request_rescan();
    }
    if !changes.is_empty() {
        state.live_at = Some(SystemTime::now());
    }
    let at = millis(SystemTime::now());
    for (path, delta, total) in changes {
        lt.changes.fetch_add(1, Ordering::Relaxed);
        store.publish(
            "change",
            json!({
                "t": at, "host": store.host, "target": lt.target.name, "path": path,
                "db": delta.blocks, "da": delta.apparent, "df": delta.files, "b": total,
                "src": "lvm",
            }),
        );
    }
    if !io.is_empty() {
        store.broadcast(
            "io",
            json!({ "t": at, "host": store.host, "target": lt.target.name, "disks": io }),
        );
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const LVS: &str = r#"{"report":[{"lv":[
        {"lv_name":"data","vg_name":"pve","pool_lv":"","lv_size":"1884119105536","lv_active":"active"},
        {"lv_name":"vm-100-disk-0","vg_name":"pve","pool_lv":"data","lv_size":"274877906944","lv_active":"active"},
        {"lv_name":"vm-101-disk-0","vg_name":"pve","pool_lv":"data","lv_size":"2147483648","lv_active":"active"},
        {"lv_name":"vm-103-disk-1","vg_name":"pve","pool_lv":"data","lv_size":"34359738368","lv_active":""},
        {"lv_name":"vm-110-disk-0","vg_name":"pve","pool_lv":"data","lv_size":"8589934592","lv_active":"active"}
    ]}],"log":[]}"#;

    const TABLE: &str = "\
pve-data: 0 3679920128 linear 252:4 0
pve-data-tpool: 0 3679920128 thin-pool 252:2 252:3 128 0 0
pve-root: 0 201326592 linear 259:3 16779264
pve-vm--100--disk--0: 0 536870912 thin 252:4 9
pve-vm--101--disk--0: 0 4194304 thin 252:4 6
pve-vm--110--disk--0: 0 16777216 thin 252:4 40
";

    const STATUS: &str = "\
pve-data: 0 3679920128 linear
pve-data-tpool: 0 3679920128 thin-pool 6479 44985/4161600 7317162/28749376 - rw discard_passdown queue_if_no_space - 1024
pve-root: 0 201326592 linear
pve-vm--100--disk--0: 0 536870912 thin 248346880 536870911
pve-vm--101--disk--0: 0 4194304 thin 4180096 4194303
pve-vm--110--disk--0: 0 16777216 thin 2048 2047
";

    const STORAGE: &str = "\
dir: local
\tpath /var/lib/vz
\tcontent vztmpl,iso,backup

lvmthin: local-lvm
\tthinpool data
\tvgname pve
\tcontent images,rootdir
";

    const QEMU_100: &str = "\
boot: order=scsi0
ide2: local:iso/ubuntu.iso,media=cdrom
name: NUC
scsi0: local-lvm:vm-100-disk-0,discard=on,size=256G,ssd=1
smbios1: uuid=B43CEE7A-FE05-47EC-A7AB-6A0AEC8F248C
[before-upgrade]
scsi1: local-lvm:vm-100-disk-9,size=1G
";

    const LXC_101: &str = "\
hostname: tailscale
mp0: /mnt/host,mp=/data
rootfs: local-lvm:vm-101-disk-0,size=2G
unprivileged: 1
";

    const QEMU_103: &str = "\
name: hassos
sata0: local-lvm:vm-103-disk-1,size=32G
";

    fn target() -> Target {
        let config: crate::config::Config = serde_yaml::from_str(
            "defaults:\n  report_depth: 2\ntargets:\n  - name: local_lvm\n    type: lvm_thin\n    path: /local-lvm\n    pool: pve/data\n",
        )
        .unwrap();
        config.resolved_targets().unwrap().remove(0)
    }

    fn inputs() -> Inputs {
        Inputs {
            volumes: parse_lvs(LVS, "data").unwrap(),
            tables: parse_dmsetup(TABLE),
            sample: Sample {
                status: parse_dmsetup(STATUS),
                devices: HashMap::from([(
                    "pve-vm--100--disk--0".to_string(),
                    Device {
                        dev: "252:9".to_string(),
                        read: 10,
                        written: 20,
                    },
                )]),
                at: Instant::now(),
            },
            storages: parse_storage_cfg(STORAGE),
            guests: vec![
                (
                    100,
                    GuestKind::Qemu,
                    parse_guest_config(QEMU_100, GuestKind::Qemu),
                ),
                (
                    101,
                    GuestKind::Lxc,
                    parse_guest_config(LXC_101, GuestKind::Lxc),
                ),
                (
                    103,
                    GuestKind::Qemu,
                    parse_guest_config(QEMU_103, GuestKind::Qemu),
                ),
            ],
        }
    }

    #[test]
    fn parses_device_mapper_and_proxmox_configs() {
        assert_eq!(dm_name("pve", "vm-100-disk-0"), "pve-vm--100--disk--0");
        let status = parse_dmsetup(STATUS);
        let tables = parse_dmsetup(TABLE);
        assert_eq!(pool_chunk(&tables["pve-data-tpool"]), Some(64 * 1024));
        assert_eq!(
            pool_usage(&status["pve-data-tpool"], 64 * 1024),
            Some((
                7317162 * 65536,
                28749376 * 65536,
                44985 * 4096,
                4161600 * 4096
            ))
        );
        assert_eq!(
            thin_mapped(&status["pve-vm--100--disk--0"]),
            Some(248346880)
        );
        assert_eq!(thin_mapped(&status["pve-root"]), None);

        let qemu = parse_guest_config(QEMU_100, GuestKind::Qemu);
        assert_eq!(qemu.name.as_deref(), Some("NUC"));
        assert_eq!(
            qemu.uuid.as_deref(),
            Some("b43cee7a-fe05-47ec-a7ab-6a0aec8f248c")
        );
        // Volumes on any storage (the build keeps the pool's); not the snapshot section's.
        assert_eq!(
            qemu.volumes,
            vec![
                (
                    "ide2".to_string(),
                    "local".to_string(),
                    "iso/ubuntu.iso".to_string(),
                    false
                ),
                (
                    "scsi0".to_string(),
                    "local-lvm".to_string(),
                    "vm-100-disk-0".to_string(),
                    true
                ),
            ]
        );
        let lxc = parse_guest_config(LXC_101, GuestKind::Lxc);
        assert_eq!(lxc.name.as_deref(), Some("tailscale"));
        assert_eq!(lxc.volumes.len(), 1, "the bind mount is not a volume");
        let storages = parse_storage_cfg(STORAGE);
        assert_eq!(storages[1].id, "local-lvm");
        assert_eq!(storages[1].thinpool.as_deref(), Some("data"));
    }

    #[test]
    fn builds_pool_guests_and_disks() {
        let (pool, tree) = build(&target(), target().lvm.as_ref().unwrap(), &inputs()).unwrap();
        assert_eq!(pool.storage, "local-lvm");
        assert_eq!(pool.dm, "pve-data-tpool");
        assert_eq!(pool.used, 7317162 * 65536);
        assert_eq!(
            pool.provisioned,
            274877906944 + 2147483648 + 34359738368 + 8589934592
        );
        let names: Vec<String> = pool.guests.iter().map(|g| g.name.clone()).collect();
        assert_eq!(names, ["NUC", "tailscale", "hassos", "Unattached"]);
        let nuc = tree.find("/local-lvm/NUC (100)/scsi0").unwrap();
        assert_eq!(tree.nodes[nuc as usize].total_blocks(), 248346880 * 512);
        // An inactive volume: listed, size unknown.
        let hassos = &pool.guests[2].disks[0];
        assert_eq!(
            (hassos.active, hassos.allocated, hassos.size),
            (false, None, 34359738368)
        );
        // Counters as of the scan, not zero until the first poll.
        let scsi0 = &pool.guests[0].disks[0];
        assert_eq!((scsi0.read, scsi0.written), (10 * 512, 20 * 512));
        assert!(tree.find("/local-lvm/Unattached/vm-110-disk-0").is_some());
        let disks: u64 = pool
            .guests
            .iter()
            .flat_map(|g| &g.disks)
            .filter_map(|d| d.allocated)
            .sum();
        assert_eq!(tree.root().total_blocks(), disks);

        let mut object = Map::new();
        pool.annotate(nuc, &mut object);
        assert_eq!(object["v"], "disk");
        assert_eq!(object["p"], 274877906944u64);
        assert_eq!(object["u"], 248346880u64 * 512);
        let reported = native::reported(&target(), &tree);
        assert!(reported
            .iter()
            .any(|o| o.path == "/local-lvm/NUC (100)/scsi0"));
    }

    #[test]
    fn a_walked_container_sits_in_its_root_disk() {
        let temp = tempfile::tempdir().unwrap();
        let root = &temp.path().join("ct");
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::create_dir_all(root.join("var/lib")).unwrap();
        fs::write(root.join("var/lib/db"), vec![1u8; 300_000]).unwrap();
        fs::write(root.join("etc/conf"), vec![1u8; 10_000]).unwrap();
        let target = target();
        let (mut pool, mut tree) = build(&target, target.lvm.as_ref().unwrap(), &inputs()).unwrap();
        let display = PathBuf::from(tree.display_path(pool.guests[1].disks[0].node));
        // Through a symlink with a trailing slash, as `/proc/<pid>/root/` is walked.
        let link = temp.path().join("root-link");
        std::os::unix::fs::symlink(root, &link).unwrap();
        let mut walk = target.clone();
        walk.lvm = None;
        walk.scan_path = PathBuf::from(format!("{}/", link.display()));
        walk.display_path = display;
        walk.report_depth = 0;
        let walked = NativeScanner::new(&walk)
            .unwrap()
            .scan(&walk, &AtomicBool::new(false))
            .unwrap()
            .tree
            .unwrap();
        let files = walked.root().total_blocks();
        let before = tree.root().total_blocks();
        graft_walk(&mut tree, &mut pool.guests[1].disks[0], walked);
        pool.reindex();
        let disk_node = pool.guests[1].disks[0].node;
        let allocated = 4180096 * 512;
        assert_eq!(tree.nodes[disk_node as usize].total_blocks(), allocated);
        assert_eq!(
            tree.root().total_blocks(),
            before,
            "the disk keeps its size"
        );
        assert_eq!(pool.guests[1].disks[0].unaccounted, allocated - files);
        let db = tree
            .find("/local-lvm/tailscale (101)/rootfs/var/lib")
            .expect("container directories under the disk");
        assert_eq!(tree.nodes[db as usize].depth, 4);
        let mut object = Map::new();
        pool.annotate(disk_node, &mut object);
        assert_eq!(object["v"], "disk", "the walked root is the disk now");

        // Allocation grows: only the unaccounted part moves.
        let (delta, opaque) =
            set_allocated(&mut tree, &mut pool.guests[1].disks[0], allocated + 65536);
        assert_eq!((delta.blocks, opaque), (65536, false));
        assert_eq!(tree.root().total_blocks(), before + 65536);
        // Trimmed below what the walk found: the disk is its allocation again, opaque, until
        // a scan walks it.
        let (_, opaque) = set_allocated(&mut tree, &mut pool.guests[1].disks[0], files / 2);
        assert!(opaque);
        assert_eq!(tree.nodes[disk_node as usize].total_blocks(), files / 2);
        assert_eq!(tree.root().total_blocks(), before - allocated + files / 2);
        assert!(tree.find("/local-lvm/tailscale (101)/rootfs/var").is_none());
        assert!(!pool.guests[1].disks[0].walked);
        let guest = tree.find("/local-lvm/tailscale (101)").unwrap();
        assert_eq!(tree.nodes[guest as usize].sub.files, 0);
    }

    /// Polls follow a volume that comes and goes between scans, and never write a sample over
    /// a newer scan.
    #[test]
    fn polls_follow_activation_and_skip_replaced_trees() {
        let target = target();
        let (pool, mut tree) = build(&target, target.lvm.as_ref().unwrap(), &inputs()).unwrap();
        tree.pool = Some(Box::new(pool));
        let store = LiveStore::new(
            "pve".into(),
            std::slice::from_ref(&target),
            Path::new("/"),
            Duration::ZERO,
        )
        .unwrap();
        store.replace(0, tree, SystemTime::now(), Duration::ZERO);
        let lt = &store.targets[0];
        let mut events = store.subscribe();
        let total = || {
            lt.state
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .tree
                .root()
                .total_blocks()
        };
        let hassos = |f: &dyn Fn(&Disk)| {
            let guard = lt.state.read().unwrap();
            f(&guard.as_ref().unwrap().tree.pool.as_ref().unwrap().guests[2].disks[0])
        };
        let before = total();
        let started = Instant::now();
        let sample = |sectors: Option<u64>, written: u64, at: Duration| {
            let mut status = parse_dmsetup(STATUS);
            let mut devices = HashMap::new();
            if let Some(sectors) = sectors {
                let name = "pve-vm--103--disk--1".to_string();
                status.insert(name.clone(), format!("0 67108864 thin {sectors} 2047"));
                devices.insert(
                    name,
                    Device {
                        dev: "252:31".to_string(),
                        read: 0,
                        written,
                    },
                );
            }
            Sample {
                status,
                devices,
                at: started + at,
            }
        };
        let mut last = Counters::new();

        // Started after the scan: picked up by the next poll.
        assert!(apply(
            &store,
            lt,
            1,
            &sample(Some(2000), 100, Duration::ZERO),
            &mut last
        ));
        assert_eq!(total(), before + 2000 * 512);
        hassos(&|disk| assert_eq!((disk.active, disk.allocated), (true, Some(2000 * 512))));
        let event: Value = serde_json::from_str(&events.try_recv().unwrap().data).unwrap();
        assert_eq!(event["path"], "/local-lvm/hassos (103)/sata0");
        assert_eq!(event["db"], 2000 * 512);
        // Writing: a rate from the second sample on.
        apply(
            &store,
            lt,
            1,
            &sample(Some(2000), 300, Duration::from_secs(1)),
            &mut last,
        );
        hassos(&|disk| assert_eq!(disk.write_rate, 200 * 512));
        // Stopped: inactive, idle, its allocation kept (the pool still holds it).
        apply(
            &store,
            lt,
            1,
            &sample(None, 0, Duration::from_secs(2)),
            &mut last,
        );
        hassos(&|disk| {
            assert_eq!((disk.active, disk.write_rate), (false, 0));
            assert_eq!(disk.allocated, Some(2000 * 512));
        });
        assert!(!last.contains_key("pve-vm--103--disk--1"));
        // Sampled for a tree a scan has replaced since: dropped.
        assert!(!apply(
            &store,
            lt,
            0,
            &sample(Some(9000), 0, Duration::ZERO),
            &mut last
        ));
        assert_eq!(total(), before + 2000 * 512);
    }

    #[test]
    fn commands_past_their_deadline_are_killed() {
        let started = Instant::now();
        let error = run("sleep", &["5"], Duration::from_millis(200)).unwrap_err();
        assert!(error.to_string().contains("took longer"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(
            run("sh", &["-c", "echo hi"], Duration::from_secs(5)).unwrap(),
            "hi\n"
        );
    }

    /// The walk follows the directory a descriptor holds, wherever its path goes, and a root
    /// on another device than the container's volume is refused.
    #[cfg(target_os = "linux")]
    #[test]
    fn container_roots_are_pinned_and_checked() {
        use std::os::unix::fs::MetadataExt;
        let temp = tempfile::tempdir().unwrap();
        let ct = temp.path().join("ct");
        fs::create_dir_all(ct.join("etc")).unwrap();
        fs::write(ct.join("etc/conf"), vec![1u8; 50_000]).unwrap();
        let root = fs::File::open(&ct).unwrap();
        let dev = root.metadata().unwrap().dev();
        check_root_device(&root, &format!("{}:{}", libc::major(dev), libc::minor(dev))).unwrap();
        assert!(check_root_device(&root, "1:2").is_err());

        // Swap the path for one leading elsewhere: the walk still sees the original.
        fs::rename(&ct, temp.path().join("moved")).unwrap();
        fs::create_dir_all(ct.join("other")).unwrap();
        let mut target = target();
        target.exclude.clear();
        let walked = walk_container(
            &target,
            &root,
            PathBuf::from("/local-lvm/ct (1)/rootfs"),
            1000,
            &AtomicBool::new(false),
        )
        .unwrap()
        .tree
        .unwrap();
        assert!(walked.find("/local-lvm/ct (1)/rootfs/etc").is_some());
        assert!(walked.find("/local-lvm/ct (1)/rootfs/other").is_none());
    }
}
