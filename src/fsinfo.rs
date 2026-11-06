//! Which filesystem a target lives on, and how full that filesystem is.
//!
//! Targets can alias one another: on the NUC, `/var/lib/docker` is a bind mount of a directory
//! on the disk mounted at `/mnt/scratch`. Mount IDs and paths *inside* the filesystem (from
//! `/proc/self/mountinfo`) tell the atlas that one target contains another.
//!
//! It also says which whole disks a filesystem sits on, and which machine this is, so the atlas
//! can draw a VM's filesystems inside the hypervisor's disk for that VM.

use std::ffi::CString;
use std::fs;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsLocation {
    /// `major:minor` of the filesystem.
    pub id: String,
    pub fstype: String,
    /// The mount point, as a host path (with `host_root` taken off).
    pub mount: String,
    /// The target's path inside the filesystem.
    pub fs_path: String,
    /// The whole disks under it (see [`disks_of`]).
    pub disks: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub size: u64,
    pub used: u64,
    pub avail: u64,
    /// Free to root only.
    pub reserved: u64,
}

#[derive(Debug, Clone)]
struct Mount {
    id: String,
    root: PathBuf,
    point: PathBuf,
    fstype: String,
}

/// Where `scan_path` lives. Without mountinfo (not Linux), the device number stands in.
pub fn locate(scan_path: &Path, host_root: &Path) -> Option<FsLocation> {
    let mounts = fs::read_to_string("/proc/self/mountinfo")
        .map(|text| parse_mountinfo(&text))
        .unwrap_or_default();
    let mut location =
        locate_in(&mounts, scan_path, host_root).or_else(|| fallback(scan_path, host_root))?;
    location.disks = disks_of(&location.id);
    Some(location)
}

fn fallback(scan_path: &Path, host_root: &Path) -> Option<FsLocation> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(scan_path).ok()?;
    let dev = metadata.dev();
    Some(FsLocation {
        id: format!("dev:{dev}"),
        fstype: String::new(),
        mount: "/".to_string(),
        fs_path: host_path(scan_path, host_root),
        disks: Vec::new(),
    })
}

fn locate_in(mounts: &[Mount], scan_path: &Path, host_root: &Path) -> Option<FsLocation> {
    // The last mount listed over a path is the visible one; take the longest mount point and,
    // among equals, the latest.
    let mount = mounts
        .iter()
        .enumerate()
        .filter(|(_, mount)| scan_path.starts_with(&mount.point))
        .max_by_key(|(order, mount)| (mount.point.components().count(), *order))
        .map(|(_, mount)| mount)?;
    let inside = scan_path.strip_prefix(&mount.point).ok()?;
    let fs_path = normalize(&mount.root.join(inside));
    // Name the filesystem by where its root is mounted, not by a bind mount of a part of it.
    let label = mounts
        .iter()
        .find(|other| other.id == mount.id && other.root == Path::new("/"))
        .unwrap_or(mount);
    Some(FsLocation {
        id: mount.id.clone(),
        fstype: mount.fstype.clone(),
        mount: host_path(&label.point, host_root),
        fs_path,
        disks: Vec::new(),
    })
}

/// A container path as the host sees it: `/host/mnt/x` with host_root `/host` is `/mnt/x`.
fn host_path(path: &Path, host_root: &Path) -> String {
    let relative = path.strip_prefix(host_root).unwrap_or(path);
    normalize(&Path::new("/").join(relative))
}

fn normalize(path: &Path) -> String {
    let mut out = PathBuf::from("/");
    for component in path.components() {
        if let Component::Normal(part) = component {
            out.push(part);
        }
    }
    out.display().to_string()
}

fn parse_mountinfo(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|line| {
            let (left, right) = line.split_once(" - ")?;
            let fields: Vec<&str> = left.split(' ').collect();
            let fstype = right.split(' ').next()?;
            Some(Mount {
                id: fields.get(2)?.to_string(),
                root: PathBuf::from(unescape(fields.get(3)?)),
                point: PathBuf::from(unescape(fields.get(4)?)),
                fstype: fstype.to_string(),
            })
        })
        .collect()
}

/// mountinfo writes space, tab, newline and backslash as `\ooo`.
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 4 <= bytes.len() {
            let digits = std::str::from_utf8(&bytes[index + 1..index + 4]).unwrap_or("");
            if let Ok(value) = u8::from_str_radix(digits, 8) {
                out.push(value);
                index += 4;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn usage(path: &Path) -> Option<Usage> {
    let path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is NUL-terminated and `stat` is valid for writes.
    if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: `statvfs` succeeded, so it filled `stat`.
    let stat = unsafe { stat.assume_init() };
    // The field types differ between platforms.
    #[allow(clippy::unnecessary_cast)]
    let (blocks, free, avail, frsize) = (
        stat.f_blocks as u64,
        stat.f_bfree as u64,
        stat.f_bavail as u64,
        stat.f_frsize as u64,
    );
    Some(Usage {
        size: blocks.saturating_mul(frsize),
        used: blocks.saturating_sub(free).saturating_mul(frsize),
        avail: avail.saturating_mul(frsize),
        reserved: free.saturating_sub(avail).saturating_mul(frsize),
    })
}

/// The whole disks under block device `id` (`major:minor`), through partitions and
/// device-mapper or md stacks, each named by [`disk_id`]. Empty when sysfs does not know the
/// device (btrfs and other filesystems on anonymous devices, or no `/sys`).
pub fn disks_of(id: &str) -> Vec<String> {
    let mut disks = Vec::new();
    for disk in whole_disks(id) {
        if let Some(name) = disk_id(&disk) {
            if !disks.contains(&name) {
                disks.push(name);
            }
        }
    }
    disks
}

/// The sysfs directories of the whole disks under block device `id`.
fn whole_disks(id: &str) -> Vec<PathBuf> {
    let mut disks: Vec<PathBuf> = Vec::new();
    let mut seen = Vec::new();
    let mut stack = vec![PathBuf::from(format!("/sys/dev/block/{id}"))];
    while let Some(path) = stack.pop() {
        let Ok(device) = fs::canonicalize(&path) else {
            continue;
        };
        if seen.contains(&device) {
            continue;
        }
        seen.push(device.clone());
        let below: Vec<PathBuf> = fs::read_dir(device.join("slaves"))
            .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default();
        if !below.is_empty() {
            stack.extend(below);
            continue;
        }
        let disk = if device.join("partition").exists() {
            device.parent().map(Path::to_path_buf).unwrap_or(device)
        } else {
            device
        };
        if !disks.contains(&disk) {
            disks.push(disk);
        }
    }
    disks
}

/// One block device on a disk under a reported filesystem: the disk itself, a partition, or a
/// device-mapper or md device built on one, and what it holds. The atlas splits a VM disk's
/// blocks that no scanned file accounts for with these: other filesystems, swap, and each
/// filesystem's own metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Block {
    /// The kernel's name: `sda`, `sda2`, `dm-0`.
    pub dev: String,
    /// A whole disk's stable name ([`disk_id`]), a device-mapper device's name.
    pub name: Option<String>,
    pub size: u64,
    pub content: Content,
    /// Partitions of a disk, or the devices built on this one (LVM, md, crypt).
    pub parts: Vec<Block>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Content {
    /// A mounted filesystem. `overhead` is what it keeps for itself (journal, inode tables,
    /// bitmaps): the device's size less the blocks `statvfs` counts.
    Filesystem {
        id: String,
        fstype: String,
        mount: String,
        used: u64,
        size: u64,
        overhead: u64,
    },
    /// A swap area, and how much of it is in use now.
    Swap { used: u64 },
    /// A device-mapper thin pool: its volumes are the `lvm_thin` target's business.
    ThinPool,
    /// Something else is built on it (`parts`), or nothing this machine has mounted.
    #[default]
    Other,
}

impl Block {
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;
        let mut object = json!({ "dev": self.dev, "size": self.size });
        if let Some(name) = &self.name {
            object["name"] = json!(name);
        }
        match &self.content {
            Content::Filesystem {
                id,
                fstype,
                mount,
                used,
                size,
                overhead,
            } => {
                object["use"] = json!("fs");
                object["fs"] = json!(id);
                object["type"] = json!(fstype);
                object["mount"] = json!(mount);
                object["used"] = json!(used);
                object["fs_size"] = json!(size);
                object["overhead"] = json!(overhead);
            }
            Content::Swap { used } => {
                object["use"] = json!("swap");
                object["swap_used"] = json!(used);
            }
            Content::ThinPool => object["use"] = json!("thin_pool"),
            Content::Other => {
                object["use"] = json!(if self.parts.is_empty() {
                    "none"
                } else {
                    "holder"
                });
            }
        }
        if !self.parts.is_empty() {
            object["parts"] = json!(self.parts.iter().map(Block::to_json).collect::<Vec<_>>());
        }
        object
    }
}

/// The whole disks under the filesystems `ids` (`major:minor`), each with its partitions and
/// what is on them. Empty without `/sys` (or for filesystems on no block device).
pub fn layout(ids: &[String], host_root: &Path) -> Vec<Block> {
    let mounts = fs::read_to_string("/proc/self/mountinfo")
        .map(|text| parse_mountinfo(&text))
        .unwrap_or_default();
    let swaps = fs::read_to_string("/proc/swaps")
        .map(|text| parse_swaps(&text))
        .unwrap_or_default();
    let mut disks: Vec<PathBuf> = Vec::new();
    for id in ids {
        for disk in whole_disks(id) {
            if !disks.contains(&disk) {
                disks.push(disk);
            }
        }
    }
    disks
        .iter()
        .map(|disk| {
            let mut block = describe(disk, &mounts, &swaps, host_root, 0);
            block.name = disk_id(disk);
            block
        })
        .collect()
}

fn describe(
    device: &Path,
    mounts: &[Mount],
    swaps: &[(String, u64)],
    host_root: &Path,
    depth: usize,
) -> Block {
    let read = |file: &str| fs::read_to_string(device.join(file)).map(|t| t.trim().to_string());
    let dev = device
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let size = read("size")
        .ok()
        .and_then(|sectors| sectors.parse::<u64>().ok())
        .unwrap_or(0)
        * 512;
    let name = read("dm/name").ok().filter(|name| !name.is_empty());
    let pool = name.as_deref().is_some_and(|name| name.ends_with("-tpool"));
    let mut parts = Vec::new();
    if depth < 4 && !pool {
        let mut partitions: Vec<PathBuf> = fs::read_dir(device)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.path())
                    .filter(|path| path.join("partition").exists())
                    .collect()
            })
            .unwrap_or_default();
        if partitions.is_empty() {
            partitions = fs::read_dir(device.join("holders"))
                .map(|entries| {
                    entries
                        .flatten()
                        .filter_map(|entry| fs::canonicalize(entry.path()).ok())
                        .collect()
                })
                .unwrap_or_default();
        }
        partitions.sort();
        for part in partitions {
            let mut block = describe(&part, mounts, swaps, host_root, depth + 1);
            // A partition's own holders hang under it.
            if block.parts.is_empty() && block.content == Content::Other {
                block.parts = fs::read_dir(part.join("holders"))
                    .map(|entries| {
                        entries
                            .flatten()
                            .filter_map(|entry| fs::canonicalize(entry.path()).ok())
                            .map(|holder| describe(&holder, mounts, swaps, host_root, depth + 2))
                            .collect()
                    })
                    .unwrap_or_default();
            }
            parts.push(block);
        }
    }
    let number = read("dev").unwrap_or_default();
    let content = if pool {
        Content::ThinPool
    } else if !parts.is_empty() {
        Content::Other
    } else if let Some((_, used)) = swaps
        .iter()
        .find(|(swap, _)| *swap == dev || name.as_deref() == Some(swap.as_str()))
    {
        Content::Swap { used: *used }
    } else if let Some(mount) =
        mounts
            .iter()
            .filter(|mount| mount.id == number)
            .min_by_key(|mount| {
                (
                    mount.root != Path::new("/"),
                    mount.point.components().count(),
                )
            })
    {
        match usage(&mount.point) {
            Some(usage) => Content::Filesystem {
                id: number.clone(),
                fstype: mount.fstype.clone(),
                mount: host_path(&mount.point, host_root),
                used: usage.used,
                size: usage.size,
                overhead: size.saturating_sub(usage.size),
            },
            None => Content::Other,
        }
    } else {
        Content::Other
    };
    Block {
        dev,
        name,
        size,
        content,
        parts,
    }
}

/// `/proc/swaps`: each swap area's device name (`sdb1`, or a device-mapper name for
/// `/dev/mapper/x`) and the bytes in use.
fn parse_swaps(text: &str) -> Vec<(String, u64)> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.get(1) != Some(&"partition") {
                return None;
            }
            let name = fields.first()?.rsplit('/').next()?.to_string();
            let used: u64 = fields.get(3)?.parse().ok()?;
            Some((name, used * 1024))
        })
        .collect()
}

/// Which hypervisor this machine runs under, if any: `qemu` (KVM/Proxmox), `vmware`,
/// `hyperv`, `virtualbox`, `xen`, or `vm` for one the CPU flags give away but the firmware
/// does not name. `None` on bare metal.
pub fn machine_virt(host_root: &Path) -> Option<String> {
    let dmi = |file: &str| {
        [
            host_root.join("sys/class/dmi/id").join(file),
            PathBuf::from("/sys/class/dmi/id").join(file),
        ]
        .iter()
        .find_map(|path| fs::read_to_string(path).ok())
        .map(|text| text.trim().to_string())
        .unwrap_or_default()
    };
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    virt_from(&dmi("sys_vendor"), &dmi("product_name"), &cpuinfo)
}

fn virt_from(vendor: &str, product: &str, cpuinfo: &str) -> Option<String> {
    let both = format!("{vendor} {product}").to_ascii_lowercase();
    let named = [
        ("qemu", "qemu"),
        ("kvm", "qemu"),
        ("vmware", "vmware"),
        ("virtualbox", "virtualbox"),
        ("innotek", "virtualbox"),
        ("xen", "xen"),
    ]
    .iter()
    .find(|(needle, _)| both.contains(needle))
    .map(|(_, kind)| kind.to_string());
    if named.is_some() {
        return named;
    }
    if both.contains("microsoft") && both.contains("virtual") {
        return Some("hyperv".to_string());
    }
    let flagged = cpuinfo.lines().any(|line| {
        line.starts_with("flags") && line.split_whitespace().any(|flag| flag == "hypervisor")
    });
    flagged.then(|| "vm".to_string())
}

/// A disk's stable name: the vendor-specific designator of SCSI VPD page 0x83 (QEMU names its
/// disks `drive-scsi0`, `drive-virtio1`, ...), else its serial or WWID.
fn disk_id(disk: &Path) -> Option<String> {
    if let Some(name) = fs::read(disk.join("device/vpd_pg83"))
        .ok()
        .and_then(|page| vpd83_vendor_id(&page))
    {
        return Some(name);
    }
    ["serial", "device/serial", "wwid", "device/wwid"]
        .iter()
        .filter_map(|file| fs::read_to_string(disk.join(file)).ok())
        .map(|text| text.trim().to_string())
        .find(|text| !text.is_empty())
}

/// The first ASCII or UTF-8 vendor-specific (type 0) designator in a VPD page 0x83.
fn vpd83_vendor_id(page: &[u8]) -> Option<String> {
    if page.len() < 4 || page[1] != 0x83 {
        return None;
    }
    let end = (4 + u16::from_be_bytes([page[2], page[3]]) as usize).min(page.len());
    let mut at = 4;
    while at + 4 <= end {
        let code_set = page[at] & 0x0f;
        let kind = page[at + 1] & 0x0f;
        let len = page[at + 3] as usize;
        let data = page.get(at + 4..at + 4 + len)?;
        if kind == 0 && matches!(code_set, 2 | 3) {
            let text = String::from_utf8_lossy(data);
            let text = text.trim_matches(|c: char| c == '\0' || c.is_whitespace());
            if !text.is_empty() {
                return Some(text.to_string());
            }
        }
        at += 4 + len;
    }
    None
}

/// This machine's SMBIOS product UUID, lowercase. For a Proxmox VM it is the `smbios1: uuid=`
/// of its config. Root-only; `None` when unreadable.
pub fn machine_uuid(host_root: &Path) -> Option<String> {
    [
        host_root.join("sys/class/dmi/id/product_uuid"),
        PathBuf::from("/sys/class/dmi/id/product_uuid"),
    ]
    .iter()
    .filter_map(|path| fs::read_to_string(path).ok())
    .map(|text| text.trim().to_ascii_lowercase())
    .find(|text| text.len() == 36 && text.chars().all(|c| c.is_ascii_hexdigit() || c == '-'))
}

/// The filesystem ID fanotify stamps on every event (`statfs`'s `f_fsid`).
#[cfg(target_os = "linux")]
pub fn fsid(path: &Path) -> Option<[i32; 2]> {
    let path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `path` is NUL-terminated and `stat` is valid for writes.
    if unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: `statfs` succeeded. `fsid_t` is two ints with private fields in the libc crate.
    let stat = unsafe { stat.assume_init() };
    Some(unsafe { std::mem::transmute::<libc::fsid_t, [i32; 2]>(stat.f_fsid) })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
29 1 252:0 / / rw,relatime shared:1 - ext4 /dev/mapper/vg-root rw
5293 5200 252:0 / /host ro,relatime master:1 - ext4 /dev/mapper/vg-root rw
5821 5293 8:18 / /host/mnt/scratch ro,relatime master:66 - ext4 /dev/sdb2 rw
6074 5293 8:18 /docker /host/var/lib/docker ro,relatime master:66 - ext4 /dev/sdb2 rw
7000 5293 0:45 /@syno /host/volume1 ro - btrfs /dev/mapper/cachedev_1 rw
7001 5293 0:46 /my\\040share /host/odd\\040place ro - ext4 /dev/sdc1 rw
";

    #[test]
    fn bind_mounts_resolve_to_paths_inside_one_filesystem() {
        let mounts = parse_mountinfo(SAMPLE);
        let host = Path::new("/host");
        let containers =
            locate_in(&mounts, Path::new("/host/var/lib/docker/containers"), host).unwrap();
        assert_eq!(containers.id, "8:18");
        assert_eq!(containers.fs_path, "/docker/containers");
        assert_eq!(containers.mount, "/mnt/scratch", "named by the root mount");
        let scratch = locate_in(&mounts, Path::new("/host/mnt/scratch"), host).unwrap();
        assert_eq!(
            (scratch.id.as_str(), scratch.fs_path.as_str()),
            ("8:18", "/")
        );
        let root = locate_in(&mounts, Path::new("/host/var/log"), host).unwrap();
        assert_eq!(
            (root.id.as_str(), root.fs_path.as_str(), root.mount.as_str()),
            ("252:0", "/var/log", "/")
        );
        let share = locate_in(&mounts, Path::new("/host/volume1/data"), host).unwrap();
        assert_eq!(
            (share.fstype.as_str(), share.fs_path.as_str()),
            ("btrfs", "/@syno/data")
        );
        let odd = locate_in(&mounts, Path::new("/host/odd place/x"), host).unwrap();
        assert_eq!(odd.fs_path, "/my share/x");
    }

    #[test]
    fn qemu_disks_are_named_by_their_vpd_vendor_designator() {
        // /sys/block/sda/device/vpd_pg83 of a Proxmox VM's scsi0.
        let page = b"\x00\x83\x00\x0f\x02\x00\x00\x0bdrive-scsi0";
        assert_eq!(vpd83_vendor_id(page).as_deref(), Some("drive-scsi0"));
        // An NAA designator (binary, type 3) first, then the vendor one.
        let mut page = vec![0x00, 0x83, 0x00, 0x18, 0x01, 0x03, 0x00, 0x08];
        page.extend_from_slice(&[0x60, 0, 0, 0, 0, 0, 0, 1]);
        page.extend_from_slice(b"\x02\x00\x00\x0ddrive-virtio1");
        page[3] = (page.len() - 4) as u8;
        assert_eq!(vpd83_vendor_id(&page).as_deref(), Some("drive-virtio1"));
        assert_eq!(vpd83_vendor_id(b"\x00\x80\x00\x00"), None);
    }

    #[test]
    fn swaps_and_hypervisors_are_read() {
        let swaps = parse_swaps(
            "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n\
             /dev/sdb1                               partition\t8388604\t\t6541156\t\t10\n\
             /swapfile                               file\t\t1048572\t\t0\t\t-2\n\
             /dev/mapper/pbs-swap                    partition\t8388604\t\t0\t\t-3\n",
        );
        assert_eq!(
            swaps,
            vec![
                ("sdb1".to_string(), 6541156 * 1024),
                ("pbs-swap".to_string(), 0)
            ]
        );
        let flags = "flags\t\t: fpu vme de pse hypervisor lahf_lm\n";
        assert_eq!(
            virt_from("QEMU", "Standard PC (i440FX + PIIX, 1996)", flags).as_deref(),
            Some("qemu")
        );
        assert_eq!(
            virt_from("Microsoft Corporation", "Virtual Machine", "").as_deref(),
            Some("hyperv")
        );
        assert_eq!(
            virt_from("Some Board Co", "Venus Series", flags).as_deref(),
            Some("vm")
        );
        assert_eq!(
            virt_from(
                "Micro Computer (HK) Tech Limited",
                "Venus Series",
                "flags : fpu vme\n"
            ),
            None
        );
    }

    #[test]
    fn a_block_describes_its_contents_as_json() {
        let disk = Block {
            dev: "sdb".to_string(),
            name: Some("drive-scsi1".to_string()),
            size: 200,
            content: Content::Other,
            parts: vec![
                Block {
                    dev: "sdb1".to_string(),
                    size: 80,
                    content: Content::Swap { used: 60 },
                    ..Block::default()
                },
                Block {
                    dev: "sdb2".to_string(),
                    size: 120,
                    content: Content::Filesystem {
                        id: "8:18".to_string(),
                        fstype: "ext4".to_string(),
                        mount: "/mnt/scratch".to_string(),
                        used: 50,
                        size: 115,
                        overhead: 5,
                    },
                    ..Block::default()
                },
            ],
        };
        let json = disk.to_json();
        assert_eq!(json["name"], "drive-scsi1");
        assert_eq!(json["use"], "holder");
        assert_eq!(json["parts"][0]["use"], "swap");
        assert_eq!(json["parts"][0]["swap_used"], 60);
        assert_eq!(json["parts"][1]["fs"], "8:18");
        assert_eq!(json["parts"][1]["overhead"], 5);
    }

    #[test]
    fn usage_of_the_current_directory_adds_up() {
        let usage = usage(Path::new(".")).unwrap();
        assert!(usage.size > 0);
        assert!(usage.used + usage.avail + usage.reserved <= usage.size + 4096);
    }
}
