//! Synology's synotify: change events with full paths, on DSM kernels.
//!
//! DSM 7's 4.4 kernel has fanotify compiled out, so its btrfs targets were followed by
//! generation polling alone. A new entry showed within a poll, but a write only once writeback
//! put its extents in the tree (~15 s), and a deletion only once the transaction committed
//! (~30 s). Synology's kernel adds its own notifier, which its indexer and Drive use (syscalls
//! 822-824 on x86_64). A mark covers one mount, and each event names the changed entry by its
//! full path, as the process that made the change sees it, with that process's pid.
//!
//! - Creates, deletes, renames and truncations reach the marks on every mount of the
//!   filesystem in the acting process's mount namespace; writes reach only the mount the file
//!   was opened through. So the watcher marks every mount of the targets' filesystems in every
//!   mount namespace it can see: containers' too, given `pid: host`, with `CAP_SYS_PTRACE` to
//!   pass through `/proc/<pid>/root` of other users' processes. It looks again every few
//!   seconds, for containers started since.
//! - A path is mapped back through the mount table of the acting process's namespace to the
//!   filesystem, then to a target. The directory holding the entry is the one re-read.
//!
//! Generation polling keeps running underneath: it catches what no mark saw (mounts made
//! between looks, an overflowed queue, writes through `mmap`, reflinks).
#![cfg_attr(
    not(all(target_os = "linux", target_arch = "x86_64")),
    allow(dead_code)
)]

use std::collections::HashMap;
use std::path::PathBuf;

/// A mount of a watched filesystem, as one mount namespace has it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NsMount {
    dev: String,
    /// The mounted directory, inside the filesystem.
    root: Vec<u8>,
    /// Where it is mounted, in the namespace.
    point: Vec<u8>,
}

/// A target that changes are mapped into.
#[derive(Debug, Clone)]
pub struct Watched {
    pub index: usize,
    /// `major:minor` of its filesystem.
    pub dev: String,
    /// Its directory inside the filesystem ([`crate::fsinfo::FsLocation::fs_path`]).
    pub fs_path: Vec<u8>,
    /// Where this process reads it.
    pub scan_path: PathBuf,
}

/// `path` below `base`, from the `/` that follows it (empty for `base` itself), if `base` is
/// a whole-component prefix of it.
fn below<'a>(path: &'a [u8], base: &[u8]) -> Option<&'a [u8]> {
    let base = base.strip_suffix(b"/").unwrap_or(base);
    let rest = path.strip_prefix(base)?;
    (rest.is_empty() || rest[0] == b'/').then_some(rest)
}

/// The directory holding the entry `path` names.
fn parent(path: &[u8]) -> Option<&[u8]> {
    let path = path.strip_suffix(b"/").unwrap_or(path);
    let cut = path.iter().rposition(|&byte| byte == b'/')?;
    Some(if cut == 0 { b"/" } else { &path[..cut] })
}

/// The mounts in a mountinfo listing that are on `devs` and show some part of a target.
fn parse_mounts(text: &str, targets: &[Watched]) -> Vec<NsMount> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split(' ');
            let dev = fields.nth(2)?;
            let root = unescape(fields.next()?);
            let point = unescape(fields.next()?);
            // A container's own root filesystem can sit on the same btrfs volume; its events
            // could never land in a target, so it is not marked.
            let shows_target = targets.iter().any(|target| {
                target.dev == dev
                    && (below(&target.fs_path, &root).is_some()
                        || below(&root, &target.fs_path).is_some())
            });
            shows_target.then(|| NsMount {
                dev: dev.to_string(),
                root,
                point,
            })
        })
        .collect()
}

/// mountinfo writes space, tab, newline and backslash as `\ooo`.
fn unescape(field: &str) -> Vec<u8> {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 4 <= bytes.len() {
            if let Some(value) = std::str::from_utf8(&bytes[index + 1..index + 4])
                .ok()
                .and_then(|digits| u8::from_str_radix(digits, 8).ok())
            {
                out.push(value);
                index += 4;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

/// Where `path` (as a process in a namespace with `mounts` sees it) lands: each target holding
/// it, with the path inside that target (empty for its root).
fn map(mounts: &[NsMount], targets: &[Watched], path: &[u8]) -> Vec<(usize, Vec<u8>)> {
    // The longest mount point over the path is the mount it was reached through; `max_by_key`
    // keeps the last of equals, the one stacked on top.
    let Some((mount, rest)) = mounts
        .iter()
        .filter_map(|mount| below(path, &mount.point).map(|rest| (mount, rest)))
        .max_by_key(|(mount, _)| mount.point.len())
    else {
        return Vec::new();
    };
    let mut inside_fs = mount
        .root
        .strip_suffix(b"/")
        .unwrap_or(&mount.root)
        .to_vec();
    inside_fs.extend_from_slice(rest);
    targets
        .iter()
        .enumerate()
        .filter(|(_, target)| target.dev == mount.dev)
        .filter_map(|(slot, target)| {
            below(&inside_fs, &target.fs_path).map(|inside| (slot, inside.to_vec()))
        })
        .collect()
}

/// Mount namespaces, by the inode of `/proc/<pid>/ns/mnt`, with their watched mounts.
#[derive(Default)]
struct Namespaces {
    mounts: HashMap<u64, Vec<NsMount>>,
    /// A process in each namespace, to reach its mounts through `/proc/<pid>/root`.
    entry: HashMap<u64, u32>,
    /// Where each process seen at the last look was.
    of_pid: HashMap<u32, u64>,
    /// The namespace of pid 1, tried first for a process gone before its event was read.
    host: Option<u64>,
}

impl Namespaces {
    /// Every place `path`, changed by a process in namespace `ns`, may land. That namespace
    /// decides; when it is unknown, every namespace is asked and each distinct answer kept.
    fn resolve(&self, ns: Option<u64>, targets: &[Watched], path: &[u8]) -> Vec<(usize, Vec<u8>)> {
        if let Some(mounts) = ns.and_then(|ns| self.mounts.get(&ns)) {
            return map(mounts, targets, path);
        }
        let order = self.host.into_iter().chain(
            self.mounts
                .keys()
                .copied()
                .filter(|ns| Some(*ns) != self.host),
        );
        let mut all: Vec<(usize, Vec<u8>)> = Vec::new();
        for ns in order {
            for found in map(&self.mounts[&ns], targets, path) {
                if !all.contains(&found) {
                    all.push(found);
                }
            }
        }
        all
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod imp {
    use std::collections::{HashMap, HashSet};
    use std::ffi::{CString, OsStr};
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use tracing::{info, warn};

    use super::{parent, parse_mounts, Namespaces, Watched};
    use crate::live::LiveStore;
    use crate::who::{Lookup, Resolver};

    const SYS_INIT: libc::c_long = 822;
    const SYS_ADD_WATCH: libc::c_long = 823;
    const SYNO_CLOEXEC: libc::c_long = 0x1;
    const SYNO_EVENT_V2: libc::c_long = 0x4;

    const MODIFY: u32 = 0x2;
    const MOVE_FROM: u32 = 0x40;
    const MOVE_TO: u32 = 0x80;
    const CREATE: u32 = 0x100;
    const DELETE: u32 = 0x200;
    const Q_OVERFLOW: u32 = 0x4000;
    /// Every change to what a directory holds or how big its files are. (Truncation arrives
    /// as a modify; directory events need no flag of their own.)
    const MASK: u64 = (MODIFY | MOVE_FROM | MOVE_TO | CREATE | DELETE) as u64;
    /// `struct synotify_event_v2`: mask, cookie, len, pid, uid; then `len` bytes of path.
    const HEADER: usize = 20;
    /// The pause after each read, for events to gather.
    const READ_PAUSE: Duration = Duration::from_millis(20);
    /// How often to look for new mount namespaces (containers started since). Listing
    /// `/proc` is most of the watcher's cost: about 1.5 ms for 800 processes.
    const LOOK_EVERY: Duration = Duration::from_secs(2);
    /// Every this many looks, every namespace is read again, for mounts added to one.
    const FULL_LOOK: u32 = 15;

    pub struct Watcher {
        fd: OwnedFd,
        targets: Vec<Watched>,
        /// `st_dev` of each target's root: a directory on another (a nested subvolume) is not
        /// the target's.
        root_devs: Vec<u64>,
        namespaces: Namespaces,
        /// Namespaces the last look found.
        young: Vec<u64>,
        /// Names the process behind each change, when its PID means something here.
        resolver: Option<Resolver>,
        /// Whether event PIDs are this process's PIDs; without it they name nothing here.
        host_pids: bool,
        marks: usize,
        unreachable: usize,
    }

    /// Whether this process sees the host's PIDs, the ones synotify reports (`pid: host`): it
    /// is in the initial PID namespace, whose inode is fixed (`PROC_PID_INIT_INO`).
    fn host_pids() -> bool {
        std::fs::read_link("/proc/self/ns/pid").is_ok_and(|ns| ns.as_os_str() == "pid:[4026531836]")
    }

    /// Whether this kernel is Synology's: other kernels may give 822 to another syscall.
    pub fn available() -> bool {
        Path::new("/proc/sys/fs/synotify").is_dir()
    }

    impl Watcher {
        pub fn open(targets: Vec<Watched>) -> io::Result<Self> {
            // SAFETY: a plain syscall with a flag argument.
            let fd = unsafe { libc::syscall(SYS_INIT, SYNO_CLOEXEC | SYNO_EVENT_V2) };
            if fd < 0 {
                let error = io::Error::last_os_error();
                let hint = if error.raw_os_error() == Some(libc::EPERM) {
                    " (needs root)"
                } else {
                    ""
                };
                return Err(io::Error::new(error.kind(), format!("{error}{hint}")));
            }
            let root_devs = targets
                .iter()
                .map(|target| {
                    std::fs::metadata(&target.scan_path)
                        .map(|meta| meta.dev())
                        .unwrap_or(u64::MAX)
                })
                .collect();
            let host_pids = host_pids();
            let mut watcher = Self {
                // SAFETY: the kernel returned a descriptor nothing else owns.
                fd: unsafe { OwnedFd::from_raw_fd(fd as i32) },
                targets,
                root_devs,
                namespaces: Namespaces::default(),
                young: Vec::new(),
                resolver: host_pids.then(Resolver::start),
                host_pids,
                marks: 0,
                unreachable: 0,
            };
            watcher.look(true);
            if watcher.marks == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no mount of a target could be marked",
                ));
            }
            Ok(watcher)
        }

        /// Finds mount namespaces and marks their mounts of the targets. A quick look (`full`
        /// false) asks only processes new since the last one, and marks only namespaces new
        /// to it: a container started a second ago. A full look re-reads every namespace, for
        /// mounts added to one already known. Marking a mount twice keeps one mark, and marks
        /// on mounts that went away went with them.
        fn look(&mut self, full: bool) {
            let Ok(proc) = std::fs::read_dir("/proc") else {
                return;
            };
            let mut namespaces = if full {
                Namespaces::default()
            } else {
                std::mem::take(&mut self.namespaces)
            };
            let mut running = HashSet::new();
            // A container's mounts may still have been going up at the last look: those
            // namespaces are read once more.
            let mut fresh: Vec<u64> = if full {
                Vec::new()
            } else {
                std::mem::take(&mut self.young)
                    .into_iter()
                    .filter(|ns| self.reread(&mut namespaces, *ns))
                    .collect()
            };
            let rereads = fresh.len();
            for entry in proc.flatten() {
                let Some(pid) = entry
                    .file_name()
                    .to_str()
                    .and_then(|name| name.parse::<u32>().ok())
                else {
                    continue;
                };
                running.insert(pid);
                if namespaces.of_pid.contains_key(&pid) {
                    continue;
                }
                let Ok(ns) = std::fs::metadata(format!("/proc/{pid}/ns/mnt")).map(|m| m.ino())
                else {
                    continue;
                };
                namespaces.of_pid.insert(pid, ns);
                if pid == 1 {
                    namespaces.host = Some(ns);
                }
                if namespaces.mounts.contains_key(&ns) {
                    continue;
                }
                // Unreadable for another user's process without CAP_SYS_PTRACE: another
                // process in the namespace may do.
                let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/mountinfo")) else {
                    continue;
                };
                namespaces
                    .mounts
                    .insert(ns, parse_mounts(&text, &self.targets));
                namespaces.entry.insert(ns, pid);
                fresh.push(ns);
            }
            namespaces.of_pid.retain(|pid, _| running.contains(pid));
            let (mut marks, mut unreachable) = if full {
                (0, 0)
            } else {
                (self.marks, self.unreachable)
            };
            for (order, ns) in fresh.iter().enumerate() {
                let pid = namespaces.entry[ns];
                // A namespace read again was counted at the look that found it.
                let counts = order >= rereads;
                for mount in &namespaces.mounts[ns] {
                    let mut path = format!("/proc/{pid}/root").into_bytes();
                    path.extend_from_slice(&mount.point);
                    match self.mark(path) {
                        Ok(()) if counts => marks += 1,
                        Err(_) if counts => unreachable += 1,
                        _ => {}
                    }
                }
            }
            self.young = fresh[rereads..].to_vec();
            if full && (marks != self.marks || unreachable != self.unreachable) {
                info!(
                    marks,
                    unreachable,
                    namespaces = namespaces.mounts.len(),
                    "synotify marks"
                );
            }
            self.marks = marks;
            self.unreachable = unreachable;
            self.namespaces = namespaces;
        }

        /// Reads namespace `ns`'s mounts again, through the process it was found by.
        fn reread(&self, namespaces: &mut Namespaces, ns: u64) -> bool {
            let Some(&pid) = namespaces.entry.get(&ns) else {
                return false;
            };
            let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/mountinfo")) else {
                return false;
            };
            namespaces
                .mounts
                .insert(ns, parse_mounts(&text, &self.targets));
            true
        }

        fn mark(&self, path: Vec<u8>) -> io::Result<()> {
            let path =
                CString::new(path).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            // SAFETY: `path` is NUL-terminated; the mask goes in the low 32 bits.
            let status =
                unsafe { libc::syscall(SYS_ADD_WATCH, self.fd.as_raw_fd(), path.as_ptr(), MASK) };
            if status < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        pub fn run(mut self, store: &LiveStore) {
            let mut buf = vec![0u8; 256 * 1024];
            let mut next_look = Instant::now() + LOOK_EVERY;
            let mut looks: u32 = 0;
            loop {
                let wait = next_look.saturating_duration_since(Instant::now());
                let mut poll = libc::pollfd {
                    fd: self.fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: one valid pollfd.
                let ready = unsafe { libc::poll(&mut poll, 1, wait.as_millis() as i32) };
                if ready > 0 {
                    // SAFETY: the buffer is valid for its length.
                    let read = unsafe {
                        libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len())
                    };
                    if read < 0 {
                        let error = io::Error::last_os_error();
                        if error.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        warn!(%error, "synotify read failed; btrfs polling carries on alone");
                        store.note_error(format!("synotify read: {error}"));
                        return;
                    }
                    self.handle(&buf[..read as usize], store);
                    // Busy files (a log, a download) write in small pieces, an event each;
                    // a pause lets them gather, so one read handles many. The engine waits
                    // longer (`SETTLE`) before a re-read anyway.
                    std::thread::sleep(READ_PAUSE);
                } else if ready < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        warn!(%error, "synotify poll failed; btrfs polling carries on alone");
                        store.note_error(format!("synotify poll: {error}"));
                        return;
                    }
                }
                if Instant::now() >= next_look {
                    looks = looks.wrapping_add(1);
                    self.look(looks.is_multiple_of(FULL_LOOK));
                    next_look = Instant::now() + LOOK_EVERY;
                }
            }
        }

        /// One read's worth of events. A busy file writes thousands of events a second, all
        /// naming the same directory, so each directory is looked up once per read.
        fn handle(&mut self, mut events: &[u8], store: &LiveStore) {
            // Each directory, with the last process seen changing it.
            let mut dirs: HashMap<(Option<u64>, Vec<u8>), u32> = HashMap::new();
            while events.len() >= HEADER {
                let word = |at: usize| u32::from_ne_bytes(events[at..at + 4].try_into().unwrap());
                let (mask, len, pid) = (word(0), word(8) as usize, word(12));
                let Some(name) = events.get(HEADER..HEADER + len) else {
                    break;
                };
                events = &events[HEADER + len..];
                if mask & Q_OVERFLOW != 0 {
                    store.overflows.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let path = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
                let Some(dir) = parent(path) else {
                    continue;
                };
                let ns = self.ns_of(pid);
                dirs.insert((ns, dir.to_vec()), pid);
            }
            let mut signalled: HashSet<(usize, u64)> = HashSet::new();
            for ((ns, dir), pid) in dirs {
                let mut who: Option<Option<Arc<Lookup>>> = None;
                for (slot, inside) in self.namespaces.resolve(ns, &self.targets, &dir) {
                    if let Some(ino) = self.existing_dir(slot, &inside) {
                        let index = self.targets[slot].index;
                        if signalled.insert((index, ino)) {
                            let who = who
                                .get_or_insert_with(|| {
                                    let resolver = self.resolver.as_mut()?;
                                    resolver.lookup(i32::try_from(pid).ok()?)
                                })
                                .clone();
                            store.signal_ino_by(index, ino, &|| who.clone());
                        }
                    }
                }
            }
        }

        fn ns_of(&mut self, pid: u32) -> Option<u64> {
            if !self.host_pids {
                return None;
            }
            if let Some(ns) = self.namespaces.of_pid.get(&pid) {
                return Some(*ns);
            }
            let ns = std::fs::metadata(format!("/proc/{pid}/ns/mnt")).ok()?.ino();
            if !self.namespaces.mounts.contains_key(&ns) {
                // A namespace made since the last look; marks wait for the next one.
                return None;
            }
            self.namespaces.of_pid.insert(pid, ns);
            Some(ns)
        }

        /// The inode of the directory at `inside` in target `slot`, or of its nearest
        /// ancestor still there (a tree deleted under it).
        fn existing_dir(&self, slot: usize, inside: &[u8]) -> Option<u64> {
            let target = &self.targets[slot];
            let mut inside = inside;
            loop {
                let mut bytes = target.scan_path.as_os_str().as_bytes().to_vec();
                bytes.extend_from_slice(inside);
                let path = PathBuf::from(OsStr::from_bytes(&bytes));
                match std::fs::symlink_metadata(&path) {
                    Ok(meta) if meta.is_dir() => {
                        return (meta.dev() == self.root_devs[slot]).then(|| meta.ino());
                    }
                    Ok(_) => return None,
                    Err(_) if inside.is_empty() => return None,
                    Err(_) => inside = parent(inside).filter(|up| *up != b"/").unwrap_or(b""),
                }
            }
        }
    }

    /// Starts following `targets` (btrfs ones, each already polled) by synotify; returns the
    /// target indexes it follows.
    pub fn start(store: &Arc<LiveStore>, targets: Vec<Watched>) -> Vec<usize> {
        if targets.is_empty() || !available() {
            return Vec::new();
        }
        let watcher = match Watcher::open(targets) {
            Ok(watcher) => watcher,
            Err(error) => {
                warn!(%error, "synotify unavailable; btrfs polling alone");
                return Vec::new();
            }
        };
        if watcher.unreachable > 0 {
            warn!(
                unreachable = watcher.unreachable,
                "some mounts could not be marked (containers need pid: host and \
                 CAP_SYS_PTRACE); changes made through them wait for btrfs polling"
            );
        }
        info!(
            marks = watcher.marks,
            namespaces = watcher.namespaces.mounts.len(),
            "following changes by synotify"
        );
        let followed: Vec<usize> = watcher.targets.iter().map(|t| t.index).collect();
        let store = Arc::clone(store);
        std::thread::Builder::new()
            .name("harvester-synotify".to_string())
            .spawn(move || watcher.run(&store))
            .expect("spawn the synotify watcher");
        followed
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use imp::start;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn start(
    _store: &std::sync::Arc<crate::live::LiveStore>,
    _targets: Vec<Watched>,
) -> Vec<usize> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(index: usize, dev: &str, fs_path: &str) -> Watched {
        Watched {
            index,
            dev: dev.to_string(),
            fs_path: fs_path.as_bytes().to_vec(),
            scan_path: PathBuf::from(format!("/host{fs_path}")),
        }
    }

    // The NAS as seen from the host, and from a qBittorrent container holding one folder.
    const HOST: &str = "\
42 18 0:35 /@syno /volume1 rw,nodev,relatime - btrfs /dev/mapper/cachedev_1 rw
44 18 0:34 /@syno /volume2 rw,nodev,relatime - btrfs /dev/mapper/cachedev_0 rw
47 46 0:34 /@syno/@docker/btrfs /volume2/@docker/btrfs rw - btrfs /dev/mapper/cachedev_0 rw
61 44 0:35 /@syno/data /volume2/@appdata/ContainerManager/all_shares/data rw - btrfs x rw
483 44 0:35 /@syno/MacBook\\040Pro\\040Backup /volume2/@appdata/all_shares/MacBook\\040Pro\\040Backup rw - btrfs x rw
";
    const QBIT: &str = "\
900 800 0:34 /@syno/@docker/btrfs/subvolumes/abc / rw - btrfs /dev/mapper/cachedev_0 rw
901 900 0:35 /@syno/data/torrents /data/torrents rw - btrfs /dev/mapper/cachedev_1 rw
902 900 0:34 /@syno/docker/qbittorrent /config rw - btrfs /dev/mapper/cachedev_0 rw
";

    fn targets() -> Vec<Watched> {
        vec![
            target(0, "0:35", "/@syno/data"),
            target(3, "0:35", "/@syno/MacBook Pro Backup"),
            target(6, "0:34", "/@syno/docker"),
        ]
    }

    #[test]
    fn whole_component_prefixes_only() {
        assert_eq!(below(b"/data/x", b"/data"), Some(&b"/x"[..]));
        assert_eq!(below(b"/data", b"/data"), Some(&b""[..]));
        assert_eq!(below(b"/database", b"/data"), None);
        assert_eq!(below(b"/anything", b"/"), Some(&b"/anything"[..]));
        assert_eq!(parent(b"/a/b/c"), Some(&b"/a/b"[..]));
        assert_eq!(parent(b"/a"), Some(&b"/"[..]));
        assert_eq!(parent(b"a"), None);
    }

    #[test]
    fn marks_only_mounts_that_show_a_target() {
        let mounts = parse_mounts(HOST, &targets());
        let points: Vec<&[u8]> = mounts.iter().map(|m| m.point.as_slice()).collect();
        assert_eq!(
            points,
            vec![
                &b"/volume1"[..],
                b"/volume2",
                b"/volume2/@appdata/ContainerManager/all_shares/data",
                b"/volume2/@appdata/all_shares/MacBook Pro Backup",
            ],
            "the docker storage mount shows no target"
        );
        let qbit = parse_mounts(QBIT, &targets());
        assert_eq!(qbit.len(), 2, "not the container's own root filesystem");
    }

    #[test]
    fn maps_paths_through_the_actors_namespace() {
        let targets = targets();
        let host = parse_mounts(HOST, &targets);
        let qbit = parse_mounts(QBIT, &targets);
        assert_eq!(
            map(&qbit, &targets, b"/data/torrents/linux.iso.part"),
            vec![(0, b"/torrents/linux.iso.part".to_vec())]
        );
        assert_eq!(
            map(&qbit, &targets, b"/config/qBittorrent.conf"),
            vec![(2, b"/qbittorrent/qBittorrent.conf".to_vec())]
        );
        assert_eq!(map(&qbit, &targets, b"/etc/hosts"), vec![]);
        assert_eq!(
            map(&host, &targets, b"/volume1/data"),
            vec![(0, Vec::new())],
            "the target's own root"
        );
        assert_eq!(
            map(
                &host,
                &targets,
                b"/volume2/@appdata/ContainerManager/all_shares/data/media"
            ),
            vec![(0, b"/media".to_vec())]
        );
        assert_eq!(
            map(
                &host,
                &targets,
                b"/volume1/MacBook Pro Backup/x.sparsebundle"
            ),
            vec![(1, b"/x.sparsebundle".to_vec())]
        );
        assert_eq!(map(&host, &targets, b"/volume1/homes/a"), vec![]);
    }

    #[test]
    fn an_unknown_actor_is_tried_in_every_namespace() {
        let targets = targets();
        let mut namespaces = Namespaces {
            host: Some(1),
            ..Namespaces::default()
        };
        namespaces.mounts.insert(1, parse_mounts(HOST, &targets));
        namespaces.mounts.insert(2, parse_mounts(QBIT, &targets));
        assert_eq!(
            namespaces.resolve(None, &targets, b"/data/torrents/a"),
            vec![(0, b"/torrents/a".to_vec())]
        );
        assert_eq!(
            namespaces.resolve(Some(1), &targets, b"/data/torrents/a"),
            vec![],
            "a known actor's namespace decides alone"
        );
    }
}
