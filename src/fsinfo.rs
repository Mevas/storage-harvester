//! Which filesystem a target lives on, and how full that filesystem is.
//!
//! Targets can alias one another: on the NUC, `/var/lib/docker` is a bind mount of a directory
//! on the disk mounted at `/mnt/scratch`. Mount IDs and paths *inside* the filesystem (from
//! `/proc/self/mountinfo`) tell the atlas that one target contains another.

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
    locate_in(&mounts, scan_path, host_root).or_else(|| fallback(scan_path, host_root))
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
    fn usage_of_the_current_directory_adds_up() {
        let usage = usage(Path::new(".")).unwrap();
        assert!(usage.size > 0);
        assert!(usage.used + usage.avail + usage.reserved <= usage.size + 4096);
    }
}
