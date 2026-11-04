//! btrfs metadata, read with `BTRFS_IOC_TREE_SEARCH_V2` (needs `CAP_SYS_ADMIN`).
//!
//! - [`sharing`]: which bytes each directory holds alone. A file's size overstates what deleting
//!   it frees when its extents are shared (reflinks, dedup, cross-seed copies). Every extent
//!   reference in the subvolume is grouped by extent; an extent belongs to the lowest directory
//!   containing all of its references, so a directory's subtree sum is exactly what deleting it
//!   would free within the subvolume. Snapshots and other subvolumes are not looked at.
//! - [`Watcher`]: which directories changed since the last poll, from the generation numbers
//!   btrfs stamps on every metadata block. For kernels without fanotify's directory events.

use std::collections::{BinaryHeap, HashMap, HashSet};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::tree::NONE;

const IOC_TREE_SEARCH_V2: u64 = 0xC070_9411;
const IOC_INO_LOOKUP: u64 = 0xD000_9412;
const SUPER_MAGIC: i64 = 0x9123_683E;
const FIRST_FREE_OBJECTID: u64 = 256;
const ROOT_TREE: u64 = 1;

const INODE_ITEM: u32 = 1;
const INODE_REF: u32 = 12;
const INODE_EXTREF: u32 = 13;
const DIR_ITEM: u32 = 84;
const DIR_INDEX: u32 = 96;
const EXTENT_DATA: u32 = 108;
const ROOT_ITEM: u32 = 132;

const KEY_LEN: usize = 104;
const HEADER_LEN: usize = 32;

pub fn is_btrfs(path: &Path) -> bool {
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `path` is NUL-terminated and `stat` is valid for writes.
    if unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return false;
    }
    // SAFETY: `statfs` succeeded.
    let stat = unsafe { stat.assume_init() };
    #[allow(clippy::unnecessary_cast)]
    let kind = stat.f_type as i64;
    kind == SUPER_MAGIC
}

#[derive(Debug, Clone, Copy)]
struct Key {
    objectid: u64,
    kind: u32,
    offset: u64,
}

impl Key {
    const MIN: Key = Key {
        objectid: 0,
        kind: 0,
        offset: 0,
    };
    const MAX: Key = Key {
        objectid: u64::MAX,
        kind: 255,
        offset: u64::MAX,
    };

    fn successor(self) -> Option<Key> {
        if self.offset < u64::MAX {
            Some(Key {
                offset: self.offset + 1,
                ..self
            })
        } else if self.kind < 255 {
            Some(Key {
                kind: self.kind + 1,
                offset: 0,
                ..self
            })
        } else if self.objectid < u64::MAX {
            Some(Key {
                objectid: self.objectid + 1,
                kind: 0,
                offset: 0,
            })
        } else {
            None
        }
    }
}

/// One item a search returned.
struct Item<'a> {
    key: Key,
    data: &'a [u8],
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    bytes
        .get(at..at + 8)
        .map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap()))
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    bytes
        .get(at..at + 4)
        .map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()))
}

struct Searcher {
    fd: OwnedFd,
    /// `btrfs_ioctl_search_args_v2`: the key, `buf_size`, then the result buffer.
    buf: Vec<u64>,
}

impl Searcher {
    fn open(path: &Path, buf_bytes: usize) -> io::Result<Self> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `path` is NUL-terminated.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            // SAFETY: `open` returned a descriptor nothing else owns.
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            buf: vec![0; (KEY_LEN + 8 + buf_bytes).div_ceil(8)],
        })
    }

    /// Calls `each` for every item of `tree` (0: the subvolume `fd` is in) between `min` and
    /// `max`, in leaves of generation >= `min_transid`. `each` returns false to stop.
    fn search(
        &mut self,
        tree: u64,
        min: Key,
        max: Key,
        min_transid: u64,
        cancel: Option<&AtomicBool>,
        mut each: impl FnMut(&Item) -> bool,
    ) -> io::Result<()> {
        let buf_size = self.buf.len() * 8 - KEY_LEN - 8;
        let mut from = min;
        loop {
            if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
            }
            // SAFETY: plain bytes over our own u64 buffer.
            let bytes = unsafe {
                std::slice::from_raw_parts_mut(self.buf.as_mut_ptr() as *mut u8, self.buf.len() * 8)
            };
            let fields: [u64; 7] = [
                tree,
                from.objectid,
                max.objectid,
                from.offset,
                max.offset,
                min_transid,
                u64::MAX,
            ];
            for (index, value) in fields.iter().enumerate() {
                bytes[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
            }
            bytes[56..60].copy_from_slice(&from.kind.to_le_bytes());
            bytes[60..64].copy_from_slice(&max.kind.to_le_bytes());
            bytes[64..68].copy_from_slice(&u32::MAX.to_le_bytes());
            bytes[68..KEY_LEN].fill(0);
            bytes[KEY_LEN..KEY_LEN + 8].copy_from_slice(&(buf_size as u64).to_le_bytes());
            // SAFETY: the buffer is laid out as `btrfs_ioctl_search_args_v2` with `buf_size`
            // bytes of room after the header, and the kernel writes no more than that.
            let status = unsafe {
                libc::ioctl(
                    self.fd.as_raw_fd(),
                    IOC_TREE_SEARCH_V2 as _,
                    bytes.as_mut_ptr(),
                )
            };
            if status != 0 {
                return Err(io::Error::last_os_error());
            }
            let count = u32_at(bytes, 64);
            if count == 0 {
                return Ok(());
            }
            let data = &bytes[KEY_LEN + 8..];
            let mut at = 0;
            let mut last = from;
            for _ in 0..count {
                let len = u32_at(data, at + 28) as usize;
                let item = Item {
                    key: Key {
                        objectid: u64_at(data, at + 8),
                        kind: u32_at(data, at + 24),
                        offset: u64_at(data, at + 16),
                    },
                    data: &data[at + HEADER_LEN..at + HEADER_LEN + len],
                };
                last = item.key;
                if !each(&item) {
                    return Ok(());
                }
                at += HEADER_LEN + len;
            }
            match last.successor() {
                Some(next) => from = next,
                None => return Ok(()),
            }
        }
    }

    /// The subvolume (tree) `fd` is in.
    fn subvolume(&self) -> io::Result<u64> {
        let mut args = vec![0u64; 4096 / 8];
        args[1] = FIRST_FREE_OBJECTID;
        // SAFETY: `args` is a 4096-byte `btrfs_ioctl_ino_lookup_args`.
        let status =
            unsafe { libc::ioctl(self.fd.as_raw_fd(), IOC_INO_LOOKUP as _, args.as_mut_ptr()) };
        if status != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(args[0])
    }

    /// The last committed generation of subvolume `tree`.
    fn generation(&mut self, tree: u64) -> io::Result<u64> {
        let mut generation = None;
        self.search(
            ROOT_TREE,
            Key {
                objectid: tree,
                kind: ROOT_ITEM,
                offset: 0,
            },
            Key {
                objectid: tree,
                kind: ROOT_ITEM,
                offset: u64::MAX,
            },
            0,
            None,
            |item| {
                generation = Some(u64_at(item.data, 160));
                false
            },
        )?;
        generation.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no root item"))
    }
}

/// The parts of a tree the sharing pass needs, copied so the tree stays unlocked meanwhile.
pub struct Skeleton {
    pub parent: Vec<u32>,
    pub depth: Vec<u32>,
    pub by_ino: HashMap<u64, u32>,
    /// Display paths of directories some of whose entries are excluded, to test link names.
    pub pruned: HashMap<u32, Vec<u8>>,
    pub exclude: globset::GlobSet,
}

impl Skeleton {
    /// The node a link named `name` in directory `parent` counts in: NONE when the tree does
    /// not hold it (outside the target, untracked, or excluded).
    fn holder(&self, parent: u64, name: &[u8]) -> u32 {
        let Some(&node) = self.by_ino.get(&parent) else {
            return NONE;
        };
        if let Some(dir) = self.pruned.get(&node) {
            let mut path = dir.clone();
            if path.last() != Some(&b'/') {
                path.push(b'/');
            }
            path.extend_from_slice(name);
            if self
                .exclude
                .is_match(Path::new(std::ffi::OsStr::from_bytes(&path)))
            {
                return NONE;
            }
        }
        node
    }

    fn ancestor_at(&self, mut node: u32, depth: u32) -> u32 {
        while self.depth[node as usize] > depth {
            node = self.parent[node as usize];
        }
        node
    }

    fn common(&self, mut a: u32, mut b: u32) -> u32 {
        if a == NONE || b == NONE {
            return NONE;
        }
        while self.depth[a as usize] > self.depth[b as usize] {
            a = self.parent[a as usize];
        }
        while self.depth[b as usize] > self.depth[a as usize] {
            b = self.parent[b as usize];
        }
        while a != b {
            a = self.parent[a as usize];
            b = self.parent[b as usize];
        }
        a
    }
}

#[derive(Debug, Clone, Default)]
pub struct Sharing {
    /// Per node: bytes of extents whose references all lie in its subtree and in no smaller
    /// one. Summed over a subtree: what deleting it frees.
    pub alone: Vec<u64>,
    /// Unique bytes on disk the subvolume's files reference.
    pub disk: u64,
    /// Part of `disk` also referenced from files the tree does not hold (excluded or outside
    /// the target): deleting the whole target would not free it.
    pub outside: u64,
    /// `(a, b)` → bytes of extents referenced from both, for directories at depth 1 and 2.
    pub pairs: Vec<(u32, u32, u64)>,
    pub items: u64,
    pub duration: Duration,
}

/// One reference to an extent, sortable by extent. 16 bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Ref {
    bytenr: u64,
    /// The directory of one link of the referencing inode; a multiply-linked inode adds one
    /// reference per directory, so a hard link shares an extent the way a reflink does.
    node: u32,
    /// Extent size in 4 KiB units (btrfs data extents are at most 128 MiB).
    pages: u32,
}

const CHUNK: usize = 1 << 20;

pub fn sharing(path: &Path, skeleton: &Skeleton, cancel: &AtomicBool) -> io::Result<Sharing> {
    let started = Instant::now();
    let mut searcher = Searcher::open(path, 4 << 20)?;
    let mut result = Sharing {
        alone: vec![0; skeleton.parent.len()],
        ..Sharing::default()
    };
    let mut chunks: Vec<Vec<Ref>> = vec![Vec::with_capacity(CHUNK)];
    // Items come in key order: an inode's INODE_REFs before its EXTENT_DATA.
    let mut inode = u64::MAX;
    // The directories holding the current inode's links (NONE: one the tree does not hold).
    let mut dirs: Vec<u32> = Vec::new();
    searcher.search(0, Key::MIN, Key::MAX, 0, Some(cancel), |item| {
        result.items += 1;
        let key = item.key;
        if key.objectid != inode {
            inode = key.objectid;
            dirs.clear();
        }
        let mut link = |parent: u64, name: &[u8]| {
            let node = skeleton.holder(parent, name);
            if !dirs.contains(&node) {
                dirs.push(node);
            }
        };
        let data = item.data;
        match key.kind {
            // `{index u64, name_len u16, name}` per name in that directory.
            INODE_REF => {
                let mut at = 0;
                while at + 10 <= data.len() {
                    let len = u16::from_le_bytes([data[at + 8], data[at + 9]]) as usize;
                    link(key.offset, data.get(at + 10..at + 10 + len).unwrap_or(&[]));
                    at += 10 + len;
                }
            }
            // `{parent u64, index u64, name_len u16, name}` per name.
            INODE_EXTREF => {
                let mut at = 0;
                while at + 18 <= data.len() {
                    let len = u16::from_le_bytes([data[at + 16], data[at + 17]]) as usize;
                    link(
                        u64_at(data, at),
                        data.get(at + 18..at + 18 + len).unwrap_or(&[]),
                    );
                    at += 18 + len;
                }
            }
            EXTENT_DATA if item.data.len() >= 21 => {
                if item.data[20] == 0 {
                    // Inline: the data lives in this item, so it is this inode's alone.
                    let bytes = (item.data.len() - 21) as u64;
                    let holder = dirs
                        .iter()
                        .copied()
                        .reduce(|a, b| skeleton.common(a, b))
                        .unwrap_or(NONE);
                    if holder != NONE {
                        result.disk += bytes;
                        result.alone[holder as usize] += bytes;
                    }
                } else {
                    let bytenr = u64_at(item.data, 21);
                    if bytenr != 0 {
                        let pages = u64_at(item.data, 29).div_ceil(4096).min(u32::MAX as u64);
                        let holders: &[u32] = if dirs.is_empty() { &[NONE] } else { &dirs };
                        for &node in holders {
                            if chunks.last().is_some_and(|chunk| chunk.len() == CHUNK) {
                                chunks.last_mut().unwrap().sort_unstable();
                                chunks.push(Vec::with_capacity(CHUNK));
                            }
                            chunks.last_mut().unwrap().push(Ref {
                                bytenr,
                                node,
                                pages: pages as u32,
                            });
                        }
                    }
                }
            }
            _ => {}
        }
        true
    })?;
    if let Some(last) = chunks.last_mut() {
        last.sort_unstable();
    }

    // Merge the sorted chunks and settle each extent.
    let mut heap: BinaryHeap<std::cmp::Reverse<(Ref, usize, usize)>> = chunks
        .iter()
        .enumerate()
        .filter(|(_, chunk)| !chunk.is_empty())
        .map(|(index, chunk)| std::cmp::Reverse((chunk[0], index, 0)))
        .collect();
    let mut pairs: HashMap<(u32, u32), u64> = HashMap::new();
    let mut group: Vec<u32> = Vec::new();
    let mut current: Option<Ref> = None;
    let mut common = NONE;
    let mut settle = |current: Ref, common: u32, group: &mut Vec<u32>, result: &mut Sharing| {
        let bytes = current.pages as u64 * 4096;
        // Extents only files outside the tree use are none of its business.
        if group.iter().any(|&node| node != NONE) {
            result.disk += bytes;
            match common {
                NONE => result.outside += bytes,
                node => result.alone[node as usize] += bytes,
            }
        }
        if group.len() > 1 {
            for depth in [1, 2] {
                let mut tops: Vec<u32> = group
                    .iter()
                    .filter(|&&node| node != NONE && skeleton.depth[node as usize] >= depth)
                    .map(|&node| skeleton.ancestor_at(node, depth))
                    .collect();
                tops.sort_unstable();
                tops.dedup();
                tops.truncate(8);
                for (i, &a) in tops.iter().enumerate() {
                    for &b in &tops[i + 1..] {
                        *pairs.entry((a, b)).or_default() += bytes;
                    }
                }
            }
        }
        group.clear();
    };
    while let Some(std::cmp::Reverse((next, chunk, at))) = heap.pop() {
        if let Some(following) = chunks[chunk].get(at + 1) {
            heap.push(std::cmp::Reverse((*following, chunk, at + 1)));
        }
        match current {
            Some(open) if open.bytenr == next.bytenr => {
                common = skeleton.common(common, next.node);
                if group.len() < 16 && !group.contains(&next.node) {
                    group.push(next.node);
                }
            }
            _ => {
                if let Some(open) = current {
                    settle(open, common, &mut group, &mut result);
                }
                current = Some(next);
                common = next.node;
                group.push(next.node);
            }
        }
    }
    if let Some(open) = current {
        settle(open, common, &mut group, &mut result);
    }
    drop(chunks);

    let mut pairs: Vec<(u32, u32, u64)> = pairs.into_iter().map(|((a, b), n)| (a, b, n)).collect();
    pairs.sort_by(|x, y| y.2.cmp(&x.2));
    pairs.truncate(50);
    result.pairs = pairs;
    result.duration = started.elapsed();
    Ok(result)
}

/// The parent directories in an INODE_EXTREF item: packed `{parent u64, index u64,
/// name_len u16, name}` records, several when names collide on the hash.
fn extref_parents(data: &[u8]) -> Vec<u64> {
    let mut parents = Vec::new();
    let mut at = 0;
    while at + 18 <= data.len() {
        parents.push(u64_at(data, at));
        let len = u16::from_le_bytes([data[at + 16], data[at + 17]]) as usize;
        at += 18 + len;
    }
    parents
}

/// Polls a subvolume for directories changed since the last poll.
pub struct Watcher {
    searcher: Searcher,
    subvolume: u64,
    /// Leaves of this generation or newer may hold changes not reported yet.
    floor: u64,
}

impl Watcher {
    pub fn open(path: &Path) -> io::Result<Self> {
        let mut searcher = Searcher::open(path, 1 << 20)?;
        let subvolume = searcher.subvolume()?;
        let floor = searcher.generation(subvolume)?;
        Ok(Self {
            searcher,
            subvolume,
            floor,
        })
    }

    /// Calls `changed` with the inode of every directory whose entries or files changed.
    /// Returns how many directories that was.
    pub fn poll(&mut self, mut changed: impl FnMut(u64)) -> io::Result<usize> {
        // Everything up to `committed` is visible to the search below, and the running
        // transaction (`committed + 1`) is searched again next time, so nothing slips between.
        let committed = self.searcher.generation(self.subvolume)?;
        let floor = self.floor;
        let mut dirs: HashSet<u64> = HashSet::new();
        let mut files: HashSet<u64> = HashSet::new();
        self.searcher
            .search(0, Key::MIN, Key::MAX, floor, None, |item| {
                let key = item.key;
                match key.kind {
                    INODE_ITEM if u64_at(item.data, 8) >= floor => {
                        if u32_at(item.data, 52) & libc::S_IFMT == libc::S_IFDIR {
                            dirs.insert(key.objectid);
                        } else {
                            files.insert(key.objectid);
                        }
                    }
                    DIR_ITEM | DIR_INDEX if u64_at(item.data, 17) >= floor => {
                        dirs.insert(key.objectid);
                    }
                    EXTENT_DATA if u64_at(item.data, 0) >= floor => {
                        files.insert(key.objectid);
                    }
                    _ => {}
                }
                true
            })?;
        // Every directory holding a link, from an unfiltered search: a new hard link changes the
        // inode, and the older link's directory must hear of it too (its reference may sit in a
        // block this poll did not return), or the file counts in both.
        for file in files {
            dirs.extend(self.parents_of(file)?);
        }
        self.floor = committed + 1;
        let count = dirs.len();
        for dir in dirs {
            changed(dir);
        }
        Ok(count)
    }

    fn parents_of(&mut self, inode: u64) -> io::Result<Vec<u64>> {
        let mut parents = Vec::new();
        self.searcher.search(
            0,
            Key {
                objectid: inode,
                kind: INODE_REF,
                offset: 0,
            },
            Key {
                objectid: inode,
                kind: INODE_EXTREF,
                offset: u64::MAX,
            },
            0,
            None,
            |item| {
                match item.key.kind {
                    INODE_REF => parents.push(item.key.offset),
                    _ => parents.extend(extref_parents(item.data)),
                }
                true
            },
        )?;
        Ok(parents)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_step_to_their_successor() {
        let key = Key {
            objectid: 5,
            kind: 108,
            offset: u64::MAX,
        };
        let next = key.successor().unwrap();
        assert_eq!((next.objectid, next.kind, next.offset), (5, 109, 0));
        assert!(Key::MAX.successor().is_none());
    }

    #[test]
    fn extref_items_name_every_packed_parent() {
        let mut item = Vec::new();
        for (parent, name) in [(300u64, &b"a"[..]), (301, &b"bb"[..])] {
            item.extend_from_slice(&parent.to_le_bytes());
            item.extend_from_slice(&7u64.to_le_bytes());
            item.extend_from_slice(&(name.len() as u16).to_le_bytes());
            item.extend_from_slice(name);
        }
        assert_eq!(extref_parents(&item), [300, 301]);
    }

    #[test]
    fn common_ancestor_walks_both_sides() {
        // 0 -> 1 -> 3, 0 -> 2
        let skeleton = Skeleton {
            parent: vec![NONE, 0, 0, 1],
            depth: vec![0, 1, 1, 2],
            by_ino: HashMap::new(),
            pruned: HashMap::new(),
            exclude: globset::GlobSet::empty(),
        };
        assert_eq!(skeleton.common(3, 2), 0);
        assert_eq!(skeleton.common(3, 1), 1);
        assert_eq!(skeleton.common(3, NONE), NONE);
        assert_eq!(skeleton.ancestor_at(3, 1), 1);
    }
}
