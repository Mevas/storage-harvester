//! The directory tree a scan leaves behind: every directory it walked (up to
//! `tree_max_directories`), with what sits directly in it and what sits below.
//!
//! `/api/tree` serves pruned views of it, the live engine edits it in place between scans, and
//! the next scan replaces it.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use serde_json::{json, Map, Value};

pub const NONE: u32 = u32::MAX;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Tally {
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    pub blocks: u64,
    pub apparent: u64,
}

impl Tally {
    pub fn add(&mut self, other: &Tally) {
        self.files += other.files;
        self.dirs += other.dirs;
        self.symlinks += other.symlinks;
        self.add_size(other.blocks, other.apparent);
    }

    pub fn add_size(&mut self, blocks: u64, apparent: u64) {
        self.blocks = self.blocks.saturating_add(blocks);
        self.apparent = self.apparent.saturating_add(apparent);
    }

    pub fn is_empty(&self) -> bool {
        *self == Tally::default()
    }

    /// `self += delta`, clamped at zero.
    pub fn apply(&mut self, delta: &Delta) {
        fn shift(value: &mut u64, by: i64) {
            *value = if by < 0 {
                value.saturating_sub(by.unsigned_abs())
            } else {
                value.saturating_add(by as u64)
            };
        }
        shift(&mut self.files, delta.files);
        shift(&mut self.dirs, delta.dirs);
        shift(&mut self.symlinks, delta.symlinks);
        shift(&mut self.blocks, delta.blocks);
        shift(&mut self.apparent, delta.apparent);
    }
}

/// A signed difference between two tallies.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Delta {
    pub files: i64,
    pub dirs: i64,
    pub symlinks: i64,
    pub blocks: i64,
    pub apparent: i64,
}

impl Delta {
    pub fn between(old: &Tally, new: &Tally) -> Self {
        fn diff(old: u64, new: u64) -> i64 {
            (new as i128 - old as i128).clamp(i64::MIN as i128, i64::MAX as i128) as i64
        }
        Self {
            files: diff(old.files, new.files),
            dirs: diff(old.dirs, new.dirs),
            symlinks: diff(old.symlinks, new.symlinks),
            blocks: diff(old.blocks, new.blocks),
            apparent: diff(old.apparent, new.apparent),
        }
    }

    pub fn plus(self, other: Delta) -> Self {
        Self {
            files: self.files.saturating_add(other.files),
            dirs: self.dirs.saturating_add(other.dirs),
            symlinks: self.symlinks.saturating_add(other.symlinks),
            blocks: self.blocks.saturating_add(other.blocks),
            apparent: self.apparent.saturating_add(other.apparent),
        }
    }

    pub fn negate(self) -> Self {
        Self {
            files: -self.files,
            dirs: -self.dirs,
            symlinks: -self.symlinks,
            blocks: -self.blocks,
            apparent: -self.apparent,
        }
    }

    pub fn is_zero(&self) -> bool {
        *self == Delta::default()
    }
}

impl From<&Tally> for Delta {
    fn from(tally: &Tally) -> Self {
        Delta::between(&Tally::default(), tally)
    }
}

#[derive(Debug, Clone)]
pub struct DirNode {
    /// The last path component, as the filesystem spells it. Empty for the root.
    pub name: Box<[u8]>,
    pub parent: u32,
    pub depth: u32,
    pub ino: u64,
    /// The directory's own inode. Also counted in its parent's `direct`.
    pub own_blocks: u64,
    pub own_apparent: u64,
    /// Last modification of its entries, in nanoseconds: a re-read of its parent compares it.
    pub mtime: i64,
    /// Entries directly inside, subdirectories' own inodes included.
    pub direct: Tally,
    /// Everything below the directory: `direct`, plus the contents of untracked
    /// subdirectories, plus each child's `sub`.
    pub sub: Tally,
    /// Tracked subdirectories, sorted by name.
    pub children: Vec<u32>,
    /// Its contents were not all walked (depth cap, unreadable, or subdirectories past
    /// `tree_max_directories`), so a live re-read could not tell what changed.
    pub sealed: bool,
    /// Some entries directly inside are excluded from the tree.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub pruned: bool,
    pub alive: bool,
}

impl DirNode {
    pub fn total_blocks(&self) -> u64 {
        self.own_blocks.saturating_add(self.sub.blocks)
    }

    pub fn total_apparent(&self) -> u64 {
        self.own_apparent.saturating_add(self.sub.apparent)
    }
}

/// The directory a multiply-linked file's allocation is counted in, and the other tracked
/// directories holding a link to it, which take it over when the counted link goes.
#[derive(Debug, Clone)]
pub struct LinkOwner {
    pub node: u32,
    pub blocks: u64,
    pub apparent: u64,
    pub others: Vec<u32>,
}

#[derive(Clone)]
pub struct DirTree {
    /// The target's path as reported (labels, API).
    pub display_root: Vec<u8>,
    /// Where the target is read from (`host_root` joined).
    pub scan_root: Vec<u8>,
    pub root_dev: u64,
    pub nodes: Vec<DirNode>,
    pub links: HashMap<(u64, u64), LinkOwner>,
    /// `(node, file handle)` per tracked directory, when the walk recorded them.
    pub handles: Vec<(u32, Box<[u8]>)>,
    /// `(plain_key(dev, ino), node)` for every singly linked file in a tracked directory, sorted,
    /// when the walk recorded them (fanotify). fanotify reports a new hard link only to the new
    /// link's directory; this finds the directory that counted the file while it had one link.
    pub plain: Vec<(u32, u32)>,
    /// Multiply-linked files counted in an untracked directory (no node, so not in `links`),
    /// when the walk recorded them (fanotify).
    pub untracked_links: Vec<(u64, u64)>,
}

/// A singly linked file's key in [`DirTree::plain`]: its inode folded to 32 bits (exact for
/// ext4's 32-bit inode numbers). Two files may share a key; a match only says which
/// directories to re-read.
pub fn plain_key(dev: u64, ino: u64) -> u32 {
    (ino as u32 ^ (ino >> 32) as u32).wrapping_add((dev as u32).wrapping_mul(0x9E37_79B9))
}

impl std::fmt::Debug for DirTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirTree")
            .field("root", &String::from_utf8_lossy(&self.display_root))
            .field("nodes", &self.nodes.len())
            .finish()
    }
}

impl DirTree {
    pub fn root(&self) -> &DirNode {
        &self.nodes[0]
    }

    /// Path components from the root, root excluded.
    pub fn components(&self, index: u32) -> Vec<&[u8]> {
        let mut parts = Vec::new();
        let mut at = index;
        while at != 0 && at != NONE {
            let node = &self.nodes[at as usize];
            parts.push(&node.name[..]);
            at = node.parent;
        }
        parts.reverse();
        parts
    }

    fn join(base: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let mut path = base.to_vec();
        for part in parts {
            if path.last() != Some(&b'/') {
                path.push(b'/');
            }
            path.extend_from_slice(part);
        }
        path
    }

    pub fn display_path_bytes(&self, index: u32) -> Vec<u8> {
        Self::join(&self.display_root, &self.components(index))
    }

    pub fn display_path(&self, index: u32) -> String {
        String::from_utf8_lossy(&self.display_path_bytes(index)).into_owned()
    }

    pub fn scan_path(&self, index: u32) -> Vec<u8> {
        Self::join(&self.scan_root, &self.components(index))
    }

    /// The path relative to the root, for ordering.
    pub fn relative_path(&self, index: u32) -> Vec<u8> {
        self.components(index).join(&b'/')
    }

    pub fn child_named(&self, index: u32, name: &[u8]) -> Option<u32> {
        let children = &self.nodes[index as usize].children;
        children
            .binary_search_by(|&child| self.nodes[child as usize].name[..].cmp(name))
            .ok()
            .map(|at| children[at])
    }

    /// The node at `display_path`, if the tree holds it.
    pub fn find(&self, display_path: &str) -> Option<u32> {
        let path = Path::new(display_path);
        let root = Path::new(OsStr::from_bytes(&self.display_root));
        let rest = path.strip_prefix(root).ok()?;
        let mut at = 0;
        for component in rest.components() {
            at = self.child_named(at, component.as_os_str().as_bytes())?;
        }
        Some(at)
    }

    /// Adds `delta` to the `sub` of `index` and of every ancestor.
    pub fn propagate(&mut self, index: u32, delta: &Delta) {
        if delta.is_zero() {
            return;
        }
        let mut at = index;
        while at != NONE {
            let node = &mut self.nodes[at as usize];
            node.sub.apply(delta);
            at = node.parent;
        }
    }

    /// Inserts `child` into `parent`'s children, keeping them sorted.
    pub fn attach(&mut self, parent: u32, child: u32) {
        let name = self.nodes[child as usize].name.clone();
        let position = {
            let nodes = &self.nodes;
            nodes[parent as usize]
                .children
                .binary_search_by(|&other| nodes[other as usize].name[..].cmp(&name[..]))
                .unwrap_or_else(|at| at)
        };
        self.nodes[parent as usize].children.insert(position, child);
    }

    /// Unlinks `child` from its parent and marks its whole subtree dead. Its sizes stay on the
    /// nodes; the caller subtracts them from the ancestors. Returns the links that were counted
    /// in the subtree, with `others` cut to directories still alive, for the caller to hand on.
    pub fn detach(&mut self, child: u32) -> Vec<((u64, u64), LinkOwner)> {
        let parent = self.nodes[child as usize].parent;
        if parent != NONE {
            self.nodes[parent as usize]
                .children
                .retain(|&other| other != child);
        }
        let mut stack = vec![child];
        while let Some(at) = stack.pop() {
            let node = &mut self.nodes[at as usize];
            node.alive = false;
            stack.extend(node.children.iter().copied());
        }
        let DirTree { nodes, links, .. } = self;
        let mut counted = Vec::new();
        links.retain(|inode, owner| {
            owner.others.retain(|&other| nodes[other as usize].alive);
            if nodes[owner.node as usize].alive {
                return true;
            }
            counted.push((*inode, owner.clone()));
            false
        });
        counted
    }

    /// Appends `other` (a tree of the directory `under`'s new subdirectory) as a child of
    /// `under`. `other`'s root must already be named. Returns the new node of `other`'s root.
    pub fn graft(&mut self, under: u32, mut other: DirTree) -> u32 {
        let offset = self.nodes.len() as u32;
        let base_depth = self.nodes[under as usize].depth + 1;
        for node in &mut other.nodes {
            node.parent = if node.parent == NONE {
                under
            } else {
                node.parent + offset
            };
            node.depth += base_depth;
            for child in &mut node.children {
                *child += offset;
            }
        }
        self.nodes.extend(other.nodes);
        self.attach(under, offset);
        for (inode, mut owner) in other.links {
            owner.node += offset;
            for holder in &mut owner.others {
                *holder += offset;
            }
            self.links.entry(inode).or_insert(owner);
        }
        for (node, handle) in other.handles {
            self.handles.push((node + offset, handle));
        }
        for (key, node) in other.plain {
            self.plain.push((key, node + offset));
        }
        offset
    }

    /// The JSON view `/api/tree` serves: best-first, the largest listed node is expanded next,
    /// until `limit` nodes are listed or nothing within `depth` levels is at least `min_bytes`.
    pub fn pruned(
        &self,
        start: u32,
        limit: usize,
        depth: u32,
        min_bytes: u64,
        exclusive: Option<&HashMap<u64, u64>>,
    ) -> Value {
        #[derive(PartialEq, Eq)]
        struct Candidate(u64, u32);
        impl Ord for Candidate {
            fn cmp(&self, other: &Self) -> Ordering {
                self.0.cmp(&other.0).then(other.1.cmp(&self.1))
            }
        }
        impl PartialOrd for Candidate {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        let base = self.nodes[start as usize].depth;
        let mut listed: HashMap<u32, Vec<u32>> = HashMap::new();
        let mut count = 1;
        let mut heap = BinaryHeap::new();
        heap.push(Candidate(self.nodes[start as usize].total_blocks(), start));
        while let Some(Candidate(_, at)) = heap.pop() {
            if count >= limit {
                break;
            }
            let node = &self.nodes[at as usize];
            if node.depth - base >= depth {
                continue;
            }
            let mut kids: Vec<u32> = node
                .children
                .iter()
                .copied()
                .filter(|&child| self.nodes[child as usize].total_blocks() >= min_bytes.max(1))
                .collect();
            kids.sort_by_key(|&child| std::cmp::Reverse(self.nodes[child as usize].total_blocks()));
            kids.truncate(limit - count);
            count += kids.len();
            for &child in &kids {
                heap.push(Candidate(self.nodes[child as usize].total_blocks(), child));
            }
            listed.insert(at, kids);
        }
        self.node_json(start, &listed, exclusive)
    }

    fn node_json(
        &self,
        index: u32,
        listed: &HashMap<u32, Vec<u32>>,
        exclusive: Option<&HashMap<u64, u64>>,
    ) -> Value {
        let node = &self.nodes[index as usize];
        let subdir_own: u64 = node
            .children
            .iter()
            .map(|&child| self.nodes[child as usize].own_blocks)
            .sum();
        let files_here = node.direct.blocks.saturating_sub(subdir_own);
        let mut object = Map::new();
        let name = if index == 0 {
            let root = Path::new(OsStr::from_bytes(&self.display_root));
            root.file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "/".to_string())
        } else {
            String::from_utf8_lossy(&node.name).into_owned()
        };
        object.insert("n".into(), json!(name));
        object.insert("t".into(), json!(node.total_blocks()));
        object.insert("a".into(), json!(node.total_apparent()));
        object.insert("f".into(), json!(node.sub.files));
        object.insert("d".into(), json!(node.sub.dirs));
        object.insert("l".into(), json!(node.sub.symlinks));
        object.insert("o".into(), json!(files_here));
        object.insert("k".into(), json!(node.direct.dirs));
        if let Some(bytes) = exclusive.and_then(|map| map.get(&node.ino)) {
            object.insert("x".into(), json!(bytes));
        }
        let kids = listed.get(&index).map(Vec::as_slice).unwrap_or(&[]);
        let listed_total: u64 = kids
            .iter()
            .map(|&child| self.nodes[child as usize].total_blocks())
            .sum();
        let rest = node
            .total_blocks()
            .saturating_sub(node.own_blocks)
            .saturating_sub(files_here)
            .saturating_sub(listed_total);
        object.insert("r".into(), json!(rest));
        if !kids.is_empty() {
            let children: Vec<Value> = kids
                .iter()
                .map(|&child| self.node_json(child, listed, exclusive))
                .collect();
            object.insert("c".into(), Value::Array(children));
        }
        Value::Object(object)
    }

    /// Directory-level differences from `self` (older) to `newer`, as `(path, delta)` where
    /// each delta is the change *directly* in that directory, or a whole subtree that appeared
    /// or vanished. Applying them all to `self`'s totals gives `newer`'s.
    pub fn diff(&self, newer: &DirTree) -> Vec<(String, Delta)> {
        let mut out = Vec::new();
        if self.nodes.is_empty() || newer.nodes.is_empty() {
            return out;
        }
        let mut stack = vec![(0u32, 0u32)];
        while let Some((old, new)) = stack.pop() {
            let old_node = &self.nodes[old as usize];
            let new_node = &newer.nodes[new as usize];
            // What changed here, apart from what moved below tracked children.
            let mut here = Delta::between(&old_node.sub, &new_node.sub);
            let (mut i, mut j) = (0, 0);
            let (old_kids, new_kids) = (&old_node.children, &new_node.children);
            while i < old_kids.len() || j < new_kids.len() {
                let order = match (old_kids.get(i), new_kids.get(j)) {
                    (Some(&a), Some(&b)) => self.nodes[a as usize]
                        .name
                        .cmp(&newer.nodes[b as usize].name),
                    (Some(_), None) => Ordering::Less,
                    _ => Ordering::Greater,
                };
                match order {
                    Ordering::Equal => {
                        let (a, b) = (old_kids[i], new_kids[j]);
                        let moved = Delta::between(
                            &self.nodes[a as usize].sub,
                            &newer.nodes[b as usize].sub,
                        );
                        here = here.plus(moved.negate());
                        stack.push((a, b));
                        i += 1;
                        j += 1;
                    }
                    // A subtree that went or came. Its own inode is counted here, in `direct`.
                    Ordering::Less => {
                        let a = old_kids[i];
                        let gone = Delta::from(&self.nodes[a as usize].sub).negate();
                        here = here.plus(gone.negate());
                        out.push((self.display_path(a), gone));
                        i += 1;
                    }
                    Ordering::Greater => {
                        let b = new_kids[j];
                        let came = Delta::from(&newer.nodes[b as usize].sub);
                        here = here.plus(came.negate());
                        out.push((newer.display_path(b), came));
                        j += 1;
                    }
                }
            }
            if !here.is_zero() {
                out.push((newer.display_path(new), here));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, parent: u32, depth: u32, direct_blocks: u64) -> DirNode {
        DirNode {
            name: name.as_bytes().into(),
            parent,
            depth,
            ino: 100 + depth as u64,
            own_blocks: 4,
            own_apparent: 4,
            mtime: 0,
            direct: Tally {
                blocks: direct_blocks,
                ..Tally::default()
            },
            sub: Tally::default(),
            children: Vec::new(),
            sealed: false,
            pruned: false,
            alive: true,
        }
    }

    /// root(10) -> a(100) -> a/x(1000); root -> b(50)
    fn sample() -> DirTree {
        let mut nodes = vec![
            node("", NONE, 0, 10 + 4 + 4),
            node("a", 0, 1, 100 + 4),
            node("b", 0, 1, 50),
            node("x", 1, 2, 1000),
        ];
        for index in (0..nodes.len()).rev() {
            let direct = nodes[index].direct;
            nodes[index].sub.add(&direct);
            let parent = nodes[index].parent;
            if parent != NONE {
                let sub = nodes[index].sub;
                nodes[parent as usize].sub.add(&sub);
            }
        }
        nodes[0].children = vec![1, 2];
        nodes[1].children = vec![3];
        DirTree {
            display_root: b"/data".to_vec(),
            scan_root: b"/host/data".to_vec(),
            root_dev: 1,
            nodes,
            links: HashMap::new(),
            handles: Vec::new(),
            plain: Vec::new(),
            untracked_links: Vec::new(),
        }
    }

    #[test]
    fn finds_paths_and_builds_them_back() {
        let tree = sample();
        assert_eq!(tree.find("/data"), Some(0));
        assert_eq!(tree.find("/data/a/x"), Some(3));
        assert_eq!(tree.find("/data/a/y"), None);
        assert_eq!(tree.display_path(3), "/data/a/x");
        assert_eq!(tree.scan_path(3), b"/host/data/a/x".to_vec());
    }

    #[test]
    fn pruned_view_keeps_the_invariant_and_the_limit() {
        let tree = sample();
        let full = tree.pruned(0, 100, 10, 1, None);
        let sum_children: u64 = full["c"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["t"].as_u64().unwrap())
            .sum();
        let t = full["t"].as_u64().unwrap();
        let o = full["o"].as_u64().unwrap();
        let r = full["r"].as_u64().unwrap();
        assert_eq!(t, 4 + o + r + sum_children);
        assert_eq!(full["c"][0]["n"], "a", "largest first");
        assert_eq!(full["c"][0]["c"][0]["n"], "x");

        let small = tree.pruned(0, 2, 10, 1, None);
        assert_eq!(small["c"].as_array().unwrap().len(), 1);
        assert!(small["r"].as_u64().unwrap() >= 54, "b goes to the rest");
    }

    #[test]
    fn propagate_detach_and_graft_keep_totals_consistent() {
        let mut tree = sample();
        let before = tree.root().total_blocks();
        tree.propagate(
            3,
            &Delta {
                blocks: 500,
                ..Delta::default()
            },
        );
        assert_eq!(tree.root().total_blocks(), before + 500);

        let gone = tree.nodes[1].sub;
        tree.detach(1);
        tree.propagate(0, &Delta::from(&gone).negate());
        assert!(!tree.nodes[3].alive);
        assert_eq!(tree.find("/data/a"), None);

        let mut new = sample();
        new.nodes[0].name = b"n".to_vec().into_boxed_slice();
        let at = tree.graft(2, new);
        assert_eq!(tree.display_path(at + 3), "/data/b/n/a/x");
        assert_eq!(tree.find("/data/b/n/a/x"), Some(at + 3));
        assert_eq!(tree.nodes[(at + 3) as usize].depth, 4);
    }

    #[test]
    fn diff_explains_every_byte() {
        let old = sample();
        let mut new = sample();
        new.nodes[3].direct.blocks += 7;
        new.propagate(
            3,
            &Delta {
                blocks: 7,
                ..Delta::default()
            },
        );
        let gone = new.nodes[2].sub;
        new.detach(2);
        new.propagate(0, &Delta::from(&gone).negate());
        let changes = old.diff(&new);
        let total: i64 = changes.iter().map(|(_, d)| d.blocks).sum();
        assert_eq!(
            total,
            new.root().total_blocks() as i64 - old.root().total_blocks() as i64
        );
        assert!(changes
            .iter()
            .any(|(p, d)| p == "/data/a/x" && d.blocks == 7));
        assert!(changes
            .iter()
            .any(|(p, d)| p == "/data/b" && d.blocks == -50));
    }
}
