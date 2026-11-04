//! Keeps each target's tree current between scans and tells `/api/events` what changed.
//!
//! A *source* says which directories may have changed: fanotify's directory events (Linux 5.9+)
//! or btrfs generation polling (older kernels). The engine then re-reads just those
//! directories (one `getdents64` + `fstatat` per entry, as in a scan), applies the difference to
//! the tree and every ancestor, and publishes it. A directory is re-read at most once per
//! `min_relist_interval`, and less often the longer a re-read of it takes, so a busy directory
//! costs at most about 1% of a CPU.
//!
//! Both sources need `CAP_SYS_ADMIN`. Without one, trees still change at each scan, and the
//! scan's differences are published the same way.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use globset::GlobSet;
use serde_json::{json, Value};
use tokio::sync::broadcast;
#[cfg(target_os = "linux")]
use tracing::info;
use tracing::warn;

use crate::config::{ReportMode, Target};
use crate::fsinfo::{self, FsLocation};
use crate::scanner::native::{self, NativeScanner};
use crate::scanner::Scanner;
use std::cmp::Ordering as Order;

use crate::tree::{plain_key, Delta, DirTree, LinkOwner, NONE};

/// Events kept for clients that connect later.
const REPLAY: usize = 200;
/// Scan differences published per scan, largest first.
const SCAN_CHANGES: usize = 200;

#[derive(Clone, Debug)]
pub struct Message {
    pub kind: &'static str,
    pub data: Arc<str>,
}

pub struct LiveStore {
    pub host: String,
    pub targets: Vec<Arc<LiveTarget>>,
    events: broadcast::Sender<Message>,
    recent: Mutex<VecDeque<Message>>,
    queue: Mutex<Queue>,
    wake: Condvar,
    min_relist: Duration,
    status: Mutex<Status>,
    /// Raw signals from the sources (fanotify events, btrfs directories).
    pub signals: AtomicU64,
    pub overflows: AtomicU64,
}

#[derive(Debug, Default, Clone)]
struct Status {
    errors: Vec<String>,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct LiveTarget {
    pub index: usize,
    pub target: Target,
    exclude: GlobSet,
    pub location: Option<FsLocation>,
    pub fsid: Option<[i32; 2]>,
    pub btrfs: bool,
    pub state: RwLock<Option<TreeState>>,
    pub sharing: RwLock<Option<Arc<SharingReport>>>,
    /// The source following this target, once one runs.
    pub source: Mutex<Option<&'static str>>,
    /// Set while a scan runs: changes signalled meanwhile are re-applied to its tree.
    pub scanning: AtomicBool,
    during_scan: Mutex<HashSet<StableKey>>,
    pub relists: AtomicU64,
    pub changes: AtomicU64,
    /// Wakes the scheduler for an early scan, when the live tree cannot settle a change itself.
    pub rescan: tokio::sync::Notify,
    pub rescans_requested: AtomicU64,
}

/// A directory's identity that survives a rescan, unlike its node number.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum StableKey {
    Handle(Box<[u8]>),
    Ino(u64),
}

pub struct TreeState {
    pub tree: DirTree,
    /// Bumped by every rescan; queued work for an older tree is dropped.
    pub generation: u64,
    pub scanned_at: SystemTime,
    pub live_at: Option<SystemTime>,
    handles: HashMap<Box<[u8]>, u32>,
    inos: HashMap<u64, u32>,
    /// The scan's [`DirTree::plain`], and what re-reads found since: which directory each
    /// singly linked file was in.
    plain: Vec<(u32, u32)>,
    /// `(key, node)`, like `plain`; a set, so files sharing a key keep every holder. A
    /// re-read replaces its directory's entries (`plain_by_node`).
    plain_live: BTreeSet<(u32, u32)>,
    plain_by_node: HashMap<u32, Vec<u32>>,
    /// Multiply-linked files counted in untracked directories: not in `tree.links`, so a new
    /// link to one cannot be settled against the tree.
    untracked: HashSet<(u64, u64)>,
}

impl TreeState {
    fn new(mut tree: DirTree, generation: u64, scanned_at: SystemTime) -> Self {
        let handles = std::mem::take(&mut tree.handles)
            .into_iter()
            .map(|(node, handle)| (handle, node))
            .collect();
        let inos = tree
            .nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.ino, index as u32))
            .collect();
        let plain = std::mem::take(&mut tree.plain);
        let untracked = std::mem::take(&mut tree.untracked_links)
            .into_iter()
            .collect();
        Self {
            tree,
            generation,
            scanned_at,
            live_at: None,
            handles,
            inos,
            plain,
            plain_live: BTreeSet::new(),
            plain_by_node: HashMap::new(),
            untracked,
        }
    }

    /// Registers handles and inodes of nodes grafted since the last call.
    fn index_new(&mut self, from: usize) {
        for (node, handle) in self.tree.handles.drain(..) {
            self.handles.insert(handle, node);
        }
        for index in from..self.tree.nodes.len() {
            self.inos.insert(self.tree.nodes[index].ino, index as u32);
        }
        // Grafted directories are new, so they have no entries to replace.
        let mut grafted: HashMap<u32, Vec<u32>> = HashMap::new();
        for (key, node) in self.tree.plain.drain(..) {
            self.plain_live.insert((key, node));
            grafted.entry(node).or_default().push(key);
        }
        for (node, mut keys) in grafted {
            keys.sort_unstable();
            keys.dedup();
            self.plain_by_node.insert(node, keys);
        }
    }

    /// What a re-read of `node` found singly linked in it, in place of what it had. Only the
    /// keys that came or went touch the index.
    fn set_plain(&mut self, node: u32, mut keys: Vec<u32>) {
        keys.sort_unstable();
        keys.dedup();
        let old = self.plain_by_node.remove(&node).unwrap_or_default();
        for &gone in old.iter().filter(|key| keys.binary_search(key).is_err()) {
            self.plain_live.remove(&(gone, node));
        }
        for &new in keys.iter().filter(|key| old.binary_search(key).is_err()) {
            self.plain_live.insert((new, node));
        }
        if !keys.is_empty() {
            self.plain_by_node.insert(node, keys);
        }
    }

    /// Adds singly linked files counted under `node` to what it already holds.
    fn add_plain(&mut self, node: u32, keys: impl Iterator<Item = u32>) {
        let held = self.plain_by_node.entry(node).or_default();
        for key in keys {
            self.plain_live.insert((key, node));
            held.push(key);
        }
        held.sort_unstable();
        held.dedup();
    }

    /// Links a scan saw while it also saw the same file with one link elsewhere: the file was
    /// linked while the scan ran, between its two directories' reads, and is counted twice.
    /// Returns the holders to re-read, and whether one is out of reach (sealed or untracked).
    fn linked_during_scan(&self) -> (Vec<u32>, bool) {
        let mut reread = Vec::new();
        if self.plain.is_empty() {
            // Not a fanotify target: nothing recorded, nothing to reconcile.
            return (reread, false);
        }
        let mut out_of_reach = false;
        for (inode, owner) in &self.tree.links {
            for holder in self.plain_holders(*inode) {
                if holder == owner.node || !self.tree.nodes[holder as usize].alive {
                    continue;
                }
                if self.tree.nodes[holder as usize].sealed {
                    out_of_reach = true;
                } else if !reread.contains(&holder) {
                    reread.push(holder);
                }
            }
        }
        out_of_reach |= self
            .untracked
            .iter()
            .any(|inode| !self.plain_holders(*inode).is_empty());
        (reread, out_of_reach)
    }

    /// Whether the tree already counts this multiply-linked file: under a live owner, or in an
    /// untracked directory.
    fn already_counted(&self, inode: &(u64, u64)) -> bool {
        self.untracked.contains(inode)
            || self
                .tree
                .links
                .get(inode)
                .is_some_and(|owner| self.tree.nodes[owner.node as usize].alive)
    }

    /// Whether a link just adopted may already be counted where the tree cannot reach it: as
    /// a plain file under a sealed directory, or as a link in an untracked one.
    fn counted_out_of_reach(&self, inode: (u64, u64)) -> bool {
        self.untracked.contains(&inode)
            || self.plain_holders(inode).into_iter().any(|holder| {
                let held = &self.tree.nodes[holder as usize];
                held.alive && held.sealed
            })
    }

    /// Directories that held a singly linked file with this inode, at the scan or since. Some
    /// may not any more, or may have held another file with the same key.
    fn plain_holders(&self, (dev, ino): (u64, u64)) -> Vec<u32> {
        let key = plain_key(dev, ino);
        let start = self.plain.partition_point(|&(k, _)| k < key);
        let mut holders: Vec<u32> = self.plain[start..]
            .iter()
            .take_while(|&&(k, _)| k == key)
            .map(|&(_, node)| node)
            .collect();
        holders.extend(
            self.plain_live
                .range((key, 0)..=(key, u32::MAX))
                .map(|&(_, node)| node),
        );
        holders
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn path_of_ino(&self, ino: u64) -> Option<String> {
        let node = self.resolve(&StableKey::Ino(ino))?;
        Some(self.tree.display_path(node))
    }

    fn resolve(&self, key: &StableKey) -> Option<u32> {
        let node = match key {
            StableKey::Handle(handle) => self.handles.get(handle),
            StableKey::Ino(ino) => self.inos.get(ino),
        }
        .copied()?;
        self.tree.nodes[node as usize].alive.then_some(node)
    }
}

/// What the btrfs sharing pass found for one target.
#[derive(Debug, Clone)]
pub struct SharingReport {
    pub at: SystemTime,
    pub duration: Duration,
    /// What the files add up to (the tree's total) when the pass ran.
    pub logical: u64,
    pub disk: u64,
    pub outside: u64,
    pub pairs: Vec<(String, String, u64)>,
    /// Directory inode → bytes deleting it would free.
    pub by_ino: HashMap<u64, u64>,
}

#[derive(Default)]
struct Queue {
    /// `(target, node)` → the tree generation it was queued for.
    pending: HashMap<(usize, u32), u64>,
    /// Not before: when each directory may be re-read again.
    cooldown: HashMap<(usize, u32), Instant>,
}

/// What a re-read changed.
#[derive(Default)]
struct Outcome {
    /// Directories whose subtree total changed, and by how much.
    changes: Vec<(u32, Delta)>,
    /// Directories to re-read next: a vanished one's parent, a link's new owner.
    requeue: Vec<u32>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn millis(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn seconds(time: SystemTime) -> f64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

impl LiveTarget {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn exclude(&self) -> &GlobSet {
        &self.exclude
    }

    /// Asks for a scan sooner than the interval (the scheduler spaces them out).
    fn request_rescan(&self) {
        self.rescans_requested.fetch_add(1, Ordering::Relaxed);
        self.rescan.notify_one();
    }
}

impl LiveStore {
    pub fn new(
        host: String,
        targets: &[Target],
        host_root: &std::path::Path,
        min_relist: Duration,
    ) -> anyhow::Result<Arc<Self>> {
        let targets = targets
            .iter()
            .enumerate()
            .map(|(index, target)| {
                Ok(Arc::new(LiveTarget {
                    index,
                    exclude: native::exclude_set(&target.exclude)?,
                    location: fsinfo::locate(&target.scan_path, host_root),
                    fsid: fsid(&target.scan_path),
                    btrfs: is_btrfs(&target.scan_path),
                    target: target.clone(),
                    state: RwLock::new(None),
                    sharing: RwLock::new(None),
                    source: Mutex::new(None),
                    scanning: AtomicBool::new(false),
                    during_scan: Mutex::new(HashSet::new()),
                    relists: AtomicU64::new(0),
                    changes: AtomicU64::new(0),
                    rescan: tokio::sync::Notify::new(),
                    rescans_requested: AtomicU64::new(0),
                }))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let (events, _) = broadcast::channel(4096);
        Ok(Arc::new(Self {
            host,
            targets,
            events,
            recent: Mutex::new(VecDeque::new()),
            queue: Mutex::new(Queue::default()),
            wake: Condvar::new(),
            min_relist,
            status: Mutex::new(Status::default()),
            signals: AtomicU64::new(0),
            overflows: AtomicU64::new(0),
        }))
    }

    pub fn target(&self, name: &str) -> Option<&Arc<LiveTarget>> {
        self.targets.iter().find(|lt| lt.target.name == name)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Message> {
        self.events.subscribe()
    }

    pub fn recent(&self) -> Vec<Message> {
        lock(&self.recent).iter().cloned().collect()
    }

    pub fn note_error(&self, error: String) {
        warn!(%error, "live updates limited");
        lock(&self.status).errors.push(error);
    }

    /// `{source, active, error}` for `/api/info` and the SSE greeting.
    pub fn summary(&self) -> Value {
        let mut sources: Vec<&str> = self
            .targets
            .iter()
            .filter_map(|lt| *lock(&lt.source))
            .collect();
        sources.sort_unstable();
        sources.dedup();
        let status = lock(&self.status);
        let error = (!status.errors.is_empty()).then(|| status.errors.join("; "));
        json!({
            "source": if sources.is_empty() { "scans".to_string() } else { sources.join("+") },
            "active": !sources.is_empty(),
            "error": error,
        })
    }

    pub fn publish(&self, kind: &'static str, value: Value) {
        let message = Message {
            kind,
            data: value.to_string().into(),
        };
        if kind == "change" {
            let mut recent = lock(&self.recent);
            if recent.len() == REPLAY {
                recent.pop_front();
            }
            recent.push_back(message.clone());
        }
        let _ = self.events.send(message);
    }

    fn enqueue(&self, target: usize, node: u32, generation: u64) {
        let mut queue = lock(&self.queue);
        queue.pending.insert((target, node), generation);
        drop(queue);
        self.wake.notify_one();
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn signal(&self, lt: &LiveTarget, key: StableKey) {
        self.signals.fetch_add(1, Ordering::Relaxed);
        // Under the read lock, so `replace` (which drains `during_scan` and clears `scanning`
        // under the write lock) sees this signal either in the old tree's queue or in the
        // replay set.
        let guard = lt.state.read().unwrap_or_else(PoisonError::into_inner);
        if let Some(state) = guard.as_ref() {
            if let Some(node) = state.resolve(&key) {
                self.enqueue(lt.index, node, state.generation);
            }
        }
        if lt.scanning.load(Ordering::Relaxed) {
            lock(&lt.during_scan).insert(key);
        }
    }

    /// fanotify: a directory with this handle, on the filesystem with this ID, changed.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn signal_handle(&self, fsid: [i32; 2], handle: &[u8]) {
        for lt in &self.targets {
            if lt.fsid == Some(fsid) && *lock(&lt.source) == Some("fanotify") {
                self.signal(lt, StableKey::Handle(handle.into()));
            }
        }
    }

    /// btrfs: the directory with this inode, in target `index`, changed.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn signal_ino(&self, index: usize, ino: u64) {
        self.signal(&self.targets[index], StableKey::Ino(ino));
    }

    /// Takes a finished scan's tree: publishes how it differs from the live one, swaps it in,
    /// and replays the changes signalled while the scan ran.
    pub fn replace(&self, index: usize, tree: DirTree, started: SystemTime, duration: Duration) {
        let lt = &self.targets[index];
        let mut guard = lt.state.write().unwrap_or_else(PoisonError::into_inner);
        let (generation, mut changes) = match guard.as_ref() {
            Some(old) => (old.generation + 1, old.tree.diff(&tree)),
            None => (1, Vec::new()),
        };
        let state = TreeState::new(tree, generation, started);
        let total = state.tree.root().total_blocks();
        let keys: Vec<StableKey> = lock(&lt.during_scan).drain().collect();
        let mut replay: Vec<u32> = keys.iter().filter_map(|key| state.resolve(key)).collect();
        let (reread, out_of_reach) = state.linked_during_scan();
        replay.extend(reread);
        if out_of_reach {
            lt.request_rescan();
        }
        *guard = Some(state);
        lt.scanning.store(false, Ordering::Relaxed);
        drop(guard);
        for node in replay {
            self.enqueue(index, node, generation);
        }

        changes.sort_by_key(|(_, delta)| std::cmp::Reverse(delta.blocks.unsigned_abs()));
        changes.truncate(SCAN_CHANGES);
        let now = millis(SystemTime::now());
        for (path, delta) in changes {
            self.publish(
                "change",
                json!({
                    "t": now, "host": self.host, "target": lt.target.name, "path": path,
                    "db": delta.blocks, "da": delta.apparent, "df": delta.files,
                    "src": "scan",
                }),
            );
        }
        self.publish(
            "scan",
            json!({
                "t": now, "host": self.host, "target": lt.target.name,
                "duration_s": duration.as_secs_f64(), "b": total,
            }),
        );
    }

    /// The engine: waits for queued directories, re-reads each once its cooldown is over.
    pub fn run(self: Arc<Self>) {
        loop {
            let due = self.next_due();
            let mut by_target: HashMap<usize, Vec<(u32, u64)>> = HashMap::new();
            for (target, node, generation) in due {
                by_target
                    .entry(target)
                    .or_default()
                    .push((node, generation));
            }
            for (target, nodes) in by_target {
                self.relist_all(target, nodes);
            }
        }
    }

    fn next_due(&self) -> Vec<(usize, u32, u64)> {
        let mut queue = lock(&self.queue);
        loop {
            let now = Instant::now();
            let Queue { pending, cooldown } = &mut *queue;
            let mut due = Vec::new();
            let mut wake_at: Option<Instant> = None;
            pending.retain(|&key, &mut generation| match cooldown.get(&key) {
                Some(&until) if until > now => {
                    wake_at = Some(wake_at.map_or(until, |at| at.min(until)));
                    true
                }
                _ => {
                    due.push((key.0, key.1, generation));
                    false
                }
            });
            if cooldown.len() > 100_000 {
                cooldown.retain(|_, until| *until > now);
            }
            if !due.is_empty() {
                return due;
            }
            let wait = wake_at.map_or(Duration::from_secs(5), |at| at - now);
            queue = self
                .wake
                .wait_timeout(queue, wait)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    fn relist_all(&self, index: usize, nodes: Vec<(u32, u64)>) {
        let lt = &self.targets[index];
        let mut changed = Vec::new();
        let mut requeue = Vec::new();
        {
            let mut guard = lt.state.write().unwrap_or_else(PoisonError::into_inner);
            let Some(state) = guard.as_mut() else {
                return;
            };
            for (node, generation) in nodes {
                if generation != state.generation {
                    continue;
                }
                let started = Instant::now();
                let outcome = relist(lt, state, node);
                let cost = started.elapsed();
                lt.relists.fetch_add(1, Ordering::Relaxed);
                lock(&self.queue).cooldown.insert(
                    (index, node),
                    Instant::now() + self.min_relist.max(cost * 100),
                );
                for (dir, delta) in outcome.changes {
                    if delta.is_zero() {
                        continue;
                    }
                    state.live_at = Some(SystemTime::now());
                    // A file rewritten in place changes its apparent size only: the tree
                    // takes it, the event stream does not.
                    if delta.blocks != 0
                        || delta.files != 0
                        || delta.dirs != 0
                        || delta.symlinks != 0
                    {
                        let tree = &state.tree;
                        changed.push((
                            tree.display_path(dir),
                            delta,
                            tree.nodes[dir as usize].total_blocks(),
                        ));
                    }
                }
                requeue.extend(
                    outcome
                        .requeue
                        .into_iter()
                        .map(|dir| (dir, state.generation)),
                );
            }
        }
        for (dir, generation) in requeue {
            self.enqueue(index, dir, generation);
        }
        let source = (*lock(&lt.source)).unwrap_or("scan");
        let now = millis(SystemTime::now());
        for (path, delta, total) in changed {
            lt.changes.fetch_add(1, Ordering::Relaxed);
            self.publish(
                "change",
                json!({
                    "t": now, "host": self.host, "target": lt.target.name, "path": path,
                    "db": delta.blocks, "da": delta.apparent, "df": delta.files, "b": total,
                    "src": source,
                }),
            );
        }
    }
}

/// `plain_live` may hold this many entries more than the scan's index before a scan is asked
/// for to rebuild it. (A re-read of a directory lists all of its files there again.)
const PLAIN_LIVE_HEADROOM: usize = if cfg!(test) { 100 } else { 100_000 };

/// Re-reads one directory and applies what changed to it and its ancestors.
fn relist(lt: &LiveTarget, state: &mut TreeState, node: u32) -> Outcome {
    let mut out = Outcome::default();
    let current = &state.tree.nodes[node as usize];
    if !current.alive || current.sealed {
        return out;
    }
    let by_handle = *lock(&lt.source) == Some("fanotify");
    let listing = match native::read_direct(
        &lt.target,
        &lt.exclude,
        &state.tree.scan_path(node),
        &state.tree.display_path_bytes(node),
        state.tree.root_dev,
        by_handle,
    ) {
        Ok(listing) => listing,
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP)
            ) =>
        {
            // Gone: its parent's re-read drops it.
            let parent = state.tree.nodes[node as usize].parent;
            if parent != NONE {
                out.requeue.push(parent);
            }
            return out;
        }
        Err(_) => return out,
    };

    let mut direct = listing.direct;
    let Settled {
        mut handed,
        writes,
        here,
        mut adopted,
    } = settle_links(&mut state.tree, node, &listing.links, &mut direct);
    state.set_plain(node, listing.plain);

    // Subdirectories that came or went. A directory replaced under the same name is a new one.
    let mut moved = Delta::default();
    let old_children = state.tree.nodes[node as usize].children.clone();
    let (mut i, mut j) = (0, 0);
    while i < old_children.len() || j < listing.subdirs.len() {
        let order = match (old_children.get(i), listing.subdirs.get(j)) {
            (Some(&child), Some(subdir)) => {
                match state.tree.nodes[child as usize].name[..].cmp(&subdir.name) {
                    Order::Equal if replaced(state, child, subdir, by_handle) => Order::Less,
                    order => order,
                }
            }
            (Some(_), None) => Order::Less,
            _ => Order::Greater,
        };
        match order {
            Order::Equal => {
                let child = &mut state.tree.nodes[old_children[i] as usize];
                child.own_blocks = listing.subdirs[j].blocks;
                child.own_apparent = listing.subdirs[j].apparent;
                // Its entries changed (or it was replaced by one with a reused inode number):
                // read it too.
                if child.mtime != listing.subdirs[j].mtime {
                    out.requeue.push(old_children[i]);
                }
                i += 1;
                j += 1;
            }
            Order::Less => {
                let child = old_children[i];
                moved = moved.plus(Delta::from(&state.tree.nodes[child as usize].sub).negate());
                handed.extend(state.tree.detach(child));
                i += 1;
            }
            Order::Greater => {
                if let Some((sub, shared)) =
                    walk_new(lt, &state.tree, node, &listing.subdirs[j].name)
                {
                    moved = moved.plus(Delta::from(&sub.nodes[0].sub));
                    let from = state.tree.nodes.len();
                    let fits = from + sub.nodes.len() <= lt.target.tree_max_directories;
                    // Links counted without a node (in the subtree's untracked part, or all of
                    // them past the cap) cannot be settled against the tree: if one may be
                    // counted elsewhere as a plain file, a scan has to settle it.
                    // Links it counts in untracked directories are not settled by walk_new
                    // either: one the tree already counts is counted twice.
                    let unsettled = sub
                        .untracked_links
                        .iter()
                        .chain(sub.links.keys().filter(|_| !fits))
                        .any(|inode| {
                            !state.plain_holders(*inode).is_empty() || state.already_counted(inode)
                        });
                    if unsettled {
                        lt.request_rescan();
                    }
                    state.untracked.extend(sub.untracked_links.iter().copied());
                    if !fits {
                        // Past the cap: counted, but without nodes, as a scan would. What it
                        // counts stays on record, under this now sealed directory, for links
                        // made to it later.
                        state.tree.nodes[node as usize].sealed = true;
                        state.add_plain(node, sub.plain.iter().map(|&(key, _)| key));
                        state.untracked.extend(sub.links.keys().copied());
                        j += 1;
                        continue;
                    }
                    adopted.extend(sub.links.keys().copied());
                    state.tree.graft(node, sub);
                    // Links in the new subtree that are counted elsewhere: it holds them too.
                    for (inode, holders) in shared {
                        if let Some(owner) = state.tree.links.get_mut(&inode) {
                            owner
                                .others
                                .extend(holders.iter().map(|&h| h + from as u32));
                        }
                    }
                    state.index_new(from);
                }
                j += 1;
            }
        }
    }

    // fanotify reports a new hard link only to the new link's directory. If the file had one
    // link before, the directory holding that link still counts it as a plain file: re-read it,
    // and it sees the file is now counted here.
    // A sealed directory is never re-read (it has untracked contents), so a scan settles it.
    for inode in adopted {
        if state.counted_out_of_reach(inode) {
            lt.request_rescan();
        }
        for holder in state.plain_holders(inode) {
            let held = &state.tree.nodes[holder as usize];
            if held.alive && !held.sealed && holder != node && !out.requeue.contains(&holder) {
                out.requeue.push(holder);
            }
        }
    }
    // Entries of directories that died since the scan linger; past this, a scan rebuilds it.
    if state.plain_live.len() > state.plain.len() + PLAIN_LIVE_HEADROOM {
        lt.request_rescan();
    }

    let tree = &mut state.tree;
    let old_direct = tree.nodes[node as usize].direct;
    tree.nodes[node as usize].direct = direct;
    let mut delta = Delta::between(&old_direct, &direct).plus(moved);
    tree.propagate(node, &delta);
    // The directory's own inode grows with its entries; its parent counts it.
    let own = &mut tree.nodes[node as usize];
    let grown = Delta {
        blocks: listing.own.blocks as i64 - own.own_blocks as i64,
        apparent: listing.own.apparent as i64 - own.own_apparent as i64,
        ..Delta::default()
    };
    own.own_blocks = listing.own.blocks;
    own.own_apparent = listing.own.apparent;
    own.mtime = listing.own.mtime;
    if !grown.is_zero() {
        let parent = tree.nodes[node as usize].parent;
        if parent != NONE {
            tree.nodes[parent as usize].direct.apply(&grown);
            tree.propagate(parent, &grown);
        }
        delta = delta.plus(grown);
    }
    out.changes.push((node, delta));

    // A link written through here changes the size where it is counted.
    for (owner, change) in writes {
        tree.nodes[owner as usize].direct.apply(&change);
        tree.propagate(owner, &change);
        out.changes.push((owner, change));
    }
    // A counted link that went: another directory holding one takes the file over, and is
    // re-read to confirm it still does.
    for (inode, mut owner) in handed {
        let DirTree { nodes, links, .. } = &mut *tree;
        // A graft already counts it (the subtree was renamed): it only gains holders.
        if let Some(counted) = links.get_mut(&inode) {
            if nodes[counted.node as usize].alive {
                for other in owner.others {
                    if other != counted.node && !counted.others.contains(&other) {
                        counted.others.push(other);
                    }
                }
                continue;
            }
        }
        owner.others.retain(|&other| {
            nodes[other as usize].alive && (other != node || here.contains(&inode))
        });
        // This directory, if it still holds a link, else the first other holder.
        let next = if owner.others.contains(&node) {
            node
        } else if let Some(&first) = owner.others.first() {
            first
        } else {
            continue;
        };
        owner.others.retain(|&other| other != next);
        let size = Delta {
            blocks: owner.blocks as i64,
            apparent: owner.apparent as i64,
            ..Delta::default()
        };
        tree.nodes[next as usize].direct.apply(&size);
        tree.propagate(next, &size);
        out.changes.push((next, size));
        if next != node {
            out.requeue.push(next);
        }
        owner.node = next;
        tree.links.insert(inode, owner);
    }
    out
}

/// Whether `subdir`, listed under the name of `child`, is another directory: a different
/// inode, or (fanotify, where ext4 reuses inode numbers) a different file handle.
fn replaced(state: &TreeState, child: u32, subdir: &native::Subdir, by_handle: bool) -> bool {
    let node = &state.tree.nodes[child as usize];
    if node.ino != subdir.ino {
        return true;
    }
    if !by_handle || node.mtime == subdir.mtime {
        return false;
    }
    native::dir_handle(&state.tree.scan_path(child))
        .is_some_and(|handle| state.handles.get(&handle) != Some(&child))
}

/// What settling one directory's multiply-linked files found.
struct Settled {
    /// Links the directory counted but no longer lists, to hand on.
    handed: Vec<((u64, u64), LinkOwner)>,
    /// Size changes made through the directory's link to files counted elsewhere.
    writes: Vec<(u32, Delta)>,
    /// Every multiply-linked inode the directory lists.
    here: HashSet<(u64, u64)>,
    /// Multiply-linked inodes the tree did not know, now counted here.
    adopted: Vec<(u64, u64)>,
}

/// Counts the multiply-linked files listed in `node` once each, where they already count, and
/// adds the ones `node` owns to `direct`.
fn settle_links(
    tree: &mut DirTree,
    node: u32,
    listed: &[((u64, u64), u64, u64)],
    direct: &mut crate::tree::Tally,
) -> Settled {
    let DirTree { nodes, links, .. } = tree;
    let mut seen = HashSet::new();
    let mut writes = Vec::new();
    let mut adopted = Vec::new();
    for &(inode, blocks, apparent) in listed {
        // Two links in one directory are still one file.
        if !seen.insert(inode) {
            continue;
        }
        match links.get_mut(&inode) {
            Some(owner) if owner.node == node => {
                owner.blocks = blocks;
                owner.apparent = apparent;
                direct.add_size(blocks, apparent);
            }
            Some(owner) if nodes[owner.node as usize].alive => {
                if !owner.others.contains(&node) {
                    owner.others.push(node);
                }
                let change = Delta {
                    blocks: blocks as i64 - owner.blocks as i64,
                    apparent: apparent as i64 - owner.apparent as i64,
                    ..Delta::default()
                };
                if !change.is_zero() {
                    (owner.blocks, owner.apparent) = (blocks, apparent);
                    writes.push((owner.node, change));
                }
            }
            previous => {
                if previous.is_none() {
                    adopted.push(inode);
                }
                let mut others = previous
                    .map(|owner| owner.others.clone())
                    .unwrap_or_default();
                others.retain(|&other| other != node && nodes[other as usize].alive);
                links.insert(
                    inode,
                    LinkOwner {
                        node,
                        blocks,
                        apparent,
                        others,
                    },
                );
                direct.add_size(blocks, apparent);
            }
        }
    }
    let gone: Vec<(u64, u64)> = links
        .iter()
        .filter(|(inode, owner)| owner.node == node && !seen.contains(inode))
        .map(|(inode, _)| *inode)
        .collect();
    let handed = gone
        .into_iter()
        .filter_map(|inode| links.remove(&inode).map(|owner| (inode, owner)))
        .collect();
    for (inode, owner) in links.iter_mut() {
        if !seen.contains(inode) {
            owner.others.retain(|&other| other != node);
        }
    }
    Settled {
        handed,
        writes,
        here: seen,
        adopted,
    }
}

/// Walks a directory that appeared since the scan, as a tree to graft under `parent`, with
/// the links in it that `tree` already counts elsewhere: `(inode, directories in the new tree
/// holding it)`.
#[allow(clippy::type_complexity)]
fn walk_new(
    lt: &LiveTarget,
    tree: &DirTree,
    parent: u32,
    name: &[u8],
) -> Option<(DirTree, Vec<((u64, u64), Vec<u32>)>)> {
    fn join(mut base: Vec<u8>, name: &[u8]) -> PathBuf {
        if base.last() != Some(&b'/') {
            base.push(b'/');
        }
        base.extend_from_slice(name);
        PathBuf::from(OsStr::from_bytes(&base))
    }
    let depth = tree.nodes[parent as usize].depth as usize + 1;
    let mut target = lt.target.clone();
    target.display_path = join(tree.display_path_bytes(parent), name);
    target.scan_path = join(tree.scan_path(parent), name);
    target.report_mode = ReportMode::Tree;
    target.report_depth = 0;
    target.scan_threads = 1;
    target.max_depth = target.max_depth.map(|cap| cap.saturating_sub(depth));
    // What is left of the target's directory budget.
    target.tree_max_directories = target.tree_max_directories.saturating_sub(tree.nodes.len());
    // fanotify reports changes inside the new directories by handle from now on.
    target.collect_handles = *lock(&lt.source) == Some("fanotify");
    let scanner = NativeScanner::new(&target).ok()?;
    let mut sub = scanner.scan(&target, &AtomicBool::new(false)).ok()?.tree?;
    sub.nodes[0].name = name.into();
    // Links the main tree already counts stay counted there.
    let taken: Vec<((u64, u64), LinkOwner)> = sub
        .links
        .iter()
        .filter(|(inode, _)| {
            tree.links
                .get(inode)
                .is_some_and(|owner| tree.nodes[owner.node as usize].alive)
        })
        .map(|(inode, owner)| (*inode, owner.clone()))
        .collect();
    let mut shared = Vec::new();
    for (inode, owner) in taken {
        sub.links.remove(&inode);
        let delta = Delta {
            blocks: -(owner.blocks as i64),
            apparent: -(owner.apparent as i64),
            ..Delta::default()
        };
        sub.nodes[owner.node as usize].direct.apply(&delta);
        sub.propagate(owner.node, &delta);
        let mut holders = owner.others;
        holders.push(owner.node);
        shared.push((inode, holders));
    }
    Some((sub, shared))
}

#[cfg(target_os = "linux")]
fn fsid(path: &std::path::Path) -> Option<[i32; 2]> {
    fsinfo::fsid(path)
}

#[cfg(not(target_os = "linux"))]
fn fsid(_path: &std::path::Path) -> Option<[i32; 2]> {
    None
}

#[cfg(target_os = "linux")]
fn is_btrfs(path: &std::path::Path) -> bool {
    crate::btrfs::is_btrfs(path)
}

#[cfg(not(target_os = "linux"))]
fn is_btrfs(_path: &std::path::Path) -> bool {
    false
}

/// Starts the sources for every live target; returns the targets whose walks must record
/// file handles (the fanotify ones).
pub fn start_sources(store: &Arc<LiveStore>, poll_interval: Duration) -> Vec<usize> {
    let live: Vec<&Arc<LiveTarget>> = store.targets.iter().filter(|lt| lt.target.live).collect();
    if live.is_empty() {
        return Vec::new();
    }
    let engine = Arc::clone(store);
    std::thread::Builder::new()
        .name("harvester-live".to_string())
        .spawn(move || engine.run())
        .expect("spawn the live engine");

    let (btrfs, others): (Vec<_>, Vec<_>) = live.into_iter().partition(|lt| lt.btrfs);
    for lt in btrfs {
        start_btrfs(store, lt, poll_interval);
    }
    if others.is_empty() {
        return Vec::new();
    }
    start_fanotify(store, &others)
}

#[cfg(target_os = "linux")]
fn start_btrfs(store: &Arc<LiveStore>, lt: &Arc<LiveTarget>, interval: Duration) {
    let mut watcher = match crate::btrfs::Watcher::open(&lt.target.scan_path) {
        Ok(watcher) => watcher,
        Err(error) => {
            store.note_error(format!(
                "btrfs polling for {}: {error}{}",
                lt.target.name,
                if error.raw_os_error() == Some(libc::EPERM) {
                    " (needs CAP_SYS_ADMIN)"
                } else {
                    ""
                }
            ));
            return;
        }
    };
    *lock(&lt.source) = Some("btrfs");
    info!(target = %lt.target.name, "following changes by btrfs generation");
    let store = Arc::clone(store);
    let index = lt.index;
    std::thread::Builder::new()
        .name("harvester-btrfs".to_string())
        .spawn(move || loop {
            std::thread::sleep(interval);
            if let Err(error) = watcher.poll(|ino| store.signal_ino(index, ino)) {
                warn!(%error, "btrfs poll failed");
                std::thread::sleep(interval * 10);
            }
        })
        .expect("spawn a btrfs watcher");
}

#[cfg(not(target_os = "linux"))]
fn start_btrfs(_store: &Arc<LiveStore>, _lt: &Arc<LiveTarget>, _interval: Duration) {}

#[cfg(target_os = "linux")]
fn start_fanotify(store: &Arc<LiveStore>, targets: &[&Arc<LiveTarget>]) -> Vec<usize> {
    match fanotify::Fanotify::new() {
        Ok(mut notify) => {
            let mut marked = Vec::new();
            for lt in targets {
                match notify.mark(&lt.target.scan_path) {
                    Ok(()) if lt.fsid.is_some() => {
                        *lock(&lt.source) = Some("fanotify");
                        marked.push(lt.index);
                    }
                    Ok(()) => store.note_error(format!("fanotify for {}: no fsid", lt.target.name)),
                    Err(error) => {
                        store.note_error(format!("fanotify for {}: {error}", lt.target.name))
                    }
                }
            }
            if !marked.is_empty() {
                info!(targets = marked.len(), "following changes with fanotify");
                let store = Arc::clone(store);
                std::thread::Builder::new()
                    .name("harvester-fanotify".to_string())
                    .spawn(move || notify.run(&store))
                    .expect("spawn the fanotify reader");
            }
            marked
        }
        Err(error) => {
            store.note_error(format!("fanotify: {error}"));
            Vec::new()
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn start_fanotify(store: &Arc<LiveStore>, _targets: &[&Arc<LiveTarget>]) -> Vec<usize> {
    store.note_error("live updates need Linux".to_string());
    Vec::new()
}

#[cfg(target_os = "linux")]
mod fanotify {
    use std::ffi::CString;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::sync::atomic::Ordering;

    use tracing::warn;

    use super::LiveStore;

    const FAN_CLOEXEC: u32 = 0x1;
    const FAN_CLASS_NOTIF: u32 = 0x0;
    const FAN_REPORT_DIR_FID: u32 = 0x400;
    const FAN_REPORT_NAME: u32 = 0x800;
    const FAN_MARK_ADD: u32 = 0x1;
    const FAN_MARK_FILESYSTEM: u32 = 0x100;
    const FAN_MODIFY: u64 = 0x2;
    const FAN_CLOSE_WRITE: u64 = 0x8;
    const FAN_MOVED_FROM: u64 = 0x40;
    const FAN_MOVED_TO: u64 = 0x80;
    const FAN_CREATE: u64 = 0x100;
    const FAN_DELETE: u64 = 0x200;
    const FAN_ONDIR: u64 = 0x4000_0000;
    const FAN_Q_OVERFLOW: u64 = 0x4000;
    const INFO_DFID_NAME: u8 = 2;
    const INFO_DFID: u8 = 3;
    const MASK: u64 = FAN_MODIFY
        | FAN_CLOSE_WRITE
        | FAN_MOVED_FROM
        | FAN_MOVED_TO
        | FAN_CREATE
        | FAN_DELETE
        | FAN_ONDIR;

    pub struct Fanotify {
        fd: OwnedFd,
    }

    impl Fanotify {
        pub fn new() -> io::Result<Self> {
            // SAFETY: plain syscall with flag arguments.
            let fd = unsafe {
                libc::syscall(
                    libc::SYS_fanotify_init,
                    FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_REPORT_DIR_FID | FAN_REPORT_NAME,
                    (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
                )
            };
            if fd < 0 {
                let error = io::Error::last_os_error();
                let hint = match error.raw_os_error() {
                    Some(libc::EPERM) => " (needs CAP_SYS_ADMIN)",
                    Some(libc::EINVAL) => " (directory events need Linux 5.9+)",
                    _ => "",
                };
                return Err(io::Error::new(error.kind(), format!("{error}{hint}")));
            }
            Ok(Self {
                // SAFETY: the kernel returned a descriptor nothing else owns.
                fd: unsafe { OwnedFd::from_raw_fd(fd as i32) },
            })
        }

        /// Follows the whole filesystem `path` is on.
        pub fn mark(&mut self, path: &Path) -> io::Result<()> {
            let path = CString::new(path.as_os_str().as_bytes())
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            // SAFETY: `path` is NUL-terminated.
            let status = unsafe {
                libc::syscall(
                    libc::SYS_fanotify_mark,
                    self.fd.as_raw_fd(),
                    FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                    MASK,
                    libc::AT_FDCWD,
                    path.as_ptr(),
                )
            };
            if status != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        pub fn run(self, store: &LiveStore) {
            let mut buf = vec![0u8; 256 * 1024];
            loop {
                // SAFETY: the buffer is valid for its length.
                let read =
                    unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                if read < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    warn!(%error, "fanotify read failed; live updates stop");
                    store.note_error(format!("fanotify read: {error}"));
                    return;
                }
                parse(&buf[..read as usize], store);
            }
        }
    }

    fn parse(mut events: &[u8], store: &LiveStore) {
        while events.len() >= 24 {
            let event_len = u32::from_ne_bytes(events[0..4].try_into().unwrap()) as usize;
            if event_len < 24 || event_len > events.len() {
                return;
            }
            let event = &events[..event_len];
            let metadata_len = u16::from_ne_bytes(event[6..8].try_into().unwrap()) as usize;
            let mask = u64::from_ne_bytes(event[8..16].try_into().unwrap());
            let fd = i32::from_ne_bytes(event[16..20].try_into().unwrap());
            if fd >= 0 {
                // SAFETY: the kernel handed us this descriptor.
                unsafe { libc::close(fd) };
            }
            if mask & FAN_Q_OVERFLOW != 0 {
                store.overflows.fetch_add(1, Ordering::Relaxed);
            }
            let mut info = &event[metadata_len.min(event.len())..];
            while info.len() >= 4 {
                let kind = info[0];
                let len = u16::from_ne_bytes(info[2..4].try_into().unwrap()) as usize;
                if len < 4 || len > info.len() {
                    break;
                }
                let record = &info[..len];
                if (kind == INFO_DFID_NAME || kind == INFO_DFID) && record.len() >= 20 {
                    let fsid = [
                        i32::from_ne_bytes(record[4..8].try_into().unwrap()),
                        i32::from_ne_bytes(record[8..12].try_into().unwrap()),
                    ];
                    let bytes = u32::from_ne_bytes(record[12..16].try_into().unwrap()) as usize;
                    if record.len() >= 20 + bytes {
                        // The key `name_to_handle_at` gave the walk: handle type, then handle.
                        let key = &record[16..20 + bytes];
                        store.signal_handle(fsid, key);
                    }
                }
                info = &info[len..];
            }
            events = &events[event_len..];
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::Path;

    use super::*;
    use crate::config::SizeMode;

    fn target(root: &Path) -> Target {
        Target {
            name: "t".to_string(),
            target_type: "filesystem".to_string(),
            scanner: "native".to_string(),
            display_path: PathBuf::from("/data"),
            scan_path: root.to_path_buf(),
            baseline_interval: Duration::from_secs(60),
            timeout: Duration::from_secs(30),
            no_cross_filesystem: true,
            follow_symlinks: false,
            report_mode: ReportMode::Tree,
            report_depth: 1,
            max_depth: None,
            scan_threads: 2,
            size_modes: vec![SizeMode::Blocks],
            exclude: vec!["**/skip/**".to_string()],
            tree_max_directories: 1000,
            live: true,
            sharing_interval: None,
            collect_handles: false,
            labels: BTreeMap::new(),
        }
    }

    fn write(path: &Path, len: usize) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        File::create(path)
            .unwrap()
            .write_all(&vec![7; len])
            .unwrap();
    }

    /// A store following `target`, holding its first scan.
    fn started(target: &Target) -> Arc<LiveStore> {
        let store = LiveStore::new(
            "test".into(),
            std::slice::from_ref(target),
            Path::new("/"),
            Duration::ZERO,
        )
        .unwrap();
        store.replace(0, scan(target), SystemTime::now(), Duration::ZERO);
        store
    }

    fn scan(target: &Target) -> DirTree {
        NativeScanner::new(target)
            .unwrap()
            .scan(target, &AtomicBool::new(false))
            .unwrap()
            .tree
            .unwrap()
    }

    /// `path -> (total blocks, files, dirs)` for every live directory.
    fn totals(tree: &DirTree) -> BTreeMap<String, (u64, u64, u64)> {
        (0..tree.nodes.len() as u32)
            .filter(|&n| tree.nodes[n as usize].alive)
            .map(|n| {
                let node = &tree.nodes[n as usize];
                (
                    tree.display_path(n),
                    (node.total_blocks(), node.sub.files, node.sub.dirs),
                )
            })
            .collect()
    }

    fn relist_paths(store: &LiveStore, paths: &[&str]) {
        let nodes: Vec<(u32, u64)> = {
            let guard = store.targets[0].state.read().unwrap();
            let state = guard.as_ref().unwrap();
            paths
                .iter()
                .map(|path| (state.tree.find(path).unwrap(), state.generation))
                .collect()
        };
        store.relist_all(0, nodes);
    }

    #[test]
    fn relists_converge_to_what_a_fresh_scan_finds() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        write(&root.join("a/one.bin"), 10_000);
        write(&root.join("a/b/two.bin"), 20_000);
        write(&root.join("c/three.bin"), 30_000);
        write(&root.join("c/deep/four.bin"), 40_000);
        let target = target(root);
        let store = started(&target);
        let mut events = store.subscribe();

        // Growth, a new subtree (with an excluded part), and a removed subtree.
        write(&root.join("a/one.bin"), 110_000);
        write(&root.join("a/new/five.bin"), 50_000);
        write(&root.join("a/new/sub/six.bin"), 60_000);
        write(&root.join("a/new/skip/hidden.bin"), 70_000);
        fs::remove_dir_all(root.join("c")).unwrap();
        relist_paths(&store, &["/data", "/data/a"]);

        let live = totals(
            &store.targets[0]
                .state
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .tree,
        );
        assert_eq!(live, totals(&scan(&target)));

        let mut changed = Vec::new();
        while let Ok(message) = events.try_recv() {
            let value: Value = serde_json::from_str(&message.data).unwrap();
            changed.push((
                value["path"].as_str().unwrap().to_string(),
                value["db"].as_i64().unwrap(),
            ));
        }
        assert!(
            changed
                .iter()
                .any(|(path, db)| path == "/data/a" && *db > 0),
            "{changed:?}"
        );
        assert!(
            changed.iter().any(|(path, db)| path == "/data" && *db < 0),
            "{changed:?}"
        );
    }

    #[test]
    fn a_new_hard_link_is_not_counted_twice() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        write(&root.join("a/movie.bin"), 200_000);
        fs::create_dir_all(root.join("b")).unwrap();
        let target = target(root);
        let store = started(&target);
        let before = store.targets[0]
            .state
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .tree
            .root()
            .total_blocks();

        fs::hard_link(root.join("a/movie.bin"), root.join("b/movie.bin")).unwrap();
        relist_paths(&store, &["/data/b", "/data/a"]);

        let guard = store.targets[0].state.read().unwrap();
        let tree = &guard.as_ref().unwrap().tree;
        let fresh = scan(&target);
        assert_eq!(tree.root().total_blocks(), fresh.root().total_blocks());
        // Only the directory-inode sizes may differ, if any; the 200 kB are not doubled.
        assert!(tree.root().total_blocks().abs_diff(before) < 100_000);
    }

    /// fanotify tells only the new link's directory about a new hard link: the directory that
    /// counted the file while it had one link must be found and re-read too.
    #[test]
    fn a_new_link_reported_only_where_it_was_made_counts_once() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        write(&root.join("a/movie.bin"), 200_000);
        // In its own directory: nothing but the grafted link gets it re-read.
        write(&root.join("c/third.bin"), 400_000);
        fs::create_dir_all(root.join("b/sub")).unwrap();
        let mut target = target(root);
        target.collect_handles = true;
        let store = started(&target);
        *lock(&store.targets[0].source) = Some("fanotify");
        // Created after the scan: only a re-read saw where it is.
        write(&root.join("a/later.bin"), 300_000);
        settle(&store, &["/data/a"]);

        fs::hard_link(root.join("a/movie.bin"), root.join("b/movie.bin")).unwrap();
        fs::hard_link(root.join("a/later.bin"), root.join("b/sub/later.bin")).unwrap();
        // A new directory holding the only new link to a file, grafted by its parent's re-read.
        fs::create_dir_all(root.join("b/fresh")).unwrap();
        fs::hard_link(root.join("c/third.bin"), root.join("b/fresh/third.bin")).unwrap();
        settle(&store, &["/data/b", "/data/b/sub"]);

        let live = tree_totals(&store);
        let fresh = totals(&scan(&target));
        assert_eq!(live["/data"], fresh["/data"], "{live:#?}");
        for moved in ["/data/a", "/data/c"] {
            assert!(
                live[moved].0 < 100_000,
                "{moved}'s files are now counted under b/: {live:#?}"
            );
        }
    }

    /// Files sharing a folded key keep every holder: one cannot hide another.
    #[test]
    fn colliding_keys_keep_every_holder() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("a")).unwrap();
        fs::create_dir_all(root.join("c")).unwrap();
        let mut target = target(root);
        target.collect_handles = true;
        let store = started(&target);
        let mut guard = store.targets[0].state.write().unwrap();
        let state = guard.as_mut().unwrap();
        let (a, c) = (
            state.tree.find("/data/a").unwrap(),
            state.tree.find("/data/c").unwrap(),
        );
        let key = plain_key(1, 42);
        state.plain_live.extend([(key, a), (key, c)]);
        let mut holders = state.plain_holders((1, 42));
        holders.sort_unstable();
        assert_eq!(holders, [a.min(c), a.max(c)]);
    }

    /// A tree of the root and `a`, `b`, `c` (depth 1, always tracked) and at most `cap`
    /// directories. With `sealed`, `a/deep/er` is past the cap so `a` is sealed. `a/file.bin`
    /// and `c/other.bin` are singly linked.
    fn capped(root: &Path, cap: usize, sealed: bool) -> Arc<LiveStore> {
        write(&root.join("a/file.bin"), 300_000);
        if sealed {
            fs::create_dir_all(root.join("a/deep/er")).unwrap();
        }
        write(&root.join("c/other.bin"), 300_000);
        fs::create_dir_all(root.join("b")).unwrap();
        let mut target = target(root);
        target.collect_handles = true;
        target.tree_max_directories = cap;
        let store = started(&target);
        *lock(&store.targets[0].source) = Some("fanotify");
        let guard = store.targets[0].state.read().unwrap();
        let tree = &guard.as_ref().unwrap().tree;
        assert_eq!(
            tree.nodes[tree.find("/data/a").unwrap() as usize].sealed,
            sealed
        );
        drop(guard);
        store
    }

    fn rescans(store: &LiveStore) -> u64 {
        store.targets[0].rescans_requested.load(Ordering::Relaxed)
    }

    /// Where the tree is already approximate, a new link that may be counted twice asks for a
    /// scan instead: a sealed holder (never re-read), whether or not something else queued it.
    #[test]
    fn a_link_to_a_file_in_a_sealed_directory_asks_for_a_scan() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let store = capped(root, 4, true);
        fs::hard_link(root.join("a/file.bin"), root.join("b/file.bin")).unwrap();
        settle(&store, &["/data/b"]);
        assert_eq!(rescans(&store), 1);

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let store = capped(root, 4, true);
        // The parent's re-read queues `a` (its entries changed) and adopts the new link.
        write(&root.join("a/touched.bin"), 10);
        fs::hard_link(root.join("a/file.bin"), root.join("file.bin")).unwrap();
        settle(&store, &["/data"]);
        assert_eq!(rescans(&store), 1, "already queued, still asks");
    }

    /// ...and links a new subtree counts without a node: past the cap, or in its untracked
    /// part, whether the subtree itself is grafted or not.
    #[test]
    fn links_a_new_subtree_counts_without_a_node_ask_for_a_scan() {
        // At 4 nothing new fits; at 5 (without `a/deep`) `new` does, but `deep` does not.
        for (cap, sealed, link, case) in [
            (4, true, "b/new/other.bin", "past the cap"),
            (
                4,
                true,
                "b/new/deep/other.bin",
                "past the cap, untracked part",
            ),
            (5, false, "b/new/deep/other.bin", "grafted, untracked part"),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path();
            let store = capped(root, cap, sealed);
            let at = root.join(link);
            fs::create_dir_all(at.parent().unwrap()).unwrap();
            fs::hard_link(root.join("c/other.bin"), &at).unwrap();
            settle(&store, &["/data/b"]);
            assert_eq!(rescans(&store), 1, "{case}");
            let guard = store.targets[0].state.read().unwrap();
            let grafted = guard.as_ref().unwrap().tree.find("/data/b/new").is_some();
            assert_eq!(grafted, !sealed, "{case}");
        }
    }

    /// A new link to a file the tree counts where it cannot settle it (already linked, or in
    /// an untracked directory) asks for a scan.
    #[test]
    fn links_to_files_counted_out_of_reach_ask_for_a_scan() {
        // (cap, sealed, prepare before the scan, link from, link at, case)
        type Prepare = fn(&Path);
        let cases: [(usize, bool, Prepare, &str, &str, &str); 4] = [
            (
                5,
                false,
                |root| {
                    write(&root.join("a/twin.bin"), 300_000);
                    fs::hard_link(root.join("a/twin.bin"), root.join("a/twin2.bin")).unwrap();
                },
                "a/twin.bin",
                "b/new/deep/twin.bin",
                "linked file, new link in a grafted subtree's untracked part",
            ),
            (
                4,
                true,
                |root| {
                    write(&root.join("a/twin.bin"), 300_000);
                    fs::hard_link(root.join("a/twin.bin"), root.join("a/twin2.bin")).unwrap();
                },
                "a/twin.bin",
                "b/new/deep/twin.bin",
                "linked file, new link past the cap",
            ),
            (
                4,
                true,
                |root| write(&root.join("a/deep/orig.bin"), 300_000),
                "a/deep/orig.bin",
                "b/orig.bin",
                "plain original in an untracked directory",
            ),
            (
                4,
                true,
                |root| {
                    write(&root.join("a/deep/x.bin"), 300_000);
                    fs::hard_link(root.join("a/deep/x.bin"), root.join("a/deep/y.bin")).unwrap();
                },
                "a/deep/x.bin",
                "b/z.bin",
                "linked original counted in an untracked directory",
            ),
        ];
        for (cap, sealed, prepare, from, at, case) in cases {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path();
            prepare(root);
            let store = capped(root, cap, sealed);
            let at = root.join(at);
            fs::create_dir_all(at.parent().unwrap()).unwrap();
            fs::hard_link(root.join(from), &at).unwrap();
            settle(&store, &["/data/b"]);
            assert_eq!(rescans(&store), 1, "{case}");
        }
    }

    /// What a subtree too big to graft counts stays on record: a later link to one of its
    /// files, made elsewhere, asks for a scan.
    #[test]
    fn links_into_a_rejected_subtree_ask_for_a_scan() {
        for (prepare, case) in [
            (
                (|root: &Path| write(&root.join("b/new/file.bin"), 300_000)) as fn(&Path),
                "plain file",
            ),
            (
                |root: &Path| {
                    write(&root.join("b/new/file.bin"), 300_000);
                    fs::hard_link(root.join("b/new/file.bin"), root.join("b/new/twin.bin"))
                        .unwrap();
                },
                "linked file",
            ),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path();
            let store = capped(root, 4, false);
            prepare(root);
            settle(&store, &["/data/b"]);
            assert_eq!(rescans(&store), 0, "{case}: nothing to settle yet");
            fs::hard_link(root.join("b/new/file.bin"), root.join("c/file.bin")).unwrap();
            settle(&store, &["/data/c"]);
            assert_eq!(rescans(&store), 1, "{case}");
        }
    }

    /// A file linked while a scan ran, between the reads of its two directories, is counted
    /// in both by the scan; installing the scan re-reads the one that saw it alone.
    #[test]
    fn a_link_made_during_a_scan_is_reconciled_when_the_scan_lands() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        write(&root.join("a/file.bin"), 300_000);
        fs::create_dir_all(root.join("b")).unwrap();
        fs::hard_link(root.join("a/file.bin"), root.join("b/file.bin")).unwrap();
        let mut target = target(root);
        target.collect_handles = true;
        let store = started(&target);
        *lock(&store.targets[0].source) = Some("fanotify");
        let truth = tree_totals(&store);

        // The scan as it would have come out: the other directory read the file while it had
        // one link, and counted it too.
        let mut tree = scan(&target);
        let (inode, owner) = tree.links.iter().next().map(|(i, o)| (*i, o.node)).unwrap();
        let other = ["/data/a", "/data/b"]
            .iter()
            .map(|path| tree.find(path).unwrap())
            .find(|&node| node != owner)
            .unwrap();
        let size = Delta {
            blocks: tree.links[&inode].blocks as i64,
            apparent: tree.links[&inode].apparent as i64,
            ..Delta::default()
        };
        tree.nodes[other as usize].direct.apply(&size);
        tree.propagate(other, &size);
        tree.plain.push((plain_key(inode.0, inode.1), other));
        tree.plain.sort_unstable();
        store.replace(0, tree, SystemTime::now(), Duration::ZERO);
        assert_ne!(tree_totals(&store), truth, "counted twice as installed");

        settle(&store, &[]);
        assert_eq!(tree_totals(&store), truth);
    }

    /// A large directory re-read lists all of its files in the live index again; that alone
    /// does not ask for a scan.
    #[test]
    fn a_large_directory_growing_does_not_ask_for_scans() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        for n in 0..PLAIN_LIVE_HEADROOM + 50 {
            write(&root.join(format!("spool/{n}.tmp")), 10);
        }
        let mut target = target(root);
        target.collect_handles = true;
        let store = started(&target);
        *lock(&store.targets[0].source) = Some("fanotify");
        for n in 0..3 {
            write(&root.join(format!("spool/new-{n}.tmp")), 10);
            settle(&store, &["/data/spool"]);
        }
        assert_eq!(rescans(&store), 0);
    }

    /// A re-read replaces its directory's entries in the live index.
    #[test]
    fn re_reads_replace_their_directory_in_the_live_index() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("spool")).unwrap();
        let mut target = target(root);
        target.collect_handles = true;
        let store = started(&target);
        *lock(&store.targets[0].source) = Some("fanotify");
        for round in 0..5 {
            write(&root.join(format!("spool/{round}.tmp")), 10);
            if round > 0 {
                fs::remove_file(root.join(format!("spool/{}.tmp", round - 1))).unwrap();
            }
            settle(&store, &["/data/spool"]);
        }
        let guard = store.targets[0].state.read().unwrap();
        assert_eq!(guard.as_ref().unwrap().plain_live.len(), 1);
    }

    fn tree_totals(store: &LiveStore) -> BTreeMap<String, (u64, u64, u64)> {
        totals(
            &store.targets[0]
                .state
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .tree,
        )
    }

    /// Re-reads `paths`, then whatever that queued, until nothing is due.
    fn settle(store: &LiveStore, paths: &[&str]) {
        relist_paths(store, paths);
        loop {
            let due: Vec<(u32, u64)> = {
                let mut queue = lock(&store.queue);
                queue.cooldown.clear();
                queue
                    .pending
                    .drain()
                    .map(|((_, node), generation)| (node, generation))
                    .collect()
            };
            if due.is_empty() {
                return;
            }
            store.relist_all(0, due);
        }
    }

    #[test]
    fn two_links_in_one_directory_count_once() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        write(&root.join("a/one"), 200_000);
        fs::hard_link(root.join("a/one"), root.join("a/two")).unwrap();
        let target = target(root);
        let store = started(&target);
        settle(&store, &["/data/a"]);
        assert_eq!(tree_totals(&store), totals(&scan(&target)));
    }

    #[test]
    fn hard_links_follow_writes_and_deletions_of_either_link() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        write(&root.join("x/file"), 200_000);
        fs::create_dir_all(root.join("y")).unwrap();
        fs::hard_link(root.join("x/file"), root.join("y/file")).unwrap();
        let target = target(root);
        let store = started(&target);
        let owner = {
            let guard = store.targets[0].state.read().unwrap();
            let tree = &guard.as_ref().unwrap().tree;
            let record = tree.links.values().next().unwrap();
            tree.display_path(record.node)
        };
        let (counted, other) = if owner == "/data/x" {
            ("x", "y")
        } else {
            ("y", "x")
        };

        // Written through the link that is not counted: the counted one grows.
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(root.join(other).join("file"))
            .unwrap();
        file.write_all(&[1; 100_000]).unwrap();
        drop(file);
        settle(&store, &[&format!("/data/{other}")]);
        assert_eq!(tree_totals(&store), totals(&scan(&target)));

        // The counted link goes; the file is still there through the other.
        fs::remove_file(root.join(counted).join("file")).unwrap();
        settle(&store, &[&format!("/data/{counted}")]);
        assert_eq!(tree_totals(&store), totals(&scan(&target)));
    }

    /// Where the one multiply-linked file is counted.
    fn counted_in(store: &LiveStore) -> String {
        let guard = store.targets[0].state.read().unwrap();
        let tree = &guard.as_ref().unwrap().tree;
        tree.display_path(tree.links.values().next().unwrap().node)
    }

    /// Builds trees with `build(attempt)` until the walk counts the linked file in `want`.
    fn counted_where(
        want: &str,
        build: impl Fn(&Path, usize),
    ) -> (tempfile::TempDir, Target, Arc<LiveStore>) {
        for attempt in 0..64 {
            let temp = tempfile::tempdir().unwrap();
            build(temp.path(), attempt);
            let target = target(temp.path());
            let store = started(&target);
            if counted_in(&store) == want {
                return (temp, target, store);
            }
        }
        panic!("no name put the count in {want}");
    }

    #[test]
    fn a_removed_subtree_hands_its_links_to_the_parent() {
        let (temp, target, store) = counted_where("/data/p/c", |root, attempt| {
            write(&root.join("p/l1"), 200_000);
            fs::hard_link(root.join("p/l1"), root.join("p/l2")).unwrap();
            fs::create_dir_all(root.join("p/c")).unwrap();
            fs::hard_link(root.join("p/l1"), root.join(format!("p/c/x{attempt}"))).unwrap();
        });
        fs::remove_dir_all(temp.path().join("p/c")).unwrap();
        settle(&store, &["/data/p"]);
        assert_eq!(tree_totals(&store), totals(&scan(&target)));
    }

    #[test]
    fn a_renamed_subtree_keeps_its_links_counted_once() {
        let (temp, target, store) = counted_where("/data/c", |root, attempt| {
            write(&root.join(format!("c/x{attempt}")), 200_000);
            fs::create_dir_all(root.join("e")).unwrap();
            fs::hard_link(root.join(format!("c/x{attempt}")), root.join("e/f")).unwrap();
        });
        fs::rename(temp.path().join("c"), temp.path().join("d")).unwrap();
        settle(&store, &["/data"]);
        let guard = store.targets[0].state.read().unwrap();
        let live = guard.as_ref().unwrap().tree.root().total_blocks();
        assert_eq!(live, scan(&target).root().total_blocks());
    }

    #[test]
    fn a_directory_replaced_under_the_same_name_is_read_afresh() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        write(&root.join("cache/old.bin"), 200_000);
        let target = target(root);
        let store = started(&target);
        fs::remove_dir_all(root.join("cache")).unwrap();
        write(&root.join("cache/new.bin"), 400_000);
        settle(&store, &["/data"]);
        assert_eq!(tree_totals(&store), totals(&scan(&target)));
    }

    /// ext4 hands a recreated directory its predecessor's inode number; fanotify still knows it
    /// by a new file handle, which the tree must learn.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_recreated_directory_is_known_by_its_new_handle() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        write(&root.join("cache/old.bin"), 100_000);
        let cache = root.join("cache");
        if native::dir_handle(cache.as_os_str().as_bytes()).is_none() {
            eprintln!("no file handles on this filesystem; skipping");
            return;
        }
        let mut target = target(root);
        target.collect_handles = true;
        let store = started(&target);
        *lock(&store.targets[0].source) = Some("fanotify");
        use std::os::unix::fs::MetadataExt;
        let old_ino = fs::metadata(&cache).unwrap().ino();
        fs::remove_dir_all(&cache).unwrap();
        // Recreate it until it gets the old inode number back, as ext4 tends to give.
        let reused = (0..64).any(|attempt| {
            fs::create_dir(&cache).unwrap();
            if fs::metadata(&cache).unwrap().ino() == old_ino {
                return true;
            }
            fs::rename(&cache, root.join(format!("other{attempt}"))).unwrap();
            false
        });
        if !reused {
            eprintln!("the inode number was not reused; skipping");
            return;
        }
        write(&cache.join("new.bin"), 300_000);
        settle(&store, &["/data"]);
        let handle = native::dir_handle(cache.as_os_str().as_bytes()).unwrap();
        let guard = store.targets[0].state.read().unwrap();
        let state = guard.as_ref().unwrap();
        let node = state
            .resolve(&StableKey::Handle(handle))
            .expect("new handle resolves");
        assert_eq!(state.tree.display_path(node), "/data/cache");
        assert_eq!(totals(&state.tree), totals(&scan(&target)));
    }

    #[test]
    fn a_directory_growing_its_own_allocation_is_followed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("spool")).unwrap();
        let target = target(root);
        let store = started(&target);
        // Enough entries that ext4 gives the directory more blocks.
        for i in 0..400 {
            File::create(root.join(format!("spool/entry-with-a-long-name-{i:04}"))).unwrap();
        }
        settle(&store, &["/data/spool"]);
        assert_eq!(tree_totals(&store), totals(&scan(&target)));
    }

    #[test]
    fn the_directory_cap_holds_for_scans_and_new_directories() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        for i in 0..20 {
            write(&root.join(format!("d{i}/f")), 10);
        }
        let mut target = target(root);
        target.report_depth = 0;
        target.tree_max_directories = 3;
        let tree = scan(&target);
        assert!(tree.nodes.len() <= 3, "{} nodes", tree.nodes.len());

        // Room for exactly the two directories there are; new ones are counted, not tracked.
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        write(&root.join("d0/f"), 10);
        write(&root.join("d1/f"), 10);
        target.scan_path = root.to_path_buf();
        let store = started(&target);
        for i in 0..10 {
            write(&root.join(format!("d0/new{i}/f")), 4096);
        }
        settle(&store, &["/data/d0"]);
        let guard = store.targets[0].state.read().unwrap();
        let tree = &guard.as_ref().unwrap().tree;
        assert!(
            tree.nodes.len() <= 3,
            "{} nodes after new directories",
            tree.nodes.len()
        );
        assert_eq!(
            tree.root().total_blocks(),
            scan(&target).root().total_blocks()
        );
    }

    #[test]
    fn a_vanished_directory_is_settled_by_its_parent() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        write(&root.join("gone/x.bin"), 50_000);
        let target = target(root);
        let store = started(&target);

        fs::remove_dir_all(root.join("gone")).unwrap();
        relist_paths(&store, &["/data/gone"]);
        // The parent was queued; run what is due.
        let due = store.next_due();
        assert_eq!(due.len(), 1);
        store.relist_all(
            0,
            due.into_iter()
                .map(|(_, node, generation)| (node, generation))
                .collect(),
        );
        let live = totals(
            &store.targets[0]
                .state
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .tree,
        );
        assert_eq!(live, totals(&scan(&target)));
    }
}
