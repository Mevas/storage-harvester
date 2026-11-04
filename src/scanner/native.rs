//! The native scanner: a parallel walk that does a constant amount of work per entry.
//!
//! - Each entry costs one `fstatat` relative to its directory's descriptor (on Linux, names come
//!   from `getdents64` straight into a reused buffer) and a few additions. Nothing per entry is
//!   allocated, hashed or looked up by path.
//! - Sizes are summed per directory, then added once to the directory's *node*: its own when it
//!   is tracked, otherwise its nearest tracked ancestor's. Directories at depth <= `report_depth`
//!   are always tracked; deeper ones are while fewer than `tree_max_directories` are, so memory
//!   is bounded by that cap, not by the walk.
//! - Tracked nodes roll up into their parents after the walk, into the [`DirTree`] that
//!   `/api/tree` and the live engine use; the reported nodes are read off it.
//! - Directories are shared between `scan_threads` workers through one LIFO stack; a worker
//!   keeps one child to descend into, so a walk stays roughly depth-first and the stack small.
//! - A multiply-linked file is counted once, at the link with the smallest path hash, so its
//!   allocation lands in the same directory whatever order the workers met its links in.

use std::collections::hash_map::{DefaultHasher, Entry};
use std::collections::HashMap;
use std::ffi::{CStr, CString, OsStr};
use std::hash::Hasher;
use std::io;
use std::ops::Range;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Instant, SystemTime};

use anyhow::{bail, Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::config::{ReportMode, Target};
use crate::scanner::{EntryObservation, EntryType, NodeObservation, ScanResult, Scanner};
use crate::tree::{plain_key, DirNode, DirTree, LinkOwner, Tally, NONE};

#[derive(Debug)]
pub struct NativeScanner {
    exclude: GlobSet,
    threads: usize,
}

impl NativeScanner {
    pub fn new(target: &Target) -> Result<Self> {
        Ok(Self {
            exclude: exclude_set(&target.exclude)?,
            threads: target.scan_threads.max(1),
        })
    }
}

pub(crate) fn exclude_set(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(
            Glob::new(pattern).with_context(|| format!("invalid exclude pattern {pattern:?}"))?,
        );
    }
    Ok(builder.build()?)
}

/// One directory's own entries, read with the walk's rules (excludes, the device boundary,
/// symlinks), for a live re-read of a directory the tree already holds.
#[derive(Debug, Default)]
pub(crate) struct Listing {
    /// Every entry counted; sizes of subdirectories' inodes and of singly linked entries.
    pub direct: Tally,
    /// Subdirectories, sorted by name.
    pub subdirs: Vec<Subdir>,
    /// Multiply-linked entries: `((dev, ino), blocks, apparent)`. Whose they are is the
    /// tree's call.
    pub links: Vec<((u64, u64), u64, u64)>,
    /// [`plain_key`]s of the singly linked files, when asked for (fanotify).
    pub plain: Vec<u32>,
    /// The directory's own inode.
    pub own: Own,
}

#[derive(Debug)]
pub(crate) struct Subdir {
    pub name: Box<[u8]>,
    pub ino: u64,
    pub blocks: u64,
    pub apparent: u64,
    pub mtime: i64,
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Own {
    pub blocks: u64,
    pub apparent: u64,
    pub mtime: i64,
}

/// A directory's file handle, as fanotify reports it.
pub(crate) fn dir_handle(path: &[u8]) -> Option<Box<[u8]>> {
    sys::path_handle(Path::new(OsStr::from_bytes(path)))
}

pub(crate) fn read_direct(
    target: &Target,
    exclude: &GlobSet,
    scan_path: &[u8],
    display_path: &[u8],
    root_dev: u64,
    record_plain: bool,
) -> io::Result<Listing> {
    let follow = target.follow_symlinks;
    let path = CString::new(scan_path).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut dir = sys::Dir::open(&path, follow)?;
    let own = dir.stat_self()?;
    let mut batch = sys::Batch::default();
    let mut display = display_path.to_vec();
    let dir_len = display.len();
    let mut listing = Listing {
        own: Own {
            blocks: own.blocks,
            apparent: own.size,
            mtime: own.mtime,
        },
        ..Listing::default()
    };
    while dir.read(&mut batch)? {
        for index in 0..batch.len() {
            let name = batch.name(index);
            let bytes = name.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            if !exclude.is_empty() {
                display.truncate(dir_len);
                push_component(&mut display, bytes);
                if exclude.is_match(Path::new(OsStr::from_bytes(&display))) {
                    continue;
                }
            }
            let Ok(stat) = dir.stat(name, follow) else {
                continue;
            };
            if target.no_cross_filesystem && stat.dev != root_dev {
                continue;
            }
            let direct = &mut listing.direct;
            match stat.kind {
                Kind::Directory => {
                    direct.dirs += 1;
                    direct.add_size(stat.blocks, stat.size);
                    listing.subdirs.push(Subdir {
                        name: bytes.into(),
                        ino: stat.ino,
                        blocks: stat.blocks,
                        apparent: stat.size,
                        mtime: stat.mtime,
                    });
                    continue;
                }
                Kind::Symlink => direct.symlinks += 1,
                Kind::File | Kind::Other => direct.files += 1,
            }
            if stat.nlink > 1 {
                listing
                    .links
                    .push(((stat.dev, stat.ino), stat.blocks, stat.size));
            } else {
                direct.add_size(stat.blocks, stat.size);
                if record_plain && stat.kind == Kind::File {
                    listing.plain.push(plain_key(stat.dev, stat.ino));
                }
            }
        }
    }
    listing.subdirs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(listing)
}

impl Scanner for NativeScanner {
    fn backend(&self) -> &'static str {
        "native"
    }

    fn scan(&self, target: &Target, cancel: &AtomicBool) -> Result<ScanResult> {
        let started = Instant::now();
        let timestamp = SystemTime::now();
        let display_root = target.display_path.as_os_str().as_bytes().to_vec();
        let scan_root = target.scan_path.as_os_str().as_bytes();
        let mut first = Worker::default();

        let root = sys::stat_path(&target.scan_path, target.follow_symlinks)
            .with_context(|| format!("failed to stat {}", target.scan_path.display()))?;
        // The root is matched as `<display path>/`, as it always has been: `**/cache/**`
        // excludes a `/var/cache` target, and `**/cache` does not.
        if !self.exclude.is_empty() && self.exclude.is_match(target.display_path.join("")) {
            first.counts.skipped_excluded += 1;
            return Ok(finish(
                self.backend(),
                target,
                Nodes::default(),
                vec![first],
                started,
                timestamp,
                root.dev,
            ));
        }
        let walk = Walk {
            target,
            exclude: &self.exclude,
            cancel,
            root_dev: root.dev,
            display_root,
            rel_start: scan_root.len() + usize::from(!scan_root.ends_with(b"/")),
            nodes: Mutex::new(Nodes::default()),
            tracked: AtomicUsize::new(1),
            cap: target.tree_max_directories,
            for_fanotify: target.collect_handles,
            queue: Mutex::new(Queue::default()),
            ready: Condvar::new(),
            halted: AtomicBool::new(false),
            failure: Mutex::new(None),
        };

        let mut root_job = None;
        match root.kind {
            Kind::Directory => {
                first.counts.scanned_directories += 1;
                let handle = if walk.for_fanotify {
                    sys::path_handle(&target.scan_path)
                } else {
                    None
                };
                lock(&walk.nodes).list.push(TrackedNode {
                    name: 0..0,
                    depth: 0,
                    parent: NONE,
                    ino: root.ino,
                    own_blocks: root.blocks,
                    own_apparent: root.size,
                    mtime: root.mtime,
                    sealed: target.max_depth == Some(0),
                    pruned: false,
                    handle,
                });
                if target.max_depth == Some(0) {
                    first.counts.depth_limit_hits += 1;
                } else {
                    root_job = Some(Job {
                        path: CString::new(scan_root).context("scan path contains NUL")?,
                        depth: 0,
                        node: 0,
                        tracked: true,
                    });
                }
            }
            Kind::File => first.counts.scanned_files += 1,
            Kind::Symlink => first.counts.scanned_symlinks += 1,
            Kind::Other => {}
        }

        let mut workers = vec![first];
        if let Some(job) = root_job {
            workers.resize_with(self.threads, Worker::default);
            walk.run(job, &mut workers);
            if let Some(error) = lock(&walk.failure).take() {
                return Err(error);
            }
            if cancel.load(Ordering::Relaxed) {
                bail!("scan of {} cancelled", target.scan_path.display());
            }
        }
        let nodes = walk
            .nodes
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner);
        Ok(finish(
            self.backend(),
            target,
            nodes,
            workers,
            started,
            timestamp,
            root.dev,
        ))
    }
}

/// Shared state of one scan.
struct Walk<'a> {
    target: &'a Target,
    exclude: &'a GlobSet,
    cancel: &'a AtomicBool,
    root_dev: u64,
    display_root: Vec<u8>,
    /// Where a directory's path relative to the scan root starts in its scan path.
    rel_start: usize,
    /// Tracked directories, in discovery order, so a parent precedes its children.
    nodes: Mutex<Nodes>,
    /// Directories offered a node so far, counted without the lock to apply `cap`.
    tracked: AtomicUsize,
    cap: usize,
    /// Record what fanotify needs: each tracked directory's file handle, and which tracked
    /// directory each singly linked file is in.
    for_fanotify: bool,
    queue: Mutex<Queue>,
    ready: Condvar,
    halted: AtomicBool,
    failure: Mutex<Option<anyhow::Error>>,
}

#[derive(Default)]
struct Queue {
    jobs: Vec<Job>,
    /// Workers holding a job. The walk is over when none is and `jobs` is empty.
    busy: usize,
    idle: usize,
    stopped: bool,
}

/// A directory to read.
struct Job {
    path: CString,
    depth: usize,
    /// The directory's own node when `tracked`, otherwise its nearest tracked ancestor.
    node: u32,
    tracked: bool,
}

/// Tracked directories, and their names in one buffer: no allocation per directory, which
/// musl's allocator would serialize across the walkers.
#[derive(Default)]
struct Nodes {
    list: Vec<TrackedNode>,
    names: Vec<u8>,
}

struct TrackedNode {
    /// Where the name is in `Nodes::names`.
    name: Range<usize>,
    depth: usize,
    parent: u32,
    ino: u64,
    own_blocks: u64,
    own_apparent: u64,
    mtime: i64,
    /// Not (fully) read: past `max_depth`, or unreadable.
    sealed: bool,
    /// Some entries directly inside were excluded.
    pruned: bool,
    handle: Option<Box<[u8]>>,
}

/// A subdirectory to track, gathered while its parent is read and registered in one lock.
struct PendingDir {
    /// Its name, in the worker's `arena`.
    name: Range<usize>,
    stat: Stat,
    handle: Option<Box<[u8]>>,
    descend: bool,
}

/// What one node has gathered: entries directly inside it, and entries in untracked
/// directories below it.
#[derive(Debug, Default, Clone, Copy)]
struct NodeTally {
    direct: Tally,
    below: Tally,
}

impl NodeTally {
    fn part(&mut self, direct: bool) -> &mut Tally {
        if direct {
            &mut self.direct
        } else {
            &mut self.below
        }
    }
}

#[derive(Debug, Default)]
struct Counts {
    permission_errors: u64,
    missing_path_races: u64,
    skipped_cross_device: u64,
    skipped_excluded: u64,
    scanned_files: u64,
    scanned_directories: u64,
    scanned_symlinks: u64,
    max_observed_depth: usize,
    depth_limit_hits: u64,
}

impl Counts {
    fn add(&mut self, other: &Counts) {
        self.permission_errors += other.permission_errors;
        self.missing_path_races += other.missing_path_races;
        self.skipped_cross_device += other.skipped_cross_device;
        self.skipped_excluded += other.skipped_excluded;
        self.scanned_files += other.scanned_files;
        self.scanned_directories += other.scanned_directories;
        self.scanned_symlinks += other.scanned_symlinks;
        self.max_observed_depth = self.max_observed_depth.max(other.max_observed_depth);
        self.depth_limit_hits += other.depth_limit_hits;
    }
}

/// One link of a multiply-linked file, the candidate to carry its allocation.
#[derive(Debug, Clone, Copy)]
struct Link {
    key: u64,
    node: u32,
    /// Whether the link is directly inside `node`, rather than deeper.
    direct: bool,
    blocks: u64,
    apparent: u64,
    /// Index into the worker's `entries`, when the link is listed on the status page.
    entry: Option<usize>,
}

/// Everything a worker accumulates without sharing; merged after the walk.
#[derive(Default)]
struct Worker {
    tallies: Vec<NodeTally>,
    counts: Counts,
    entries: Vec<EntryObservation>,
    links: HashMap<(u64, u64), Link>,
    batch: sys::Batch,
    /// Display path of the directory being read, then of each entry in turn.
    display: Vec<u8>,
    pending: Vec<PendingDir>,
    arena: Vec<u8>,
    /// Every link of a multiply-linked file seen directly in a tracked directory.
    link_dirs: Vec<((u64, u64), u32)>,
    /// `(plain_key, node)` per singly linked file directly in a tracked directory (fanotify).
    plain: Vec<(u32, u32)>,
}

impl Worker {
    fn tally(&mut self, node: u32) -> &mut NodeTally {
        let index = node as usize;
        if index >= self.tallies.len() {
            self.tallies.resize(index + 1, NodeTally::default());
        }
        &mut self.tallies[index]
    }
}

enum Stop {
    Cancelled,
    Failed(anyhow::Error),
}

impl Walk<'_> {
    fn run(&self, root: Job, workers: &mut [Worker]) {
        {
            let mut queue = lock(&self.queue);
            queue.jobs.push(root);
            queue.busy = workers.len();
        }
        std::thread::scope(|scope| {
            let (first, rest) = workers.split_first_mut().expect("at least one worker");
            for worker in rest {
                let spawned = std::thread::Builder::new()
                    .name("harvester-walk".to_string())
                    .spawn_scoped(scope, || self.work(worker));
                if spawned.is_err() {
                    // Fewer workers than asked for: correct, only slower. Wake the idle ones,
                    // since this worker's slot may have been all that kept the walk open.
                    lock(&self.queue).busy -= 1;
                    self.ready.notify_all();
                }
            }
            self.work(first);
        });
    }

    fn work(&self, worker: &mut Worker) {
        let _halt_on_panic = HaltOnPanic(self);
        let mut children = Vec::new();
        let mut next = self.exchange(&mut children);
        while let Some(job) = next {
            if let Err(stop) = self.read_dir(worker, &job, &mut children) {
                self.halt(stop);
                return;
            }
            next = self.exchange(&mut children);
        }
    }

    /// Publishes all but one of `children` and returns the job to do next: the kept child, or
    /// one from the shared stack once this worker's subtree is done.
    fn exchange(&self, children: &mut Vec<Job>) -> Option<Job> {
        let own = children.pop();
        if own.is_some() && children.is_empty() {
            return own;
        }
        let mut queue = lock(&self.queue);
        let published = children.len();
        queue.jobs.append(children);
        for _ in 0..published.min(queue.idle) {
            self.ready.notify_one();
        }
        if own.is_some() {
            return own;
        }
        queue.busy -= 1;
        loop {
            if queue.stopped {
                return None;
            }
            if let Some(job) = queue.jobs.pop() {
                queue.busy += 1;
                return Some(job);
            }
            if queue.busy == 0 {
                queue.stopped = true;
                self.ready.notify_all();
                return None;
            }
            queue.idle += 1;
            queue = self
                .ready
                .wait(queue)
                .unwrap_or_else(PoisonError::into_inner);
            queue.idle -= 1;
        }
    }

    fn halt(&self, stop: Stop) {
        if let Stop::Failed(error) = stop {
            lock(&self.failure).get_or_insert(error);
        }
        self.halted.store(true, Ordering::Relaxed);
        lock(&self.queue).stopped = true;
        self.ready.notify_all();
    }

    fn read_dir(
        &self,
        worker: &mut Worker,
        job: &Job,
        children: &mut Vec<Job>,
    ) -> Result<(), Stop> {
        let target = self.target;
        let follow = target.follow_symlinks;
        let Worker {
            counts,
            entries,
            links,
            batch,
            display,
            pending,
            arena,
            link_dirs,
            plain,
            ..
        } = worker;
        let mut dir = match sys::Dir::open(&job.path, follow) {
            Ok(dir) => dir,
            Err(error) => {
                self.seal(job);
                return tolerate(counts, error, || {
                    format!("failed to read {}", lossy(job.path.to_bytes()))
                });
            }
        };

        let reported = job.tracked && is_reported(target, job.depth);
        let excluding = !self.exclude.is_empty();
        let naming = reported || excluding;
        if naming {
            display.clear();
            display.extend_from_slice(&self.display_root);
            if job.depth > 0 {
                push_component(display, &job.path.to_bytes()[self.rel_start..]);
            }
        }
        let dir_len = display.len();
        let parent_path = reported.then(|| lossy(display));
        let depth = job.depth + 1;
        let mut sums = Tally::default();
        let mut pruned = false;

        loop {
            match dir.read(batch) {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    self.seal(job);
                    tolerate(counts, error, || {
                        format!("failed to read entry in {}", lossy(job.path.to_bytes()))
                    })?;
                    break;
                }
            }
            for index in 0..batch.len() {
                if self.cancel.load(Ordering::Relaxed) || self.halted.load(Ordering::Relaxed) {
                    return Err(Stop::Cancelled);
                }
                let name = batch.name(index);
                let bytes = name.to_bytes();
                if bytes == b"." || bytes == b".." {
                    continue;
                }
                if naming {
                    display.truncate(dir_len);
                    push_component(display, bytes);
                }
                if excluding && self.exclude.is_match(Path::new(OsStr::from_bytes(display))) {
                    counts.skipped_excluded += 1;
                    pruned = true;
                    continue;
                }
                let stat = match dir.stat(name, follow) {
                    Ok(stat) => stat,
                    Err(error) if is_permission_denied(&error) => {
                        counts.permission_errors += 1;
                        continue;
                    }
                    Err(_) => {
                        counts.missing_path_races += 1;
                        continue;
                    }
                };
                if target.no_cross_filesystem && stat.dev != self.root_dev {
                    counts.skipped_cross_device += 1;
                    continue;
                }
                counts.max_observed_depth = counts.max_observed_depth.max(depth);

                if stat.kind == Kind::Directory {
                    counts.scanned_directories += 1;
                    sums.dirs += 1;
                    sums.add_size(stat.blocks, stat.size);
                    let descend = target.max_depth.is_none_or(|max_depth| depth < max_depth);
                    if !descend {
                        counts.depth_limit_hits += 1;
                    }
                    if job.tracked && self.keeps(depth) {
                        let start = arena.len();
                        arena.extend_from_slice(bytes);
                        pending.push(PendingDir {
                            name: start..arena.len(),
                            stat,
                            handle: if self.for_fanotify {
                                dir.handle(name)
                            } else {
                                None
                            },
                            descend,
                        });
                    } else if descend {
                        children.push(Job {
                            path: child_path(&job.path, bytes),
                            depth,
                            node: job.node,
                            tracked: false,
                        });
                    }
                    continue;
                }

                let entry_type = match stat.kind {
                    Kind::File => {
                        counts.scanned_files += 1;
                        sums.files += 1;
                        EntryType::File
                    }
                    Kind::Symlink => {
                        counts.scanned_symlinks += 1;
                        sums.symlinks += 1;
                        EntryType::Symlink
                    }
                    _ => {
                        sums.files += 1;
                        EntryType::Other
                    }
                };
                // A multiply-linked file's allocation is added after the walk, at one link.
                let shared = stat.nlink > 1;
                let (blocks, apparent) = if shared {
                    (0, 0)
                } else {
                    (stat.blocks, stat.size)
                };
                sums.add_size(blocks, apparent);
                let entry = parent_path.as_ref().map(|parent_path| {
                    entries.push(EntryObservation {
                        parent_path: parent_path.clone(),
                        path: lossy(display),
                        entry_type,
                        depth,
                        blocks,
                        apparent,
                    });
                    entries.len() - 1
                });
                if shared {
                    let link = Link {
                        key: link_key(&job.path, bytes),
                        node: job.node,
                        direct: job.tracked,
                        blocks: stat.blocks,
                        apparent: stat.size,
                        entry,
                    };
                    keep_lowest(links, (stat.dev, stat.ino), link, |link| link.key);
                    if job.tracked {
                        link_dirs.push(((stat.dev, stat.ino), job.node));
                    }
                } else if self.for_fanotify && job.tracked && stat.kind == Kind::File {
                    plain.push((plain_key(stat.dev, stat.ino), job.node));
                }
            }
        }
        drop(dir);
        if pruned && job.tracked {
            lock(&self.nodes).list[job.node as usize].pruned = true;
        }

        if !pending.is_empty() {
            let first = {
                let mut nodes = lock(&self.nodes);
                let Nodes { list, names } = &mut *nodes;
                let first = list.len();
                for dir in pending.iter_mut() {
                    let start = names.len();
                    names.extend_from_slice(&arena[dir.name.clone()]);
                    list.push(TrackedNode {
                        name: start..names.len(),
                        depth,
                        parent: job.node,
                        ino: dir.stat.ino,
                        own_blocks: dir.stat.blocks,
                        own_apparent: dir.stat.size,
                        mtime: dir.stat.mtime,
                        sealed: !dir.descend,
                        pruned: false,
                        handle: dir.handle.take(),
                    });
                }
                first
            };
            for (offset, dir) in pending.drain(..).enumerate() {
                if dir.descend {
                    children.push(Job {
                        path: child_path(&job.path, &arena[dir.name]),
                        depth,
                        node: u32::try_from(first + offset)
                            .expect("fewer than 2^32 tracked directories"),
                        tracked: true,
                    });
                }
            }
            arena.clear();
        }

        worker.tally(job.node).part(job.tracked).add(&sums);
        Ok(())
    }

    /// Whether a directory found at `depth` under a tracked one gets a node of its own.
    /// Reserves the slot as it answers, so siblings and other workers cannot all pass the cap.
    fn keeps(&self, depth: usize) -> bool {
        let reserved = self.tracked.fetch_add(1, Ordering::Relaxed);
        depth <= self.target.report_depth || reserved < self.cap
    }

    /// Marks a tracked directory whose contents could not all be read.
    fn seal(&self, job: &Job) {
        if job.tracked {
            lock(&self.nodes).list[job.node as usize].sealed = true;
        }
    }
}

/// Stops the other workers if one panics, so they do not wait forever for its subtree.
struct HaltOnPanic<'a, 'b>(&'a Walk<'b>);

impl Drop for HaltOnPanic<'_, '_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.halt(Stop::Cancelled);
        }
    }
}

/// Counts an expected failure (a path that vanished, one we may not read, or one too long to
/// open) and carries on; anything else fails the scan.
fn tolerate(
    counts: &mut Counts,
    error: io::Error,
    context: impl FnOnce() -> String,
) -> Result<(), Stop> {
    if is_permission_denied(&error) {
        counts.permission_errors += 1;
        Ok(())
    } else if matches!(
        error.raw_os_error(),
        Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP | libc::ENAMETOOLONG)
    ) {
        counts.missing_path_races += 1;
        Ok(())
    } else {
        Err(Stop::Failed(anyhow::Error::new(error).context(context())))
    }
}

fn is_permission_denied(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM))
}

fn finish(
    backend: &str,
    target: &Target,
    nodes: Nodes,
    workers: Vec<Worker>,
    started: Instant,
    timestamp: SystemTime,
    root_dev: u64,
) -> ScanResult {
    let mut tallies = vec![NodeTally::default(); nodes.list.len()];
    let mut counts = Counts::default();
    let mut entries = Vec::with_capacity(workers.iter().map(|w| w.entries.len()).sum());
    let mut winners: HashMap<(u64, u64), (usize, Link)> = HashMap::new();
    let mut entry_offsets = Vec::with_capacity(workers.len());
    let mut holders: HashMap<(u64, u64), Vec<u32>> = HashMap::new();
    let mut plain = Vec::with_capacity(workers.iter().map(|w| w.plain.len()).sum());
    for (index, worker) in workers.into_iter().enumerate() {
        plain.extend(worker.plain);
        for (inode, node) in worker.link_dirs {
            holders.entry(inode).or_default().push(node);
        }
        for (node, tally) in worker.tallies.iter().enumerate() {
            tallies[node].direct.add(&tally.direct);
            tallies[node].below.add(&tally.below);
        }
        counts.add(&worker.counts);
        for (inode, link) in worker.links {
            keep_lowest(&mut winners, inode, (index, link), |(_, link)| link.key);
        }
        entry_offsets.push(entries.len());
        entries.extend(worker.entries);
    }
    let mut owners = HashMap::new();
    for (inode, (worker, link)) in winners {
        tallies[link.node as usize]
            .part(link.direct)
            .add_size(link.blocks, link.apparent);
        if link.direct {
            let mut others = holders.remove(&inode).unwrap_or_default();
            others.sort_unstable();
            others.dedup();
            others.retain(|&node| node != link.node);
            owners.insert(
                inode,
                LinkOwner {
                    node: link.node,
                    blocks: link.blocks,
                    apparent: link.apparent,
                    others,
                },
            );
        }
        if let Some(entry) = link.entry {
            let entry = &mut entries[entry_offsets[worker] + entry];
            entry.blocks = link.blocks;
            entry.apparent = link.apparent;
        }
    }

    plain.sort_unstable();
    let tree = build_tree(target, nodes, &tallies, owners, plain, root_dev);
    let mut reported: Vec<(Vec<u8>, NodeObservation)> = tree
        .as_ref()
        .map(|tree| {
            (0..tree.nodes.len() as u32)
                .filter(|&index| is_reported(target, tree.nodes[index as usize].depth as usize))
                .map(|index| (tree.relative_path(index), observe(tree, index)))
                .collect()
        })
        .unwrap_or_default();
    reported.sort_by(|(left, _), (right, _)| {
        Path::new(OsStr::from_bytes(left)).cmp(Path::new(OsStr::from_bytes(right)))
    });
    entries.sort_by(|left, right| left.path.cmp(&right.path));

    ScanResult {
        backend: backend.to_string(),
        observations: reported.into_iter().map(|(_, node)| node).collect(),
        entries,
        permission_errors: counts.permission_errors,
        missing_path_races: counts.missing_path_races,
        skipped_cross_device: counts.skipped_cross_device,
        skipped_excluded: counts.skipped_excluded,
        scanned_files: counts.scanned_files,
        scanned_directories: counts.scanned_directories,
        scanned_symlinks: counts.scanned_symlinks,
        max_observed_depth: counts.max_observed_depth,
        depth_limit_hits: counts.depth_limit_hits,
        duration: started.elapsed(),
        timestamp,
        tree,
    }
}

/// Rolls the tracked directories up into a tree. `None` when there is no directory to hold
/// (an excluded or non-directory root).
fn build_tree(
    target: &Target,
    nodes: Nodes,
    tallies: &[NodeTally],
    links: HashMap<(u64, u64), LinkOwner>,
    plain: Vec<(u32, u32)>,
    root_dev: u64,
) -> Option<DirTree> {
    if nodes.list.is_empty() {
        return None;
    }
    let names = nodes.names;
    let mut handles = Vec::new();
    let mut tree_nodes: Vec<DirNode> = nodes
        .list
        .into_iter()
        .enumerate()
        .map(|(index, node)| {
            if let Some(handle) = node.handle {
                handles.push((index as u32, handle));
            }
            let tally = tallies[index];
            let mut sub = tally.direct;
            sub.add(&tally.below);
            DirNode {
                name: names[node.name].into(),
                parent: node.parent,
                depth: node.depth as u32,
                ino: node.ino,
                own_blocks: node.own_blocks,
                own_apparent: node.own_apparent,
                mtime: node.mtime,
                direct: tally.direct,
                sub,
                children: Vec::new(),
                sealed: node.sealed || !tally.below.is_empty(),
                pruned: node.pruned,
                alive: true,
            }
        })
        .collect();
    // A parent precedes its children, so one backwards pass rolls everything up.
    for index in (1..tree_nodes.len()).rev() {
        let parent = tree_nodes[index].parent as usize;
        let sub = tree_nodes[index].sub;
        tree_nodes[parent].sub.add(&sub);
        tree_nodes[parent].children.push(index as u32);
    }
    for index in 0..tree_nodes.len() {
        let mut children = std::mem::take(&mut tree_nodes[index].children);
        children.sort_by(|&a, &b| {
            tree_nodes[a as usize]
                .name
                .cmp(&tree_nodes[b as usize].name)
        });
        let node = &mut tree_nodes[index];
        // Subdirectories past the cap have no node, so a re-read would mistake them for new.
        node.sealed |= (children.len() as u64) < node.direct.dirs;
        node.children = children;
    }
    Some(DirTree {
        display_root: target.display_path.as_os_str().as_bytes().to_vec(),
        scan_root: target.scan_path.as_os_str().as_bytes().to_vec(),
        root_dev,
        nodes: tree_nodes,
        links,
        handles,
        plain,
    })
}

/// The exported view of one reported directory.
fn observe(tree: &DirTree, index: u32) -> NodeObservation {
    let node = &tree.nodes[index as usize];
    let (parent, name) = if index == 0 {
        (String::new(), ".".to_string())
    } else {
        (tree.display_path(node.parent), lossy(&node.name))
    };
    NodeObservation {
        path: tree.display_path(index),
        parent,
        node: name,
        depth: node.depth as usize,
        ino: node.ino,
        own_blocks: node.own_blocks,
        children_blocks: node.sub.blocks,
        own_apparent: node.own_apparent,
        children_apparent: node.sub.apparent,
        file_count: node.direct.files,
        directory_count: node.direct.dirs,
        symlink_count: node.direct.symlinks,
        children_file_count: node.sub.files - node.direct.files,
        children_directory_count: node.sub.dirs - node.direct.dirs,
        children_symlink_count: node.sub.symlinks - node.direct.symlinks,
    }
}

/// Keeps, per inode, the link whose path hashes lowest: the same link in any walk order.
fn keep_lowest<V>(
    links: &mut HashMap<(u64, u64), V>,
    inode: (u64, u64),
    candidate: V,
    key: impl Fn(&V) -> u64,
) {
    match links.entry(inode) {
        Entry::Occupied(mut slot) => {
            if key(&candidate) < key(slot.get()) {
                slot.insert(candidate);
            }
        }
        Entry::Vacant(slot) => {
            slot.insert(candidate);
        }
    }
}

fn is_reported(target: &Target, depth: usize) -> bool {
    match target.report_mode {
        ReportMode::Tree => depth <= target.report_depth,
        ReportMode::Leaves => depth == 0 || depth == target.report_depth,
    }
}

/// Appends `/part`, without doubling a trailing `/` (the root of `/` is `/`).
fn push_component(path: &mut Vec<u8>, part: &[u8]) {
    if path.last() != Some(&b'/') {
        path.push(b'/');
    }
    path.extend_from_slice(part);
}

fn child_path(parent: &CStr, name: &[u8]) -> CString {
    let mut path = Vec::with_capacity(parent.to_bytes().len() + name.len() + 2);
    path.extend_from_slice(parent.to_bytes());
    push_component(&mut path, name);
    CString::new(path).expect("directory entry names contain no NUL")
}

/// A stable key for one link of a file: the hash of its full path.
fn link_key(dir: &CStr, name: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    hasher.write(dir.to_bytes());
    hasher.write_u8(b'/');
    hasher.write(name);
    hasher.finish()
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Directory,
    Symlink,
    Other,
}

/// The fields of a `stat` the scanner uses. `blocks` is in bytes.
#[derive(Debug, Clone, Copy)]
struct Stat {
    kind: Kind,
    dev: u64,
    ino: u64,
    nlink: u64,
    blocks: u64,
    size: u64,
    /// Nanoseconds since the epoch.
    mtime: i64,
}

mod sys {
    use std::ffi::CStr;
    use std::fs;
    use std::io;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    use super::{Kind, Stat};

    pub fn stat_path(path: &Path, follow: bool) -> io::Result<Stat> {
        let metadata = if follow {
            fs::metadata(path)?
        } else {
            fs::symlink_metadata(path)?
        };
        let file_type = metadata.file_type();
        Ok(Stat {
            kind: if file_type.is_dir() {
                Kind::Directory
            } else if file_type.is_file() {
                Kind::File
            } else if file_type.is_symlink() {
                Kind::Symlink
            } else {
                Kind::Other
            },
            dev: metadata.dev(),
            ino: metadata.ino(),
            nlink: metadata.nlink(),
            blocks: metadata.blocks().saturating_mul(512),
            size: metadata.size(),
            mtime: metadata.mtime() * 1_000_000_000 + metadata.mtime_nsec(),
        })
    }

    /// Entry names from one read of a directory, NUL-terminated in `buf`.
    #[derive(Default)]
    pub struct Batch {
        buf: Vec<u8>,
        names: Vec<usize>,
    }

    impl Batch {
        pub fn len(&self) -> usize {
            self.names.len()
        }

        pub fn name(&self, index: usize) -> &CStr {
            CStr::from_bytes_until_nul(&self.buf[self.names[index]..])
                .expect("directory entry names are NUL-terminated")
        }
    }

    #[cfg(target_os = "linux")]
    pub use linux::{path_handle, Dir};
    #[cfg(not(target_os = "linux"))]
    pub use portable::{path_handle, Dir};

    #[cfg(target_os = "linux")]
    mod linux {
        use std::ffi::CStr;
        use std::io;
        use std::mem::MaybeUninit;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        use super::{Batch, Kind, Stat};

        /// `MAX_HANDLE_SZ` in the kernel.
        const MAX_HANDLE: usize = 128;

        /// `struct file_handle` with room for any handle.
        #[repr(C)]
        struct FileHandle {
            handle_bytes: u32,
            handle_type: i32,
            f_handle: [u8; MAX_HANDLE],
        }

        /// `name_to_handle_at` relative to `dirfd`, as the key fanotify reports a directory by:
        /// the handle type, then the handle.
        fn handle_at(dirfd: i32, name: &CStr, flags: i32) -> Option<Box<[u8]>> {
            let mut handle = FileHandle {
                handle_bytes: MAX_HANDLE as u32,
                handle_type: 0,
                f_handle: [0; MAX_HANDLE],
            };
            let mut mount_id = 0i32;
            // SAFETY: `name` is NUL-terminated and both out-pointers are valid for writes.
            let status = unsafe {
                libc::syscall(
                    libc::SYS_name_to_handle_at,
                    dirfd,
                    name.as_ptr(),
                    &mut handle as *mut FileHandle,
                    &mut mount_id as *mut i32,
                    flags,
                )
            };
            if status != 0 {
                return None;
            }
            let len = (handle.handle_bytes as usize).min(MAX_HANDLE);
            let mut key = handle.handle_type.to_ne_bytes().to_vec();
            key.extend_from_slice(&handle.f_handle[..len]);
            Some(key.into_boxed_slice())
        }

        pub fn path_handle(path: &std::path::Path) -> Option<Box<[u8]>> {
            use std::os::unix::ffi::OsStrExt;
            let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
            handle_at(libc::AT_FDCWD, &path, 0)
        }

        /// Large enough that most directories take one `getdents64` call.
        const BATCH_BYTES: usize = 64 * 1024;
        /// `d_name` in `struct linux_dirent64`, after `d_ino` (8), `d_off` (8), `d_reclen` (2)
        /// and `d_type` (1).
        const NAME_OFFSET: usize = 19;

        pub struct Dir {
            fd: OwnedFd,
        }

        impl Dir {
            pub fn open(path: &CStr, follow: bool) -> io::Result<Self> {
                let mut flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
                if !follow {
                    // The entry was a directory when we stat'ed it; do not follow a symlink
                    // that has replaced it since.
                    flags |= libc::O_NOFOLLOW;
                }
                // SAFETY: `path` is NUL-terminated.
                let fd = unsafe { libc::open(path.as_ptr(), flags) };
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: `open` returned a descriptor nothing else owns.
                Ok(Self {
                    fd: unsafe { OwnedFd::from_raw_fd(fd) },
                })
            }

            /// Reads the next entries into `batch`; false at the end of the directory.
            pub fn read(&mut self, batch: &mut Batch) -> io::Result<bool> {
                batch.names.clear();
                batch.buf.resize(BATCH_BYTES, 0);
                let read = loop {
                    // SAFETY: the buffer is valid for `len` bytes and the kernel writes at most
                    // that many.
                    let read = unsafe {
                        libc::syscall(
                            libc::SYS_getdents64,
                            self.fd.as_raw_fd(),
                            batch.buf.as_mut_ptr(),
                            batch.buf.len(),
                        )
                    };
                    if read >= 0 {
                        break read as usize;
                    }
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                };
                let mut offset = 0;
                while offset < read {
                    let reclen =
                        u16::from_ne_bytes([batch.buf[offset + 16], batch.buf[offset + 17]]);
                    batch.names.push(offset + NAME_OFFSET);
                    offset += usize::from(reclen);
                }
                Ok(read > 0)
            }

            pub fn stat_self(&self) -> io::Result<Stat> {
                let mut stat = MaybeUninit::<libc::stat>::uninit();
                // SAFETY: the descriptor is open and `stat` is valid for writes.
                if unsafe { libc::fstat(self.fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: `fstat` succeeded, so it filled `stat`.
                Ok(to_stat(unsafe { stat.assume_init() }))
            }

            /// The file handle of the entry `name` (a directory), as fanotify reports it.
            pub fn handle(&self, name: &CStr) -> Option<Box<[u8]>> {
                handle_at(self.fd.as_raw_fd(), name, 0)
            }

            pub fn stat(&self, name: &CStr, follow: bool) -> io::Result<Stat> {
                let flags = if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW };
                let mut stat = MaybeUninit::<libc::stat>::uninit();
                // SAFETY: `name` is NUL-terminated and `stat` is valid for writes.
                let status = unsafe {
                    libc::fstatat(self.fd.as_raw_fd(), name.as_ptr(), stat.as_mut_ptr(), flags)
                };
                if status != 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: `fstatat` succeeded, so it filled `stat`.
                Ok(to_stat(unsafe { stat.assume_init() }))
            }
        }

        // The field types differ between architectures (`st_nlink` is u32 on arm64).
        #[allow(clippy::unnecessary_cast)]
        fn to_stat(stat: libc::stat) -> Stat {
            Stat {
                kind: match stat.st_mode & libc::S_IFMT {
                    libc::S_IFDIR => Kind::Directory,
                    libc::S_IFREG => Kind::File,
                    libc::S_IFLNK => Kind::Symlink,
                    _ => Kind::Other,
                },
                dev: stat.st_dev as u64,
                ino: stat.st_ino as u64,
                nlink: stat.st_nlink as u64,
                blocks: (stat.st_blocks as u64).saturating_mul(512),
                size: stat.st_size as u64,
                mtime: stat.st_mtime as i64 * 1_000_000_000 + stat.st_mtime_nsec as i64,
            }
        }
    }

    /// Everything but Linux: development machines. Correct, not tuned.
    #[cfg(not(target_os = "linux"))]
    mod portable {
        use std::ffi::{CStr, OsStr};
        use std::fs;
        use std::io;
        use std::os::unix::ffi::OsStrExt;
        use std::path::PathBuf;

        use super::{stat_path, Batch, Stat};

        pub fn path_handle(_path: &std::path::Path) -> Option<Box<[u8]>> {
            None
        }

        pub struct Dir {
            path: PathBuf,
            entries: Option<fs::ReadDir>,
        }

        impl Dir {
            pub fn open(path: &CStr, _follow: bool) -> io::Result<Self> {
                let path = PathBuf::from(OsStr::from_bytes(path.to_bytes()));
                let entries = fs::read_dir(&path)?;
                Ok(Self {
                    path,
                    entries: Some(entries),
                })
            }

            pub fn read(&mut self, batch: &mut Batch) -> io::Result<bool> {
                batch.names.clear();
                batch.buf.clear();
                let Some(entries) = self.entries.take() else {
                    return Ok(false);
                };
                for entry in entries {
                    let name = entry?.file_name();
                    batch.names.push(batch.buf.len());
                    batch.buf.extend_from_slice(name.as_bytes());
                    batch.buf.push(0);
                }
                Ok(true)
            }

            pub fn handle(&self, _name: &CStr) -> Option<Box<[u8]>> {
                None
            }

            pub fn stat_self(&self) -> io::Result<Stat> {
                stat_path(&self.path, true)
            }

            pub fn stat(&self, name: &CStr, follow: bool) -> io::Result<Stat> {
                stat_path(&self.path.join(OsStr::from_bytes(name.to_bytes())), follow)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs::{self, File};
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;
    use std::time::Duration;

    use tempfile::tempdir;

    use super::*;
    use crate::config::SizeMode;

    #[test]
    fn scans_regular_files_and_directories() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("nested")).unwrap();
        let mut file = File::create(temp.path().join("nested/file.txt")).unwrap();
        writeln!(file, "hello").unwrap();

        let target = test_target(temp.path().to_path_buf(), temp.path().to_path_buf(), vec![]);
        let scanner = NativeScanner::new(&target).unwrap();
        let result = scanner.scan(&target, &AtomicBool::new(false)).unwrap();

        assert_eq!(result.backend, "native");
        assert_eq!(result.scanned_directories, 2);
        assert_eq!(result.scanned_files, 1);
        let root = result
            .observations
            .iter()
            .find(|node| node.path == temp.path().display().to_string())
            .unwrap();
        assert_eq!(root.directory_count, 1);
        assert!(root.children_blocks > 0);
        assert_eq!(root.children_file_count, 1);
        assert_eq!(root.children_directory_count, 0);
        assert!(result
            .observations
            .iter()
            .any(|node| node.own_blocks + node.children_blocks > 0));
        assert!(result
            .observations
            .iter()
            .any(|node| node.own_apparent + node.children_apparent > 0));
    }

    #[test]
    fn excludes_matching_paths() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join(".cache")).unwrap();
        File::create(temp.path().join(".cache/file.txt")).unwrap();
        File::create(temp.path().join("kept.txt")).unwrap();

        let target = test_target(
            temp.path().to_path_buf(),
            PathBuf::from("/home/example"),
            vec!["**/.cache/**".to_string()],
        );
        let scanner = NativeScanner::new(&target).unwrap();
        let result = scanner.scan(&target, &AtomicBool::new(false)).unwrap();

        assert_eq!(result.scanned_files, 1);
        assert!(result.skipped_excluded >= 1);
    }

    #[test]
    fn stops_when_cancelled() {
        let temp = tempdir().unwrap();
        File::create(temp.path().join("file.txt")).unwrap();
        let target = test_target(temp.path().to_path_buf(), temp.path().to_path_buf(), vec![]);
        let scanner = NativeScanner::new(&target).unwrap();
        let error = scanner.scan(&target, &AtomicBool::new(true)).unwrap_err();
        assert!(error.to_string().contains("cancelled"), "{error}");
    }

    #[test]
    fn reports_depth_nodes_and_children_size() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("a/b")).unwrap();
        let mut file = File::create(temp.path().join("a/b/file.txt")).unwrap();
        writeln!(file, "hello").unwrap();

        let mut target = test_target(temp.path().to_path_buf(), PathBuf::from("/root"), vec![]);
        target.report_depth = 1;
        let scanner = NativeScanner::new(&target).unwrap();
        let result = scanner.scan(&target, &AtomicBool::new(false)).unwrap();

        assert!(result.observations.iter().any(|node| node.path == "/root"));
        let child = result
            .observations
            .iter()
            .find(|node| node.path == "/root/a")
            .unwrap();
        let root = result
            .observations
            .iter()
            .find(|node| node.path == "/root")
            .unwrap();
        assert_eq!(child.depth, 1);
        assert_eq!(child.directory_count, 1);
        // A directory's own size is its inode's allocation: 0 on APFS, a block or more on ext4.
        let a_blocks = fs::symlink_metadata(temp.path().join("a"))
            .unwrap()
            .blocks()
            * 512;
        assert_eq!(child.own_blocks, a_blocks);
        assert!(child.children_blocks > 0);
        assert!(root.children_blocks >= child.own_blocks + child.children_blocks);
        assert_eq!(root.children_file_count, 1);
        assert_eq!(root.children_directory_count, 1);
        assert_eq!(child.children_file_count, 1);
        assert_eq!(child.children_directory_count, 0);
        assert!(!result
            .observations
            .iter()
            .any(|node| node.path == "/root/a/b"));
    }

    #[test]
    fn hardlink_attribution_does_not_depend_on_walk_order() {
        let temp = tempdir().unwrap();
        for dir in ["a", "b", "c", "d"] {
            fs::create_dir(temp.path().join(dir)).unwrap();
        }
        let mut file = File::create(temp.path().join("a/original")).unwrap();
        file.write_all(&[7; 64 * 1024]).unwrap();
        for dir in ["b", "c", "d"] {
            fs::hard_link(
                temp.path().join("a/original"),
                temp.path().join(dir).join("link"),
            )
            .unwrap();
        }

        let mut target = test_target(temp.path().to_path_buf(), PathBuf::from("/data"), vec![]);
        let mut seen = Vec::new();
        for threads in [1, 2, 4, 8, 1, 8] {
            target.scan_threads = threads;
            let scanner = NativeScanner::new(&target).unwrap();
            let result = scanner.scan(&target, &AtomicBool::new(false)).unwrap();
            let sizes: Vec<(String, u64)> = result
                .observations
                .iter()
                .map(|node| (node.path.clone(), node.children_blocks))
                .collect();
            let charged: Vec<&str> = result
                .entries
                .iter()
                .filter(|entry| entry.blocks > 0)
                .map(|entry| entry.path.as_str())
                .collect();
            assert_eq!(
                charged.len(),
                1,
                "one link carries the allocation: {charged:?}"
            );
            seen.push((sizes, charged[0].to_string()));
        }
        assert!(seen.windows(2).all(|pair| pair[0] == pair[1]), "{seen:#?}");
    }

    #[test]
    fn root_exclusion_matches_the_root_with_a_trailing_slash() {
        let temp = tempdir().unwrap();
        File::create(temp.path().join("kept.txt")).unwrap();
        let display = PathBuf::from("/var/cache");
        for (pattern, excluded) in [("**/cache/**", true), ("**/cache", false)] {
            let target = test_target(
                temp.path().to_path_buf(),
                display.clone(),
                vec![pattern.to_string()],
            );
            let scanner = NativeScanner::new(&target).unwrap();
            let result = scanner.scan(&target, &AtomicBool::new(false)).unwrap();
            assert_eq!(result.observations.is_empty(), excluded, "{pattern}");
            assert_eq!(result.skipped_excluded, u64::from(excluded), "{pattern}");
        }

        // An excluded root is still stat'ed first, so a missing one fails the scan.
        let target = test_target(
            temp.path().join("missing"),
            display,
            vec!["**/cache/**".to_string()],
        );
        let scanner = NativeScanner::new(&target).unwrap();
        assert!(scanner.scan(&target, &AtomicBool::new(false)).is_err());
    }

    #[test]
    fn directories_too_deep_to_open_are_counted_not_fatal() {
        // Deeper than PATH_MAX: built with mkdirat/openat, since no path reaches the bottom.
        // On Linux each entry is stat'ed relative to its directory, so the walk gets as far as
        // opening a directory by a path the kernel refuses.
        let temp = tempdir().unwrap();
        let name = CString::new("d".repeat(200)).unwrap();
        let file = CString::new("f").unwrap();
        let path = CString::new(temp.path().as_os_str().as_bytes()).unwrap();
        // SAFETY: plain libc calls on NUL-terminated strings; every descriptor is closed.
        unsafe {
            let mut fd = libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
            assert!(fd >= 0);
            for _ in 0..30 {
                let created =
                    libc::openat(fd, file.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644);
                assert!(created >= 0);
                libc::close(created);
                assert_eq!(libc::mkdirat(fd, name.as_ptr(), 0o755), 0);
                let next = libc::openat(fd, name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
                assert!(next >= 0);
                libc::close(fd);
                fd = next;
            }
            libc::close(fd);
        }

        let target = test_target(temp.path().to_path_buf(), PathBuf::from("/deep"), vec![]);
        let scanner = NativeScanner::new(&target).unwrap();
        let result = scanner.scan(&target, &AtomicBool::new(false)).unwrap();
        assert!(result.missing_path_races >= 1, "{result:?}");
        assert!(
            result.scanned_files > 1 && result.scanned_files < 30,
            "{result:?}"
        );
    }

    fn test_target(scan_path: PathBuf, display_path: PathBuf, exclude: Vec<String>) -> Target {
        Target {
            name: "test".to_string(),
            target_type: "filesystem".to_string(),
            scanner: "native".to_string(),
            display_path,
            scan_path,
            baseline_interval: Duration::from_secs(60),
            timeout: Duration::from_secs(30),
            no_cross_filesystem: true,
            follow_symlinks: false,
            report_mode: ReportMode::Tree,
            report_depth: 1,
            max_depth: None,
            scan_threads: 4,
            size_modes: vec![SizeMode::Blocks],
            exclude,
            tree_max_directories: 1000,
            live: false,
            sharing_interval: None,
            collect_handles: false,
            labels: BTreeMap::new(),
        }
    }
}
