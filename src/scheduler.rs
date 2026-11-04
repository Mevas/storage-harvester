use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time;
use tracing::{error, info, warn};

use crate::cache::SnapshotStore;
use crate::config::Target;
use crate::live::{LiveStore, LiveTarget, SharingReport};
use crate::scanner;

#[derive(Clone)]
pub struct Scheduler {
    targets: Vec<Target>,
    store: SnapshotStore,
    live: Arc<LiveStore>,
}

impl Scheduler {
    pub fn new(targets: Vec<Target>, store: SnapshotStore, live: Arc<LiveStore>) -> Self {
        Self {
            targets,
            store,
            live,
        }
    }

    pub fn start(self) -> Vec<JoinHandle<()>> {
        // One sharing pass at a time: the biggest share holds ~180 MB of extent references.
        let sharing_gate = Arc::new(AsyncMutex::new(()));
        let mut tasks = Vec::new();
        for (index, target) in self.targets.into_iter().enumerate() {
            if let Some(interval) = target.sharing_interval {
                let lt = Arc::clone(&self.live.targets[index]);
                if lt.btrfs {
                    tasks.push(tokio::spawn(sharing_loop(
                        lt,
                        interval,
                        Arc::clone(&sharing_gate),
                    )));
                } else {
                    warn!(target = %target.name, "sharing_interval is set but the target is not on btrfs; ignored");
                }
            }
            let store = self.store.clone();
            let live = Arc::clone(&self.live);
            tasks.push(tokio::spawn(async move {
                loop {
                    run_scan(&target, index, &store, &live).await;
                    time::sleep(target.baseline_interval).await;
                }
            }));
        }
        tasks
    }
}

async fn run_scan(target: &Target, index: usize, store: &SnapshotStore, live: &Arc<LiveStore>) {
    info!(
        target = %target.name,
        path = %target.display_path.display(),
        interval_seconds = target.baseline_interval.as_secs(),
        timeout_seconds = target.timeout.as_secs(),
        report_depth = target.report_depth,
        max_depth = ?target.max_depth,
        "scan started"
    );
    store.record_scan_start(&target.name).await;
    live.targets[index].scanning.store(true, Ordering::Relaxed);
    let target_clone = target.clone();
    let cancel = Arc::new(AtomicBool::new(false));
    let walk_cancel = Arc::clone(&cancel);
    let mut scan = tokio::task::spawn_blocking(move || {
        let scanner = scanner::build(&target_clone)?;
        scanner.scan(&target_clone, &walk_cancel)
    });

    let outcome = time::timeout(target.timeout, &mut scan).await;
    if outcome.is_err() {
        // A blocking task cannot be aborted, so stop the walk cooperatively and wait for it.
        // Otherwise it keeps reading the disk while the next scan starts.
        cancel.store(true, Ordering::Relaxed);
        let _ = scan.await;
    }

    match outcome {
        Ok(Ok(Ok(mut result))) => {
            let issue_count = result.permission_errors
                + result.missing_path_races
                + result.skipped_cross_device
                + result.skipped_excluded;
            info!(
                target = %target.name,
                backend = %result.backend,
                path = %target.display_path.display(),
                duration_seconds = result.duration.as_secs_f64(),
                scanned_directories = result.scanned_directories,
                scanned_files = result.scanned_files,
                scanned_symlinks = result.scanned_symlinks,
                reported_nodes = result.observations.len(),
                tree_directories = result.tree.as_ref().map_or(0, |tree| tree.nodes.len()),
                direct_entries = result.entries.len(),
                max_observed_depth = result.max_observed_depth,
                depth_limit_hits = result.depth_limit_hits,
                issue_count,
                permission_errors = result.permission_errors,
                missing_path_races = result.missing_path_races,
                skipped_cross_device = result.skipped_cross_device,
                skipped_excluded = result.skipped_excluded,
                "scan completed"
            );
            // The tree goes to the live store; cached results stay small, since every
            // /metrics scrape copies them.
            if let Some(tree) = result.tree.take() {
                let live = Arc::clone(live);
                let (started, duration) = (result.timestamp, result.duration);
                let _ = tokio::task::spawn_blocking(move || {
                    live.replace(index, tree, started, duration)
                })
                .await;
            } else {
                live.targets[index].scanning.store(false, Ordering::Relaxed);
            }
            store.record_success(&target.name, result).await;
        }
        Ok(Ok(Err(error))) => {
            live.targets[index].scanning.store(false, Ordering::Relaxed);
            warn!(target = %target.name, path = %target.display_path.display(), error = %error, "scan failed");
            store.record_failure(&target.name, error.to_string()).await;
        }
        Ok(Err(error)) => {
            live.targets[index].scanning.store(false, Ordering::Relaxed);
            error!(target = %target.name, path = %target.display_path.display(), error = %error, "scan task failed");
            store.record_failure(&target.name, error.to_string()).await;
        }
        Err(_) => {
            live.targets[index].scanning.store(false, Ordering::Relaxed);
            warn!(target = %target.name, path = %target.display_path.display(), timeout_seconds = target.timeout.as_secs(), "scan timed out");
            store
                .record_failure(
                    &target.name,
                    format!("scan timed out after {}s", target.timeout.as_secs()),
                )
                .await;
        }
    }
}

/// Every `interval`, once the target has a tree: which bytes each directory holds alone.
async fn sharing_loop(lt: Arc<LiveTarget>, interval: Duration, gate: Arc<AsyncMutex<()>>) {
    loop {
        let ready = lt
            .state
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some();
        if !ready {
            time::sleep(Duration::from_secs(5)).await;
            continue;
        }
        let permit = gate.lock().await;
        let pass = Arc::clone(&lt);
        let outcome = tokio::task::spawn_blocking(move || sharing_pass(&pass)).await;
        drop(permit);
        match outcome {
            Ok(Ok(report)) => {
                info!(
                    target = %lt.target.name,
                    duration_seconds = report.duration.as_secs_f64(),
                    logical_bytes = report.logical,
                    disk_bytes = report.disk,
                    outside_bytes = report.outside,
                    pairs = report.pairs.len(),
                    "sharing pass completed"
                );
                *lt.sharing.write().unwrap_or_else(PoisonError::into_inner) =
                    Some(Arc::new(report));
            }
            Ok(Err(error)) => {
                warn!(target = %lt.target.name, %error, "sharing pass failed")
            }
            Err(error) => error!(target = %lt.target.name, %error, "sharing pass panicked"),
        }
        time::sleep(interval).await;
    }
}

#[cfg(target_os = "linux")]
fn sharing_pass(lt: &LiveTarget) -> std::io::Result<SharingReport> {
    use std::collections::HashMap;
    use std::time::SystemTime;

    use crate::btrfs::{self, Skeleton};

    let (skeleton, inos, logical) = {
        let guard = lt.state.read().unwrap_or_else(PoisonError::into_inner);
        let tree = &guard.as_ref().expect("checked by the caller").tree;
        let skeleton = Skeleton {
            pruned: tree
                .nodes
                .iter()
                .enumerate()
                .filter(|(_, node)| node.alive && node.pruned)
                .map(|(index, _)| (index as u32, tree.display_path_bytes(index as u32)))
                .collect(),
            exclude: lt.exclude().clone(),
            parent: tree.nodes.iter().map(|node| node.parent).collect(),
            depth: tree.nodes.iter().map(|node| node.depth).collect(),
            by_ino: tree
                .nodes
                .iter()
                .enumerate()
                .filter(|(_, node)| node.alive)
                .map(|(index, node)| (node.ino, index as u32))
                .collect(),
        };
        let inos: Vec<u64> = tree.nodes.iter().map(|node| node.ino).collect();
        (skeleton, inos, tree.root().total_blocks())
    };
    let sharing = btrfs::sharing(&lt.target.scan_path, &skeleton, &AtomicBool::new(false))?;

    // What a subtree holds alone is what its directories hold alone; parents precede children.
    let mut freed = sharing.alone.clone();
    for index in (1..freed.len()).rev() {
        let parent = skeleton.parent[index];
        if parent != crate::tree::NONE {
            freed[parent as usize] += freed[index];
        }
    }
    let by_ino: HashMap<u64, u64> = skeleton
        .by_ino
        .iter()
        .map(|(&ino, &node)| (ino, freed[node as usize]))
        .collect();
    let pairs = {
        let guard = lt.state.read().unwrap_or_else(PoisonError::into_inner);
        let state = guard.as_ref().expect("a tree is never removed");
        sharing
            .pairs
            .iter()
            .filter_map(|&(a, b, bytes)| {
                Some((
                    state.path_of_ino(inos[a as usize])?,
                    state.path_of_ino(inos[b as usize])?,
                    bytes,
                ))
            })
            .collect()
    };
    Ok(SharingReport {
        at: SystemTime::now(),
        duration: sharing.duration,
        logical,
        disk: sharing.disk,
        outside: sharing.outside,
        pairs,
        by_ino,
    })
}

#[cfg(not(target_os = "linux"))]
fn sharing_pass(_lt: &LiveTarget) -> std::io::Result<SharingReport> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "btrfs sharing needs Linux",
    ))
}
