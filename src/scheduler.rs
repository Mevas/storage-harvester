use tokio::task::JoinHandle;
use tokio::time;
use tracing::{error, info, warn};

use crate::cache::SnapshotStore;
use crate::config::Target;
use crate::scanner;

#[derive(Debug, Clone)]
pub struct Scheduler {
    targets: Vec<Target>,
    store: SnapshotStore,
}

impl Scheduler {
    pub fn new(targets: Vec<Target>, store: SnapshotStore) -> Self {
        Self { targets, store }
    }

    pub fn start(self) -> Vec<JoinHandle<()>> {
        self.targets
            .into_iter()
            .map(|target| {
                let store = self.store.clone();
                tokio::spawn(async move {
                    loop {
                        run_scan(&target, &store).await;
                        time::sleep(target.baseline_interval).await;
                    }
                })
            })
            .collect()
    }
}

async fn run_scan(target: &Target, store: &SnapshotStore) {
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
    let target_clone = target.clone();
    let scan = tokio::task::spawn_blocking(move || {
        let scanner = scanner::build(&target_clone)?;
        scanner.scan(&target_clone)
    });

    match time::timeout(target.timeout, scan).await {
        Ok(Ok(Ok(result))) => {
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
            store.record_success(&target.name, result).await;
        }
        Ok(Ok(Err(error))) => {
            warn!(target = %target.name, path = %target.display_path.display(), error = %error, "scan failed");
            store.record_failure(&target.name, error.to_string()).await;
        }
        Ok(Err(error)) => {
            error!(target = %target.name, path = %target.display_path.display(), error = %error, "scan task failed");
            store.record_failure(&target.name, error.to_string()).await;
        }
        Err(_) => {
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
