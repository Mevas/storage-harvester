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
    store.record_scan_start(&target.name).await;
    let target_clone = target.clone();
    let scan = tokio::task::spawn_blocking(move || {
        let scanner = scanner::build(&target_clone)?;
        scanner.scan(&target_clone)
    });

    match time::timeout(target.timeout, scan).await {
        Ok(Ok(Ok(result))) => {
            info!(target = %target.name, backend = %result.backend, path = %target.display_path.display(), duration = ?result.duration, "scan completed");
            store.record_success(&target.name, result).await;
        }
        Ok(Ok(Err(error))) => {
            warn!(target = %target.name, error = %error, "scan failed");
            store.record_failure(&target.name, error.to_string()).await;
        }
        Ok(Err(error)) => {
            error!(target = %target.name, error = %error, "scan task failed");
            store.record_failure(&target.name, error.to_string()).await;
        }
        Err(_) => {
            warn!(target = %target.name, timeout = ?target.timeout, "scan timed out");
            store
                .record_failure(
                    &target.name,
                    format!("scan timed out after {}s", target.timeout.as_secs()),
                )
                .await;
        }
    }
}
