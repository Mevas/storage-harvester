use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::RwLock;

use crate::config::{SizeMode, Target};
use crate::scanner::ScanResult;

#[derive(Debug, Clone)]
pub struct TargetSnapshot {
    pub target_name: String,
    pub target_type: String,
    pub path: String,
    pub labels: BTreeMap<String, String>,
    pub size_modes: Vec<SizeMode>,
    pub last_success: Option<ScanResult>,
    pub last_error: Option<String>,
    pub last_attempt: Option<SystemTime>,
    pub scan_running: bool,
    pub scan_started: Option<SystemTime>,
    pub scan_count: u64,
    pub failure_count: u64,
    pub interval: Duration,
}

impl TargetSnapshot {
    pub fn from_target(target: &Target) -> Self {
        Self {
            target_name: target.name.clone(),
            target_type: target.target_type.clone(),
            path: target.display_path.display().to_string(),
            labels: target.labels.clone(),
            size_modes: target.size_modes.clone(),
            last_success: None,
            last_error: None,
            last_attempt: None,
            scan_running: false,
            scan_started: None,
            scan_count: 0,
            failure_count: 0,
            interval: target.baseline_interval,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotStore {
    inner: Arc<RwLock<BTreeMap<String, TargetSnapshot>>>,
}

impl SnapshotStore {
    pub fn new(targets: impl IntoIterator<Item = TargetSnapshot>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(
                targets
                    .into_iter()
                    .map(|snapshot| (snapshot.target_name.clone(), snapshot))
                    .collect(),
            )),
        }
    }

    pub async fn record_scan_start(&self, target_name: &str) {
        let mut guard = self.inner.write().await;
        if let Some(snapshot) = guard.get_mut(target_name) {
            snapshot.scan_running = true;
            snapshot.scan_started = Some(SystemTime::now());
        }
    }

    pub async fn record_success(&self, target_name: &str, result: ScanResult) {
        let mut guard = self.inner.write().await;
        if let Some(snapshot) = guard.get_mut(target_name) {
            snapshot.last_attempt = Some(result.timestamp);
            snapshot.last_success = Some(result);
            snapshot.last_error = None;
            snapshot.scan_running = false;
            snapshot.scan_started = None;
            snapshot.scan_count += 1;
        }
    }

    pub async fn record_failure(&self, target_name: &str, error: String) {
        let mut guard = self.inner.write().await;
        if let Some(snapshot) = guard.get_mut(target_name) {
            snapshot.last_attempt = Some(SystemTime::now());
            snapshot.last_error = Some(error);
            snapshot.scan_running = false;
            snapshot.scan_started = None;
            snapshot.scan_count += 1;
            snapshot.failure_count += 1;
        }
    }

    pub async fn snapshots(&self) -> Vec<TargetSnapshot> {
        self.inner.read().await.values().cloned().collect()
    }

    pub async fn ready(&self) -> bool {
        self.inner
            .read()
            .await
            .values()
            .all(|snapshot| snapshot.last_success.is_some() || snapshot.last_error.is_some())
    }
}
