use anyhow::Result;

use crate::cache::{SnapshotStore, TargetSnapshot};
use crate::collector::filesystem::FilesystemCollector;
use crate::collector::Collector;
use crate::config::{Config, Target};

#[derive(Debug, Clone)]
pub struct TargetRegistry {
    targets: Vec<Target>,
}

impl TargetRegistry {
    pub fn from_config(config: &Config) -> Result<Self> {
        let filesystem_collector = FilesystemCollector::new(config.resolved_targets()?);
        Ok(Self {
            targets: filesystem_collector.collect()?,
        })
    }

    pub fn targets(&self) -> &[Target] {
        &self.targets
    }

    pub fn snapshot_store(&self) -> SnapshotStore {
        SnapshotStore::new(self.targets.iter().map(TargetSnapshot::from_target))
    }
}
