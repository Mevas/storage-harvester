use anyhow::Result;

use crate::collector::Collector;
use crate::config::Target;

#[derive(Debug, Clone)]
pub struct FilesystemCollector {
    targets: Vec<Target>,
}

impl FilesystemCollector {
    pub fn new(targets: Vec<Target>) -> Self {
        Self { targets }
    }
}

impl Collector for FilesystemCollector {
    fn collect(&self) -> Result<Vec<Target>> {
        Ok(self.targets.clone())
    }
}
