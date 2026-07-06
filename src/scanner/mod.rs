use std::time::{Duration, SystemTime};

use anyhow::{bail, Result};

use crate::config::Target;

pub mod native;

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub backend: String,
    pub observations: Vec<NodeObservation>,
    pub permission_errors: u64,
    pub missing_path_races: u64,
    pub skipped_cross_device: u64,
    pub skipped_excluded: u64,
    pub scanned_files: u64,
    pub scanned_directories: u64,
    pub scanned_symlinks: u64,
    pub max_observed_depth: usize,
    pub depth_limit_hits: u64,
    pub duration: Duration,
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone)]
pub struct NodeObservation {
    pub path: String,
    pub parent: String,
    pub node: String,
    pub depth: usize,
    pub own_blocks: u64,
    pub children_blocks: u64,
    pub own_apparent: u64,
    pub children_apparent: u64,
    pub file_count: u64,
    pub directory_count: u64,
    pub symlink_count: u64,
    pub children_file_count: u64,
    pub children_directory_count: u64,
    pub children_symlink_count: u64,
}

pub trait Scanner: Send + Sync {
    fn backend(&self) -> &'static str;
    fn scan(&self, target: &Target) -> Result<ScanResult>;
}

pub fn build(target: &Target) -> Result<Box<dyn Scanner>> {
    match target.scanner.as_str() {
        "native" => Ok(Box::new(native::NativeScanner::new(target)?)),
        backend => bail!(
            "target {} uses unsupported scanner {backend:?}",
            target.name
        ),
    }
}
