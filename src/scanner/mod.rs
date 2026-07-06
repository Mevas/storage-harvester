use std::time::{Duration, SystemTime};

use anyhow::{bail, Result};

use crate::config::Target;

pub mod native;

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub backend: String,
    pub observations: Vec<NodeObservation>,
    pub entries: Vec<EntryObservation>,
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
pub struct EntryObservation {
    pub parent_path: String,
    pub path: String,
    pub name: String,
    pub entry_type: EntryType,
    pub depth: usize,
    pub blocks: u64,
    pub apparent: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum EntryType {
    File,
    Directory,
    Symlink,
    Other,
}

impl EntryType {
    pub fn as_str(self) -> &'static str {
        match self {
            EntryType::File => "file",
            EntryType::Directory => "directory",
            EntryType::Symlink => "symlink",
            EntryType::Other => "other",
        }
    }
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
