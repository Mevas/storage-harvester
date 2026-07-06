use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::config::{ReportMode, Target};
use crate::scanner::{EntryObservation, EntryType, NodeObservation, ScanResult, Scanner};

#[derive(Debug)]
pub struct NativeScanner {
    exclude: GlobSet,
}

impl NativeScanner {
    pub fn new(target: &Target) -> Result<Self> {
        let mut builder = GlobSetBuilder::new();
        for pattern in &target.exclude {
            builder.add(
                Glob::new(pattern)
                    .with_context(|| format!("invalid exclude pattern {pattern:?}"))?,
            );
        }
        Ok(Self {
            exclude: builder.build()?,
        })
    }

    fn is_excluded(&self, target: &Target, scan_path: &Path) -> bool {
        if self.exclude.is_empty() {
            return false;
        }

        let display_path = scan_path
            .strip_prefix(&target.scan_path)
            .ok()
            .map(|relative| target.display_path.join(relative))
            .unwrap_or_else(|| PathBuf::from(scan_path));
        self.exclude.is_match(display_path)
    }
}

impl Scanner for NativeScanner {
    fn backend(&self) -> &'static str {
        "native"
    }

    fn scan(&self, target: &Target) -> Result<ScanResult> {
        let started = Instant::now();
        let timestamp = SystemTime::now();
        let root_metadata = metadata_for(&target.scan_path, target.follow_symlinks)
            .with_context(|| format!("failed to stat {}", target.scan_path.display()))?;
        let root_device = root_metadata.dev();

        let mut state = ScanState {
            backend: self.backend().to_string(),
            nodes: BTreeMap::new(),
            entries: Vec::new(),
            permission_errors: 0,
            missing_path_races: 0,
            skipped_cross_device: 0,
            skipped_excluded: 0,
            scanned_files: 0,
            scanned_directories: 0,
            scanned_symlinks: 0,
            max_observed_depth: 0,
            depth_limit_hits: 0,
            timestamp,
        };

        let mut stack = vec![WalkItem {
            path: target.scan_path.clone(),
            depth: 0,
        }];
        while let Some(item) = stack.pop() {
            let path = item.path;
            if self.is_excluded(target, &path) {
                state.skipped_excluded += 1;
                continue;
            }

            let metadata = match metadata_for(&path, target.follow_symlinks) {
                Ok(metadata) => metadata,
                Err(error) if is_not_found(&error) => {
                    state.missing_path_races += 1;
                    continue;
                }
                Err(error) if is_permission_denied(&error) => {
                    state.permission_errors += 1;
                    continue;
                }
                Err(error) => {
                    if path != target.scan_path {
                        state.missing_path_races += 1;
                        continue;
                    }
                    return Err(error)
                        .with_context(|| format!("failed to stat {}", path.display()));
                }
            };

            if target.no_cross_filesystem && metadata.dev() != root_device {
                state.skipped_cross_device += 1;
                continue;
            }

            state.max_observed_depth = state.max_observed_depth.max(item.depth);
            account_entry(&mut state, target, &path, item.depth, &metadata);

            if metadata.is_dir() {
                if target
                    .max_depth
                    .is_some_and(|max_depth| item.depth >= max_depth)
                {
                    state.depth_limit_hits += 1;
                    continue;
                }

                let entries = match fs::read_dir(&path) {
                    Ok(entries) => entries,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        state.missing_path_races += 1;
                        continue;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                        state.permission_errors += 1;
                        continue;
                    }
                    Err(error) => {
                        return Err(error)
                            .with_context(|| format!("failed to read {}", path.display()))
                    }
                };

                for entry in entries {
                    match entry {
                        Ok(entry) => stack.push(WalkItem {
                            path: entry.path(),
                            depth: item.depth + 1,
                        }),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            state.missing_path_races += 1;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                            state.permission_errors += 1;
                        }
                        Err(error) => {
                            return Err(error).with_context(|| {
                                format!("failed to read entry in {}", path.display())
                            })
                        }
                    }
                }
            }
        }

        Ok(state.finish(target, started.elapsed()))
    }
}

#[derive(Debug, Clone)]
struct WalkItem {
    path: PathBuf,
    depth: usize,
}

#[derive(Debug)]
struct ScanState {
    backend: String,
    nodes: BTreeMap<PathBuf, NodeAccumulator>,
    entries: Vec<EntryObservation>,
    permission_errors: u64,
    missing_path_races: u64,
    skipped_cross_device: u64,
    skipped_excluded: u64,
    scanned_files: u64,
    scanned_directories: u64,
    scanned_symlinks: u64,
    max_observed_depth: usize,
    depth_limit_hits: u64,
    timestamp: SystemTime,
}

impl ScanState {
    fn node_mut(&mut self, target: &Target, path: &Path, depth: usize) -> &mut NodeAccumulator {
        self.nodes
            .entry(path.to_path_buf())
            .or_insert_with(|| NodeAccumulator::new(target, path, depth))
    }

    fn finish(self, target: &Target, duration: Duration) -> ScanResult {
        let reported = reported_paths(target, &self.nodes);
        let observations = self
            .nodes
            .into_iter()
            .filter(|(path, _)| reported.contains(path))
            .map(|(_, node)| node.into_observation())
            .collect();
        let entries = self
            .entries
            .into_iter()
            .filter(|entry| reported.contains(Path::new(&entry.parent_path)))
            .collect();

        ScanResult {
            backend: self.backend,
            observations,
            entries,
            permission_errors: self.permission_errors,
            missing_path_races: self.missing_path_races,
            skipped_cross_device: self.skipped_cross_device,
            skipped_excluded: self.skipped_excluded,
            scanned_files: self.scanned_files,
            scanned_directories: self.scanned_directories,
            scanned_symlinks: self.scanned_symlinks,
            max_observed_depth: self.max_observed_depth,
            depth_limit_hits: self.depth_limit_hits,
            duration,
            timestamp: self.timestamp,
        }
    }
}

#[derive(Debug)]
struct NodeAccumulator {
    path: String,
    parent: String,
    node: String,
    depth: usize,
    own_blocks: u64,
    children_blocks: u64,
    own_apparent: u64,
    children_apparent: u64,
    is_directory: bool,
    file_count: u64,
    directory_count: u64,
    symlink_count: u64,
    children_file_count: u64,
    children_directory_count: u64,
    children_symlink_count: u64,
}

impl NodeAccumulator {
    fn new(target: &Target, scan_path: &Path, depth: usize) -> Self {
        let display_path = display_path_for(target, scan_path);
        let parent = if depth == 0 {
            String::new()
        } else {
            display_path
                .parent()
                .map(|path| path.display().to_string())
                .unwrap_or_default()
        };
        let node = if depth == 0 {
            ".".to_string()
        } else {
            display_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| display_path.display().to_string())
        };

        Self {
            path: display_path.display().to_string(),
            parent,
            node,
            depth,
            own_blocks: 0,
            children_blocks: 0,
            own_apparent: 0,
            children_apparent: 0,
            is_directory: false,
            file_count: 0,
            directory_count: 0,
            symlink_count: 0,
            children_file_count: 0,
            children_directory_count: 0,
            children_symlink_count: 0,
        }
    }

    fn into_observation(self) -> NodeObservation {
        NodeObservation {
            path: self.path,
            parent: self.parent,
            node: self.node,
            depth: self.depth,
            own_blocks: self.own_blocks,
            children_blocks: self.children_blocks,
            own_apparent: self.own_apparent,
            children_apparent: self.children_apparent,
            file_count: self.file_count,
            directory_count: self.directory_count,
            symlink_count: self.symlink_count,
            children_file_count: self.children_file_count,
            children_directory_count: self.children_directory_count,
            children_symlink_count: self.children_symlink_count,
        }
    }

    fn add_child_entry(&mut self, entry_kind: EntryKind) {
        match entry_kind {
            EntryKind::File | EntryKind::Other => self.children_file_count += 1,
            EntryKind::Directory => self.children_directory_count += 1,
            EntryKind::Symlink => self.children_symlink_count += 1,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum EntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

fn account_entry(
    state: &mut ScanState,
    target: &Target,
    path: &Path,
    depth: usize,
    metadata: &fs::Metadata,
) {
    let blocks = metadata.blocks().saturating_mul(512);
    let apparent = metadata.size();
    let file_type = metadata.file_type();

    state.scanned_files += u64::from(metadata.is_file());
    state.scanned_directories += u64::from(metadata.is_dir());
    state.scanned_symlinks += u64::from(file_type.is_symlink());

    if metadata.is_dir() {
        if depth > 0 {
            let parent = path.parent().unwrap_or(&target.scan_path);
            let parent_depth = relative_depth(target, parent);
            let parent_node = state.node_mut(target, parent, parent_depth);
            parent_node.directory_count += 1;
            parent_node.children_blocks = parent_node.children_blocks.saturating_add(blocks);
            parent_node.children_apparent = parent_node.children_apparent.saturating_add(apparent);

            for ancestor in ancestors_between(target, parent) {
                let ancestor_depth = relative_depth(target, &ancestor);
                let ancestor_node = state.node_mut(target, &ancestor, ancestor_depth);
                ancestor_node.children_blocks =
                    ancestor_node.children_blocks.saturating_add(blocks);
                ancestor_node.children_apparent =
                    ancestor_node.children_apparent.saturating_add(apparent);
                ancestor_node.add_child_entry(EntryKind::Directory);
            }
        }

        let node = state.node_mut(target, path, depth);
        node.is_directory = true;
        node.own_blocks = node.own_blocks.saturating_add(blocks);
        node.own_apparent = node.own_apparent.saturating_add(apparent);
        return;
    }

    let parent = path.parent().unwrap_or(&target.scan_path);
    let parent_depth = relative_depth(target, parent);
    let parent_node = state.node_mut(target, parent, parent_depth);
    parent_node.children_blocks = parent_node.children_blocks.saturating_add(blocks);
    parent_node.children_apparent = parent_node.children_apparent.saturating_add(apparent);
    let entry_kind = if metadata.is_file() {
        parent_node.file_count += 1;
        EntryKind::File
    } else if file_type.is_symlink() {
        parent_node.symlink_count += 1;
        EntryKind::Symlink
    } else if file_type.is_socket()
        || file_type.is_fifo()
        || file_type.is_char_device()
        || file_type.is_block_device()
    {
        parent_node.file_count += 1;
        EntryKind::Other
    } else {
        EntryKind::Other
    };
    record_direct_entry(state, target, parent, path, depth, metadata, entry_kind);

    for ancestor in ancestors_between(target, parent) {
        let ancestor_depth = relative_depth(target, &ancestor);
        let ancestor_node = state.node_mut(target, &ancestor, ancestor_depth);
        ancestor_node.children_blocks = ancestor_node.children_blocks.saturating_add(blocks);
        ancestor_node.children_apparent = ancestor_node.children_apparent.saturating_add(apparent);
        ancestor_node.add_child_entry(entry_kind);
    }
}

fn record_direct_entry(
    state: &mut ScanState,
    target: &Target,
    parent: &Path,
    path: &Path,
    depth: usize,
    metadata: &fs::Metadata,
    entry_kind: EntryKind,
) {
    let display_path = display_path_for(target, path);
    let parent_display_path = display_path_for(target, parent);
    let name = display_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| display_path.display().to_string());

    state.entries.push(EntryObservation {
        parent_path: parent_display_path.display().to_string(),
        path: display_path.display().to_string(),
        name,
        entry_type: entry_type_for(entry_kind),
        depth,
        blocks: metadata.blocks().saturating_mul(512),
        apparent: metadata.size(),
    });
}

fn entry_type_for(entry_kind: EntryKind) -> EntryType {
    match entry_kind {
        EntryKind::File => EntryType::File,
        EntryKind::Directory => EntryType::Directory,
        EntryKind::Symlink => EntryType::Symlink,
        EntryKind::Other => EntryType::Other,
    }
}

fn ancestors_between(target: &Target, leaf_parent: &Path) -> Vec<PathBuf> {
    let mut ancestors = Vec::new();
    let mut current = leaf_parent;
    while current != target.scan_path {
        if let Some(parent) = current.parent() {
            ancestors.push(parent.to_path_buf());
            current = parent;
        } else {
            break;
        }
    }
    ancestors
}

fn reported_paths(
    target: &Target,
    nodes: &BTreeMap<PathBuf, NodeAccumulator>,
) -> BTreeSet<PathBuf> {
    nodes
        .keys()
        .filter(|path| {
            let Some(node) = nodes.get(*path) else {
                return false;
            };
            if !node.is_directory {
                return false;
            }
            let depth = relative_depth(target, path);
            match target.report_mode {
                ReportMode::Tree => depth <= target.report_depth,
                ReportMode::Leaves => depth == 0 || depth == target.report_depth,
            }
        })
        .cloned()
        .collect()
}

fn relative_depth(target: &Target, path: &Path) -> usize {
    path.strip_prefix(&target.scan_path)
        .ok()
        .map(|relative| relative.components().count())
        .unwrap_or(0)
}

fn display_path_for(target: &Target, scan_path: &Path) -> PathBuf {
    scan_path
        .strip_prefix(&target.scan_path)
        .ok()
        .map(|relative| {
            if relative.as_os_str().is_empty() {
                target.display_path.clone()
            } else {
                target.display_path.join(relative)
            }
        })
        .unwrap_or_else(|| PathBuf::from(scan_path))
}

fn metadata_for(path: &Path, follow_symlinks: bool) -> std::io::Result<fs::Metadata> {
    if follow_symlinks {
        fs::metadata(path)
    } else {
        fs::symlink_metadata(path)
    }
}

fn is_not_found(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound
}

fn is_permission_denied(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::PermissionDenied
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs::{self, File};
    use std::io::Write;
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
        let result = scanner.scan(&target).unwrap();

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
        let result = scanner.scan(&target).unwrap();

        assert_eq!(result.scanned_files, 1);
        assert!(result.skipped_excluded >= 1);
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
        let result = scanner.scan(&target).unwrap();

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
        assert_eq!(child.own_blocks, 0);
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
            size_modes: vec![SizeMode::Blocks],
            exclude,
            labels: BTreeMap::new(),
        }
    }
}
