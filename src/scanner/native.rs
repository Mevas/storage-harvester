use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::config::{ReportMode, Target};
use crate::scanner::{NodeObservation, ScanResult, Scanner};

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
            reported_ancestor: target.scan_path.clone(),
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
                    return Err(error).with_context(|| format!("failed to stat {}", path.display()))
                }
            };

            if target.no_cross_filesystem && metadata.dev() != root_device {
                state.skipped_cross_device += 1;
                continue;
            }

            state.max_observed_depth = state.max_observed_depth.max(item.depth);
            account_entry(
                &mut state,
                target,
                &path,
                item.depth,
                &item.reported_ancestor,
                &metadata,
            );

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

                let child_reported_ancestor = if should_report(target, item.depth) {
                    path.clone()
                } else {
                    item.reported_ancestor.clone()
                };

                for entry in entries {
                    match entry {
                        Ok(entry) => stack.push(WalkItem {
                            path: entry.path(),
                            depth: item.depth + 1,
                            reported_ancestor: child_reported_ancestor.clone(),
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
    reported_ancestor: PathBuf,
}

#[derive(Debug)]
struct ScanState {
    backend: String,
    nodes: BTreeMap<PathBuf, NodeAccumulator>,
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

        ScanResult {
            backend: self.backend,
            observations,
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
    inclusive_blocks: u64,
    exclusive_blocks: u64,
    breakdown_blocks: u64,
    inclusive_apparent: u64,
    exclusive_apparent: u64,
    breakdown_apparent: u64,
    file_count: u64,
    directory_count: u64,
    symlink_count: u64,
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
            inclusive_blocks: 0,
            exclusive_blocks: 0,
            breakdown_blocks: 0,
            inclusive_apparent: 0,
            exclusive_apparent: 0,
            breakdown_apparent: 0,
            file_count: 0,
            directory_count: 0,
            symlink_count: 0,
        }
    }

    fn into_observation(self) -> NodeObservation {
        NodeObservation {
            path: self.path,
            parent: self.parent,
            node: self.node,
            depth: self.depth,
            inclusive_blocks: self.inclusive_blocks,
            exclusive_blocks: self.exclusive_blocks,
            breakdown_blocks: self.breakdown_blocks,
            inclusive_apparent: self.inclusive_apparent,
            exclusive_apparent: self.exclusive_apparent,
            breakdown_apparent: self.breakdown_apparent,
            file_count: self.file_count,
            directory_count: self.directory_count,
            symlink_count: self.symlink_count,
        }
    }
}

fn account_entry(
    state: &mut ScanState,
    target: &Target,
    path: &Path,
    depth: usize,
    reported_ancestor: &Path,
    metadata: &fs::Metadata,
) {
    let blocks = metadata.blocks().saturating_mul(512);
    let apparent = metadata.size();
    let file_type = metadata.file_type();

    state.scanned_files += u64::from(metadata.is_file());
    state.scanned_directories += u64::from(metadata.is_dir());
    state.scanned_symlinks += u64::from(file_type.is_symlink());

    for ancestor in ancestors_from_root(target, path) {
        let ancestor_depth = relative_depth(target, &ancestor);
        let node = state.node_mut(target, &ancestor, ancestor_depth);
        node.inclusive_blocks = node.inclusive_blocks.saturating_add(blocks);
        node.inclusive_apparent = node.inclusive_apparent.saturating_add(apparent);
    }

    if metadata.is_dir() {
        let node = state.node_mut(target, path, depth);
        node.directory_count += 1;
        node.exclusive_blocks = node.exclusive_blocks.saturating_add(blocks);
        node.exclusive_apparent = node.exclusive_apparent.saturating_add(apparent);
        if should_report(target, depth) {
            node.breakdown_blocks = node.breakdown_blocks.saturating_add(blocks);
            node.breakdown_apparent = node.breakdown_apparent.saturating_add(apparent);
        }
        return;
    }

    let parent = path.parent().unwrap_or(&target.scan_path);
    let parent_depth = relative_depth(target, parent);
    let parent_node = state.node_mut(target, parent, parent_depth);
    parent_node.exclusive_blocks = parent_node.exclusive_blocks.saturating_add(blocks);
    parent_node.exclusive_apparent = parent_node.exclusive_apparent.saturating_add(apparent);
    if metadata.is_file() {
        parent_node.file_count += 1;
    } else if file_type.is_symlink() {
        parent_node.symlink_count += 1;
    } else if file_type.is_socket()
        || file_type.is_fifo()
        || file_type.is_char_device()
        || file_type.is_block_device()
    {
        parent_node.file_count += 1;
    }

    let breakdown_path = if target.sum_remaining {
        reported_ancestor
    } else {
        parent
    };
    let breakdown_depth = relative_depth(target, breakdown_path);
    let breakdown_node = state.node_mut(target, breakdown_path, breakdown_depth);
    breakdown_node.breakdown_blocks = breakdown_node.breakdown_blocks.saturating_add(blocks);
    breakdown_node.breakdown_apparent = breakdown_node.breakdown_apparent.saturating_add(apparent);
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
            if node.directory_count == 0 {
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

fn should_report(target: &Target, depth: usize) -> bool {
    match target.report_mode {
        ReportMode::Tree => depth <= target.report_depth,
        ReportMode::Leaves => depth == 0 || depth == target.report_depth,
    }
}

fn ancestors_from_root(target: &Target, path: &Path) -> Vec<PathBuf> {
    let mut ancestors = Vec::new();
    let mut current = Some(path);
    while let Some(path) = current {
        if path.starts_with(&target.scan_path) {
            ancestors.push(path.to_path_buf());
        }
        if path == target.scan_path {
            break;
        }
        current = path.parent();
    }
    ancestors
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
    use crate::config::{Rollup, SizeMode};

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
            .find(|node| node.depth == 0)
            .unwrap();
        assert!(root.inclusive_blocks > 0);
        assert!(root.inclusive_apparent > 0);
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
    fn reports_depth_nodes_and_breakdown_rollup() {
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
        assert_eq!(child.depth, 1);
        assert!(child.breakdown_blocks > 0);
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
            sum_remaining: true,
            rollups: vec![Rollup::Breakdown],
            size_modes: vec![SizeMode::Blocks],
            exclude,
            labels: BTreeMap::new(),
        }
    }
}
