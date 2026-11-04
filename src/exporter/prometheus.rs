use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use std::sync::atomic::Ordering;

use crate::cache::TargetSnapshot;
use crate::config::SizeMode;
use crate::fsinfo;
use crate::live::LiveStore;
use crate::scanner::NodeObservation;

/// A thin pool: its usage as the target's filesystem, its metadata, and each disk's I/O.
fn write_pool(out: &mut String, lt: &crate::live::LiveTarget, snapshot: &TargetSnapshot) {
    let base_labels = labels(snapshot, None);
    let guard = lt
        .state
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(tree) = guard.as_ref().map(|state| &state.tree) else {
        return;
    };
    let Some(pool) = &tree.pool else {
        return;
    };
    for (name, value) in [
        ("filesystem_size", pool.size),
        ("filesystem_used", pool.used),
        ("filesystem_avail", pool.size.saturating_sub(pool.used)),
        ("thin_metadata_size", pool.meta_size),
        ("thin_metadata_used", pool.meta_used),
        ("thin_provisioned", pool.provisioned),
    ] {
        writeln!(
            out,
            "storage_harvester_{name}_bytes{{{base_labels}}} {value}"
        )
        .unwrap();
    }
    for (path, disk) in pool.disks_with_paths(tree) {
        let labels = labels_at(snapshot, &path, None);
        for (name, value) in [("read", disk.read), ("written", disk.written)] {
            writeln!(
                out,
                "storage_harvester_block_{name}_bytes_total{{{labels}}} {value}"
            )
            .unwrap();
        }
    }
}

pub fn render(snapshots: &[TargetSnapshot], live: Option<&LiveStore>) -> String {
    let mut out = String::new();
    write_headers(&mut out);
    write_build_info(&mut out);

    let now = SystemTime::now();
    for snapshot in snapshots {
        let base_labels = labels(snapshot, None);
        let live_target = live.and_then(|live| live.target(&snapshot.target_name));
        let sharing = live_target.and_then(|lt| {
            lt.sharing
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        });
        if let Some(lt) = live_target {
            if lt.target.lvm.is_some() {
                write_pool(&mut out, lt, snapshot);
            } else if let Some(usage) = fsinfo::usage(&lt.target.scan_path) {
                for (name, value) in [
                    ("size", usage.size),
                    ("used", usage.used),
                    ("avail", usage.avail),
                ] {
                    writeln!(
                        out,
                        "storage_harvester_filesystem_{name}_bytes{{{base_labels}}} {value}"
                    )
                    .unwrap();
                }
            }
            writeln!(
                out,
                "storage_harvester_live_relists_total{{{base_labels}}} {}",
                lt.relists.load(Ordering::Relaxed)
            )
            .unwrap();
            writeln!(
                out,
                "storage_harvester_live_changes_total{{{base_labels}}} {}",
                lt.changes.load(Ordering::Relaxed)
            )
            .unwrap();
            writeln!(
                out,
                "storage_harvester_live_rescans_requested_total{{{base_labels}}} {}",
                lt.rescans_requested.load(Ordering::Relaxed)
            )
            .unwrap();
        }
        if let Some(report) = &sharing {
            writeln!(
                out,
                "storage_harvester_target_disk_bytes{{{base_labels}}} {}",
                report.disk
            )
            .unwrap();
            writeln!(
                out,
                "storage_harvester_sharing_duration_seconds{{{base_labels}}} {:.6}",
                report.duration.as_secs_f64()
            )
            .unwrap();
            writeln!(
                out,
                "storage_harvester_sharing_timestamp_seconds{{{base_labels}}} {}",
                unix_seconds(report.at)
            )
            .unwrap();
        }
        writeln!(out, "storage_harvester_target_info{{{base_labels}}} 1").unwrap();
        writeln!(
            out,
            "storage_harvester_target_interval_seconds{{{base_labels}}} {:.6}",
            snapshot.interval.as_secs_f64()
        )
        .unwrap();
        writeln!(
            out,
            "storage_harvester_scan_count_total{{{base_labels}}} {}",
            snapshot.scan_count
        )
        .unwrap();
        writeln!(
            out,
            "storage_harvester_scan_errors_total{{{base_labels}}} {}",
            snapshot.failure_count
        )
        .unwrap();
        writeln!(
            out,
            "storage_harvester_scan_running{{{base_labels}}} {}",
            u8::from(snapshot.scan_running)
        )
        .unwrap();
        writeln!(
            out,
            "storage_harvester_scan_running_seconds{{{base_labels}}} {:.6}",
            snapshot
                .scan_started
                .and_then(|started| now.duration_since(started).ok())
                .unwrap_or_default()
                .as_secs_f64()
        )
        .unwrap();

        if let Some(result) = &snapshot.last_success {
            // Directories only. Direct files appear on the status page, not as series: a
            // path-labelled series per file reached 27k series on one NAS share.
            for node in &result.observations {
                write_node_sizes(&mut out, snapshot, node, &result.backend);
                write_node_entries(&mut out, snapshot, node);
                if let Some(bytes) = sharing
                    .as_ref()
                    .and_then(|report| report.by_ino.get(&node.ino))
                {
                    let labels = node_labels(snapshot, node, &[]);
                    writeln!(
                        out,
                        "storage_harvester_exclusive_size_bytes{{{labels}}} {bytes}"
                    )
                    .unwrap();
                }
            }
            // The sizes below are the last good scan's; success describes the latest attempt.
            writeln!(
                out,
                "storage_harvester_scan_success{{{base_labels}}} {}",
                u8::from(snapshot.last_error.is_none())
            )
            .unwrap();
            writeln!(
                out,
                "storage_harvester_scan_duration_seconds{{{base_labels},backend=\"{}\"}} {:.6}",
                escape_label_value(&result.backend),
                result.duration.as_secs_f64()
            )
            .unwrap();
            writeln!(
                out,
                "storage_harvester_scan_timestamp_seconds{{{base_labels}}} {}",
                unix_seconds(result.timestamp)
            )
            .unwrap();
            writeln!(
                out,
                "storage_harvester_target_stale_seconds{{{base_labels}}} {:.6}",
                now.duration_since(result.timestamp)
                    .unwrap_or_default()
                    .as_secs_f64()
            )
            .unwrap();
            write_issue(
                &mut out,
                snapshot,
                "permission_errors",
                result.permission_errors,
            );
            write_issue(
                &mut out,
                snapshot,
                "missing_path_races",
                result.missing_path_races,
            );
            write_issue(
                &mut out,
                snapshot,
                "skipped_cross_device",
                result.skipped_cross_device,
            );
            write_issue(
                &mut out,
                snapshot,
                "skipped_excluded",
                result.skipped_excluded,
            );
            writeln!(
                out,
                "storage_harvester_reported_nodes{{{base_labels}}} {}",
                result.observations.len()
            )
            .unwrap();
            writeln!(
                out,
                "storage_harvester_scanned_directories{{{base_labels}}} {}",
                result.scanned_directories
            )
            .unwrap();
            writeln!(
                out,
                "storage_harvester_scanned_files{{{base_labels}}} {}",
                result.scanned_files
            )
            .unwrap();
            writeln!(
                out,
                "storage_harvester_scanned_symlinks{{{base_labels}}} {}",
                result.scanned_symlinks
            )
            .unwrap();
            writeln!(
                out,
                "storage_harvester_max_observed_depth{{{base_labels}}} {}",
                result.max_observed_depth
            )
            .unwrap();
            writeln!(
                out,
                "storage_harvester_depth_limit_hits{{{base_labels}}} {}",
                result.depth_limit_hits
            )
            .unwrap();
        } else {
            writeln!(out, "storage_harvester_scan_success{{{base_labels}}} 0").unwrap();
            writeln!(
                out,
                "storage_harvester_target_stale_seconds{{{base_labels}}} +Inf"
            )
            .unwrap();
        }
    }

    if let Some(live) = live {
        writeln!(
            out,
            "storage_harvester_live_signals_total {}",
            live.signals.load(Ordering::Relaxed)
        )
        .unwrap();
        writeln!(
            out,
            "storage_harvester_live_overflows_total {}",
            live.overflows.load(Ordering::Relaxed)
        )
        .unwrap();
    }

    out
}

fn write_headers(out: &mut String) {
    let headers = [
        (
            "storage_harvester_build_info",
            "gauge",
            "Storage Harvester build metadata.",
        ),
        (
            "storage_harvester_own_size_bytes",
            "gauge",
            "Storage bytes directly owned by this reported node.",
        ),
        (
            "storage_harvester_children_size_bytes",
            "gauge",
            "Storage bytes under this reported node's child directories, including unreported descendants when configured.",
        ),
        (
            "storage_harvester_exclusive_size_bytes",
            "gauge",
            "Bytes deleting this reported node would free: extents no directory outside it references (btrfs sharing pass; snapshots not counted).",
        ),
        (
            "storage_harvester_target_disk_bytes",
            "gauge",
            "Unique bytes on disk the target's files reference (btrfs sharing pass).",
        ),
        (
            "storage_harvester_sharing_duration_seconds",
            "gauge",
            "Duration of the last btrfs sharing pass.",
        ),
        (
            "storage_harvester_sharing_timestamp_seconds",
            "gauge",
            "When the last btrfs sharing pass finished.",
        ),
        (
            "storage_harvester_filesystem_size_bytes",
            "gauge",
            "Size of the filesystem the target is on.",
        ),
        (
            "storage_harvester_filesystem_used_bytes",
            "gauge",
            "Used bytes of the filesystem the target is on.",
        ),
        (
            "storage_harvester_filesystem_avail_bytes",
            "gauge",
            "Bytes available to unprivileged users on the filesystem the target is on.",
        ),
        (
            "storage_harvester_thin_metadata_size_bytes",
            "gauge",
            "Metadata size of the thin pool (lvm_thin targets).",
        ),
        (
            "storage_harvester_thin_metadata_used_bytes",
            "gauge",
            "Used metadata of the thin pool; a full metadata area stops the pool.",
        ),
        (
            "storage_harvester_thin_provisioned_bytes",
            "gauge",
            "Sum of the virtual sizes of the thin pool's volumes.",
        ),
        (
            "storage_harvester_block_read_bytes_total",
            "counter",
            "Bytes read from a thin volume since the host booted (lvm_thin targets).",
        ),
        (
            "storage_harvester_block_written_bytes_total",
            "counter",
            "Bytes written to a thin volume since the host booted (lvm_thin targets).",
        ),
        (
            "storage_harvester_live_relists_total",
            "counter",
            "Directories re-read between scans after a change signal.",
        ),
        (
            "storage_harvester_live_changes_total",
            "counter",
            "Re-reads between scans that found a change.",
        ),
        (
            "storage_harvester_live_rescans_requested_total",
            "counter",
            "Early scans asked for by changes the live tree could not settle itself.",
        ),
        (
            "storage_harvester_live_signals_total",
            "counter",
            "Change signals received from fanotify or btrfs polling.",
        ),
        (
            "storage_harvester_live_overflows_total",
            "counter",
            "fanotify queue overflows (changes lost until the next scan).",
        ),
        (
            "storage_harvester_own_entries",
            "gauge",
            "Filesystem entries directly owned by this reported node.",
        ),
        (
            "storage_harvester_children_entries",
            "gauge",
            "Filesystem entries under this reported node's child directories.",
        ),
        (
            "storage_harvester_scan_success",
            "gauge",
            "Last scan success by target, 1 for success and 0 for failure.",
        ),
        (
            "storage_harvester_scan_duration_seconds",
            "gauge",
            "Last successful scan duration in seconds.",
        ),
        (
            "storage_harvester_scan_timestamp_seconds",
            "gauge",
            "Last successful scan timestamp.",
        ),
        (
            "storage_harvester_scan_errors_total",
            "counter",
            "Total failed scans by target.",
        ),
        (
            "storage_harvester_scan_count_total",
            "counter",
            "Total scan attempts by target.",
        ),
        (
            "storage_harvester_scan_issue_count",
            "gauge",
            "Last successful scan issue counts by target and issue type.",
        ),
        (
            "storage_harvester_scan_running",
            "gauge",
            "Whether a target scan is currently running, 1 for running and 0 otherwise.",
        ),
        (
            "storage_harvester_scan_running_seconds",
            "gauge",
            "Seconds since the current target scan started, or 0 when no scan is running.",
        ),
        (
            "storage_harvester_target_stale_seconds",
            "gauge",
            "Seconds since the last successful target scan.",
        ),
        (
            "storage_harvester_target_info",
            "gauge",
            "Configured storage harvester target metadata.",
        ),
        (
            "storage_harvester_target_interval_seconds",
            "gauge",
            "Configured baseline scan interval by target.",
        ),
        (
            "storage_harvester_reported_nodes",
            "gauge",
            "Number of storage nodes emitted for the last successful scan.",
        ),
        (
            "storage_harvester_scanned_directories",
            "gauge",
            "Number of directories visited during the last successful scan.",
        ),
        (
            "storage_harvester_scanned_files",
            "gauge",
            "Number of files visited during the last successful scan.",
        ),
        (
            "storage_harvester_scanned_symlinks",
            "gauge",
            "Number of symlinks visited during the last successful scan.",
        ),
        (
            "storage_harvester_max_observed_depth",
            "gauge",
            "Maximum relative depth observed during the last successful scan.",
        ),
        (
            "storage_harvester_depth_limit_hits",
            "gauge",
            "Number of directories not descended because max_depth was reached.",
        ),
    ];

    for (name, metric_type, help) in headers {
        writeln!(out, "# HELP {name} {help}").unwrap();
        writeln!(out, "# TYPE {name} {metric_type}").unwrap();
    }
}

fn write_build_info(out: &mut String) {
    writeln!(
        out,
        "storage_harvester_build_info{{version=\"{}\"}} 1",
        escape_label_value(env!("CARGO_PKG_VERSION"))
    )
    .unwrap();
}

fn write_node_sizes(
    out: &mut String,
    snapshot: &TargetSnapshot,
    node: &NodeObservation,
    backend: &str,
) {
    for size_mode in &snapshot.size_modes {
        let labels = node_labels(
            snapshot,
            node,
            &[("size_mode", size_mode.as_str()), ("backend", backend)],
        );
        writeln!(
            out,
            "storage_harvester_own_size_bytes{{{labels}}} {}",
            node_value(node, SizeComponent::Own, *size_mode)
        )
        .unwrap();
        writeln!(
            out,
            "storage_harvester_children_size_bytes{{{labels}}} {}",
            node_value(node, SizeComponent::Children, *size_mode)
        )
        .unwrap();
    }
}

fn write_node_entries(out: &mut String, snapshot: &TargetSnapshot, node: &NodeObservation) {
    for (entry_type, value) in [
        ("file", node.file_count),
        ("directory", node.directory_count),
        ("symlink", node.symlink_count),
    ] {
        let labels = node_labels(snapshot, node, &[("entry_type", entry_type)]);
        writeln!(out, "storage_harvester_own_entries{{{labels}}} {value}").unwrap();
    }
    for (entry_type, value) in [
        ("file", node.children_file_count),
        ("directory", node.children_directory_count),
        ("symlink", node.children_symlink_count),
    ] {
        let labels = node_labels(snapshot, node, &[("entry_type", entry_type)]);
        writeln!(
            out,
            "storage_harvester_children_entries{{{labels}}} {value}"
        )
        .unwrap();
    }
}

#[derive(Debug, Clone, Copy)]
enum SizeComponent {
    Own,
    Children,
}

fn node_value(node: &NodeObservation, component: SizeComponent, size_mode: SizeMode) -> u64 {
    match (component, size_mode) {
        (SizeComponent::Own, SizeMode::Blocks) => node.own_blocks,
        (SizeComponent::Children, SizeMode::Blocks) => node.children_blocks,
        (SizeComponent::Own, SizeMode::Apparent) => node.own_apparent,
        (SizeComponent::Children, SizeMode::Apparent) => node.children_apparent,
    }
}

fn write_issue(out: &mut String, snapshot: &TargetSnapshot, issue: &str, value: u64) {
    let labels = labels(snapshot, Some(("issue", issue)));
    writeln!(
        out,
        "storage_harvester_scan_issue_count{{{labels}}} {value}"
    )
    .unwrap();
}

fn labels(snapshot: &TargetSnapshot, extra: Option<(&str, &str)>) -> String {
    labels_at(snapshot, &snapshot.path, extra)
}

/// The target's labels with `path` set to `path` (a thin pool's disk, say).
fn labels_at(snapshot: &TargetSnapshot, path: &str, extra: Option<(&str, &str)>) -> String {
    let mut labels = vec![
        ("target".to_string(), snapshot.target_name.clone()),
        ("target_type".to_string(), snapshot.target_type.clone()),
        ("path".to_string(), path.to_string()),
    ];
    labels.extend(
        snapshot
            .labels
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    if let Some((key, value)) = extra {
        labels.push((key.to_string(), value.to_string()));
    }
    labels
        .into_iter()
        .map(|(key, value)| {
            format!(
                "{}=\"{}\"",
                sanitize_label_name(&key),
                escape_label_value(&value)
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn node_labels(
    snapshot: &TargetSnapshot,
    node: &NodeObservation,
    extra: &[(&str, &str)],
) -> String {
    let depth = node.depth.to_string();
    let mut labels = vec![
        ("target", snapshot.target_name.as_str()),
        ("target_type", snapshot.target_type.as_str()),
        ("path", node.path.as_str()),
        ("parent", node.parent.as_str()),
        ("node", node.node.as_str()),
        ("depth", depth.as_str()),
    ];
    labels.extend(
        snapshot
            .labels
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    );
    labels.extend(extra.iter().copied());

    labels_from_pairs(labels)
}

fn labels_from_pairs<'a>(labels: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    labels
        .into_iter()
        .map(|(key, value)| {
            format!(
                "{}=\"{}\"",
                sanitize_label_name(key),
                escape_label_value(value)
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn sanitize_label_name(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

fn unix_seconds(timestamp: SystemTime) -> u64 {
    timestamp
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl SizeMode {
    fn as_str(self) -> &'static str {
        match self {
            SizeMode::Blocks => "blocks",
            SizeMode::Apparent => "apparent",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_label_values() {
        assert_eq!(escape_label_value("a\\b\"c"), "a\\\\b\\\"c");
    }
}
