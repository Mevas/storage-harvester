use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cache::TargetSnapshot;
use crate::config::SizeMode;
use crate::scanner::NodeObservation;

pub fn render(snapshots: &[TargetSnapshot]) -> String {
    let mut out = String::new();
    write_headers(&mut out);
    write_build_info(&mut out);

    let now = SystemTime::now();
    for snapshot in snapshots {
        let base_labels = labels(snapshot, None);
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
            for node in &result.observations {
                write_node_sizes(&mut out, snapshot, node, &result.backend);
                write_node_entries(&mut out, snapshot, node);
            }
            writeln!(out, "storage_harvester_scan_success{{{base_labels}}} 1").unwrap();
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
                "storage_harvester_target_stale_seconds{{{base_labels}}} NaN"
            )
            .unwrap();
        }
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
    let mut labels = vec![
        ("target".to_string(), snapshot.target_name.clone()),
        ("target_type".to_string(), snapshot.target_type.clone()),
        ("path".to_string(), snapshot.path.clone()),
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
