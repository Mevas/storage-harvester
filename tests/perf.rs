//! How fast is a scan, what does it cost, and is it still correct at size?
//!
//! Generates a metadata-heavy tree, runs the real binary against it, and reports:
//! - scan duration and entries/s, for the first scan (cold when caches were dropped) and a warm
//!   rescan, from the harvester's own `scan_duration_seconds`;
//! - the same walk done by the independent oracle, as a same-machine baseline;
//! - resident memory of the harvester process;
//! - the size and render time of `/metrics`, and series per target (cardinality).
//!
//! The report goes to stdout and to `$CARGO_TARGET_TMPDIR/perf-report.json`.
//!
//! Knobs (environment):
//! - `HARVESTER_PERF_FILES` (default 20000): files in the generated tree.
//! - `HARVESTER_PERF_DROP_CACHES=1`: drop Linux caches before the first scan (needs sudo -n).
//! - `HARVESTER_PERF_MAX_RATIO` (default 4.0): fail if a warm harvester scan takes longer than
//!   this multiple of the oracle's warm walk.
//!
//! Run optimised for meaningful numbers: `cargo test --release --test perf -- --nocapture`.

mod support;

use std::fs;
use std::time::{Duration, Instant};

use support::*;

#[test]
fn scan_performance_report() {
    let files: u64 = env_or("HARVESTER_PERF_FILES", 20_000);
    let max_ratio: f64 = env_or("HARVESTER_PERF_MAX_RATIO", 4.0);

    let tmp = tempfile::tempdir().unwrap();
    let host_root = tmp.path().join("host");
    let data = host_root.join("srv/perf");
    let started = Instant::now();
    perf_tree(&data, files, 99);
    let generate_seconds = started.elapsed().as_secs_f64();

    let cold = drop_caches_if_requested();
    let h = Harvester::start(
        &tmp.path().join("run"),
        &format!(
            "\
host_root: {}
defaults:
  baseline_interval: 1s
  timeout: 1800s
  report_depth: 2
targets:
  - name: perf
    path: /srv/perf
",
            yaml_quote(&host_root)
        ),
    );

    let timeout = Duration::from_secs(1800);
    let first = h.wait_for_scans("perf", 1, timeout);
    assert_eq!(
        first.target_value("storage_harvester_scan_success", "perf"),
        Some(1.0),
        "first scan failed:\n{}",
        h.log_tail(20)
    );
    let first_seconds = first
        .target_value("storage_harvester_scan_duration_seconds", "perf")
        .unwrap();
    let warm = h.wait_for_scans("perf", 3, timeout);
    // Scan counts include failures, and a failed rescan leaves the last success's numbers in
    // place, so without this the "warm" figures could be the first scan's.
    assert_eq!(
        warm.target_value("storage_harvester_scan_errors_total", "perf"),
        Some(0.0),
        "a rescan failed:\n{}",
        h.log_tail(20)
    );
    let warm_seconds = warm
        .target_value("storage_harvester_scan_duration_seconds", "perf")
        .unwrap();

    let (rss_kib, rss_kind) = rss_kib(h.pid()).unwrap_or((0, "unavailable"));
    let fetch = Instant::now();
    let (status, body) = h.get("/metrics");
    let metrics_seconds = fetch.elapsed().as_secs_f64();
    assert_eq!(status, 200);
    let exported = Metrics::parse(&body);
    let series = exported
        .samples
        .iter()
        .filter(|s| s.labels.get("target").map(String::as_str) == Some("perf"))
        .count();
    drop(h); // stop rescanning before timing the oracle on the same disk

    let oracle_started = Instant::now();
    let walk = oracle_walk(&data, &WalkRules::default());
    let oracle_seconds = oracle_started.elapsed().as_secs_f64();

    // Speed only means something if the walk was complete and right.
    let mut out = Mismatches::default();
    out.check(
        "scanned_files",
        warm.target_value("storage_harvester_scanned_files", "perf")
            .map(|x| x as u64),
        Some(walk.regular_files),
    );
    out.check(
        "total blocks",
        warm.total_size("perf", "/srv/perf", "blocks"),
        Some(walk.root().total_blocks),
    );
    out.assert_none("perf tree correctness");

    let entries = walk.regular_files + walk.directories + walk.symlinks;
    let ratio = warm_seconds / oracle_seconds.max(1e-6);
    let report = format!(
        r#"{{
  "profile": "{profile}",
  "os": "{os}",
  "files": {files},
  "entries": {entries},
  "directories": {dirs},
  "allocated_bytes": {bytes},
  "generate_seconds": {generate_seconds:.3},
  "first_scan": {{ "cold": {cold}, "seconds": {first_seconds:.3}, "entries_per_second": {first_rate:.0}, "us_per_entry": {first_us:.2} }},
  "warm_scan": {{ "seconds": {warm_seconds:.3}, "entries_per_second": {warm_rate:.0}, "us_per_entry": {warm_us:.2} }},
  "oracle_warm_walk": {{ "seconds": {oracle_seconds:.3}, "us_per_entry": {oracle_us:.2} }},
  "warm_scan_vs_oracle": {ratio:.2},
  "rss_kib": {{ "value": {rss_kib}, "kind": "{rss_kind}" }},
  "metrics": {{ "bytes": {metrics_bytes}, "render_seconds": {metrics_seconds:.3}, "series_for_target": {series} }}
}}
"#,
        profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        os = std::env::consts::OS,
        dirs = walk.directories,
        bytes = walk.root().total_blocks,
        first_rate = entries as f64 / first_seconds.max(1e-6),
        first_us = first_seconds * 1e6 / entries as f64,
        warm_rate = entries as f64 / warm_seconds.max(1e-6),
        warm_us = warm_seconds * 1e6 / entries as f64,
        oracle_us = oracle_seconds * 1e6 / entries as f64,
        metrics_bytes = exported.bytes,
    );
    println!("{report}");
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("perf-report.json");
    fs::write(&path, &report).unwrap();
    println!("report written to {}", path.display());

    assert!(
        ratio <= max_ratio,
        "warm scan took {warm_seconds:.3}s, {ratio:.2}x the oracle's {oracle_seconds:.3}s walk of \
         the same tree (budget {max_ratio}x)"
    );
}
