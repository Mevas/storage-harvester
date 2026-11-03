//! Does the harvester report what is actually on disk?
//!
//! Each test builds a real tree, runs the real binary against it through a `host_root` mount the
//! way production does (`/host` + display paths), and compares every exported number with an
//! independent walk (`support::oracle_walk`) or with `du`.
//!
//! Tests marked `#[ignore = "known bug: ..."]` assert the *correct* behaviour for defects that
//! are documented in the v2 plan and not fixed yet. `cargo test -- --ignored` shows them failing;
//! each one should be un-ignored by the change that fixes it.

mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use support::*;
use tempfile::TempDir;

const SCAN_TIMEOUT: Duration = Duration::from_secs(120);

/// A host root containing the tree at `/srv/data`, as the container sees `/host/srv/data`.
struct Host {
    tmp: TempDir,
}

impl Host {
    fn new() -> Self {
        Self {
            tmp: tempfile::tempdir().unwrap(),
        }
    }
    fn root(&self) -> std::path::PathBuf {
        self.tmp.path().join("host")
    }
    fn data(&self) -> std::path::PathBuf {
        self.root().join("srv/data")
    }
    fn start(&self, body: &str) -> Harvester {
        Harvester::start(
            &self.tmp.path().join("run"),
            &format!("host_root: {}\n{body}", yaml_quote(&self.root())),
        )
    }
}

const DATA: &str = "/srv/data";

fn display(root: &str, rel: &Path) -> String {
    if rel.as_os_str().is_empty() {
        root.to_string()
    } else {
        format!("{root}/{}", rel.display())
    }
}

fn scanned(h: &Harvester, target: &str) -> Metrics {
    let m = h.wait_for_scans(target, 1, SCAN_TIMEOUT);
    assert_eq!(
        m.target_value("storage_harvester_scan_success", target),
        Some(1.0),
        "first scan of {target} failed:\n{}",
        h.log_tail(20)
    );
    m
}

/// Compares every reported directory with the oracle: sizes in both modes and entry counts.
fn check_dirs(
    m: &Metrics,
    target: &str,
    root: &str,
    walk: &Walk,
    report_depth: usize,
    out: &mut Mismatches,
) {
    let reported: Vec<_> = walk
        .dirs
        .iter()
        .filter(|(_, dir)| dir.depth <= report_depth)
        .collect();
    out.check(
        "reported_nodes",
        m.target_value("storage_harvester_reported_nodes", target),
        Some(reported.len() as f64),
    );

    for (rel, dir) in reported {
        let path = display(root, rel);
        for (mode, own, total) in [
            ("blocks", dir.own_blocks, dir.total_blocks),
            ("apparent", dir.own_apparent, dir.total_apparent),
        ] {
            out.check(
                format!("{path} own {mode}"),
                m.size("storage_harvester_own_size_bytes", target, &path, mode),
                Some(own),
            );
            out.check(
                format!("{path} total {mode}"),
                m.total_size(target, &path, mode),
                Some(total),
            );
        }
        for (kind, direct, deeper) in [
            ("file", dir.direct_files, dir.deeper_files),
            ("directory", dir.direct_dirs, dir.deeper_dirs),
            ("symlink", dir.direct_symlinks, dir.deeper_symlinks),
        ] {
            out.check(
                format!("{path} own {kind} entries"),
                m.entries("storage_harvester_own_entries", target, &path, kind),
                Some(direct),
            );
            out.check(
                format!("{path} deeper {kind} entries"),
                m.entries("storage_harvester_children_entries", target, &path, kind),
                Some(deeper),
            );
        }
    }
}

fn check_scan_counts(m: &Metrics, target: &str, walk: &Walk, out: &mut Mismatches) {
    let v = |name: &str| m.target_value(name, target).map(|x| x as u64);
    out.check(
        "scanned_files",
        v("storage_harvester_scanned_files"),
        Some(walk.regular_files),
    );
    out.check(
        "scanned_directories",
        v("storage_harvester_scanned_directories"),
        Some(walk.directories),
    );
    out.check(
        "scanned_symlinks",
        v("storage_harvester_scanned_symlinks"),
        Some(walk.symlinks),
    );
    out.check(
        "max_observed_depth",
        v("storage_harvester_max_observed_depth"),
        Some(walk.max_depth as u64),
    );
    out.check(
        "depth_limit_hits",
        v("storage_harvester_depth_limit_hits"),
        Some(walk.depth_limit_hits),
    );
    out.check(
        "skipped_excluded",
        m.issue(target, "skipped_excluded").map(|x| x as u64),
        Some(walk.excluded_children),
    );
    out.check(
        "permission_errors",
        m.issue(target, "permission_errors").map(|x| x as u64),
        Some(walk.unreadable_dirs),
    );
}

const REALISTIC_CONFIG: &str = "\
defaults:
  baseline_interval: 1h
  timeout: 120s
  report_depth: 2
  size_modes: [blocks, apparent]
  exclude: ['**/node_modules/**', '**/.git/**']
targets:
  - name: data
    path: /srv/data
";

fn realistic_rules() -> WalkRules {
    WalkRules {
        exclude_contents_of: vec!["node_modules".into(), ".git".into()],
        max_depth: None,
    }
}

#[test]
fn realistic_tree_matches_an_independent_walk() {
    let host = Host::new();
    realistic_tree(&host.data(), 42);
    let h = host.start(REALISTIC_CONFIG);
    let m = scanned(&h, "data");
    let walk = oracle_walk(&host.data(), &realistic_rules());

    let mut out = Mismatches::default();
    check_scan_counts(&m, "data", &walk, &mut out);
    check_dirs(&m, "data", DATA, &walk, 2, &mut out);
    out.assert_none("realistic tree vs oracle");

    // Sanity on the fixture itself, so a silently trivial tree cannot pass.
    assert!(walk.regular_files > 500, "fixture too small: {walk:?}");
    assert!(walk.max_depth >= 15);
    assert!(walk.excluded_children > 0);
}

/// Paths of the file rows on the status page, unescaped.
fn status_page_entries(h: &Harvester) -> std::collections::BTreeSet<String> {
    let (status, page) = h.get("/status/fragment");
    assert_eq!(status, 200);
    page.split("<tr class=\"entry-row\"")
        .skip(1)
        .map(|row| {
            let code = row.split_once("<code>").unwrap().1;
            let path = code.split_once("</code>").unwrap().0;
            path.replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&#39;", "'")
                .replace("&amp;", "&")
        })
        .collect()
}

#[test]
fn status_page_lists_every_direct_entry_under_a_host_root() {
    // The tree view shows each reported directory's direct files. Under a host_root (production
    // uses /host) it showed none, because entries were filtered by display path against scan
    // paths.
    let host = Host::new();
    realistic_tree(&host.data(), 42);
    let h = host.start(REALISTIC_CONFIG);
    scanned(&h, "data");
    let walk = oracle_walk(&host.data(), &realistic_rules());
    let expected: std::collections::BTreeSet<String> = walk
        .entries
        .iter()
        .filter(|(_, entry)| entry.depth <= 3)
        .map(|(rel, _)| display(DATA, rel))
        .collect();
    assert!(expected.len() > 40, "fixture has too few direct entries");

    let listed = status_page_entries(&h);
    let missing: Vec<_> = expected.difference(&listed).collect();
    let extra: Vec<_> = listed.difference(&expected).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "status page: {} missing (e.g. {:?}), {} unexpected (e.g. {:?})",
        missing.len(),
        missing.first(),
        extra.len(),
        extra.first()
    );
}

#[test]
fn metrics_carry_directories_only() {
    // A path-labelled series per file reached 27k series on one NAS share. Size series exist
    // for reported directories, one per size mode, and for nothing else.
    let host = Host::new();
    realistic_tree(&host.data(), 42);
    let h = host.start(REALISTIC_CONFIG);
    let m = scanned(&h, "data");
    let walk = oracle_walk(&host.data(), &realistic_rules());
    let directories: std::collections::BTreeSet<String> = walk
        .dirs
        .iter()
        .filter(|(_, dir)| dir.depth <= 2)
        .map(|(rel, _)| display(DATA, rel))
        .collect();

    let sized = m.find("storage_harvester_own_size_bytes", &[("target", "data")]);
    assert_eq!(
        sized.len(),
        directories.len() * 2,
        "blocks + apparent per directory"
    );
    let not_directories: Vec<_> = sized
        .iter()
        .filter(|s| !directories.contains(&s.labels["path"]))
        .map(|s| s.labels["path"].clone())
        .collect();
    assert!(
        not_directories.is_empty(),
        "{} size series for non-directories, e.g. {:?}",
        not_directories.len(),
        not_directories.first()
    );
}

#[test]
fn total_agrees_with_du() {
    // `du` is the tool people will check this against. No excludes, no hardlinks, so the
    // two are specified to agree exactly, up to du's rounding to whole KiB.
    let host = Host::new();
    realistic_tree(&host.data(), 7);
    let h = host.start(
        "\
defaults:
  baseline_interval: 1h
  report_depth: 0
targets:
  - name: data
    path: /srv/data
",
    );
    let m = scanned(&h, "data");
    let harvester = m.total_size("data", DATA, "blocks").unwrap();

    let output = Command::new("du")
        .arg("-sk")
        .arg(host.data())
        .output()
        .unwrap();
    assert!(output.status.success(), "du failed: {output:?}");
    let du_kib: u64 = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let du_bytes = du_kib * 1024;
    assert!(
        harvester.abs_diff(du_bytes) < 1024,
        "harvester {harvester} B vs du -sk {du_bytes} B"
    );
}

#[test]
fn rescans_follow_real_growth_and_deletion() {
    let host = Host::new();
    realistic_tree(&host.data(), 3);
    let h = host.start(
        "\
defaults:
  baseline_interval: 1s
  report_depth: 2
  size_modes: [blocks, apparent]
targets:
  - name: data
    path: /srv/data
",
    );
    let before = scanned(&h, "data");
    let before_total = before.total_size("data", DATA, "apparent").unwrap();
    let before_logs = before
        .total_size("data", "/srv/data/logs", "apparent")
        .unwrap();
    let media = oracle_walk(&host.data().join("media"), &WalkRules::default())
        .root()
        .total_apparent;

    // A balloon: the runaway log grows, a new directory fills up, and an old one is removed.
    let runaway = host.data().join("logs/runaway.log");
    append(&runaway, 3 * 1024 * 1024);
    for i in 0..50 {
        write_file(&host.data().join(format!("spool/batch-{i}.bin")), 20_000);
    }
    fs::remove_dir_all(host.data().join("media")).unwrap();

    // A scan that was already running may have seen part of the change; the one after it
    // started once the change was complete.
    let count = h
        .metrics()
        .target_value("storage_harvester_scan_count_total", "data")
        .unwrap() as u64;
    let after = h.wait_for_scans("data", count + 2, SCAN_TIMEOUT);
    let walk = oracle_walk(&host.data(), &WalkRules::default());

    let mut out = Mismatches::default();
    check_scan_counts(&after, "data", &walk, &mut out);
    check_dirs(&after, "data", DATA, &walk, 2, &mut out);
    // The growth is attributed to the directory holding the runaway log, byte for byte.
    out.check(
        "logs/ apparent growth",
        after
            .total_size("data", "/srv/data/logs", "apparent")
            .map(|now| now - before_logs),
        Some(3 * 1024 * 1024),
    );
    out.check(
        "media/ is gone",
        after.size(
            "storage_harvester_own_size_bytes",
            "data",
            "/srv/data/media",
            "blocks",
        ),
        None,
    );
    // The change in the reported level is exactly what was done to the tree. The new `spool/`
    // directory's own inode is the only term the test cannot know in advance.
    let spool_inode = walk.dirs[Path::new("spool")].own_apparent;
    let after_total = after.total_size("data", DATA, "apparent").unwrap();
    out.check(
        "net apparent change",
        after_total as i64 - before_total as i64,
        (3 * 1024 * 1024 + 50 * 20_000 + spool_inode) as i64 - media as i64,
    );
    out.assert_none("after growth and deletion");
}

#[test]
fn explicit_max_depth_is_honoured_and_counted() {
    let host = Host::new();
    realistic_tree(&host.data(), 11);
    let h = host.start(
        "\
defaults:
  baseline_interval: 1h
  report_depth: 1
  max_depth: 3
  size_modes: [blocks, apparent]
targets:
  - name: data
    path: /srv/data
",
    );
    let m = scanned(&h, "data");
    let walk = oracle_walk(
        &host.data(),
        &WalkRules {
            max_depth: Some(3),
            ..WalkRules::default()
        },
    );
    assert!(walk.depth_limit_hits > 0, "fixture never reaches depth 3");

    let mut out = Mismatches::default();
    check_scan_counts(&m, "data", &walk, &mut out);
    check_dirs(&m, "data", DATA, &walk, 1, &mut out);
    out.assert_none("max_depth: 3");
}

/// Restores permissions on drop so the temp dir can be cleaned up even if the test fails.
struct Unreadable<'a>(&'a Path);

impl Drop for Unreadable<'_> {
    fn drop(&mut self) {
        let _ = fs::set_permissions(self.0, fs::Permissions::from_mode(0o755));
    }
}

#[test]
fn unreadable_directory_is_reported_not_silently_dropped() {
    let host = Host::new();
    realistic_tree(&host.data(), 5);
    let secret = host.data().join("projects/proj-1/src");
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o000)).unwrap();
    let _restore = Unreadable(&secret);
    if fs::read_dir(&secret).is_ok() {
        eprintln!("skipped: running with privileges that read mode-000 directories");
        return;
    }

    let h = host.start(REALISTIC_CONFIG);
    let m = scanned(&h, "data");
    let walk = oracle_walk(&host.data(), &realistic_rules());
    assert_eq!(walk.unreadable_dirs, 1);

    let mut out = Mismatches::default();
    check_scan_counts(&m, "data", &walk, &mut out);
    check_dirs(&m, "data", DATA, &walk, 2, &mut out);
    out.assert_none("with one unreadable directory");
}

#[test]
fn exported_metrics_are_valid_prometheus_text() {
    let host = Host::new();
    realistic_tree(&host.data(), 42);
    let h = host.start(REALISTIC_CONFIG);
    let m = scanned(&h, "data");

    let mut out = Mismatches::default();
    for error in &m.parse_errors {
        out.push(format!("unparseable line: {error}"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for sample in &m.samples {
        if !m.typed_names.contains(&sample.name) {
            out.push(format!("{} has no # TYPE", sample.name));
        }
        if !sample.duplicate_label_names.is_empty() {
            out.push(format!(
                "{} repeats label(s) {:?}",
                sample.name, sample.duplicate_label_names
            ));
        }
        if !seen.insert((sample.name.clone(), sample.labels.clone())) {
            out.push(format!(
                "duplicate series {} {:?}",
                sample.name, sample.labels
            ));
        }
    }
    out.assert_none("exposition format");
    assert!(m.samples.len() > 100);
}

// ---------------------------------------------------------------------------------------------
// Regressions: each of these was a live defect (v2 plan §2, §6, §8).
// ---------------------------------------------------------------------------------------------

#[test]
fn timed_out_scan_stops_walking() {
    // A walk that never ends: two links back to the directory itself, followed, under a depth
    // cap high enough that the walk cannot finish (2^64 paths). A timeout must stop it, not
    // leave it running in the background while the scheduler moves on.
    let host = Host::new();
    write_file(&host.data().join("file.bin"), 10);
    link(".", &host.data().join("a"));
    link(".", &host.data().join("b"));
    let h = host.start(
        "\
defaults:
  baseline_interval: 1h
  timeout: 1s
  follow_symlinks: true
  max_depth: 64
targets:
  - name: data
    path: /srv/data
",
    );
    let m = h.wait_for_scans("data", 1, SCAN_TIMEOUT);
    assert_eq!(
        m.target_value("storage_harvester_scan_success", "data"),
        Some(0.0)
    );
    assert_eq!(
        m.target_value("storage_harvester_scan_errors_total", "data"),
        Some(1.0)
    );

    let before = cpu_seconds(h.pid());
    std::thread::sleep(Duration::from_secs(2));
    let used = cpu_seconds(h.pid()) - before;
    assert!(
        used < 0.5,
        "the timed-out walk kept running: {used:.2}s of CPU in the 2s after its timeout"
    );
}

#[test]
fn scan_success_reports_the_latest_scan() {
    // After a success, a failing rescan must read as a failure. Otherwise a target that
    // starts timing out looks healthy forever, with frozen numbers.
    let host = Host::new();
    realistic_tree(&host.data(), 17);
    let h = host.start(
        "\
defaults:
  baseline_interval: 1s
targets:
  - name: data
    path: /srv/data
",
    );
    scanned(&h, "data");
    fs::rename(host.data(), host.root().join("srv/moved")).unwrap();
    let m = h.wait_for("a failed rescan", SCAN_TIMEOUT, |m| {
        m.target_value("storage_harvester_scan_errors_total", "data")
            .is_some_and(|n| n >= 1.0)
    });
    assert_eq!(
        m.target_value("storage_harvester_scan_success", "data"),
        Some(0.0)
    );
    // The last good numbers stay visible, and so does their age.
    assert!(m.total_size("data", DATA, "blocks").is_some());
    assert!(m
        .target_value("storage_harvester_target_stale_seconds", "data")
        .is_some_and(f64::is_finite));
}

#[test]
fn max_depth_null_means_unlimited() {
    // The deployed nuc.yaml shape: a capped default, and a target that asks for no cap.
    let host = Host::new();
    realistic_tree(&host.data(), 13);
    let h = host.start(
        "\
defaults:
  baseline_interval: 1h
  report_depth: 1
  max_depth: 1
targets:
  - name: data
    path: /srv/data
    report_depth: 2
    max_depth: null
",
    );
    let m = scanned(&h, "data");
    let walk = oracle_walk(&host.data(), &WalkRules::default());

    let mut out = Mismatches::default();
    check_scan_counts(&m, "data", &walk, &mut out);
    out.assert_none("max_depth: null on a target with a capped default");
}

#[test]
fn check_config_rejects_effective_max_depth_below_report_depth() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("config.yaml");
    fs::write(
        &config,
        "\
defaults:
  max_depth: 1
targets:
  - name: docker
    path: /home/example/docker
    report_depth: 2
",
    )
    .unwrap();
    let output = Command::new(BIN)
        .arg("--check-config")
        .arg("--config")
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "accepted a target whose effective max_depth (1) is below its report_depth (2): {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn hardlinks_are_counted_once() {
    let host = Host::new();
    let data = host.data();
    write_file(&data.join("original.bin"), 1024 * 1024);
    for i in 0..3 {
        fs::hard_link(data.join("original.bin"), data.join(format!("link{i}.bin"))).unwrap();
    }
    let h = host.start(
        "\
defaults:
  baseline_interval: 1h
  report_depth: 0
targets:
  - name: data
    path: /srv/data
",
    );
    let m = scanned(&h, "data");
    let one_copy = fs::symlink_metadata(data.join("original.bin")).unwrap();
    let dir = fs::symlink_metadata(&data).unwrap();
    use std::os::unix::fs::MetadataExt;
    let expected = (one_copy.blocks() + dir.blocks()) * 512;
    assert_eq!(
        m.total_size("data", DATA, "blocks"),
        Some(expected),
        "four links to one 1 MiB file should count as one allocation"
    );
}

const MISSING_TARGET_CONFIG: &str = "\
defaults:
  baseline_interval: 1h
targets:
  - name: data
    path: /srv/does-not-exist
";

#[test]
fn target_that_only_failed_is_not_ready() {
    let host = Host::new();
    fs::create_dir_all(host.root()).unwrap();
    let h = host.start(MISSING_TARGET_CONFIG);
    let m = h.wait_for_scans("data", 1, SCAN_TIMEOUT);
    assert_eq!(
        m.target_value("storage_harvester_scan_success", "data"),
        Some(0.0)
    );
    let (status, body) = h.get("/-/ready");
    assert_eq!(status, 503, "ready with no successful scan: {body}");
    // The status page states readiness too, and must agree with the endpoint.
    let (_, page) = h.get("/status/fragment");
    assert!(
        page.contains("<span>Ready</span><strong>no</strong>"),
        "status page disagrees with /-/ready"
    );
}

#[test]
fn never_succeeded_target_is_infinitely_stale() {
    let host = Host::new();
    fs::create_dir_all(host.root()).unwrap();
    let h = host.start(MISSING_TARGET_CONFIG);
    let m = h.wait_for_scans("data", 1, SCAN_TIMEOUT);
    let stale = m
        .target_value("storage_harvester_target_stale_seconds", "data")
        .unwrap();
    assert!(
        stale.is_infinite() && stale > 0.0,
        "stale is {stale}; NaN compares false against every alert threshold"
    );
}

#[test]
fn user_label_cannot_duplicate_a_builtin_label() {
    let host = Host::new();
    write_file(&host.data().join("file.txt"), 100);
    let body = "\
defaults:
  baseline_interval: 1h
targets:
  - name: data
    path: /srv/data
    labels:
      path: shadowed
";
    // Refusing the config is an acceptable fix.
    let config = host.tmp.path().join("check.yaml");
    fs::write(
        &config,
        format!("host_root: {}\n{body}", yaml_quote(&host.root())),
    )
    .unwrap();
    let check = Command::new(BIN)
        .arg("--check-config")
        .arg("--config")
        .arg(&config)
        .output()
        .unwrap();
    if !check.status.success() {
        return;
    }
    // So is renaming the label. Emitting it twice is not.
    let h = host.start(body);
    let started = h.wait_for_scans("data", 1, SCAN_TIMEOUT);
    let duplicated: Vec<_> = started
        .samples
        .iter()
        .filter(|sample| !sample.duplicate_label_names.is_empty())
        .map(|sample| sample.name.clone())
        .collect();
    assert!(
        duplicated.is_empty(),
        "{} sample(s) repeat a label name, e.g. {:?}",
        duplicated.len(),
        duplicated.first()
    );
}
