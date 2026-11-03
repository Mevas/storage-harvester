//! Shared harness for the black-box suites.
//!
//! Everything here treats the harvester as a deployed service would be treated: build a real
//! directory tree on disk, start the real binary against it, and read what it exports over HTTP.
//! Expected values come from [`oracle_walk`], a separate implementation that walks the same tree
//! with plain `std::fs` and shares no code with the scanner.

#![allow(dead_code)] // each test binary uses a different subset of this module

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{symlink, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub const BIN: &str = env!("CARGO_BIN_EXE_storage-harvester");

// ---------------------------------------------------------------------------------------------
// Deterministic tree generation
// ---------------------------------------------------------------------------------------------

/// xorshift64*: deterministic, dependency-free, good enough for picking file sizes.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Inclusive range.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next_u64() % (hi - lo + 1)
    }
}

/// Writes `len` real bytes, so the allocation is real rather than sparse.
pub fn write_file(path: &Path, len: u64) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut file = File::create(path).unwrap();
    let chunk = [0x5a_u8; 64 * 1024];
    let mut left = len;
    while left > 0 {
        let n = left.min(chunk.len() as u64) as usize;
        file.write_all(&chunk[..n]).unwrap();
        left -= n as u64;
    }
}

pub fn append(path: &Path, len: u64) {
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(&vec![0x61_u8; len as usize]).unwrap();
    file.sync_all().unwrap();
}

/// A file with a large apparent size and only `tail` bytes actually written.
pub fn write_sparse(path: &Path, apparent: u64, tail: u64) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut file = File::create(path).unwrap();
    file.set_len(apparent).unwrap();
    file.seek(SeekFrom::Start(apparent - tail)).unwrap();
    file.write_all(&vec![0x5a_u8; tail as usize]).unwrap();
}

pub fn link(target: &str, at: &Path) {
    fs::create_dir_all(at.parent().unwrap()).unwrap();
    symlink(target, at).unwrap();
}

/// A tree shaped like the places the harvester is pointed at: source trees with vendored
/// dependencies and VCS metadata, rotated logs plus one runaway log, media, a sparse VM image,
/// empty files and directories, symlinks of every kind, a deep chain, and file names that stress
/// label escaping. No hardlinks: the harvester's hardlink handling has its own test.
pub fn realistic_tree(root: &Path, seed: u64) {
    let mut rng = Rng::new(seed);
    fs::create_dir_all(root).unwrap();

    for p in 0..6 {
        let project = root.join(format!("projects/proj-{p}"));
        for m in 0..rng.range(3, 8) {
            for f in 0..rng.range(5, 30) {
                write_file(
                    &project.join(format!("src/mod{m}/file{f}.rs")),
                    rng.range(0, 24_000),
                );
            }
        }
        for pkg in 0..rng.range(10, 40) {
            write_file(
                &project.join(format!("node_modules/pkg{pkg}/index.js")),
                rng.range(100, 8_000),
            );
            write_file(
                &project.join(format!("node_modules/pkg{pkg}/lib/util.js")),
                rng.range(100, 8_000),
            );
        }
        for object in 0..rng.range(5, 20) {
            let name = format!("{:016x}{:016x}", rng.next_u64(), rng.next_u64());
            write_file(
                &project.join(format!(".git/objects/{object:02x}/{name}")),
                rng.range(50, 4_000),
            );
        }
        write_file(&project.join("README.md"), rng.range(200, 6_000));
    }

    for day in 1..=20 {
        write_file(
            &root.join(format!("logs/app-2026-10-{day:02}.log")),
            rng.range(1_000, 400_000),
        );
    }
    write_file(&root.join("logs/runaway.log"), 6 * 1024 * 1024);

    for clip in 0..4 {
        write_file(
            &root.join(format!("media/clip{clip}.mp4")),
            rng.range(500_000, 3_000_000),
        );
    }

    write_sparse(&root.join("vm/disk.img"), 256 * 1024 * 1024, 4096);

    fs::create_dir_all(root.join("empty/a/b/c")).unwrap();
    for i in 0..10 {
        write_file(&root.join(format!("empty/zero{i}")), 0);
    }

    link("../logs/runaway.log", &root.join("links/to-file"));
    link("../projects", &root.join("links/to-dir"));
    link("does/not/exist", &root.join("links/dangling"));
    link("..", &root.join("links/to-parent"));

    let mut deep = root.join("deep");
    for level in 0..14 {
        deep = deep.join(format!("l{level}"));
    }
    write_file(&deep.join("leaf.txt"), 1234);

    write_file(
        &root.join("names/with space/ünïcödé ✓/quote\"back\\slash.txt"),
        777,
    );
    write_file(&root.join("names/new\nline.txt"), 10);
}

/// A balanced tree of `files` files, ~25 per directory, ~12 directories per level. Most files
/// are tiny or empty, as in real metadata-heavy trees; a few are large.
pub fn perf_tree(root: &Path, files: u64, seed: u64) {
    let mut rng = Rng::new(seed);
    for i in 0..files {
        let mut dir = root.to_path_buf();
        let mut index = i / 25;
        loop {
            dir.push(format!("d{:x}", index % 12));
            index /= 12;
            if index == 0 {
                break;
            }
        }
        let len = match rng.range(0, 999) {
            0..=1 => rng.range(64 * 1024, 256 * 1024),
            2..=249 => rng.range(1, 4096),
            _ => 0,
        };
        write_file(&dir.join(format!("f{i}.dat")), len);
    }
}

// ---------------------------------------------------------------------------------------------
// Independent oracle walk
// ---------------------------------------------------------------------------------------------

/// What the harvester should report for one directory.
#[derive(Debug, Default, Clone)]
pub struct DirTotals {
    pub depth: usize,
    /// The directory inode itself.
    pub own_blocks: u64,
    pub own_apparent: u64,
    /// Everything at or below the directory, including its own inode.
    pub total_blocks: u64,
    pub total_apparent: u64,
    /// Entries directly inside the directory.
    pub direct_files: u64,
    pub direct_dirs: u64,
    pub direct_symlinks: u64,
    /// Entries below the direct children.
    pub deeper_files: u64,
    pub deeper_dirs: u64,
    pub deeper_symlinks: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct EntryTotals {
    pub depth: usize,
    pub blocks: u64,
    pub apparent: u64,
}

#[derive(Debug, Default)]
pub struct Walk {
    /// Keyed by path relative to the walk root; the root itself is `""`.
    pub dirs: BTreeMap<PathBuf, DirTotals>,
    /// Non-directory entries, keyed the same way.
    pub entries: BTreeMap<PathBuf, EntryTotals>,
    pub regular_files: u64,
    pub directories: u64,
    pub symlinks: u64,
    pub max_depth: usize,
    pub excluded_children: u64,
    pub depth_limit_hits: u64,
    pub unreadable_dirs: u64,
}

impl Walk {
    pub fn root(&self) -> &DirTotals {
        &self.dirs[Path::new("")]
    }
}

#[derive(Debug, Default, Clone)]
pub struct WalkRules {
    /// Directory names whose contents are skipped: the meaning of `**/NAME/**` excludes.
    pub exclude_contents_of: Vec<String>,
    pub max_depth: Option<usize>,
}

/// Walks `root` the way the harvester is specified to: allocated blocks via `st_blocks * 512`,
/// symlinks never followed, every entry counted once per path, excluded directories counted
/// themselves but not descended.
pub fn oracle_walk(root: &Path, rules: &WalkRules) -> Walk {
    let mut walk = Walk::default();
    let meta = fs::symlink_metadata(root).unwrap();
    walk.directories += 1;
    visit_dir(&mut walk, rules, root, Path::new(""), 0, &meta);
    walk
}

fn visit_dir(
    walk: &mut Walk,
    rules: &WalkRules,
    abs: &Path,
    rel: &Path,
    depth: usize,
    meta: &fs::Metadata,
) -> DirTotals {
    let mut totals = DirTotals {
        depth,
        own_blocks: meta.blocks() * 512,
        own_apparent: meta.size(),
        ..DirTotals::default()
    };
    totals.total_blocks = totals.own_blocks;
    totals.total_apparent = totals.own_apparent;
    walk.max_depth = walk.max_depth.max(depth);

    if rules.max_depth.is_some_and(|max| depth >= max) {
        walk.depth_limit_hits += 1;
        walk.dirs.insert(rel.to_path_buf(), totals.clone());
        return totals;
    }

    let contents_excluded = rel
        .file_name()
        .is_some_and(|name| rules.exclude_contents_of.iter().any(|e| name == e.as_str()));

    let children = match fs::read_dir(abs) {
        Ok(children) => children,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            walk.unreadable_dirs += 1;
            walk.dirs.insert(rel.to_path_buf(), totals.clone());
            return totals;
        }
        Err(error) => panic!("oracle cannot read {}: {error}", abs.display()),
    };
    let mut names: Vec<_> = children.map(|entry| entry.unwrap().file_name()).collect();
    names.sort();

    for name in names {
        if contents_excluded {
            walk.excluded_children += 1;
            continue;
        }
        let child_abs = abs.join(&name);
        let child_rel = rel.join(&name);
        let child_meta = fs::symlink_metadata(&child_abs).unwrap();
        walk.max_depth = walk.max_depth.max(depth + 1);

        if child_meta.is_dir() {
            walk.directories += 1;
            totals.direct_dirs += 1;
            let child = visit_dir(walk, rules, &child_abs, &child_rel, depth + 1, &child_meta);
            totals.total_blocks += child.total_blocks;
            totals.total_apparent += child.total_apparent;
            totals.deeper_files += child.direct_files + child.deeper_files;
            totals.deeper_dirs += child.direct_dirs + child.deeper_dirs;
            totals.deeper_symlinks += child.direct_symlinks + child.deeper_symlinks;
        } else {
            let entry = EntryTotals {
                depth: depth + 1,
                blocks: child_meta.blocks() * 512,
                apparent: child_meta.size(),
            };
            totals.total_blocks += entry.blocks;
            totals.total_apparent += entry.apparent;
            if child_meta.file_type().is_symlink() {
                walk.symlinks += 1;
                totals.direct_symlinks += 1;
            } else {
                walk.regular_files += u64::from(child_meta.is_file());
                totals.direct_files += 1;
            }
            walk.entries.insert(child_rel, entry);
        }
    }

    walk.dirs.insert(rel.to_path_buf(), totals.clone());
    totals
}

// ---------------------------------------------------------------------------------------------
// Running the real binary
// ---------------------------------------------------------------------------------------------

pub struct Harvester {
    child: Child,
    pub port: u16,
    pub log: PathBuf,
}

impl Harvester {
    /// Starts the binary with `config_body` (everything except `listen_address`, which the
    /// harness picks) and waits until its HTTP server answers.
    pub fn start(workdir: &Path, config_body: &str) -> Self {
        fs::create_dir_all(workdir).unwrap();
        for attempt in 0..5 {
            let port = free_port();
            let config = workdir.join("config.yaml");
            fs::write(
                &config,
                format!("listen_address: 127.0.0.1:{port}\n{config_body}"),
            )
            .unwrap();
            let log = workdir.join(format!("harvester-{attempt}.log"));
            let log_file = File::create(&log).unwrap();
            let child = Command::new(BIN)
                .arg("--config")
                .arg(&config)
                .stdout(Stdio::from(log_file.try_clone().unwrap()))
                .stderr(Stdio::from(log_file))
                .spawn()
                .expect("failed to spawn storage-harvester");
            let mut harvester = Harvester { child, port, log };

            let deadline = Instant::now() + Duration::from_secs(15);
            while Instant::now() < deadline {
                if harvester.child.try_wait().unwrap().is_some() {
                    break; // exited: most likely lost the race for the port; retry
                }
                if http_get(port, "/-/health").is_ok_and(|(status, _)| status == 200) {
                    return harvester;
                }
                thread::sleep(Duration::from_millis(50));
            }
            if attempt == 4 {
                panic!(
                    "storage-harvester did not start:\n{}",
                    harvester.log_tail(40)
                );
            }
        }
        unreachable!()
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn get(&self, path: &str) -> (u16, String) {
        http_get(self.port, path)
            .unwrap_or_else(|error| panic!("GET {path} failed: {error}\n{}", self.log_tail(40)))
    }

    pub fn metrics(&self) -> Metrics {
        let (status, body) = self.get("/metrics");
        assert_eq!(status, 200, "/metrics returned {status}");
        Metrics::parse(&body)
    }

    /// Polls `/metrics` until `ready` holds, or panics with the harvester's log.
    pub fn wait_for(
        &self,
        what: &str,
        timeout: Duration,
        ready: impl Fn(&Metrics) -> bool,
    ) -> Metrics {
        let deadline = Instant::now() + timeout;
        loop {
            let metrics = self.metrics();
            if ready(&metrics) {
                return metrics;
            }
            if Instant::now() > deadline {
                panic!(
                    "timed out after {timeout:?} waiting for {what}\n{}",
                    self.log_tail(40)
                );
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// Waits until `target` has completed at least `count` scans, successful or not.
    pub fn wait_for_scans(&self, target: &str, count: u64, timeout: Duration) -> Metrics {
        self.wait_for(&format!("{count} scan(s) of {target}"), timeout, |m| {
            m.target_value("storage_harvester_scan_count_total", target)
                .is_some_and(|n| n >= count as f64)
        })
    }

    pub fn log_tail(&self, lines: usize) -> String {
        let text = fs::read_to_string(&self.log).unwrap_or_default();
        let all: Vec<_> = text.lines().collect();
        all[all.len().saturating_sub(lines)..].join("\n")
    }
}

impl Drop for Harvester {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Minimal HTTP/1.0 GET, so the response is never chunked and the suite needs no HTTP client.
pub fn http_get(port: u16, path: &str) -> std::io::Result<(u16, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    write!(stream, "GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "no header terminator")
    })?;
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no status code"))?;
    Ok((status, body.to_string()))
}

pub fn yaml_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "''"))
}

// ---------------------------------------------------------------------------------------------
// Prometheus text format
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Sample {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub value: f64,
    /// Label names that appeared more than once on this sample. Prometheus rejects the whole
    /// scrape when any sample has one.
    pub duplicate_label_names: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Metrics {
    pub samples: Vec<Sample>,
    pub typed_names: BTreeSet<String>,
    pub parse_errors: Vec<String>,
    pub bytes: usize,
}

impl Metrics {
    pub fn parse(text: &str) -> Self {
        let mut metrics = Metrics {
            bytes: text.len(),
            ..Metrics::default()
        };
        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                if let Some(name) = rest.split_whitespace().next() {
                    metrics.typed_names.insert(name.to_string());
                }
                continue;
            }
            if line.starts_with('#') {
                continue;
            }
            match parse_sample(line) {
                Ok(sample) => metrics.samples.push(sample),
                Err(error) => metrics.parse_errors.push(format!("{error}: {line}")),
            }
        }
        metrics
    }

    /// Samples named `name` whose labels include every `(key, value)` in `matching`.
    pub fn find<'a>(&'a self, name: &str, matching: &[(&str, &str)]) -> Vec<&'a Sample> {
        self.samples
            .iter()
            .filter(|sample| {
                sample.name == name
                    && matching.iter().all(|(key, value)| {
                        sample.labels.get(*key).map(String::as_str) == Some(*value)
                    })
            })
            .collect()
    }

    /// The single sample matching, or `None`. Panics on ambiguity, which is a test bug.
    pub fn value(&self, name: &str, matching: &[(&str, &str)]) -> Option<f64> {
        let found = self.find(name, matching);
        assert!(
            found.len() <= 1,
            "{} samples of {name} match {matching:?}",
            found.len()
        );
        found.first().map(|sample| sample.value)
    }

    /// A per-target scalar such as `storage_harvester_scanned_files`.
    pub fn target_value(&self, name: &str, target: &str) -> Option<f64> {
        self.value(name, &[("target", target)])
    }

    pub fn issue(&self, target: &str, issue: &str) -> Option<f64> {
        self.value(
            "storage_harvester_scan_issue_count",
            &[("target", target), ("issue", issue)],
        )
    }

    /// `own + children` bytes for a reported node or direct entry at display path `path`.
    pub fn total_size(&self, target: &str, path: &str, size_mode: &str) -> Option<u64> {
        let own = self.size("storage_harvester_own_size_bytes", target, path, size_mode)?;
        let children = self.size(
            "storage_harvester_children_size_bytes",
            target,
            path,
            size_mode,
        )?;
        Some(own + children)
    }

    pub fn size(&self, name: &str, target: &str, path: &str, size_mode: &str) -> Option<u64> {
        self.value(
            name,
            &[("target", target), ("path", path), ("size_mode", size_mode)],
        )
        .map(|value| value as u64)
    }

    pub fn entries(&self, name: &str, target: &str, path: &str, entry_type: &str) -> Option<u64> {
        self.value(
            name,
            &[
                ("target", target),
                ("path", path),
                ("entry_type", entry_type),
            ],
        )
        .map(|value| value as u64)
    }
}

fn parse_sample(line: &str) -> Result<Sample, String> {
    let name_end = line.find(['{', ' ']).ok_or("no value after metric name")?;
    let name = line[..name_end].to_string();
    let mut labels = BTreeMap::new();
    let mut duplicate_label_names = Vec::new();
    let mut rest = &line[name_end..];

    if let Some(after_brace) = rest.strip_prefix('{') {
        let mut chars = after_brace.char_indices().peekable();
        let mut consumed = None;
        loop {
            // label name
            let mut key = String::new();
            loop {
                match chars.next() {
                    Some((_, '=')) => break,
                    Some((i, '}')) if key.is_empty() => {
                        consumed = Some(i + 1);
                        break;
                    }
                    Some((_, c)) => key.push(c),
                    None => return Err("unterminated label name".into()),
                }
            }
            if consumed.is_some() {
                break;
            }
            if chars.next().map(|(_, c)| c) != Some('"') {
                return Err(format!("label {key} value is not quoted"));
            }
            let mut value = String::new();
            loop {
                match chars.next() {
                    Some((_, '\\')) => match chars.next() {
                        Some((_, 'n')) => value.push('\n'),
                        Some((_, '\\')) => value.push('\\'),
                        Some((_, '"')) => value.push('"'),
                        Some((_, other)) => return Err(format!("bad escape \\{other}")),
                        None => return Err("unterminated escape".into()),
                    },
                    Some((_, '"')) => break,
                    Some((_, c)) => value.push(c),
                    None => return Err("unterminated label value".into()),
                }
            }
            if labels.insert(key.clone(), value).is_some() {
                duplicate_label_names.push(key);
            }
            match chars.next() {
                Some((_, ',')) => continue,
                Some((i, '}')) => {
                    consumed = Some(i + 1);
                    break;
                }
                other => return Err(format!("unexpected {other:?} after label")),
            }
        }
        rest = &after_brace[consumed.unwrap()..];
    }

    let value_text = rest.split_whitespace().next().ok_or("missing value")?;
    let value = value_text
        .parse::<f64>()
        .map_err(|_| format!("unparseable value {value_text:?}"))?;
    Ok(Sample {
        name,
        labels,
        value,
        duplicate_label_names,
    })
}

// ---------------------------------------------------------------------------------------------
// Process and host measurements
// ---------------------------------------------------------------------------------------------

/// Peak resident set size on Linux (`VmHWM`); current RSS elsewhere, labelled as such.
pub fn rss_kib(pid: u32) -> Option<(u64, &'static str)> {
    if let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) {
        return status
            .lines()
            .find_map(|line| line.strip_prefix("VmHWM:"))
            .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
            .map(|kib| (kib, "peak"));
    }
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .ok()
        .map(|kib| (kib, "current"))
}

/// Drops the Linux page, dentry and inode caches when `HARVESTER_PERF_DROP_CACHES=1` and
/// passwordless sudo is available. Returns whether the next walk starts cold.
pub fn drop_caches_if_requested() -> bool {
    if std::env::var("HARVESTER_PERF_DROP_CACHES").as_deref() != Ok("1") {
        return false;
    }
    let status = Command::new("sh")
        .args([
            "-c",
            "sync && echo 3 | sudo -n tee /proc/sys/vm/drop_caches >/dev/null",
        ])
        .status();
    match status {
        Ok(status) if status.success() => true,
        _ => {
            eprintln!("HARVESTER_PERF_DROP_CACHES=1 but dropping caches failed; measuring warm");
            false
        }
    }
}

pub fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

/// Collects mismatches so a failure lists all of them, not just the first.
#[derive(Default)]
pub struct Mismatches(Vec<String>);

impl Mismatches {
    pub fn check<T: PartialEq + std::fmt::Debug>(
        &mut self,
        what: impl AsRef<str>,
        got: T,
        want: T,
    ) {
        if got != want {
            self.0.push(format!(
                "{}: harvester {got:?}, expected {want:?}",
                what.as_ref()
            ));
        }
    }

    pub fn push(&mut self, message: String) {
        self.0.push(message);
    }

    pub fn assert_none(self, context: &str) {
        if !self.0.is_empty() {
            let shown: Vec<_> = self.0.iter().take(25).cloned().collect();
            panic!(
                "{context}: {} mismatch(es){}\n  {}",
                self.0.len(),
                if self.0.len() > 25 { " (first 25)" } else { "" },
                shown.join("\n  ")
            );
        }
    }
}
