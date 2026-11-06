use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_host_root")]
    pub host_root: PathBuf,
    #[serde(default = "default_listen_address")]
    pub listen_address: SocketAddr,
    #[serde(default = "default_metrics_path")]
    pub metrics_path: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// This machine's name, as the scraper's `host` label spells it. Absent: the hostname.
    #[serde(default)]
    pub host: Option<String>,
    /// What the atlas shows for this machine. Absent: `host`.
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub atlas: AtlasConfig,
    #[serde(default)]
    pub live: LiveConfig,
    #[serde(default)]
    pub defaults: Defaults,
    pub targets: Vec<TargetConfig>,
}

/// What `/atlas` needs beyond this harvester: the others, and where history lives.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtlasConfig {
    /// Base URLs of the other harvesters, e.g. `http://nas.lan:9799`.
    #[serde(default)]
    pub peers: Vec<String>,
    /// A Prometheus-compatible query API holding this harvester's metrics.
    #[serde(default)]
    pub metrics_url: Option<String>,
    /// Long-running PromQL for a filesystem's used and total bytes, for history that predates
    /// the harvester's own `storage_harvester_filesystem_*` series.
    #[serde(default)]
    pub capacity_queries: Vec<CapacityQuery>,
    /// Pictures of image and video files, for the targets that turn them on.
    #[serde(default)]
    pub thumbnails: ThumbnailConfig,
    /// A Plex server whose posters the atlas shows on the folders of its libraries.
    #[serde(default)]
    pub plex: Option<PlexConfig>,
}

/// How `/api/thumb` makes pictures (with ffmpeg) and where it keeps them.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThumbnailConfig {
    /// Made pictures and posters live here, a few KiB each, the least recently made going first
    /// past `cache_mib`.
    #[serde(default = "default_thumbnail_cache_dir")]
    pub cache_dir: PathBuf,
    #[serde(default = "default_thumbnail_cache_mib")]
    pub cache_mib: u64,
    #[serde(default = "default_ffmpeg")]
    pub ffmpeg: PathBuf,
    #[serde(default = "default_ffprobe")]
    pub ffprobe: PathBuf,
    /// ffmpeg runs at once; more requests wait for one.
    #[serde(default = "default_thumbnail_jobs")]
    pub jobs: usize,
}

impl Default for ThumbnailConfig {
    fn default() -> Self {
        Self {
            cache_dir: default_thumbnail_cache_dir(),
            cache_mib: default_thumbnail_cache_mib(),
            ffmpeg: default_ffmpeg(),
            ffprobe: default_ffprobe(),
            jobs: default_thumbnail_jobs(),
        }
    }
}

/// A Plex server, read with the token in `token_env` (default `PLEX_TOKEN`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlexConfig {
    /// `http://host:32400`.
    pub url: String,
    #[serde(default = "default_plex_token_env")]
    pub token_env: String,
    /// Plex's paths for library folders, and the same folders as this harvester's targets show
    /// them: `/data/media: /volume1/data/media`.
    pub paths: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityQuery {
    /// Any host path on the filesystem.
    pub path: PathBuf,
    pub used: String,
    pub size: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveConfig {
    /// Follow changes between scans: fanotify where the kernel has it (5.9+), btrfs generation
    /// polling elsewhere. Both need CAP_SYS_ADMIN; without it, only scans update the tree.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// How often btrfs targets are polled for new generations.
    #[serde(
        default = "default_btrfs_poll_interval",
        deserialize_with = "deserialize_duration"
    )]
    pub btrfs_poll_interval: Duration,
    /// The shortest time between two re-reads of one directory.
    #[serde(
        default = "default_min_relist_interval",
        deserialize_with = "deserialize_duration"
    )]
    pub min_relist_interval: Duration,
    /// How often `lvm_thin` targets read allocation and I/O from device-mapper.
    #[serde(
        default = "default_block_poll_interval",
        deserialize_with = "deserialize_duration"
    )]
    pub block_poll_interval: Duration,
    /// On Synology DSM, also follow btrfs targets by synotify, Synology's own change events:
    /// writes and deletions show at once rather than at writeback (~15 s) or commit (~30 s).
    /// Needs root and CAP_SYS_ADMIN; in a container, `pid: host` and CAP_SYS_PTRACE as well,
    /// to mark the other containers' mounts.
    #[serde(default = "default_true")]
    pub synotify: bool,
}

impl Default for LiveConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            btrfs_poll_interval: default_btrfs_poll_interval(),
            min_relist_interval: default_min_relist_interval(),
            block_poll_interval: default_block_poll_interval(),
            synotify: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    #[serde(default = "default_scanner")]
    pub scanner: String,
    #[serde(
        default = "default_baseline_interval",
        deserialize_with = "deserialize_duration"
    )]
    pub baseline_interval: Duration,
    #[serde(default = "default_timeout", deserialize_with = "deserialize_duration")]
    pub timeout: Duration,
    #[serde(default = "default_true")]
    pub no_cross_filesystem: bool,
    #[serde(default)]
    pub follow_symlinks: bool,
    #[serde(default = "default_report_mode")]
    pub report_mode: ReportMode,
    #[serde(default = "default_report_depth")]
    pub report_depth: usize,
    #[serde(default)]
    pub max_depth: Option<usize>,
    /// Worker threads per scan. Absent: one per available CPU, up to 16.
    #[serde(default)]
    pub scan_threads: Option<usize>,
    #[serde(default = "default_size_modes")]
    pub size_modes: Vec<SizeMode>,
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Directories kept in memory for `/api/tree` and live updates, beyond the reported ones.
    /// 0 keeps only the reported tree.
    #[serde(default = "default_tree_max_directories")]
    pub tree_max_directories: usize,
    #[serde(default = "default_true")]
    pub live: bool,
    /// btrfs only: how often to read the subvolume's extent metadata to work out which bytes
    /// each directory holds alone. Absent: never.
    #[serde(default, deserialize_with = "deserialize_optional_duration")]
    pub sharing_interval: Option<Duration>,
    /// Whether `/api/thumb` makes pictures of the target's image and video files. It reads their
    /// contents, so it is off unless a target turns it on.
    #[serde(default)]
    pub thumbnails: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReportMode {
    Tree,
    Leaves,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SizeMode {
    Blocks,
    Apparent,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetConfig {
    pub name: String,
    #[serde(default = "default_target_type")]
    pub r#type: String,
    pub path: PathBuf,
    /// `lvm_thin` only: the thin pool, as `vg/lv`.
    #[serde(default)]
    pub pool: Option<String>,
    /// `lvm_thin` only: where Proxmox keeps guest and storage configs (default `/etc/pve`).
    #[serde(default)]
    pub pve_config: Option<PathBuf>,
    #[serde(default)]
    pub scanner: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_duration")]
    pub baseline_interval: Option<Duration>,
    #[serde(default, deserialize_with = "deserialize_optional_duration")]
    pub timeout: Option<Duration>,
    #[serde(default)]
    pub no_cross_filesystem: Option<bool>,
    #[serde(default)]
    pub follow_symlinks: Option<bool>,
    #[serde(default)]
    pub report_mode: Option<ReportMode>,
    #[serde(default)]
    pub report_depth: Option<usize>,
    /// Absent: inherit the default. `null`: no cap, whatever the default says. A number: that cap.
    #[serde(default, deserialize_with = "deserialize_explicit")]
    pub max_depth: Option<Option<usize>>,
    #[serde(default)]
    pub scan_threads: Option<usize>,
    #[serde(default)]
    pub size_modes: Option<Vec<SizeMode>>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub tree_max_directories: Option<usize>,
    #[serde(default)]
    pub live: Option<bool>,
    /// Absent: inherit. `null`: off. A duration: that interval.
    #[serde(default, deserialize_with = "deserialize_explicit_duration")]
    pub sharing_interval: Option<Option<Duration>>,
    #[serde(default)]
    pub thumbnails: Option<bool>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub name: String,
    pub target_type: String,
    pub scanner: String,
    pub display_path: PathBuf,
    pub scan_path: PathBuf,
    pub baseline_interval: Duration,
    pub timeout: Duration,
    pub no_cross_filesystem: bool,
    pub follow_symlinks: bool,
    pub report_mode: ReportMode,
    pub report_depth: usize,
    pub max_depth: Option<usize>,
    pub scan_threads: usize,
    pub size_modes: Vec<SizeMode>,
    pub exclude: Vec<String>,
    pub tree_max_directories: usize,
    pub live: bool,
    pub sharing_interval: Option<Duration>,
    pub thumbnails: bool,
    /// Set at startup when the fanotify source runs: the walk then records each directory's
    /// file handle, the key fanotify reports changes by.
    pub collect_handles: bool,
    /// Set for `type: lvm_thin`: the pool this target maps instead of a directory.
    pub lvm: Option<LvmTarget>,
    pub labels: BTreeMap<String, String>,
}

/// A Proxmox thin pool (`type: lvm_thin`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LvmTarget {
    pub vg: String,
    pub pool: String,
    /// `/etc/pve` under `host_root`.
    pub pve_config: PathBuf,
}

impl LvmTarget {
    /// The pool's filesystem id in `/api/info`.
    pub fn fs_id(&self) -> String {
        format!("lvm:{}/{}", self.vg, self.pool)
    }
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            scanner: default_scanner(),
            baseline_interval: default_baseline_interval(),
            timeout: default_timeout(),
            no_cross_filesystem: true,
            follow_symlinks: false,
            report_mode: default_report_mode(),
            report_depth: default_report_depth(),
            max_depth: None,
            scan_threads: None,
            size_modes: default_size_modes(),
            exclude: Vec::new(),
            tree_max_directories: default_tree_max_directories(),
            live: true,
            sharing_interval: None,
            thumbnails: false,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let config: Self = serde_yaml::from_str(&raw)
            .with_context(|| format!("failed to parse config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn resolved_targets(&self) -> Result<Vec<Target>> {
        self.targets
            .iter()
            .map(|target| self.resolve_target(target))
            .collect()
    }

    fn resolve_target(&self, target: &TargetConfig) -> Result<Target> {
        let lvm = match target.r#type.as_str() {
            "filesystem" => {
                if target.pool.is_some() || target.pve_config.is_some() {
                    bail!(
                        "target {}: pool and pve_config are for type lvm_thin",
                        target.name
                    );
                }
                None
            }
            "lvm_thin" => {
                let pool = target.pool.as_deref().unwrap_or_default();
                let Some((vg, lv)) = pool
                    .split_once('/')
                    .filter(|(vg, lv)| !vg.is_empty() && !lv.is_empty() && !lv.contains('/'))
                else {
                    bail!(
                        "target {} (lvm_thin) needs pool: <volume group>/<thin pool>",
                        target.name
                    );
                };
                let pve_config = target
                    .pve_config
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("/etc/pve"));
                Some(LvmTarget {
                    vg: vg.to_string(),
                    pool: lv.to_string(),
                    pve_config: join_host_root(&self.host_root, &pve_config),
                })
            }
            other => bail!(
                "target {} uses unsupported target type {other:?}",
                target.name
            ),
        };
        let scanner = match (&lvm, target.scanner.as_deref()) {
            (Some(_), None | Some("lvm")) => "lvm",
            (Some(_), Some(other)) => {
                bail!(
                    "target {} (lvm_thin) cannot use scanner {other:?}",
                    target.name
                )
            }
            (None, scanner) => scanner.unwrap_or(&self.defaults.scanner),
        };
        if lvm.is_none() && scanner != "native" {
            bail!(
                "target {} uses unsupported scanner {scanner:?}",
                target.name
            );
        }

        let display_path = normalize_display_path(&target.path)?;
        let scan_path = join_host_root(&self.host_root, &display_path);
        let report_depth = target.report_depth.unwrap_or(self.defaults.report_depth);
        let max_depth = target.max_depth.unwrap_or(self.defaults.max_depth);
        if let Some(cap) = max_depth.filter(|&cap| cap < report_depth) {
            bail!(
                "target {} max_depth ({cap}) must be greater than or equal to report_depth ({report_depth})",
                target.name
            );
        }

        Ok(Target {
            name: target.name.clone(),
            target_type: target.r#type.clone(),
            scanner: scanner.to_string(),
            display_path,
            scan_path,
            baseline_interval: target
                .baseline_interval
                .unwrap_or(self.defaults.baseline_interval),
            timeout: target.timeout.unwrap_or(self.defaults.timeout),
            no_cross_filesystem: target
                .no_cross_filesystem
                .unwrap_or(self.defaults.no_cross_filesystem),
            follow_symlinks: target
                .follow_symlinks
                .unwrap_or(self.defaults.follow_symlinks),
            report_mode: target.report_mode.unwrap_or(self.defaults.report_mode),
            report_depth,
            max_depth,
            scan_threads: target
                .scan_threads
                .or(self.defaults.scan_threads)
                .unwrap_or_else(default_scan_threads),
            size_modes: target
                .size_modes
                .clone()
                .unwrap_or_else(|| self.defaults.size_modes.clone()),
            exclude: self
                .defaults
                .exclude
                .iter()
                .chain(target.exclude.iter())
                .cloned()
                .collect(),
            tree_max_directories: target
                .tree_max_directories
                .unwrap_or(self.defaults.tree_max_directories),
            live: target.live.unwrap_or(self.defaults.live),
            sharing_interval: target
                .sharing_interval
                .unwrap_or(self.defaults.sharing_interval),
            // A thin pool's nodes are guests and disks, not files.
            thumbnails: lvm.is_none() && target.thumbnails.unwrap_or(self.defaults.thumbnails),
            collect_handles: false,
            lvm,
            labels: target.labels.clone(),
        })
    }

    fn validate(&self) -> Result<()> {
        if self.metrics_path.is_empty() || !self.metrics_path.starts_with('/') {
            bail!("metrics_path must start with /");
        }
        if self.targets.is_empty() {
            bail!("at least one target is required");
        }
        if let Some(threads) = self.defaults.scan_threads {
            check_scan_threads("defaults", threads)?;
        }
        for peer in &self.atlas.peers {
            if !(peer.starts_with("http://") || peer.starts_with("https://")) {
                bail!("atlas peer {peer:?} must be an http(s) URL");
            }
        }
        if self.atlas.thumbnails.jobs == 0 {
            bail!("atlas.thumbnails.jobs must be at least 1");
        }
        if let Some(plex) = &self.atlas.plex {
            if !plex.url.starts_with("http://") {
                bail!("atlas.plex.url {:?} must be an http:// URL", plex.url);
            }
            for (from, to) in &plex.paths {
                if !from.starts_with('/') || !to.starts_with('/') {
                    bail!("atlas.plex.paths {from:?}: {to:?} must both be absolute");
                }
            }
        }
        if self.live.btrfs_poll_interval.is_zero() {
            bail!("live.btrfs_poll_interval must be greater than zero");
        }
        if self.live.block_poll_interval.is_zero() {
            bail!("live.block_poll_interval must be greater than zero");
        }

        let mut names = HashSet::new();
        for target in &self.targets {
            if target.name.is_empty() {
                bail!("target name cannot be empty");
            }
            if !target
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
            {
                bail!(
                    "target {} contains unsupported label characters",
                    target.name
                );
            }
            if !names.insert(target.name.clone()) {
                bail!("duplicate target name {}", target.name);
            }
            if !target.path.is_absolute() {
                bail!("target {} path must be absolute", target.name);
            }
            if target.baseline_interval == Some(Duration::ZERO) {
                bail!(
                    "target {} baseline_interval must be greater than zero",
                    target.name
                );
            }
            if target.sharing_interval == Some(Some(Duration::ZERO)) {
                bail!(
                    "target {} sharing_interval must be greater than zero",
                    target.name
                );
            }
            if target.timeout == Some(Duration::ZERO) {
                bail!("target {} timeout must be greater than zero", target.name);
            }
            if let Some(threads) = target.scan_threads {
                check_scan_threads(&format!("target {}", target.name), threads)?;
            }
            if matches!(target.size_modes.as_deref(), Some([])) {
                bail!("target {} size_modes cannot be empty", target.name);
            }
            for key in target.labels.keys() {
                let valid = key.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                    && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    && !key.starts_with("__");
                if !valid {
                    bail!(
                        "target {} label {key:?} is not a valid Prometheus label name",
                        target.name
                    );
                }
                if BUILTIN_LABELS.contains(&key.as_str()) {
                    bail!(
                        "target {} label {key:?} collides with a built-in label",
                        target.name
                    );
                }
            }
        }
        Ok(())
    }
}

/// Labels the exporter sets itself (`src/exporter/prometheus.rs`). A user label with one of these
/// names would repeat a label on the sample, and Prometheus rejects the whole scrape for that.
const BUILTIN_LABELS: &[&str] = &[
    "target",
    "target_type",
    "path",
    "parent",
    "node",
    "depth",
    "size_mode",
    "backend",
    "entry_type",
    "issue",
];

impl Config {
    /// The name this machine goes by: `host`, else the kernel's hostname.
    pub fn host_name(&self) -> String {
        if let Some(host) = &self.host {
            return host.clone();
        }
        fs::read_to_string("/proc/sys/kernel/hostname")
            .ok()
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
            .or_else(|| std::env::var("HOSTNAME").ok())
            .unwrap_or_else(|| "localhost".to_string())
    }
}

const MAX_SCAN_THREADS: usize = 256;

fn check_scan_threads(scope: &str, threads: usize) -> Result<()> {
    if !(1..=MAX_SCAN_THREADS).contains(&threads) {
        bail!("{scope} scan_threads must be between 1 and {MAX_SCAN_THREADS}");
    }
    Ok(())
}

/// One walker per CPU the process may use (cgroup quotas included), up to 16: past that a
/// warm walk stops getting faster, and a cold one is bound by the disk's queue.
fn default_scan_threads() -> usize {
    std::thread::available_parallelism()
        .map_or(4, usize::from)
        .clamp(1, 16)
}

fn normalize_display_path(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("target path must be absolute");
    }
    Ok(path.components().collect())
}

fn join_host_root(host_root: &Path, display_path: &Path) -> PathBuf {
    let relative = display_path.strip_prefix("/").unwrap_or(display_path);
    host_root.join(relative)
}

/// With `#[serde(default)]`, keeps an explicit `null` distinct from an absent key: absent is
/// `None`, `null` is `Some(None)`. Plain `Option<Option<T>>` collapses both to `None`.
fn deserialize_explicit<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

fn deserialize_explicit_duration<'de, D>(
    deserializer: D,
) -> Result<Option<Option<Duration>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_duration(deserializer).map(Some)
}

fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    parse_duration(&value).map_err(serde::de::Error::custom)
}

fn deserialize_optional_duration<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?
        .map(|value| parse_duration(&value).map_err(serde::de::Error::custom))
        .transpose()
}

fn parse_duration(value: &str) -> Result<Duration> {
    let value = value.trim();
    if value.is_empty() {
        bail!("duration cannot be empty");
    }

    let split_at = value
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(split_at);
    let amount: u64 = number
        .parse()
        .with_context(|| format!("invalid duration number {number:?}"))?;

    match unit {
        "ms" => Ok(Duration::from_millis(amount)),
        "s" | "sec" | "secs" => Ok(Duration::from_secs(amount)),
        "m" | "min" | "mins" => Ok(Duration::from_secs(amount * 60)),
        "h" | "hr" | "hrs" => Ok(Duration::from_secs(amount * 60 * 60)),
        "" => Ok(Duration::from_secs(amount)),
        _ => bail!("unsupported duration unit {unit:?}"),
    }
}

fn default_host_root() -> PathBuf {
    PathBuf::from("/")
}

fn default_listen_address() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 9799))
}

fn default_metrics_path() -> String {
    "/metrics".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_scanner() -> String {
    "native".to_string()
}

fn default_target_type() -> String {
    "filesystem".to_string()
}

fn default_report_mode() -> ReportMode {
    ReportMode::Tree
}

fn default_report_depth() -> usize {
    1
}

fn default_size_modes() -> Vec<SizeMode> {
    vec![SizeMode::Blocks]
}

fn default_baseline_interval() -> Duration {
    Duration::from_secs(60)
}

fn default_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_thumbnail_cache_dir() -> PathBuf {
    PathBuf::from("/var/cache/storage-harvester")
}

fn default_thumbnail_cache_mib() -> u64 {
    512
}

fn default_ffmpeg() -> PathBuf {
    PathBuf::from("ffmpeg")
}

fn default_ffprobe() -> PathBuf {
    PathBuf::from("ffprobe")
}

fn default_thumbnail_jobs() -> usize {
    2
}

fn default_plex_token_env() -> String {
    "PLEX_TOKEN".to_string()
}

fn default_true() -> bool {
    true
}

/// About 200 bytes each: half a million directories is ~100 MB at most.
fn default_tree_max_directories() -> usize {
    500_000
}

fn default_block_poll_interval() -> Duration {
    Duration::from_secs(1)
}

fn default_btrfs_poll_interval() -> Duration {
    Duration::from_secs(3)
}

fn default_min_relist_interval() -> Duration {
    Duration::from_millis(250)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_duration_units() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
    }

    fn resolve(yaml: &str) -> Result<Vec<Target>> {
        let config: Config = serde_yaml::from_str(yaml)?;
        config.validate()?;
        config.resolved_targets()
    }

    #[test]
    fn max_depth_absent_inherits_null_uncaps_number_caps() {
        let targets = resolve(
            "
defaults: { max_depth: 1 }
targets:
  - { name: absent, path: /a }
  - { name: null_value, path: /b, max_depth: null }
  - { name: number, path: /c, max_depth: 3 }
",
        )
        .unwrap();
        let depths: Vec<_> = targets.iter().map(|t| t.max_depth).collect();
        assert_eq!(depths, [Some(1), None, Some(3)]);
    }

    #[test]
    fn rejects_effective_max_depth_below_report_depth() {
        let error = resolve(
            "
defaults: { max_depth: 1 }
targets:
  - { name: docker, path: /d, report_depth: 2 }
",
        )
        .unwrap_err();
        assert!(error.to_string().contains("max_depth (1)"), "{error}");
    }

    #[test]
    fn rejects_labels_that_collide_or_are_invalid() {
        for label in ["path", "size_mode", "my-label", "__reserved"] {
            let yaml =
                format!("targets:\n  - {{ name: t, path: /t, labels: {{ {label:?}: x }} }}\n");
            assert!(resolve(&yaml).is_err(), "accepted label {label:?}");
        }
        assert!(resolve("targets:\n  - { name: t, path: /t, labels: { host: nuc } }\n").is_ok());
    }

    #[test]
    fn scan_threads_inherit_override_and_stay_in_range() {
        let targets = resolve(
            "
defaults: { scan_threads: 3 }
targets:
  - { name: inherited, path: /a }
  - { name: own, path: /b, scan_threads: 1 }
",
        )
        .unwrap();
        let threads: Vec<_> = targets.iter().map(|t| t.scan_threads).collect();
        assert_eq!(threads, [3, 1]);

        let automatic = resolve("targets:\n  - { name: t, path: /t }\n").unwrap();
        assert!((1..=16).contains(&automatic[0].scan_threads));

        for bad in ["0", "257"] {
            for yaml in [
                format!(
                    "defaults: {{ scan_threads: {bad} }}\ntargets:\n  - {{ name: t, path: /t }}\n"
                ),
                format!("targets:\n  - {{ name: t, path: /t, scan_threads: {bad} }}\n"),
            ] {
                assert!(
                    resolve(&yaml).is_err(),
                    "accepted scan_threads {bad}: {yaml}"
                );
            }
        }
    }

    #[test]
    fn resolves_host_path_from_display_path() {
        let path = join_host_root(Path::new("/host"), Path::new("/var/log"));
        assert_eq!(path, PathBuf::from("/host/var/log"));
    }
}
