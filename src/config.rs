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
    #[serde(default)]
    pub defaults: Defaults,
    pub targets: Vec<TargetConfig>,
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
    #[serde(default = "default_size_modes")]
    pub size_modes: Vec<SizeMode>,
    #[serde(default)]
    pub exclude: Vec<String>,
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
    #[serde(default)]
    pub max_depth: Option<usize>,
    #[serde(default)]
    pub size_modes: Option<Vec<SizeMode>>,
    #[serde(default)]
    pub exclude: Vec<String>,
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
    pub size_modes: Vec<SizeMode>,
    pub exclude: Vec<String>,
    pub labels: BTreeMap<String, String>,
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
            size_modes: default_size_modes(),
            exclude: Vec::new(),
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
        let scanner = target.scanner.as_deref().unwrap_or(&self.defaults.scanner);
        if scanner != "native" {
            bail!(
                "target {} uses unsupported scanner {scanner:?}",
                target.name
            );
        }
        if target.r#type != "filesystem" {
            bail!(
                "target {} uses unsupported target type {:?}",
                target.name,
                target.r#type
            );
        }

        let display_path = normalize_display_path(&target.path)?;
        let scan_path = join_host_root(&self.host_root, &display_path);

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
            report_depth: target.report_depth.unwrap_or(self.defaults.report_depth),
            max_depth: target.max_depth.or(self.defaults.max_depth),
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
            if target.timeout == Some(Duration::ZERO) {
                bail!("target {} timeout must be greater than zero", target.name);
            }
            if let Some(max_depth) = target.max_depth {
                let report_depth = target.report_depth.unwrap_or(self.defaults.report_depth);
                if max_depth < report_depth {
                    bail!(
                        "target {} max_depth must be greater than or equal to report_depth",
                        target.name
                    );
                }
            }
            if matches!(target.size_modes.as_deref(), Some([])) {
                bail!("target {} size_modes cannot be empty", target.name);
            }
        }
        Ok(())
    }
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

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_duration_units() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
    }

    #[test]
    fn resolves_host_path_from_display_path() {
        let path = join_host_root(Path::new("/host"), Path::new("/var/log"));
        assert_eq!(path, PathBuf::from("/host/var/log"));
    }
}
