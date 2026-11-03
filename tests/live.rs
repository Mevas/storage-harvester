//! Opt-in: does a *deployed* harvester report what is on its host?
//!
//! Over SSH, this reads the live exporter's `/metrics`, then walks each configured target on the
//! host with `find` using the semantics the config *intends* (a `max_depth: null` target is
//! walked without a cap), and compares counts, allocated bytes, and depth.
//!
//! ```sh
//! HARVESTER_LIVE_SSH=nuc \
//! HARVESTER_LIVE_CONFIG=../storage-harvester-komodo/configs/nuc.yaml \
//!   cargo test --test live -- --nocapture
//! ```
//!
//! - `HARVESTER_LIVE_SSH`: SSH destination of the host running the harvester. Unset: skipped.
//! - `HARVESTER_LIVE_CONFIG`: local copy of the config the deployment runs.
//! - `HARVESTER_LIVE_METRICS_URL` (default `http://localhost:9799/metrics`), fetched on the host.
//! - `HARVESTER_LIVE_TOLERANCE` (default 0.02): relative drift allowed in counts and bytes, since
//!   a live tree changes between the harvester's last scan and the `find`.
//!
//! Everything run on the host is read-only. `find` runs under `sudo -n` when that works, since
//! the harvester runs as root and an unprivileged walk would undercount.

mod support;

use std::collections::BTreeMap;
use std::process::Command;

use serde_yaml::Value;
use support::{Metrics, Mismatches};

const GIB: f64 = (1u64 << 30) as f64;

#[test]
fn deployed_harvester_matches_its_host() {
    let Ok(ssh) = std::env::var("HARVESTER_LIVE_SSH") else {
        eprintln!("skipped: set HARVESTER_LIVE_SSH (and HARVESTER_LIVE_CONFIG) to run");
        return;
    };
    let config_path = std::env::var("HARVESTER_LIVE_CONFIG")
        .expect("HARVESTER_LIVE_CONFIG must point at the deployed config");
    let url = std::env::var("HARVESTER_LIVE_METRICS_URL")
        .unwrap_or_else(|_| "http://localhost:9799/metrics".into());
    let tolerance: f64 = support::env_or("HARVESTER_LIVE_TOLERANCE", 0.02);

    let config: Value = serde_yaml::from_str(&std::fs::read_to_string(&config_path).unwrap())
        .expect("config is not valid YAML");
    let metrics = Metrics::parse(&remote(
        &ssh,
        &format!("curl -fsS --max-time 30 {}", sh(&url)),
    ));
    assert!(
        !metrics.samples.is_empty(),
        "no samples from {url} on {ssh}"
    );
    let sudo = remote_ok(&ssh, "sudo -n true");
    if !sudo {
        eprintln!("warning: no passwordless sudo on {ssh}; find may undercount unreadable paths");
    }

    let mut out = Mismatches::default();
    println!(
        "{:<14} {:>9} {:>11} {:>12} {:>12} {:>9} {:>9}",
        "target", "intended", "files h/f", "dirs h/f", "GiB h/f", "depth h/f", "limit hits"
    );
    for target in intended_targets(&config) {
        let name = target.name.as_str();
        let scalar = |metric: &str| metrics.target_value(metric, name).unwrap_or(f64::NAN);

        if scalar("storage_harvester_scan_success") != 1.0 {
            out.push(format!("{name}: last scan did not succeed"));
            continue;
        }
        let truth = walk_on_host(&ssh, &target, sudo);
        if truth.dirs == 0 {
            // Not even the root was listed: the ground truth failed, not the harvester.
            out.push(format!(
                "{name}: host walk of {} returned nothing (find exit {})",
                target.path, truth.find_exit
            ));
            continue;
        }
        if truth.find_exit != 0 {
            eprintln!(
                "warning: {name}: find exited {} (usually files vanishing mid-walk on a live tree)",
                truth.find_exit
            );
        }
        let harvester_bytes = metrics
            .total_size(name, &target.path, "blocks")
            .unwrap_or(0) as f64;
        let files = scalar("storage_harvester_scanned_files");
        let dirs = scalar("storage_harvester_scanned_directories");
        let depth = scalar("storage_harvester_max_observed_depth");
        let hits = scalar("storage_harvester_depth_limit_hits");

        println!(
            "{:<14} {:>9} {:>11} {:>12} {:>12} {:>9} {:>9}",
            name,
            target
                .max_depth
                .map_or("unlimited".to_string(), |d| format!("depth {d}")),
            format!("{files}/{}", truth.files),
            format!("{dirs}/{}", truth.dirs),
            format!(
                "{:.2}/{:.2}",
                harvester_bytes / GIB,
                truth.bytes as f64 / GIB
            ),
            format!("{depth}/{}", truth.max_depth),
            hits,
        );

        let mut near = |what: &str, got: f64, want: f64| {
            if !got.is_finite() {
                out.push(format!(
                    "{name}: {what} missing from the harvester's metrics"
                ));
                return;
            }
            let drift = (got - want).abs() / want.max(1.0);
            if drift > tolerance {
                out.push(format!(
                    "{name}: {what} harvester {got} vs host {want} ({:.1}% off)",
                    drift * 100.0
                ));
            }
        };
        near("regular files", files, truth.files as f64);
        near("directories", dirs, truth.dirs as f64);
        near("allocated bytes", harvester_bytes, truth.bytes as f64);
        if depth != truth.max_depth as f64 {
            out.push(format!(
                "{name}: reached depth {depth}, the tree goes to {}",
                truth.max_depth
            ));
        }
        if target.max_depth.is_none() && hits != 0.0 {
            out.push(format!(
                "{name}: {hits} depth-limit hit(s) on a target configured without a depth cap"
            ));
        }
    }
    out.assert_none(&format!("deployed harvester on {ssh}"));
}

struct IntendedTarget {
    name: String,
    path: String,
    /// `None` means the config asks for an uncapped walk.
    max_depth: Option<u64>,
    exclude: Vec<String>,
    no_cross_filesystem: bool,
}

/// Resolves each target the way the config reads to a human, which is what the harvester should
/// do. In particular `max_depth: null` on a target means "no cap", whatever the default says.
fn intended_targets(config: &Value) -> Vec<IntendedTarget> {
    let empty = Value::Mapping(Default::default());
    let defaults = config.get("defaults").unwrap_or(&empty);
    let strings = |v: Option<&Value>| -> Vec<String> {
        v.and_then(Value::as_sequence)
            .map(|seq| {
                seq.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    config["targets"]
        .as_sequence()
        .expect("config has no targets")
        .iter()
        .map(|t| {
            let depth_value = t.get("max_depth").or_else(|| defaults.get("max_depth"));
            let mut exclude = strings(defaults.get("exclude"));
            exclude.extend(strings(t.get("exclude")));
            IntendedTarget {
                name: t["name"].as_str().unwrap().to_string(),
                path: t["path"].as_str().unwrap().to_string(),
                max_depth: depth_value.and_then(Value::as_u64),
                exclude,
                no_cross_filesystem: t
                    .get("no_cross_filesystem")
                    .or_else(|| defaults.get("no_cross_filesystem"))
                    .and_then(Value::as_bool)
                    .unwrap_or(true),
            }
        })
        .collect()
}

#[derive(Debug, Default)]
struct HostWalk {
    files: u64,
    dirs: u64,
    bytes: u64,
    max_depth: u64,
    find_exit: u64,
}

fn walk_on_host(ssh: &str, target: &IntendedTarget, sudo: bool) -> HostWalk {
    // `**/NAME/**` skips what is inside NAME but still counts NAME, which is exactly what
    // `-path '*/NAME/*' -prune` does. Other glob shapes would need their own translation.
    let prunes: Vec<String> = target
        .exclude
        .iter()
        .map(|glob| {
            let name = glob
                .strip_prefix("**/")
                .and_then(|g| g.strip_suffix("/**"))
                .filter(|n| !n.contains(['*', '?', '[', '/']))
                .unwrap_or_else(|| panic!("live check cannot translate exclude {glob:?}"));
            format!("-path {}", sh(&format!("*/{name}/*")))
        })
        .collect();
    let prune = if prunes.is_empty() {
        String::new()
    } else {
        format!("\\( {} \\) -prune -o", prunes.join(" -o "))
    };
    let depth = target
        .max_depth
        .map_or(String::new(), |d| format!("-maxdepth {d}"));
    let xdev = if target.no_cross_filesystem {
        "-xdev"
    } else {
        ""
    };
    // With -xdev, find still prints each mount point it refuses to enter; the harvester skips
    // those entries entirely, so drop anything not on the root's device.
    let same_dev = if target.no_cross_filesystem {
        "$1==r"
    } else {
        "1"
    };
    // find's exit status travels down the pipe as a final `EXIT n` line, so a failed walk is
    // visible without relying on the remote shell supporting pipefail. A multiply-linked file's
    // blocks count at its first link only (`%n` links, `%i` inode), as the harvester counts them.
    let command = format!(
        "{{ {sudo}find {path} {xdev} {depth} {prune} -printf '%D %y %b %d %n %i\\n' 2>/dev/null; \
           echo \"EXIT $?\"; }} \
         | awk '$1==\"EXIT\"{{e=$2; next}} NR==1{{r=$1}} \
           {same_dev}{{n[$2]++; if($4>m)m=$4; k=$1\":\"$6; \
             if($2==\"d\" || $5<2){{b+=$3}} else if(!(k in s)){{b+=$3; s[k]=1}}}} \
           END{{printf \"f=%d d=%d blocks=%.0f depth=%d exit=%d\\n\", n[\"f\"], n[\"d\"], b, m, e}}'",
        sudo = if sudo { "sudo -n " } else { "" },
        path = sh(&target.path),
    );
    let line = remote(ssh, &command);
    let fields: BTreeMap<&str, u64> = line
        .split_whitespace()
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k, v.parse().unwrap()))
        .collect();
    HostWalk {
        files: fields["f"],
        dirs: fields["d"],
        bytes: fields["blocks"] * 512,
        max_depth: fields["depth"],
        find_exit: fields["exit"],
    }
}

fn remote(ssh: &str, command: &str) -> String {
    let output = Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            ssh,
            command,
        ])
        .output()
        .expect("failed to run ssh");
    assert!(
        output.status.success(),
        "ssh {ssh} {command:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn remote_ok(ssh: &str, command: &str) -> bool {
    Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            ssh,
            command,
        ])
        .status()
        .is_ok_and(|status| status.success())
}

/// Single-quotes for a POSIX shell.
fn sh(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}
