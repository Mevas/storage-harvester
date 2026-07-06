use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use std::fmt::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::cache::{SnapshotStore, TargetSnapshot};
use crate::config::{Config, SizeMode};
use crate::exporter::prometheus;
use crate::scanner::NodeObservation;

#[derive(Clone)]
pub struct ApiState {
    store: SnapshotStore,
}

pub async fn serve(config: &Config, store: SnapshotStore) -> Result<()> {
    let state = ApiState { store };
    let metrics_path = config.metrics_path.clone();
    let app = Router::new()
        .route("/", get(status_page_handler))
        .route("/status", get(status_page_handler))
        .route("/status/fragment", get(status_fragment_handler))
        .route(&metrics_path, get(metrics_handler))
        .route("/-/health", get(health_handler))
        .route("/-/ready", get(ready_handler))
        .with_state(state);

    let listener = TcpListener::bind(config.listen_address)
        .await
        .with_context(|| format!("failed to bind {}", config.listen_address))?;
    info!(address = %config.listen_address, metrics_path = %metrics_path, "storage harvester listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server failed")?;

    Ok(())
}

async fn metrics_handler(State(state): State<ApiState>) -> Response {
    let snapshots = state.store.snapshots().await;
    let body = prometheus::render(&snapshots);
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
}

async fn status_page_handler(State(state): State<ApiState>) -> Response {
    let snapshots = state.store.snapshots().await;
    html_response(render_status_page(&snapshots))
}

async fn status_fragment_handler(State(state): State<ApiState>) -> Response {
    let snapshots = state.store.snapshots().await;
    html_response(render_status_content(&snapshots))
}

fn html_response(body: String) -> Response {
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

async fn ready_handler(State(state): State<ApiState>) -> impl IntoResponse {
    if state.store.ready().await {
        (StatusCode::OK, "ready\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "initial scans pending\n")
    }
}

fn render_status_page(snapshots: &[TargetSnapshot]) -> String {
    let mut out = String::new();
    out.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    out.push_str("<title>Storage Harvester</title>");
    out.push_str(STYLE);
    out.push_str("</head><body><main id=\"dashboard\">");
    out.push_str(&render_status_content(snapshots));
    out.push_str("</main>");
    out.push_str(SCRIPT);
    out.push_str("</body></html>");
    out
}

fn render_status_content(snapshots: &[TargetSnapshot]) -> String {
    let ready = snapshots
        .iter()
        .all(|snapshot| snapshot.last_success.is_some() || snapshot.last_error.is_some());
    let successful = snapshots
        .iter()
        .filter(|snapshot| snapshot.last_error.is_none() && snapshot.last_success.is_some())
        .count();
    let failed = snapshots
        .iter()
        .filter(|snapshot| snapshot.last_error.is_some())
        .count();

    let mut out = String::new();
    out.push_str("<header class=\"hero\"><div>");
    out.push_str("<p class=\"eyebrow\">Storage Harvester</p>");
    out.push_str("<h1>Scanner Status</h1>");
    out.push_str("<p class=\"muted\">Cached scan state only. This page never triggers a synchronous filesystem scan.</p>");
    write!(
        out,
        "<p class=\"muted small\">Version {}. Live refresh every <span id=\"refresh-interval\">1</span>s. Last render: ",
        escape_html(env!("CARGO_PKG_VERSION"))
    )
    .unwrap();
    out.push_str(&escape_html(&format_age(SystemTime::now())));
    out.push_str("</p>");
    out.push_str("</div><nav><a href=\"/metrics\">Metrics</a><a href=\"/-/ready\">Readiness</a></nav></header>");

    write!(
        out,
        "<section class=\"summary\"><article><span>Total targets</span><strong>{}</strong></article><article><span>Ready</span><strong>{}</strong></article><article><span>Successful</span><strong>{}</strong></article><article><span>Failed</span><strong>{}</strong></article></section>",
        snapshots.len(),
        if ready { "yes" } else { "no" },
        successful,
        failed
    )
    .unwrap();

    out.push_str("<section class=\"panel\"><h2>Targets</h2><div class=\"table-wrap\"><table><thead><tr><th>Target</th><th>Status</th><th>Path</th><th>Last scan</th><th>Duration</th><th>Attempts</th><th>Failures</th><th>Nodes</th><th>Visited</th></tr></thead><tbody>");
    for snapshot in snapshots {
        write_target_row(&mut out, snapshot);
    }
    out.push_str("</tbody></table></div></section>");

    for snapshot in snapshots {
        write_target_detail(&mut out, snapshot);
    }

    out
}

fn write_target_row(out: &mut String, snapshot: &TargetSnapshot) {
    let status = target_status(snapshot);
    let (last_scan, duration, nodes, visited) = match &snapshot.last_success {
        Some(result) => (
            format_age(result.timestamp),
            format_duration(result.duration),
            result.observations.len().to_string(),
            format!(
                "{} dirs / {} files / {} links",
                result.scanned_directories, result.scanned_files, result.scanned_symlinks
            ),
        ),
        None => (
            "never".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
        ),
    };

    write!(
        out,
        "<tr><td><strong>{}</strong><div class=\"labels\">{}</div></td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
        escape_html(&snapshot.target_name),
        render_labels(snapshot),
        status_badge(status),
        escape_html(&snapshot.path),
        escape_html(&last_scan),
        escape_html(&duration),
        snapshot.scan_count,
        snapshot.failure_count,
        escape_html(&nodes),
        escape_html(&visited)
    )
    .unwrap();
}

fn write_target_detail(out: &mut String, snapshot: &TargetSnapshot) {
    write!(
        out,
        "<section class=\"panel\"><h2>{}</h2>",
        escape_html(&snapshot.target_name)
    )
    .unwrap();

    if let Some(error) = &snapshot.last_error {
        write!(
            out,
            "<p class=\"error\">Last error: {}</p>",
            escape_html(error)
        )
        .unwrap();
    }

    let Some(result) = &snapshot.last_success else {
        out.push_str("<p class=\"muted\">No successful scan yet.</p></section>");
        return;
    };

    write!(
        out,
        "<div class=\"facts\"><span>Backend <strong>{}</strong></span><span>Age <strong>{}</strong></span><span>Interval <strong>{}</strong></span><span>Max depth <strong>{}</strong></span><span>Depth hits <strong>{}</strong></span><span>Issues <strong>{}</strong></span></div>",
        escape_html(&result.backend),
        escape_html(&format_age(result.timestamp)),
        escape_html(&format_duration(snapshot.interval)),
        result.max_observed_depth,
        result.depth_limit_hits,
        result.permission_errors + result.missing_path_races + result.skipped_cross_device + result.skipped_excluded
    )
    .unwrap();

    let mut nodes = result.observations.iter().collect::<Vec<_>>();
    nodes.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.depth.cmp(&right.depth))
    });

    out.push_str("<div class=\"table-wrap\"><table class=\"tree-table\"><thead><tr><th>Tree</th><th>Depth</th><th>Own</th><th>Children</th><th>Total</th><th>Direct entries</th><th>Total entries</th></tr></thead><tbody>");
    for node in nodes {
        write_node_row(out, node, &snapshot.size_modes);
    }
    out.push_str("</tbody></table></div></section>");
}

fn write_node_row(out: &mut String, node: &NodeObservation, size_modes: &[SizeMode]) {
    let preferred_mode = preferred_size_mode(size_modes);
    let own = node_size(node, SizeComponent::Own, preferred_mode);
    let children = node_size(node, SizeComponent::Children, preferred_mode);
    let total = own + children;
    let total_files = node.file_count + node.children_file_count;
    let total_dirs = node.directory_count + node.children_directory_count;
    let total_links = node.symlink_count + node.children_symlink_count;

    write!(
        out,
        "<tr style=\"--depth:{}\"><td><code>{}</code><div class=\"muted small\">parent: {}</div></td><td>{}</td><td>{}</td><td>{}</td><td><strong>{}</strong></td><td>{} files / {} dirs / {} links</td><td>{} files / {} dirs / {} links</td></tr>",
        node.depth,
        escape_html(&node.path),
        escape_html(if node.parent.is_empty() { "-" } else { &node.parent }),
        node.depth,
        escape_html(&format_bytes(own)),
        escape_html(&format_bytes(children)),
        escape_html(&format_bytes(total)),
        node.file_count,
        node.directory_count,
        node.symlink_count,
        total_files,
        total_dirs,
        total_links
    )
    .unwrap();
}

fn target_status(snapshot: &TargetSnapshot) -> TargetStatus {
    if snapshot.scan_running {
        TargetStatus::Running
    } else if snapshot.last_error.is_some() {
        TargetStatus::Failed
    } else if snapshot.last_success.is_some() {
        TargetStatus::Ok
    } else {
        TargetStatus::Pending
    }
}

#[derive(Debug, Clone, Copy)]
enum TargetStatus {
    Running,
    Ok,
    Failed,
    Pending,
}

fn status_badge(status: TargetStatus) -> &'static str {
    match status {
        TargetStatus::Running => "<span class=\"badge running\">running</span>",
        TargetStatus::Ok => "<span class=\"badge ok\">ok</span>",
        TargetStatus::Failed => "<span class=\"badge failed\">failed</span>",
        TargetStatus::Pending => "<span class=\"badge pending\">pending</span>",
    }
}

fn render_labels(snapshot: &TargetSnapshot) -> String {
    if snapshot.labels.is_empty() {
        return String::new();
    }

    snapshot
        .labels
        .iter()
        .map(|(key, value)| format!("<span>{}: {}</span>", escape_html(key), escape_html(value)))
        .collect::<Vec<_>>()
        .join("")
}

#[derive(Debug, Clone, Copy)]
enum SizeComponent {
    Own,
    Children,
}

fn preferred_size_mode(size_modes: &[SizeMode]) -> SizeMode {
    if size_modes.contains(&SizeMode::Blocks) {
        SizeMode::Blocks
    } else {
        SizeMode::Apparent
    }
}

fn node_size(node: &NodeObservation, component: SizeComponent, mode: SizeMode) -> u64 {
    match (component, mode) {
        (SizeComponent::Own, SizeMode::Blocks) => node.own_blocks,
        (SizeComponent::Children, SizeMode::Blocks) => node.children_blocks,
        (SizeComponent::Own, SizeMode::Apparent) => node.own_apparent,
        (SizeComponent::Children, SizeMode::Apparent) => node.children_apparent,
    }
}

fn format_age(timestamp: SystemTime) -> String {
    match SystemTime::now().duration_since(timestamp) {
        Ok(age) => format!("{} ago", format_duration(age)),
        Err(_) => format!("{}", unix_seconds(timestamp)),
    }
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds >= 86_400 {
        format!("{}d {}h", seconds / 86_400, seconds % 86_400 / 3_600)
    } else if seconds >= 3_600 {
        format!("{}h {}m", seconds / 3_600, seconds % 3_600 / 60)
    } else if seconds >= 60 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else if seconds > 0 {
        format!("{seconds}s")
    } else {
        format!("{}ms", duration.as_millis())
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn unix_seconds(timestamp: SystemTime) -> u64 {
    timestamp
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

const STYLE: &str = r#"<style>
:root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #080b10; color: #e8edf5; }
body { margin: 0; background: radial-gradient(circle at top left, #1f3b56 0, transparent 30rem), #080b10; }
main { width: min(1280px, calc(100% - 32px)); margin: 0 auto; padding: 32px 0 48px; }
.hero { display: flex; justify-content: space-between; gap: 24px; align-items: flex-start; margin-bottom: 24px; }
.hero h1 { font-size: clamp(2rem, 6vw, 4.5rem); margin: 0; letter-spacing: -0.06em; }
.eyebrow { margin: 0 0 8px; color: #77d7c8; font-weight: 700; text-transform: uppercase; letter-spacing: 0.14em; font-size: 0.75rem; }
.muted { color: #9da9ba; }
.small { font-size: 0.82rem; }
nav { display: flex; gap: 10px; flex-wrap: wrap; }
a { color: #d7fff7; text-decoration: none; border: 1px solid #35556b; border-radius: 999px; padding: 8px 12px; background: #0f1823cc; }
.summary { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 18px; }
.summary article, .panel { background: #0d131dcc; border: 1px solid #1f3143; border-radius: 18px; box-shadow: 0 18px 50px #00000044; }
.summary article { padding: 18px; }
.summary span { display: block; color: #9da9ba; font-size: 0.85rem; }
.summary strong { display: block; margin-top: 8px; font-size: 1.9rem; }
.panel { padding: 18px; margin-top: 18px; }
.panel h2 { margin: 0 0 14px; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 0.92rem; }
th, td { padding: 11px 10px; text-align: left; border-bottom: 1px solid #1b2b3b; vertical-align: top; }
th { color: #9da9ba; font-weight: 600; white-space: nowrap; }
code { color: #d7fff7; }
.tree-table td:first-child { padding-left: calc(10px + var(--depth, 0) * 22px); }
.badge { display: inline-flex; border-radius: 999px; padding: 4px 9px; font-weight: 700; font-size: 0.78rem; }
.running { background: #162f54; color: #9fcaff; }
.ok { background: #123d33; color: #7dffd9; }
.failed { background: #4b1717; color: #ffaaa0; }
.pending { background: #3d3412; color: #ffe68a; }
.labels { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 6px; }
.labels span { color: #9da9ba; border: 1px solid #26384a; border-radius: 999px; padding: 2px 7px; font-size: 0.74rem; }
.facts { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; }
.facts span { background: #111b28; border: 1px solid #213247; border-radius: 999px; padding: 7px 10px; color: #9da9ba; }
.facts strong { color: #e8edf5; }
.error { color: #ffaaa0; background: #3a1218; border: 1px solid #68232c; border-radius: 12px; padding: 10px 12px; }
@media (max-width: 760px) { main { width: min(100% - 20px, 1280px); padding-top: 20px; } .hero { display: block; } nav { margin-top: 14px; } .summary { grid-template-columns: repeat(2, minmax(0, 1fr)); } th, td { padding: 9px 8px; } }
</style>"#;

const SCRIPT: &str = r#"<script>
(() => {
  const refreshMs = 1000;
  const dashboard = document.getElementById('dashboard');
  let inFlight = false;
  async function refresh() {
    if (inFlight || document.hidden) return;
    inFlight = true;
    try {
      const response = await fetch('/status/fragment', { cache: 'no-store' });
      if (!response.ok) return;
      dashboard.innerHTML = await response.text();
    } catch (_) {
      // Keep the last good render visible when a refresh fails.
    } finally {
      inFlight = false;
    }
  }
  setInterval(refresh, refreshMs);
})();
</script>"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_text() {
        assert_eq!(escape_html("<&>\"'"), "&lt;&amp;&gt;&quot;&#39;");
    }

    #[test]
    fn formats_bytes() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1536), "1.5 KiB");
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            error!(%error, "failed to install Ctrl-C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => error!(%error, "failed to install SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("shutdown signal received");
}
