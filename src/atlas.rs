//! The atlas: `/atlas` (the page), and the JSON and event stream it reads from every
//! harvester. All of `/api/*` allows any origin, so a page served by one harvester can read the
//! others. Reference: the API section of the README.

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::{Arc, PoisonError};
use std::time::{Duration, SystemTime};

use axum::extract::{Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use futures_util::stream::{self, Stream, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{broadcast, watch};

use crate::cache::SnapshotStore;
use crate::config::Config;
use crate::fsinfo;
use crate::live::{seconds, LiveStore, Message};

const PAGE: &str = include_str!("atlas.html");

/// What `/api/info` reports that does not change while running.
pub struct Static {
    host: String,
    display_name: String,
    peers: Vec<String>,
    metrics_url: Option<String>,
    /// `(filesystem id, used query, size query)`.
    capacity_queries: Vec<(String, String, String)>,
}

impl Static {
    pub fn new(config: &Config, host: String) -> Self {
        let capacity_queries = config
            .atlas
            .capacity_queries
            .iter()
            .filter_map(|query| {
                let relative = query.path.strip_prefix("/").unwrap_or(&query.path);
                let scan: PathBuf = config.host_root.join(relative);
                let location = fsinfo::locate(&scan, &config.host_root)?;
                Some((location.id, query.used.clone(), query.size.clone()))
            })
            .collect();
        Self {
            display_name: config.display_name.clone().unwrap_or_else(|| host.clone()),
            host,
            peers: config.atlas.peers.clone(),
            metrics_url: config.atlas.metrics_url.clone(),
            capacity_queries,
        }
    }
}

#[derive(Clone)]
pub struct AtlasState {
    pub live: Arc<LiveStore>,
    pub store: SnapshotStore,
    pub info: Arc<Static>,
    pub stop: watch::Receiver<bool>,
}

pub fn routes(state: AtlasState) -> Router {
    let api = Router::new()
        .route("/api/info", get(info))
        .route("/api/tree", get(tree))
        .route("/api/events", get(events))
        .layer(axum::middleware::map_response(allow_any_origin));
    Router::new()
        .route("/atlas", get(page))
        .merge(api)
        .with_state(state)
}

async fn allow_any_origin(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

async fn page() -> Response {
    let mut response = PAGE.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

async fn info(State(state): State<AtlasState>) -> Response {
    let scans = state.store.summaries().await;
    let mut filesystems: BTreeMap<String, Value> = BTreeMap::new();
    let mut targets = Vec::new();
    for lt in &state.live.targets {
        let target = &lt.target;
        let location = lt.location.as_ref();
        if let Some(location) = location {
            if !filesystems.contains_key(&location.id) {
                if let Some(usage) = fsinfo::usage(&target.scan_path) {
                    filesystems.insert(
                        location.id.clone(),
                        json!({
                            "id": location.id, "type": location.fstype, "mount": location.mount,
                            "size": usage.size, "used": usage.used, "avail": usage.avail,
                            "reserved": usage.reserved,
                        }),
                    );
                }
            }
        }
        let (live_at, total) = {
            let guard = lt.state.read().unwrap_or_else(PoisonError::into_inner);
            match guard.as_ref() {
                Some(tree_state) => {
                    let root = tree_state.tree.root();
                    (
                        tree_state.live_at.map(seconds),
                        json!({
                            "blocks": root.total_blocks(), "apparent": root.total_apparent(),
                            "files": root.sub.files, "dirs": root.sub.dirs,
                            "symlinks": root.sub.symlinks,
                        }),
                    )
                }
                None => (None, Value::Null),
            }
        };
        let sharing = lt
            .sharing
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|report| {
                json!({
                    "at": seconds(report.at), "duration_s": report.duration.as_secs_f64(),
                    "logical": report.logical, "disk": report.disk, "outside": report.outside,
                    "pairs": report.pairs.iter().map(|(a, b, bytes)| json!({"a": a, "b": b, "bytes": bytes})).collect::<Vec<_>>(),
                })
            });
        let scan = scans.get(&target.name);
        let source = *lt.source.lock().unwrap_or_else(PoisonError::into_inner);
        targets.push(json!({
            "name": target.name,
            "path": target.display_path.display().to_string(),
            "labels": target.labels,
            "fs": location.map(|l| l.id.clone()),
            "fs_path": location.map(|l| l.fs_path.clone()),
            "interval_s": target.baseline_interval.as_secs(),
            "scan_running": scan.is_some_and(|s| s.running),
            "last_scan": scan.and_then(|s| s.last_scan).map(seconds),
            "scan_duration_s": scan.and_then(|s| s.duration).map(|d| d.as_secs_f64()),
            "last_error": scan.and_then(|s| s.last_error.clone()),
            "live": source.is_some(),
            "live_source": source,
            "live_at": live_at,
            "total": total,
            "sharing": sharing,
        }));
    }
    let info = &state.info;
    Json(json!({
        "host": info.host,
        "display_name": info.display_name,
        "version": env!("CARGO_PKG_VERSION"),
        "now": seconds(SystemTime::now()),
        "atlas": { "peers": info.peers, "metrics_url": info.metrics_url },
        "live": state.live.summary(),
        "filesystems": filesystems.into_values().collect::<Vec<_>>(),
        "capacity_queries": info.capacity_queries.iter().map(|(fs, used, size)| json!({"fs": fs, "used": used, "size": size})).collect::<Vec<_>>(),
        "targets": targets,
    }))
    .into_response()
}

async fn tree(
    State(state): State<AtlasState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let Some(name) = params.get("target") else {
        return error(StatusCode::BAD_REQUEST, "target is required");
    };
    let Some(lt) = state.live.target(name) else {
        return error(StatusCode::NOT_FOUND, "unknown target");
    };
    let number = |key: &str| params.get(key).and_then(|value| value.parse::<u64>().ok());
    let limit = number("limit").unwrap_or(2500).clamp(1, 20_000) as usize;
    let depth = number("depth").unwrap_or(8).clamp(1, 64) as u32;
    let sharing = lt
        .sharing
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let guard = lt.state.read().unwrap_or_else(PoisonError::into_inner);
    let Some(tree_state) = guard.as_ref() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "no scan yet");
    };
    let tree = &tree_state.tree;
    let start = match params.get("path") {
        Some(path) => match tree.find(path) {
            Some(node) => node,
            None => return error(StatusCode::NOT_FOUND, "path not in the tree"),
        },
        None => 0,
    };
    let min_bytes = number("min_bytes").unwrap_or(tree.nodes[start as usize].total_blocks() / 4000);
    let node = tree.pruned(
        start,
        limit,
        depth,
        min_bytes,
        sharing.as_ref().map(|report| &report.by_ino),
    );
    Json(json!({
        "host": state.live.host,
        "target": lt.target.name,
        "path": tree.display_path(start),
        "scanned_at": seconds(tree_state.scanned_at),
        "live_at": tree_state.live_at.map(seconds),
        "sharing_at": sharing.as_ref().map(|report| seconds(report.at)),
        "node": node,
    }))
    .into_response()
}

async fn events(
    State(state): State<AtlasState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let receiver = state.live.subscribe();
    let hello = json!({
        "host": state.live.host,
        "live": state.live.summary(),
        "now": seconds(SystemTime::now()),
    });
    let mut first = vec![Event::default().event("hello").data(hello.to_string())];
    for message in state.live.recent() {
        // `{...}` → `{"replay":true,...}`
        let data = format!("{{\"replay\":true,{}", &message.data[1..]);
        first.push(Event::default().event(message.kind).data(data));
    }
    let live = stream::unfold(receiver, |mut receiver| async move {
        loop {
            match receiver.recv().await {
                Ok(Message { kind, data }) => {
                    return Some((Event::default().event(kind).data(&*data), receiver))
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    let mut stop = state.stop.clone();
    let stream = stream::iter(first)
        .chain(live)
        .map(Ok)
        .take_until(async move {
            let _ = stop.wait_for(|stopping| *stopping).await;
        });
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    )
}
