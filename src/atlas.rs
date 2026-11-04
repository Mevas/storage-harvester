//! The atlas: `/atlas` (the page), and the JSON and event stream it reads from every
//! harvester. All of `/api/*` allows any origin, so a page served by one harvester can read the
//! others. The harvester serving the page also relays its peers and the metrics store, so the
//! page works from one origin (HTTPS behind a reverse proxy, a phone). Reference: the API
//! section of the README.

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::{Arc, PoisonError};
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::extract::{Path, Query, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode, Uri};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use futures_util::stream::{self, Stream, StreamExt};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::{json, Value};
use tokio::sync::{broadcast, watch};

use crate::cache::SnapshotStore;
use crate::config::Config;
use crate::fsinfo;
use crate::live::{seconds, LiveStore, Message};

const PAGE: &str = include_str!("atlas.html");

/// What `/atlas/<file>` serves besides the page: the web app manifest and its icons.
const ASSETS: &[(&str, &str, &[u8])] = &[
    (
        "manifest.webmanifest",
        "application/manifest+json",
        include_bytes!("atlas/manifest.webmanifest"),
    ),
    (
        "icon-192.png",
        "image/png",
        include_bytes!("atlas/icon-192.png"),
    ),
    (
        "icon-512.png",
        "image/png",
        include_bytes!("atlas/icon-512.png"),
    ),
    (
        "icon-maskable-512.png",
        "image/png",
        include_bytes!("atlas/icon-maskable-512.png"),
    ),
    (
        "apple-touch-icon.png",
        "image/png",
        include_bytes!("atlas/apple-touch-icon.png"),
    ),
];

/// The VictoriaMetrics (Prometheus API) paths the relay passes on: reads only.
fn metrics_path_allowed(rest: &str) -> bool {
    match rest {
        "api/v1/query" | "api/v1/query_range" | "api/v1/series" | "api/v1/labels" => true,
        _ => rest
            .strip_prefix("api/v1/label/")
            .and_then(|tail| tail.strip_suffix("/values"))
            .is_some_and(|name| {
                !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            }),
    }
}

/// What `/api/info` reports that does not change while running.
pub struct Static {
    host: String,
    display_name: String,
    peers: Vec<String>,
    metrics_url: Option<String>,
    /// `(filesystem id, used query, size query)`.
    capacity_queries: Vec<(String, String, String)>,
    machine_uuid: Option<String>,
    block_poll: Duration,
    relay: Client<HttpConnector, Body>,
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
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(Duration::from_secs(5)));
        Self {
            display_name: config.display_name.clone().unwrap_or_else(|| host.clone()),
            host,
            peers: config.atlas.peers.clone(),
            metrics_url: config.atlas.metrics_url.clone(),
            capacity_queries,
            machine_uuid: fsinfo::machine_uuid(&config.host_root),
            block_poll: config.live.block_poll_interval,
            relay: Client::builder(TokioExecutor::new())
                .pool_idle_timeout(Duration::from_secs(30))
                .build(connector),
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
        .route("/api/peer/:index/*rest", get(peer))
        .route("/api/metrics/*rest", get(metrics))
        .layer(axum::middleware::map_response(allow_any_origin));
    Router::new()
        .route("/atlas", get(page))
        .route("/atlas/:file", get(asset))
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

async fn asset(Path(file): Path<String>) -> Response {
    let Some((_, kind, bytes)) = ASSETS.iter().find(|(name, _, _)| *name == file) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut response = bytes.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(kind));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400"),
    );
    response
}

/// `/api/peer/<i>/<rest>`: `GET atlas.peers[i]/<rest>`, for the harvester API only.
async fn peer(
    State(state): State<AtlasState>,
    Path((index, rest)): Path<(usize, String)>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let Some(base) = state.info.peers.get(index) else {
        return error(StatusCode::NOT_FOUND, "no such peer");
    };
    if !matches!(rest.as_str(), "api/info" | "api/tree" | "api/events") {
        return error(
            StatusCode::NOT_FOUND,
            "the relay passes /api/info, /api/tree and /api/events",
        );
    }
    relay(&state, base, &rest, query, &headers).await
}

/// `/api/metrics/<rest>`: `GET atlas.metrics_url/<rest>`, for read-only query paths.
async fn metrics(
    State(state): State<AtlasState>,
    Path(rest): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let Some(base) = state.info.metrics_url.as_deref() else {
        return error(StatusCode::NOT_FOUND, "no metrics_url configured");
    };
    if !metrics_path_allowed(&rest) {
        return error(
            StatusCode::NOT_FOUND,
            "the relay passes read-only query paths",
        );
    }
    relay(&state, base, &rest, query, &headers).await
}

/// Forwards one GET, streaming the answer back (event streams included) until shutdown.
async fn relay(
    state: &AtlasState,
    base: &str,
    rest: &str,
    query: Option<String>,
    headers: &HeaderMap,
) -> Response {
    let mut url = format!("{}/{rest}", base.trim_end_matches('/'));
    if let Some(query) = query {
        url.push('?');
        url.push_str(&query);
    }
    let Ok(uri) = url.parse::<Uri>() else {
        return error(StatusCode::BAD_GATEWAY, "bad upstream URL");
    };
    if uri.scheme_str() != Some("http") {
        return error(
            StatusCode::BAD_GATEWAY,
            "the relay reaches http:// upstreams only",
        );
    }
    let mut request = Request::get(uri);
    for name in [header::ACCEPT, header::CACHE_CONTROL] {
        if let Some(value) = headers.get(&name) {
            request = request.header(name, value);
        }
    }
    let Ok(request) = request.body(Body::empty()) else {
        return error(StatusCode::BAD_GATEWAY, "bad upstream request");
    };
    let response = match tokio::time::timeout(
        Duration::from_secs(30),
        state.info.relay.request(request),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(failure)) => {
            let cause = std::error::Error::source(&failure)
                .map(|cause| cause.to_string())
                .unwrap_or_else(|| failure.to_string());
            return error(StatusCode::BAD_GATEWAY, &format!("upstream: {cause}"));
        }
        Err(_) => return error(StatusCode::GATEWAY_TIMEOUT, "upstream did not answer"),
    };
    let (mut parts, body) = response.into_parts();
    for name in [
        header::CONNECTION,
        header::TRANSFER_ENCODING,
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
    ] {
        parts.headers.remove(name);
    }
    let mut stop = state.stop.clone();
    let stream = Body::new(body).into_data_stream().take_until(async move {
        let _ = stop.wait_for(|stopping| *stopping).await;
    });
    Response::from_parts(parts, Body::from_stream(stream))
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
                            "reserved": usage.reserved, "disks": location.disks,
                        }),
                    );
                }
            }
        }
        // A thin pool is its own filesystem; the tree holds what is known of it.
        let mut guests = None;
        let (live_at, total) = {
            let guard = lt.state.read().unwrap_or_else(PoisonError::into_inner);
            match guard.as_ref() {
                Some(tree_state) => {
                    let tree = &tree_state.tree;
                    if let Some(pool) = &tree.pool {
                        filesystems.insert(pool.id.clone(), pool.filesystem_json());
                        guests = Some(pool.guests_json(tree));
                    }
                    let root = tree.root();
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
        let (fs, fs_path) = match (&target.lvm, location) {
            (Some(lvm), _) => (Some(lvm.fs_id()), Some("/".to_string())),
            (None, Some(location)) => (Some(location.id.clone()), Some(location.fs_path.clone())),
            (None, None) => (None, None),
        };
        let mut entry = json!({
            "name": target.name,
            "kind": if target.lvm.is_some() { "lvm_thin" } else { "directory" },
            "path": target.display_path.display().to_string(),
            "labels": target.labels,
            "fs": fs,
            "fs_path": fs_path,
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
        });
        if target.lvm.is_some() {
            entry["poll_s"] = json!(state.info.block_poll.as_secs_f64());
            entry["guests"] = guests.unwrap_or(json!([]));
        }
        targets.push(entry);
    }
    let info = &state.info;
    Json(json!({
        "host": info.host,
        "display_name": info.display_name,
        "version": env!("CARGO_PKG_VERSION"),
        "now": seconds(SystemTime::now()),
        "machine": info.machine_uuid.as_ref().map(|uuid| json!({ "uuid": uuid })),
        "atlas": { "peers": info.peers, "metrics_url": info.metrics_url, "proxy": true },
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
