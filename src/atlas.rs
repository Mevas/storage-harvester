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
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Request, StatusCode, Uri};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use futures_util::stream::{self, Stream, StreamExt};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::{json, Value};
use tokio::sync::{broadcast, watch, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

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
    /// Upstream requests in flight, event streams included.
    relay_slots: Arc<Semaphore>,
}

/// At most this many relayed requests at once; more get 503.
const RELAY_SLOTS: usize = 64;
/// How long an upstream may take to answer, and to send a whole finite answer.
const RELAY_ANSWER: Duration = Duration::from_secs(30);
const RELAY_BODY: Duration = Duration::from_secs(120);
/// How long a relayed stream may go quiet; event streams send a keepalive every 15 s.
const RELAY_IDLE: Duration = Duration::from_secs(45);

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
            relay_slots: Arc::new(Semaphore::new(RELAY_SLOTS)),
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

/// Forwards one GET, streaming the answer back (event streams included). A finite answer gets
/// `RELAY_BODY` in all; any answer ends after `RELAY_IDLE` without data, and at shutdown.
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
    let Ok(slot) = Arc::clone(&state.info.relay_slots).try_acquire_owned() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "relay busy");
    };
    let mut request = Request::get(uri);
    for name in [header::ACCEPT, header::CACHE_CONTROL] {
        if let Some(value) = headers.get(&name) {
            request = request.header(name, value);
        }
    }
    let Ok(request) = request.body(Body::empty()) else {
        return error(StatusCode::BAD_GATEWAY, "bad upstream request");
    };
    let mut stop = state.stop.clone();
    let answer = tokio::select! {
        answer = tokio::time::timeout(RELAY_ANSWER, state.info.relay.request(request)) => answer,
        _ = stop.wait_for(|stopping| *stopping) => {
            return error(StatusCode::SERVICE_UNAVAILABLE, "shutting down");
        }
    };
    let response = match answer {
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
    strip_hop_by_hop(&mut parts.headers);
    // Set again by this harvester's own middleware.
    parts.headers.remove(header::ACCESS_CONTROL_ALLOW_ORIGIN);
    let streaming = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|kind| kind.starts_with("text/event-stream"));
    let deadline = (!streaming).then(|| Instant::now() + RELAY_BODY);
    let body = bounded(
        Body::new(body),
        RELAY_IDLE,
        deadline,
        state.stop.clone(),
        slot,
    );
    Response::from_parts(parts, body)
}

/// Headers that describe one connection, not the answer (RFC 9110 7.6.1), plus any the
/// `Connection` header names.
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

/// `body`, relayed by a task of its own that ends it after `idle` without progress (no data
/// from upstream, or a reader that stopped reading), at `deadline`, or at shutdown, whether or
/// not anyone is polling the answer. The task holds `slot` until it ends.
fn bounded(
    body: Body,
    idle: Duration,
    deadline: Option<Instant>,
    mut stop: watch::Receiver<bool>,
    slot: OwnedSemaphorePermit,
) -> Body {
    let (sender, mut receiver) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        let _slot = slot;
        let mut data = body.into_data_stream();
        let limit = || {
            let next = Instant::now() + idle;
            deadline.map_or(next, |deadline| next.min(deadline))
        };
        loop {
            let chunk = tokio::select! {
                next = tokio::time::timeout_at(limit(), data.next()) => match next {
                    Ok(Some(chunk)) => chunk,
                    _ => break,
                },
                _ = stop.wait_for(|stopping| *stopping) => break,
            };
            let sent = tokio::select! {
                sent = tokio::time::timeout_at(limit(), sender.send(chunk)) => sent,
                _ = stop.wait_for(|stopping| *stopping) => break,
            };
            if !matches!(sent, Ok(Ok(()))) {
                break;
            }
        }
    });
    Body::from_stream(stream::poll_fn(move |context| receiver.poll_recv(context)))
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

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use axum::body::Bytes;

    use super::*;

    #[test]
    fn hop_by_hop_headers_and_the_ones_connection_names_are_dropped() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static("X-Upstream-State, keep-alive"),
        );
        headers.append(header::CONNECTION, HeaderValue::from_static("close"));
        headers.insert("x-upstream-state", HeaderValue::from_static("1"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert(header::TE, HeaderValue::from_static("trailers"));
        headers.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        strip_hop_by_hop(&mut headers);
        let left: Vec<&str> = headers.keys().map(|name| name.as_str()).collect();
        assert_eq!(left, ["content-type"]);
    }

    fn one_slot() -> (Arc<Semaphore>, OwnedSemaphorePermit) {
        let slots = Arc::new(Semaphore::new(1));
        let slot = Arc::clone(&slots).try_acquire_owned().unwrap();
        (slots, slot)
    }

    async fn chunks(body: Body) -> usize {
        body.into_data_stream().count().await
    }

    /// A reader that stops reading (but stays connected) does not hold its slot: the relay
    /// gives up on it after the idle time, and at shutdown, without being polled.
    #[tokio::test]
    async fn a_reader_that_stops_reading_releases_its_slot() {
        for shutdown in [false, true] {
            let (stop_tx, stop) = watch::channel(false);
            let (slots, slot) = one_slot();
            let endless = stream::repeat_with(|| Ok::<_, Infallible>(Bytes::from_static(b"x")));
            let idle = if shutdown {
                Duration::from_secs(30)
            } else {
                Duration::from_millis(100)
            };
            let body = bounded(Body::from_stream(endless), idle, None, stop, slot);
            if shutdown {
                stop_tx.send(true).unwrap();
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert_eq!(slots.available_permits(), 1, "shutdown: {shutdown}");
            drop(body);
        }
    }

    /// An upstream that sends headers and then nothing more is cut off, and its slot is free
    /// again; so is one that never stops sending, at the deadline, and any at shutdown.
    #[tokio::test]
    async fn relayed_bodies_end_when_stalled_overdue_or_shutting_down() {
        let (_stop_tx, stop) = watch::channel(false);
        let (slots, slot) = one_slot();
        let stalled = stream::once(async { Ok::<_, Infallible>(Bytes::from_static(b"{")) })
            .chain(stream::pending());
        let started = Instant::now();
        let body = bounded(
            Body::from_stream(stalled),
            Duration::from_millis(100),
            None,
            stop.clone(),
            slot,
        );
        assert_eq!(chunks(body).await, 1);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(slots.available_permits(), 1, "the slot is released");

        let (_, slot) = one_slot();
        let endless = stream::unfold((), |()| async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Some((Ok::<_, Infallible>(Bytes::from_static(b"x")), ()))
        });
        let body = bounded(
            Body::from_stream(endless),
            Duration::from_secs(10),
            Some(Instant::now() + Duration::from_millis(300)),
            stop.clone(),
            slot,
        );
        let sent = chunks(body).await;
        assert!((5..30).contains(&sent), "{sent} chunks");

        let (stop_tx, stop) = watch::channel(false);
        let (_, slot) = one_slot();
        let body = bounded(
            Body::from_stream(stream::pending::<Result<Bytes, Infallible>>()),
            Duration::from_secs(10),
            None,
            stop,
            slot,
        );
        let reader = tokio::spawn(chunks(body));
        tokio::time::sleep(Duration::from_millis(50)).await;
        stop_tx.send(true).unwrap();
        let read = tokio::time::timeout(Duration::from_secs(2), reader).await;
        assert_eq!(read.unwrap().unwrap(), 0);
    }
}
