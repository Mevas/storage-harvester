//! The atlas: `/atlas` (the page), and the JSON and event stream it reads from every
//! harvester. All of `/api/*` allows any origin, so a page served by one harvester can read the
//! others. The harvester serving the page also relays its peers and the metrics store, so the
//! page works from one origin (HTTPS behind a reverse proxy, a phone). Reference: the API
//! section of the README.

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
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
use crate::config::{Config, Target};
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
    /// The hypervisor this machine is a guest of (`qemu`, ...), `None` on bare metal.
    machine_virt: Option<String>,
    host_root: PathBuf,
    /// btrfs volume facts by filesystem id, with when they were read: [`btrfs_facts`].
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    btrfs: Mutex<HashMap<String, (std::time::Instant, Value)>>,
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
            machine_virt: fsinfo::machine_virt(&config.host_root),
            host_root: config.host_root.clone(),
            btrfs: Mutex::new(HashMap::new()),
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
        .route("/api/files", get(files))
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
    if !matches!(
        rest.as_str(),
        "api/info" | "api/tree" | "api/files" | "api/events"
    ) {
        return error(
            StatusCode::NOT_FOUND,
            "the relay passes /api/info, /api/tree, /api/files and /api/events",
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
                // The reader went away (a tab closed): let go of the upstream now.
                _ = sender.closed() => break,
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

/// Whether a walk of `outer` reaches `inner`'s root: inside it, through no excluded path, no
/// symlink (unless followed), and no other device when the walk stays on one. On btrfs each
/// subvolume is its own device, so a share's target is not inside the volume's.
fn walks_into(outer: &Target, inner: &Target, exclude: &globset::GlobSet) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(rel) = inner.display_path.strip_prefix(&outer.display_path) else {
        return false;
    };
    let root_dev = std::fs::metadata(&outer.scan_path).map(|m| m.dev()).ok();
    let (mut display, mut scan) = (outer.display_path.clone(), outer.scan_path.clone());
    for part in rel.components() {
        display.push(part);
        scan.push(part);
        if exclude.is_match(&display) {
            return false;
        }
        let Ok(meta) = std::fs::symlink_metadata(&scan) else {
            return false;
        };
        if meta.file_type().is_symlink() && !outer.follow_symlinks {
            return false;
        }
        if outer.no_cross_filesystem && root_dev.is_some() && Some(meta.dev()) != root_dev {
            return false;
        }
    }
    // `dir/**` excludes everything in `dir` but not `dir` itself.
    !exclude.is_match(display.join(".storage-harvester-probe"))
}

/// For each target, the targets inside it by path that its walk does not reach: the atlas
/// draws those beside it instead of inside it.
fn skipped_targets(targets: &[&Target]) -> HashMap<String, Vec<String>> {
    let mut skips: HashMap<String, Vec<String>> = HashMap::new();
    for outer in targets {
        if outer.lvm.is_some() {
            continue;
        }
        let Ok(exclude) = crate::scanner::native::exclude_set(&outer.exclude) else {
            continue;
        };
        for inner in targets {
            if inner.name == outer.name
                || inner.lvm.is_some()
                || !inner.display_path.starts_with(&outer.display_path)
            {
                continue;
            }
            if !walks_into(outer, inner, &exclude) {
                skips
                    .entry(outer.name.clone())
                    .or_default()
                    .push(inner.name.clone());
            }
        }
    }
    skips
}

/// A btrfs volume's space as btrfs keeps it, and its subvolumes that no target walks, grouped
/// by the folder they are in (`/volume2/@docker/btrfs/subvolumes`: 279, all snapshots). Read
/// at most once a minute. `targets` are `(fs_path, display path, mount)` of the targets on it.
#[cfg(target_os = "linux")]
fn btrfs_facts(
    info: &Static,
    id: &str,
    path: &std::path::Path,
    targets: &[(String, String, String)],
) -> Option<Value> {
    use crate::btrfs;
    let mut cache = info.btrfs.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((at, value)) = cache.get(id) {
        if at.elapsed() < Duration::from_secs(60) {
            return Some(value.clone());
        }
    }
    let mut value = btrfs::space(path).ok()?.to_json();
    if let Ok(subvolumes) = btrfs::subvolumes(path) {
        // The mount's root inside the volume (`/@syno` for `/volume1`), from any target.
        let (mount_root, mount) = targets
            .iter()
            .find_map(|(fs_path, display, mount)| {
                Some((mount_root(fs_path, display, mount)?, mount.clone()))
            })
            .unwrap_or_default();
        let shown = |path: &str| match path.strip_prefix(mount_root.as_str()) {
            Some(rest) if mount_root.is_empty() || rest.is_empty() || rest.starts_with('/') => {
                format!("{}{}", mount.trim_end_matches('/'), rest)
            }
            _ => format!("(volume) {path}"),
        };
        let mut groups: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        for subvolume in &subvolumes {
            if targets
                .iter()
                .any(|(fs_path, _, _)| *fs_path == subvolume.path)
            {
                continue;
            }
            let parent = subvolume
                .path
                .rsplit_once('/')
                .map(|(p, _)| p)
                .unwrap_or("");
            let group = groups
                .entry(shown(if parent.is_empty() { "/" } else { parent }))
                .or_default();
            group.0 += 1;
            group.1 += u64::from(subvolume.snapshot);
        }
        value["subvolumes"] = json!(subvolumes.len());
        value["unwalked"] = json!(groups
            .into_iter()
            .map(|(dir, (count, snapshots))| json!({"in": dir, "count": count, "snapshots": snapshots}))
            .collect::<Vec<_>>());
    }
    cache.insert(id.to_string(), (std::time::Instant::now(), value.clone()));
    Some(value)
}

/// The path inside the volume of the directory mounted at `mount`, from one target on that
/// mount: `/@syno` for `/@syno/data` shown as `/volume1/data` with `/volume1` mounted.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn mount_root(fs_path: &str, display: &str, mount: &str) -> Option<String> {
    let tail = display.strip_prefix(mount.trim_end_matches('/'))?;
    if !(tail.is_empty() || tail.starts_with('/')) {
        return None;
    }
    let tail = tail.trim_end_matches('/');
    Some(
        fs_path
            .trim_end_matches('/')
            .strip_suffix(tail)?
            .to_string(),
    )
}

#[cfg(not(target_os = "linux"))]
fn btrfs_facts(
    _: &Static,
    _: &str,
    _: &std::path::Path,
    _: &[(String, String, String)],
) -> Option<Value> {
    None
}

async fn info(State(state): State<AtlasState>) -> Response {
    let scans = state.store.summaries().await;
    let mut filesystems: BTreeMap<String, Value> = BTreeMap::new();
    let mut targets = Vec::new();
    let all: Vec<&Target> = state.live.targets.iter().map(|lt| &lt.target).collect();
    let skips = skipped_targets(&all);
    for lt in &state.live.targets {
        let target = &lt.target;
        let location = lt.location.as_ref();
        if let Some(location) = location {
            if !filesystems.contains_key(&location.id) {
                if let Some(usage) = fsinfo::usage(&target.scan_path) {
                    let mut entry = json!({
                        "id": location.id, "type": location.fstype, "mount": location.mount,
                        "size": usage.size, "used": usage.used, "avail": usage.avail,
                        "reserved": usage.reserved, "disks": location.disks,
                    });
                    if lt.btrfs {
                        let on: Vec<(String, String, String)> = state
                            .live
                            .targets
                            .iter()
                            .filter(|o| o.location.as_ref().is_some_and(|l| l.id == location.id))
                            .filter_map(|o| {
                                let l = o.location.as_ref()?;
                                Some((
                                    l.fs_path.clone(),
                                    o.target.display_path.display().to_string(),
                                    l.mount.clone(),
                                ))
                            })
                            .collect();
                        if let Some(facts) =
                            btrfs_facts(&state.info, &location.id, &target.scan_path, &on)
                        {
                            entry["btrfs"] = facts;
                        }
                    }
                    filesystems.insert(location.id.clone(), entry);
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
        if let Some(skipped) = skips.get(&target.name) {
            entry["skips"] = json!(skipped);
        }
        if target.lvm.is_some() {
            entry["poll_s"] = json!(state.info.block_poll.as_secs_f64());
            entry["guests"] = guests.unwrap_or(json!([]));
        }
        targets.push(entry);
    }
    let info = &state.info;
    // The disks under this machine's own filesystems (not a thin pool's), partition by
    // partition: what a VM's disk holds besides the scanned files.
    let block_ids: Vec<String> = filesystems
        .values()
        .filter(|fs| fs["type"] != "lvmthin")
        .filter_map(|fs| fs["id"].as_str().map(str::to_string))
        .collect();
    let disks: Vec<Value> = fsinfo::layout(&block_ids, &info.host_root)
        .iter()
        .map(fsinfo::Block::to_json)
        .collect();
    let machine = json!({ "uuid": info.machine_uuid, "virt": info.machine_virt, "disks": disks });
    Json(json!({
        "host": info.host,
        "display_name": info.display_name,
        "version": env!("CARGO_PKG_VERSION"),
        "now": seconds(SystemTime::now()),
        "machine": machine,
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

/// `/api/files?target=<name>&path=<folder>[&limit=N]`: the files directly in one folder (not
/// in its subfolders), biggest first, read from disk when asked: names, sizes, times and link
/// counts, never contents. The folder must be one the target's tree holds, so a path can only
/// name a folder the harvester already walks; entries follow the walk's rules (excludes,
/// filesystem boundary, symlinks).
async fn files(
    State(state): State<AtlasState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let Some(name) = params.get("target") else {
        return error(StatusCode::BAD_REQUEST, "target is required");
    };
    let Some(path) = params.get("path") else {
        return error(StatusCode::BAD_REQUEST, "path is required");
    };
    let Some(lt) = state.live.target(name) else {
        return error(StatusCode::NOT_FOUND, "unknown target");
    };
    let limit = params
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(FILES_LIMIT)
        .clamp(1, FILES_MAX);
    let (scan, root_dev) = {
        let guard = lt.state.read().unwrap_or_else(PoisonError::into_inner);
        let Some(tree_state) = guard.as_ref() else {
            return error(StatusCode::SERVICE_UNAVAILABLE, "no scan yet");
        };
        let tree = &tree_state.tree;
        // A thin pool's nodes are guests and disks, not folders on this machine.
        if tree.pool.is_some() {
            return error(StatusCode::NOT_FOUND, "files in a thin pool are not listed");
        }
        let Some(node) = tree.find(path) else {
            return error(StatusCode::NOT_FOUND, "path not in the tree");
        };
        (tree.scan_path(node), tree.root_dev)
    };
    let rules = Arc::clone(lt);
    let display = path.clone();
    let listed = tokio::task::spawn_blocking(move || {
        list_files(&scan, display.as_bytes(), &rules, root_dev, limit)
    })
    .await;
    match listed {
        Ok(Ok(listing)) => Json(json!({
            "host": state.live.host,
            "target": name,
            "path": path,
            "files": listing.files.iter().map(|file| json!({
                "n": file.name,
                "b": file.blocks,
                "a": file.apparent,
                "m": file.mtime,
                "l": file.links,
                "s": file.symlink,
            })).collect::<Vec<_>>(),
            "count": listing.count,
            "bytes": listing.blocks,
            "apparent": listing.apparent,
            "partial": listing.partial,
        }))
        .into_response(),
        Ok(Err(failure)) if failure.kind() == std::io::ErrorKind::NotFound => {
            error(StatusCode::NOT_FOUND, "the folder is gone")
        }
        Ok(Err(failure)) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("cannot read the folder: {failure}"),
        ),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "listing failed"),
    }
}

/// `/api/files` lists this many files unless asked, and at most `FILES_MAX`.
const FILES_LIMIT: usize = 400;
const FILES_MAX: usize = 5000;
/// A folder with more entries than this is listed in part: the first ones read.
const FILES_SCAN_MAX: u64 = 200_000;

struct FileEntry {
    name: String,
    blocks: u64,
    apparent: u64,
    mtime: i64,
    links: u64,
    symlink: bool,
}

/// One folder's non-directory entries: the biggest `limit` (by allocated bytes), and the count
/// and totals of all of them.
struct FileListing {
    files: Vec<FileEntry>,
    count: u64,
    blocks: u64,
    apparent: u64,
    partial: bool,
}

fn list_files(
    scan: &[u8],
    display: &[u8],
    lt: &crate::live::LiveTarget,
    root_dev: u64,
    limit: usize,
) -> std::io::Result<FileListing> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let target = &lt.target;
    let exclude = lt.exclude();
    let mut listing = FileListing {
        files: Vec::new(),
        count: 0,
        blocks: 0,
        apparent: 0,
        partial: false,
    };
    let mut seen = 0u64;
    let mut at = display.to_vec();
    if at.last() != Some(&b'/') {
        at.push(b'/');
    }
    let base = at.len();
    // A folder the scan walked that has since become a symlink is not followed out of the target.
    if !target.follow_symlinks
        && std::fs::symlink_metadata(OsStr::from_bytes(scan))?
            .file_type()
            .is_symlink()
    {
        return Err(std::io::ErrorKind::NotFound.into());
    }
    for entry in std::fs::read_dir(OsStr::from_bytes(scan))? {
        seen += 1;
        if seen > FILES_SCAN_MAX {
            listing.partial = true;
            break;
        }
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        if !exclude.is_empty() {
            at.truncate(base);
            at.extend_from_slice(name.as_bytes());
            if exclude.is_match(std::path::Path::new(OsStr::from_bytes(&at))) {
                continue;
            }
        }
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let meta = if kind.is_symlink() && target.follow_symlinks {
            std::fs::metadata(entry.path())
        } else {
            entry.metadata()
        };
        let Ok(meta) = meta else { continue };
        if meta.is_dir() || (target.no_cross_filesystem && meta.dev() != root_dev) {
            continue;
        }
        let blocks = meta.blocks().saturating_mul(512);
        listing.count += 1;
        listing.blocks = listing.blocks.saturating_add(blocks);
        listing.apparent = listing.apparent.saturating_add(meta.len());
        listing.files.push(FileEntry {
            name: name.to_string_lossy().into_owned(),
            blocks,
            apparent: meta.len(),
            mtime: meta.mtime(),
            links: meta.nlink(),
            symlink: kind.is_symlink(),
        });
    }
    let order = |a: &FileEntry, b: &FileEntry| {
        b.blocks
            .cmp(&a.blocks)
            .then(b.apparent.cmp(&a.apparent))
            .then_with(|| a.name.cmp(&b.name))
    };
    if listing.files.len() > limit {
        listing.files.select_nth_unstable_by(limit, order);
        listing.files.truncate(limit);
    }
    listing.files.sort_unstable_by(order);
    Ok(listing)
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

    #[test]
    fn a_target_says_where_its_volume_is_mounted() {
        let root = super::mount_root;
        assert_eq!(
            root("/@syno/data", "/volume1/data", "/volume1").as_deref(),
            Some("/@syno")
        );
        assert_eq!(
            root("/@syno", "/volume1", "/volume1").as_deref(),
            Some("/@syno")
        );
        assert_eq!(
            root("/", "/mnt/scratch", "/mnt/scratch").as_deref(),
            Some("")
        );
        assert_eq!(root("/var/log", "/var/log", "/").as_deref(), Some(""));
        assert_eq!(root("/x", "/volume10/x", "/volume1"), None);
    }

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

        // A tab closes while the upstream is quiet: the upstream is let go at once.
        let (_stop_tx, stop) = watch::channel(false);
        let (slots, slot) = one_slot();
        let body = bounded(
            Body::from_stream(stream::pending::<Result<Bytes, Infallible>>()),
            Duration::from_secs(30),
            None,
            stop,
            slot,
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(body);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(slots.available_permits(), 1);
    }
}
