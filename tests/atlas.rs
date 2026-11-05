//! Black-box checks of the atlas API: `/api/tree` against an independent walk at every depth,
//! `/api/info`, the `/api/events` stream after a real change on disk, and the relay that lets
//! one harvester serve the page for the others.

mod support;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use support::*;
use tempfile::TempDir;

const SCAN_TIMEOUT: Duration = Duration::from_secs(60);

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
            &format!(
                "host_root: {}\nhost: test-host\n{body}",
                yaml_quote(&self.root())
            ),
        )
    }
}

const ONE_TARGET: &str = "\
defaults:
  baseline_interval: 1s
  report_depth: 1
targets:
  - name: data
    path: /srv/data
";

fn json(h: &Harvester, path: &str) -> (u16, Value) {
    let (status, body) = h.get(path);
    let value =
        serde_json::from_str(&body).unwrap_or_else(|error| panic!("GET {path}: {error}: {body}"));
    (status, value)
}

fn first_scan(h: &Harvester) {
    let m = h.wait_for_scans("data", 1, SCAN_TIMEOUT);
    assert_eq!(
        m.target_value("storage_harvester_scan_success", "data"),
        Some(1.0)
    );
}

/// Visits every node of a `/api/tree` response with its path relative to the response root.
fn each_node(node: &Value, rel: &Path, visit: &mut impl FnMut(&Path, &Value)) {
    visit(rel, node);
    for child in node["c"].as_array().into_iter().flatten() {
        let name = child["n"].as_str().unwrap();
        each_node(child, &rel.join(name), visit);
    }
}

#[test]
fn tree_matches_an_independent_walk_at_every_depth() {
    let host = Host::new();
    realistic_tree(&host.data(), 11);
    // Times of their own, so a directory's newest is not just when the tree was written.
    age(&host.data(), &mut Rng::new(12));
    set_mtime(&host.data(), 1_500_000_000);
    let h = host.start(ONE_TARGET);
    first_scan(&h);

    let (status, body) = json(&h, "/api/tree?target=data&limit=20000&depth=64&min_bytes=1");
    assert_eq!(status, 200);
    assert_eq!(body["path"], "/srv/data");
    let walk = oracle_walk(&host.data(), &WalkRules::default());

    let mut out = Mismatches::default();
    let mut listed = 0;
    each_node(&body["node"], Path::new(""), &mut |rel, node| {
        listed += 1;
        let Some(dir) = walk.dirs.get(rel) else {
            out.push(format!("{} listed but not on disk", rel.display()));
            return;
        };
        let path = rel.display();
        out.check(
            format!("{path} t"),
            node["t"].as_u64(),
            Some(dir.total_blocks),
        );
        out.check(
            format!("{path} a"),
            node["a"].as_u64(),
            Some(dir.total_apparent),
        );
        out.check(
            format!("{path} f"),
            node["f"].as_u64(),
            Some(dir.direct_files + dir.deeper_files),
        );
        out.check(
            format!("{path} d"),
            node["d"].as_u64(),
            Some(dir.direct_dirs + dir.deeper_dirs),
        );
        out.check(
            format!("{path} l"),
            node["l"].as_u64(),
            Some(dir.direct_symlinks + dir.deeper_symlinks),
        );
        out.check(
            format!("{path} k"),
            node["k"].as_u64(),
            Some(dir.direct_dirs),
        );
        out.check(format!("{path} m"), node["m"].as_i64(), Some(dir.newest));
        // t = own inode + files here + pruned children + listed children.
        let children: u64 = node["c"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|child| child["t"].as_u64().unwrap())
            .sum();
        let parts = node["o"].as_u64().unwrap() + node["r"].as_u64().unwrap() + children;
        out.check(
            format!("{path} own inode"),
            node["t"].as_u64().unwrap().checked_sub(parts),
            Some(dir.own_blocks),
        );
    });
    // Every directory with any allocation is listed when nothing limits the view.
    let expected = walk
        .dirs
        .values()
        .filter(|dir| dir.total_blocks > 0)
        .count();
    out.check("listed directories", listed, expected);
    out.assert_none("/api/tree against the oracle");
}

#[test]
fn tree_lists_the_largest_first_within_the_limit() {
    let host = Host::new();
    for (name, len) in [("big", 4_000_000), ("mid", 2_000_000), ("small", 100_000)] {
        write_file(&host.data().join(name).join("blob"), len);
        write_file(&host.data().join(name).join("inner/blob"), len / 2);
    }
    let h = host.start(ONE_TARGET);
    first_scan(&h);

    let (_, body) = json(&h, "/api/tree?target=data&limit=3");
    let mut count = 0;
    each_node(&body["node"], Path::new(""), &mut |_, _| count += 1);
    assert_eq!(count, 3, "{body}");
    let children: Vec<&str> = body["node"]["c"]
        .as_array()
        .unwrap()
        .iter()
        .map(|child| child["n"].as_str().unwrap())
        .collect();
    assert_eq!(children, ["big", "mid"]);
    assert!(
        body["node"]["r"].as_u64().unwrap() >= 150_000,
        "small is in the rest"
    );

    let (status, sub) = json(&h, "/api/tree?target=data&path=/srv/data/big");
    assert_eq!(status, 200);
    assert_eq!(sub["node"]["n"], "big");
    assert_eq!(sub["node"]["c"][0]["n"], "inner");

    assert_eq!(json(&h, "/api/tree?target=nope").0, 404);
    assert_eq!(json(&h, "/api/tree?target=data&path=/srv/data/none").0, 404);
}

#[test]
fn info_describes_targets_filesystems_and_nesting() {
    let host = Host::new();
    realistic_tree(&host.data(), 5);
    let h = host.start(
        "\
atlas:
  peers: ['http://192.0.2.1:9799']
  metrics_url: http://192.0.2.2:8428
defaults:
  baseline_interval: 1s
targets:
  - name: data
    path: /srv/data
  - name: logs
    path: /srv/data/logs
",
    );
    first_scan(&h);
    h.wait_for_scans("logs", 1, SCAN_TIMEOUT);

    let (status, info) = json(&h, "/api/info");
    assert_eq!(status, 200);
    assert_eq!(info["host"], "test-host");
    assert_eq!(info["atlas"]["peers"][0], "http://192.0.2.1:9799");
    assert_eq!(info["atlas"]["metrics_url"], "http://192.0.2.2:8428");
    let targets = info["targets"].as_array().unwrap();
    let data = &targets[0];
    let logs = &targets[1];
    // Same filesystem; the inner target's path inside it is below the outer one's.
    assert_eq!(data["fs"], logs["fs"]);
    let outer = data["fs_path"].as_str().unwrap();
    let inner = logs["fs_path"].as_str().unwrap();
    assert!(Path::new(inner).starts_with(outer), "{inner} under {outer}");
    let walk = oracle_walk(&host.data(), &WalkRules::default());
    assert_eq!(
        data["total"]["blocks"].as_u64(),
        Some(walk.root().total_blocks)
    );
    let filesystem = &info["filesystems"][0];
    assert_eq!(filesystem["id"], data["fs"]);
    assert!(filesystem["size"].as_u64().unwrap() >= filesystem["used"].as_u64().unwrap());
}

#[test]
fn api_allows_any_origin_and_serves_the_page() {
    let host = Host::new();
    write_file(&host.data().join("f"), 10);
    let h = host.start(ONE_TARGET);
    first_scan(&h);
    let head = raw_head(h.port, "/api/info");
    assert!(
        head.to_ascii_lowercase()
            .contains("access-control-allow-origin: *"),
        "{head}"
    );
    let (status, page) = h.get("/atlas");
    assert_eq!(status, 200);
    assert!(page.contains("<title>Storage Atlas</title>"));
}

/// A change on disk reaches `/api/events`: from fanotify when the harvester may use it, and
/// otherwise from the next scan's difference. Either way with the directory and its delta.
#[test]
fn events_report_a_change_on_disk() {
    let host = Host::new();
    write_file(&host.data().join("spool/old.bin"), 10_000);
    let h = host.start(ONE_TARGET);
    first_scan(&h);

    let mut events = Events::open(h.port);
    let hello = events.next_named("hello", Duration::from_secs(10));
    assert_eq!(hello["host"], "test-host");

    write_file(&host.data().join("spool/new.bin"), 1_000_000);
    // A re-read may catch the file half written; the rest follows in later changes, from
    // fanotify or from the next scan's difference.
    let deadline = Instant::now() + SCAN_TIMEOUT;
    let mut arrived = 0;
    while arrived < 1_000_000 {
        let change = events.next_named("change", deadline - Instant::now());
        if change["path"] != "/srv/data/spool" || change["replay"] == true {
            continue;
        }
        assert_eq!(change["target"], "data");
        let src = change["src"].as_str().unwrap();
        assert!(["fanotify", "scan"].contains(&src), "{change}");
        if src == "fanotify" {
            // Written by this test, which shares the harvester's PID namespace.
            assert!(
                change["who"].as_str().is_some_and(|who| !who.is_empty()),
                "{change}"
            );
        } else {
            assert!(change.get("who").is_none(), "{change}");
        }
        arrived += change["db"].as_i64().unwrap();
    }
    // A client connecting now gets it replayed.
    let mut late = Events::open(h.port);
    late.next_named("hello", Duration::from_secs(10));
    let replayed = late.next_named("change", Duration::from_secs(10));
    assert_eq!(replayed["replay"], true);
}

fn raw_head(port: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.0\r\nHost: x\r\nOrigin: http://elsewhere\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let raw = String::from_utf8_lossy(&raw);
    raw.split("\r\n\r\n").next().unwrap().to_string()
}

struct Events {
    reader: BufReader<TcpStream>,
}

impl Events {
    fn open(port: u16) -> Self {
        Self::open_at(port, "/api/events")
    }

    fn open_at(port: u16, path: &str) -> Self {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: x\r\nAccept: text/event-stream\r\n\r\n"
        )
        .unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
        }
        Self { reader }
    }

    /// The next event called `name`, skipping others.
    fn next_named(&mut self, name: &str, timeout: Duration) -> Value {
        let deadline = Instant::now() + timeout;
        let mut kind = String::new();
        let mut line = String::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "no {name} event within {timeout:?}");
            self.reader.get_ref().set_read_timeout(Some(left)).unwrap();
            line.clear();
            if self.reader.read_line(&mut line).is_err() {
                continue;
            }
            // Chunked transfer: size lines are hex digits alone; skip them.
            let text = line.trim_end();
            if let Some(value) = text.strip_prefix("event: ") {
                kind = value.to_string();
            } else if let Some(data) = text.strip_prefix("data: ") {
                if kind == name {
                    return serde_json::from_str(data).unwrap();
                }
            }
        }
    }
}

/// A stand-in for VictoriaMetrics: answers every request with an empty vector and records the
/// request line.
fn fake_metrics() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            log.lock().unwrap().push(line.trim_end().to_string());
            let mut header = String::new();
            while reader.read_line(&mut header).is_ok_and(|n| n > 2) {
                header.clear();
            }
            let body = r#"{"status":"success","data":{"resultType":"vector","result":[]}}"#;
            let _ = write!(
                reader.get_mut(),
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (port, seen)
}

/// The harvester serving the page relays its peers' API, event streams included, and
/// read-only metrics queries, and nothing else.
#[test]
fn the_relay_serves_peers_and_metrics_from_one_origin() {
    let peer_host = Host::new();
    write_file(&peer_host.data().join("peer.bin"), 50_000);
    let peer = Harvester::start(
        &peer_host.tmp.path().join("run"),
        &format!(
            "host_root: {}\nhost: the-peer\n{ONE_TARGET}",
            yaml_quote(&peer_host.root())
        ),
    );
    first_scan(&peer);
    let (metrics_port, seen) = fake_metrics();
    let host = Host::new();
    write_file(&host.data().join("f"), 10);
    let h = host.start(&format!(
        "atlas:\n  peers: ['http://127.0.0.1:{}']\n  metrics_url: http://127.0.0.1:{metrics_port}\n{ONE_TARGET}",
        peer.port
    ));
    first_scan(&h);

    let (_, info) = json(&h, "/api/info");
    assert_eq!(info["atlas"]["proxy"], true);
    assert!(info["filesystems"][0]["disks"].is_array());
    assert_eq!(info["targets"][0]["kind"], "directory");
    let (status, relayed) = json(&h, "/api/peer/0/api/info");
    assert_eq!(status, 200);
    assert_eq!(relayed["host"], "the-peer");
    let (status, tree) = json(&h, "/api/peer/0/api/tree?target=data&depth=1");
    assert_eq!(status, 200, "{tree}");
    assert!(tree["node"]["t"].as_u64().unwrap() >= 50_000);
    let mut events = Events::open_at(h.port, "/api/peer/0/api/events");
    assert_eq!(
        events.next_named("hello", Duration::from_secs(10))["host"],
        "the-peer"
    );
    // And keeps streaming: a change on the peer's disk comes through.
    write_file(&peer_host.data().join("later/new.bin"), 1_000_000);
    let deadline = Instant::now() + SCAN_TIMEOUT;
    let mut arrived = 0;
    while arrived < 1_000_000 {
        let change = events.next_named("change", deadline - Instant::now());
        // `/srv/data/later` from a scan, `/srv/data` (or deeper) from fanotify, possibly in
        // parts when a re-read catches the file half written.
        let path = change["path"].as_str().unwrap();
        if path.starts_with("/srv/data") && change["replay"] != true {
            assert_eq!(change["host"], "the-peer");
            arrived += change["db"].as_i64().unwrap();
        }
    }

    for refused in [
        "/api/peer/0/metrics",
        "/api/peer/0/atlas",
        "/api/peer/1/api/info",
    ] {
        assert_eq!(h.get(refused).0, 404, "{refused}");
    }

    let (status, answer) = json(&h, "/api/metrics/api/v1/query?query=up");
    assert_eq!((status, answer["status"].as_str()), (200, Some("success")));
    assert_eq!(h.get("/api/metrics/api/v1/admin/tsdb/delete_series").0, 404);
    assert_eq!(h.get("/api/metrics/api/v1/label/__name__/values").0, 200);
    let seen = seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        [
            "GET /api/v1/query?query=up HTTP/1.1",
            "GET /api/v1/label/__name__/values HTTP/1.1"
        ],
        "only allowed paths reach the metrics store"
    );

    // A peer that is down: 502, with why.
    drop(peer);
    let (status, failed) = json(&h, "/api/peer/0/api/info");
    assert_eq!(status, 502, "{failed}");
    assert!(failed["error"].as_str().unwrap().starts_with("upstream"));
}

#[test]
fn the_root_opens_the_atlas_and_the_app_manifest_is_served() {
    let host = Host::new();
    write_file(&host.data().join("f"), 10);
    let h = host.start(ONE_TARGET);
    let mut stream = TcpStream::connect(("127.0.0.1", h.port)).unwrap();
    write!(stream, "GET / HTTP/1.0\r\nHost: x\r\n\r\n").unwrap();
    let mut head = String::new();
    stream.read_to_string(&mut head).unwrap();
    assert!(head.starts_with("HTTP/1.0 307"), "{head}");
    assert!(
        head.to_ascii_lowercase().contains("location: /atlas"),
        "{head}"
    );
    let (status, manifest) = json(&h, "/atlas/manifest.webmanifest");
    assert_eq!(status, 200);
    assert_eq!(manifest["start_url"], "/atlas");
    let head = raw_head(h.port, "/atlas/icon-192.png");
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: image/png"),
        "{head}"
    );
    assert_eq!(h.get("/atlas/nothing.png").0, 404);
}
