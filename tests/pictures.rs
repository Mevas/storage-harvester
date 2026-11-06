//! Black-box checks of the atlas's pictures: `/api/thumb` (with a stand-in ffmpeg that records
//! what it is asked, and with the real one when it is installed) and `/api/posters` and
//! `/api/poster` against a stand-in Plex server.

mod support;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use support::*;
use tempfile::TempDir;

const SCAN_TIMEOUT: Duration = Duration::from_secs(60);

/// `GET path` with extra request headers: status, response headers (lowercase), body.
fn get(port: u16, path: &str, extra: &str) -> (u16, String, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(stream, "GET {path} HTTP/1.0\r\nHost: x\r\n{extra}\r\n").unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).to_lowercase();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, head, raw[split + 4..].to_vec())
}

fn json(port: u16, path: &str) -> (u16, Value) {
    let (status, _, body) = get(port, path, "");
    let value = serde_json::from_slice(&body)
        .unwrap_or_else(|e| panic!("GET {path}: {e}: {}", String::from_utf8_lossy(&body)));
    (status, value)
}

/// A stand-in for ffmpeg and ffprobe: logs each call to `calls`, then fails on input starting
/// with `BAD`, prints a duration (ffprobe), or answers with a JPEG start marker followed by the
/// input it read (ffmpeg).
fn fake_ffmpeg(dir: &Path) -> PathBuf {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let script = r#"#!/bin/sh
[ "$1" = "-version" ] && exit 0
here=$(dirname "$0")
echo "$(basename "$0") $*" >> "$here/calls"
input="$here/input.$$"
cat > "$input"
if [ "$(head -c 3 "$input")" = "BAD" ]; then rm -f "$input"; exit 1; fi
if [ "$(basename "$0")" = "ffprobe" ]; then echo 10.000000; rm -f "$input"; exit 0; fi
printf '\377\330'
cat "$input"
rm -f "$input"
"#;
    for name in ["ffmpeg", "ffprobe"] {
        let path = bin.join(name);
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    bin
}

fn calls(bin: &Path) -> Vec<String> {
    std::fs::read_to_string(bin.join("calls"))
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect()
}

fn write_bytes(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

struct Setup {
    tmp: TempDir,
}

impl Setup {
    fn new() -> Self {
        Self {
            tmp: tempfile::tempdir().unwrap(),
        }
    }
    fn root(&self) -> PathBuf {
        self.tmp.path().join("host")
    }
    fn start(&self, run: &str, body: &str) -> Harvester {
        Harvester::start(
            &self.tmp.path().join(run),
            &format!(
                "host_root: {}\nhost: test-host\n{body}",
                yaml_quote(&self.root())
            ),
        )
    }
}

/// Thumbnails are made only for targets that turn them on, only of image and video files the
/// walk would count, once each, and never shared with other sites' scripts.
#[test]
fn thumbnails_follow_the_walks_rules_and_are_made_once() {
    let setup = Setup::new();
    let bin = fake_ffmpeg(setup.tmp.path());
    let photos = setup.root().join("srv/data/photos");
    write_bytes(&photos.join("a.jpg"), b"JPEG-A");
    write_bytes(&photos.join("clip.MP4"), b"VIDEO");
    write_bytes(&photos.join("bad.jpg"), b"BAD-IMAGE");
    write_bytes(&photos.join("notes.txt"), b"text");
    write_bytes(&photos.join("x.secret.jpg"), b"SECRET");
    write_bytes(&setup.tmp.path().join("outside/real.jpg"), b"OUTSIDE");
    link(
        setup.tmp.path().join("outside/real.jpg").to_str().unwrap(),
        &photos.join("link.jpg"),
    );
    write_bytes(&setup.root().join("srv/other/o.jpg"), b"OTHER");
    let h = setup.start(
        "run",
        &format!(
            "\
atlas:
  thumbnails:
    cache_dir: {cache}
    ffmpeg: {ffmpeg}
    ffprobe: {ffprobe}
defaults:
  baseline_interval: 1s
  report_depth: 2
  exclude: ['**/*.secret.jpg']
targets:
  - name: data
    path: /srv/data
    thumbnails: true
  - name: other
    path: /srv/other
",
            cache = yaml_quote(&setup.tmp.path().join("cache")),
            ffmpeg = yaml_quote(&bin.join("ffmpeg")),
            ffprobe = yaml_quote(&bin.join("ffprobe")),
        ),
    );
    h.wait_for_scans("data", 1, SCAN_TIMEOUT);
    h.wait_for_scans("other", 1, SCAN_TIMEOUT);

    let (_, info) = json(h.port, "/api/info");
    let thumbs: Vec<(&str, bool)> = info["targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| (t["name"].as_str().unwrap(), t["thumbs"].as_bool().unwrap()))
        .collect();
    assert_eq!(thumbs, [("data", true), ("other", false)]);

    let thumb = |name: &str| format!("/api/thumb?target=data&path=/srv/data/photos&name={name}");
    let (status, head, body) = get(h.port, &format!("{}&w=200", thumb("a.jpg")), "");
    assert_eq!(status, 200, "{head}");
    assert!(head.contains("content-type: image/jpeg"), "{head}");
    assert!(!head.contains("access-control-allow-origin"), "{head}");
    assert_eq!(body, b"\xff\xd8JPEG-A", "ffmpeg read the file itself");
    let made = calls(&bin);
    assert_eq!(made.len(), 1, "{made:?}");
    assert!(made[0].starts_with("ffmpeg "), "{made:?}");
    assert!(made[0].contains("-i /dev/stdin"), "{made:?}");
    assert!(
        made[0].contains("scale=256:256:"),
        "w=200 is made at 256: {made:?}"
    );
    assert!(!made[0].contains("-ss"), "{made:?}");

    // Kept: the second request is answered from disk, and revalidates by its tag.
    let (status, again_head, again) = get(h.port, &format!("{}&w=200", thumb("a.jpg")), "");
    assert_eq!((status, again.as_slice()), (200, body.as_slice()));
    assert_eq!(calls(&bin).len(), 1, "made once");
    let etag = again_head
        .lines()
        .find_map(|line| line.strip_prefix("etag: "))
        .unwrap();
    let (status, head, _) = get(
        h.port,
        &format!("{}&w=200", thumb("a.jpg")),
        &format!("If-None-Match: {etag}\r\n"),
    );
    assert_eq!(status, 304);
    assert!(!head.contains("access-control-allow-origin"), "{head}");

    // A video: probed for its length, then a key frame 15% in.
    let (status, _, body) = get(h.port, &thumb("clip.MP4"), "");
    assert_eq!(
        (status, body.as_slice()),
        (200, b"\xff\xd8VIDEO".as_slice())
    );
    let made = calls(&bin);
    assert!(made[1].starts_with("ffprobe "), "{made:?}");
    assert!(made[2].contains("-ss 1.50 -noaccurate_seek"), "{made:?}");

    // A file ffmpeg cannot read: no picture, and it is not tried again.
    let before = calls(&bin).len();
    assert_eq!(get(h.port, &thumb("bad.jpg"), "").0, 404);
    assert_eq!(get(h.port, &thumb("bad.jpg"), "").0, 404);
    assert_eq!(calls(&bin).len(), before + 1, "{:?}", calls(&bin));

    let before = calls(&bin).len();
    for refused in [
        thumb("notes.txt"),
        thumb("link.jpg"),
        thumb("x.secret.jpg"),
        thumb("..%2Fphotos%2Fa.jpg"),
        thumb("nope.jpg"),
        "/api/thumb?target=data&path=/srv/data/nowhere&name=a.jpg".into(),
        "/api/thumb?target=other&path=/srv/other&name=o.jpg".into(),
        "/api/thumb?target=nope&path=/srv/data/photos&name=a.jpg".into(),
    ] {
        let (status, head, body) = get(h.port, &refused, "");
        assert_eq!(status, 404, "{refused}: {}", String::from_utf8_lossy(&body));
        assert!(head.contains("application/json"), "{refused}");
    }
    assert_eq!(
        get(h.port, "/api/thumb?target=data&path=/srv/data/photos", "").0,
        400
    );
    assert_eq!(calls(&bin).len(), before, "refused before ffmpeg ran");

    // The harvester serving the page relays thumbnails, still without the CORS header.
    let hub_setup = Setup::new();
    write_file(&hub_setup.root().join("srv/data/f"), 10);
    let hub = hub_setup.start(
        "hub",
        &format!(
            "atlas:\n  peers: ['http://127.0.0.1:{}']\ndefaults:\n  baseline_interval: 1s\ntargets:\n  - name: data\n    path: /srv/data\n",
            h.port
        ),
    );
    let (status, head, body) = get(hub.port, &format!("/api/peer/0{}", thumb("a.jpg")), "");
    assert_eq!(
        (status, body.as_slice()),
        (200, b"\xff\xd8JPEG-A".as_slice()),
        "{head}"
    );
    assert!(!head.contains("access-control-allow-origin"), "{head}");
    assert!(head.contains("cache-control: private"), "{head}");
    let (status, head, _) = get(
        hub.port,
        &format!("/api/peer/0{}&w=200", thumb("a.jpg")),
        &format!("If-None-Match: {etag}\r\n"),
    );
    assert_eq!(status, 304, "{head}");
    assert!(!head.contains("access-control-allow-origin"), "{head}");
    // Everything else from the relay still allows any origin.
    let (_, head, _) = get(hub.port, "/api/peer/0/api/info", "");
    assert!(head.contains("access-control-allow-origin: *"), "{head}");
}

/// With the real ffmpeg (skipped when it is not installed): a photo and a video become JPEGs
/// whose short side is the width asked for.
#[test]
fn real_ffmpeg_makes_jpegs_of_photos_and_videos() {
    if Command::new("ffmpeg").arg("-version").output().is_err() {
        eprintln!("skipped: no ffmpeg on PATH");
        return;
    }
    let setup = Setup::new();
    let photos = setup.root().join("srv/data/photos");
    std::fs::create_dir_all(&photos).unwrap();
    let make = |args: &[&str]| {
        let status = Command::new("ffmpeg")
            .args(["-v", "error", "-y"])
            .args(args)
            .current_dir(&photos)
            .status()
            .unwrap();
        assert!(status.success(), "{args:?}");
    };
    make(&[
        "-f",
        "lavfi",
        "-i",
        "testsrc2=size=1600x1200",
        "-frames:v",
        "1",
        "photo.jpg",
    ]);
    make(&[
        "-f",
        "lavfi",
        "-i",
        "mandelbrot=size=640x480",
        "-frames:v",
        "1",
        "art.png",
    ]);
    make(&[
        "-f",
        "lavfi",
        "-i",
        "testsrc=size=1280x720:rate=25",
        "-t",
        "4",
        "-pix_fmt",
        "yuv420p",
        "clip.mp4",
    ]);
    let h = setup.start(
        "run",
        &format!(
            "atlas:\n  thumbnails:\n    cache_dir: {}\ndefaults:\n  baseline_interval: 1s\ntargets:\n  - name: data\n    path: /srv/data\n    thumbnails: true\n",
            yaml_quote(&setup.tmp.path().join("cache"))
        ),
    );
    h.wait_for_scans("data", 1, SCAN_TIMEOUT);
    for (name, w, h_want) in [
        ("photo.jpg", 256, (342, 256)),
        ("art.png", 128, (170, 128)),
        ("clip.mp4", 256, (456, 256)),
    ] {
        let (status, head, body) = get(
            h.port,
            &format!("/api/thumb?target=data&path=/srv/data/photos&name={name}&w={w}"),
            "",
        );
        assert_eq!(
            status,
            200,
            "{name}: {head} {}",
            String::from_utf8_lossy(&body)
        );
        let out = setup.tmp.path().join(format!("{name}.out.jpg"));
        std::fs::write(&out, &body).unwrap();
        let probe = Command::new("ffprobe")
            .args([
                "-v",
                "error",
                "-show_entries",
                "stream=width,height",
                "-of",
                "csv=p=0",
            ])
            .arg(&out)
            .output()
            .unwrap();
        let size = String::from_utf8_lossy(&probe.stdout).trim().to_string();
        assert_eq!(size, format!("{},{}", h_want.0, h_want.1), "{name}");
    }
}

/// A stand-in Plex: one show library (a show with season 1 and specials), one movie library,
/// a music library, and posters that echo what was asked. Records requests and tokens, and
/// answers the list of libraries after `slow`.
fn fake_plex(slow: Duration) -> (u16, Arc<Mutex<Vec<String>>>) {
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
            let target = line.split(' ').nth(1).unwrap_or("").to_string();
            let mut token = String::new();
            let mut header = String::new();
            while reader.read_line(&mut header).is_ok_and(|n| n > 2) {
                if let Some(value) = header.to_ascii_lowercase().strip_prefix("x-plex-token: ") {
                    token = value.trim().to_string();
                }
                header.clear();
            }
            log.lock().unwrap().push(format!("{target} token={token}"));
            if target == "/library/sections" {
                std::thread::sleep(slow);
            }
            let (kind, body): (&str, Vec<u8>) = match target.as_str() {
                "/library/sections" => ("application/json", br#"{"MediaContainer":{"Directory":[
                    {"key":"1","type":"show","Location":[{"path":"/media/tv"}]},
                    {"key":"2","type":"movie","Location":[{"path":"/media/movies"}]},
                    {"key":"3","type":"artist","Location":[{"path":"/media/music"}]}]}}"#.to_vec()),
                "/library/sections/1/all?type=2" => ("application/json", br#"{"MediaContainer":{"Metadata":[
                    {"ratingKey":"10","thumb":"/library/metadata/10/thumb/111"}]}}"#.to_vec()),
                "/library/metadata/10" => ("application/json", br#"{"MediaContainer":{"Metadata":[
                    {"ratingKey":"10","thumb":"/library/metadata/10/thumb/111","Location":[{"path":"/media/tv/Show A"}]}]}}"#.to_vec()),
                "/library/sections/1/all?type=3" => ("application/json", br#"{"MediaContainer":{"Metadata":[
                    {"parentRatingKey":"10","index":1,"thumb":"/library/metadata/11/thumb/222"},
                    {"parentRatingKey":"10","index":0,"thumb":"/library/metadata/12/thumb/333"},
                    {"parentRatingKey":"10","index":2}]}}"#.to_vec()),
                "/library/sections/2/all?type=1" => ("application/json", br#"{"MediaContainer":{"Metadata":[
                    {"thumb":"/library/metadata/20/thumb/444","Media":[{"Part":[{"file":"/media/movies/Film (2020)/Film.mkv"}]}]}]}}"#.to_vec()),
                photo if photo.starts_with("/photo/:/transcode?") => {
                    let mut body = b"\xff\xd8".to_vec();
                    body.extend_from_slice(photo.as_bytes());
                    ("image/jpeg", body)
                }
                _ => ("application/json", b"{}".to_vec()),
            };
            let stream = reader.get_mut();
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(&body);
        }
    });
    (port, seen)
}

fn start_with_plex(setup: &Setup, plex_port: u16, token_env: &str) -> Harvester {
    setup.start(
        "run",
        &format!(
            "\
atlas:
  thumbnails:
    cache_dir: {cache}
  plex:
    url: http://127.0.0.1:{plex_port}
    token_env: {token_env}
    paths:
      /media: /srv/data/media
defaults:
  baseline_interval: 1s
  report_depth: 3
targets:
  - name: data
    path: /srv/data
",
            cache = yaml_quote(&setup.tmp.path().join("cache")),
        ),
    )
}

/// Waits for the harvester's first read of Plex's libraries (503 until then).
fn posters_read(h: &Harvester) -> std::time::Instant {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if json(h.port, "/api/posters?target=data").0 == 200 {
            return std::time::Instant::now();
        }
        assert!(std::time::Instant::now() < deadline, "Plex never read");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Plex is read in the background: while it is slow, poster requests answer 503 at once instead
/// of waiting for it.
#[test]
fn a_slow_plex_never_holds_a_request() {
    let setup = Setup::new();
    write_file(
        &setup
            .root()
            .join("srv/data/media/movies/Film (2020)/Film.mkv"),
        1000,
    );
    let (plex_port, _) = fake_plex(Duration::from_secs(4));
    let h = start_with_plex(&setup, plex_port, "STORAGE_HARVESTER_TEST_NO_TOKEN");
    h.wait_for_scans("data", 1, SCAN_TIMEOUT);
    for path in [
        "/api/posters?target=data",
        "/api/poster?target=data&path=/srv/data/media/movies/Film%20(2020)",
    ] {
        let asked = std::time::Instant::now();
        let (status, _) = json(h.port, path);
        assert_eq!(status, 503, "{path}");
        assert!(asked.elapsed() < Duration::from_secs(1), "{path}");
    }
    posters_read(&h);
    let (status, _, _) = get(
        h.port,
        "/api/poster?target=data&path=/srv/data/media/movies/Film%20(2020)",
        "",
    );
    assert_eq!(status, 200);
}

/// Plex's posters go on the folders its libraries show (seasons' on season folders), mapped
/// from Plex's paths to the harvester's, fetched with the token and kept.
#[test]
fn posters_come_from_plex_for_its_library_folders() {
    let setup = Setup::new();
    let media = setup.root().join("srv/data/media");
    write_file(&media.join("tv/Show A/Season 01/e01.mkv"), 1000);
    write_file(&media.join("tv/Show A/Season 02/e01.mkv"), 1000);
    write_file(&media.join("tv/Show A/Specials/s01.mkv"), 1000);
    write_file(&media.join("movies/Film (2020)/Film.mkv"), 1000);
    write_file(&setup.root().join("srv/data/photos/p.jpg"), 1000);
    let (plex_port, seen) = fake_plex(Duration::ZERO);
    let token_env = format!("STORAGE_HARVESTER_TEST_PLEX_TOKEN_{}", std::process::id());
    std::env::set_var(&token_env, "the-token");
    let h = start_with_plex(&setup, plex_port, &token_env);
    h.wait_for_scans("data", 1, SCAN_TIMEOUT);
    posters_read(&h);

    let (_, info) = json(h.port, "/api/info");
    assert_eq!(info["targets"][0]["posters"], true);
    let (status, posters) = json(h.port, "/api/posters?target=data");
    assert_eq!(status, 200, "{posters}");
    assert_eq!(
        posters["paths"],
        serde_json::json!([
            "/srv/data/media/movies/Film (2020)",
            "/srv/data/media/tv/Show A",
            "/srv/data/media/tv/Show A/Season 01",
            "/srv/data/media/tv/Show A/Season 02",
            "/srv/data/media/tv/Show A/Specials",
        ]),
        "folders on disk with a poster, not the music library's"
    );

    let poster = |path: &str| format!("/api/poster?target=data&path={path}&w=256");
    let (status, head, body) = get(
        h.port,
        &poster("/srv/data/media/tv/Show%20A/Season%2001"),
        "",
    );
    assert_eq!(status, 200, "{head}");
    assert!(head.contains("content-type: image/jpeg"), "{head}");
    assert!(!head.contains("access-control-allow-origin"), "{head}");
    let asked = String::from_utf8_lossy(&body[2..]).to_string();
    assert_eq!(
        asked,
        "/photo/:/transcode?width=256&height=384&minSize=1&upscale=1&url=/library/metadata/11/thumb/222"
    );
    let fetched = |seen: &Arc<Mutex<Vec<String>>>| {
        seen.lock()
            .unwrap()
            .iter()
            .filter(|line| line.starts_with("/photo/"))
            .count()
    };
    assert_eq!(fetched(&seen), 1);
    get(
        h.port,
        &poster("/srv/data/media/tv/Show%20A/Season%2001"),
        "",
    );
    assert_eq!(fetched(&seen), 1, "kept after the first fetch");
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .all(|line| line.ends_with("token=the-token")),
        "{:?}",
        seen.lock().unwrap()
    );

    let (status, _, body) = get(h.port, &poster("/srv/data/media/movies/Film%20(2020)"), "");
    assert_eq!(status, 200);
    assert!(String::from_utf8_lossy(&body).ends_with("url=/library/metadata/20/thumb/444"));
    // Season 2 has no poster of its own in Plex: the show's.
    let (status, _, body) = get(
        h.port,
        &poster("/srv/data/media/tv/Show%20A/Season%2002"),
        "",
    );
    assert_eq!(status, 200);
    assert!(String::from_utf8_lossy(&body).ends_with("url=/library/metadata/10/thumb/111"));
    for refused in [
        poster("/srv/data/media/tv/Show%20A/Season%2003"),
        poster("/srv/data/photos"),
        poster("/srv/data/media/tv/Show%20B"),
    ] {
        assert_eq!(get(h.port, &refused, "").0, 404, "{refused}");
    }
}
