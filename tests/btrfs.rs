//! Opt-in: the btrfs sharing pass and generation polling, on a real btrfs filesystem.
//!
//! Needs a directory on btrfs and `CAP_SYS_ADMIN` (both features use `BTRFS_IOC_TREE_SEARCH`):
//!
//! ```bash
//! sudo HARVESTER_BTRFS_DIR=/mnt/btrfs cargo test --test btrfs -- --nocapture
//! ```
//!
//! Without `HARVESTER_BTRFS_DIR` the test passes without checking anything.

mod support;

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::Value;
use support::*;

const MIB: u64 = 1024 * 1024;

fn random_file(path: &Path, len: u64, seed: u64) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut rng = Rng::new(seed);
    let mut file = File::create(path).unwrap();
    let mut chunk = vec![0u8; 64 * 1024];
    let mut left = len;
    while left > 0 {
        for byte in chunk.iter_mut() {
            *byte = rng.next_u64() as u8;
        }
        let n = left.min(chunk.len() as u64) as usize;
        file.write_all(&chunk[..n]).unwrap();
        left -= n as u64;
    }
}

/// `cp --reflink=always`: the copy shares the original's extents.
fn reflink(from: &Path, to: &Path) {
    const FICLONE: u64 = 0x4004_9409;
    fs::create_dir_all(to.parent().unwrap()).unwrap();
    let source = File::open(from).unwrap();
    let target = File::create(to).unwrap();
    // SAFETY: both descriptors are open for the duration of the call.
    let status = unsafe { libc::ioctl(target.as_raw_fd(), FICLONE as _, source.as_raw_fd()) };
    assert_eq!(status, 0, "FICLONE: {}", std::io::Error::last_os_error());
}

fn sync() {
    // SAFETY: no arguments.
    unsafe { libc::sync() };
}

fn json(h: &Harvester, path: &str) -> Value {
    let (status, body) = h.get(path);
    assert_eq!(status, 200, "GET {path}: {body}");
    serde_json::from_str(&body).unwrap()
}

fn find<'a>(node: &'a Value, path: &[&str]) -> &'a Value {
    path.iter().fold(node, |node, name| {
        node["c"]
            .as_array()
            .and_then(|children| children.iter().find(|child| child["n"] == *name))
            .unwrap_or_else(|| panic!("{name} not listed in {node}"))
    })
}

#[test]
fn sharing_and_generation_polling_on_btrfs() {
    let Ok(base) = std::env::var("HARVESTER_BTRFS_DIR") else {
        eprintln!("HARVESTER_BTRFS_DIR not set; skipping");
        return;
    };
    let case = PathBuf::from(base).join(format!("sharing-{}", std::process::id()));
    let root = case.join("host");
    let data = root.join("srv/data");
    random_file(&data.join("a/x"), 4 * MIB, 1);
    reflink(&data.join("a/x"), &data.join("b/x"));
    random_file(&data.join("c/y"), 2 * MIB, 2);
    fs::create_dir_all(data.join("d")).unwrap();
    fs::hard_link(data.join("c/y"), data.join("d/y")).unwrap();
    random_file(&data.join("e/f/z"), MIB, 3);
    reflink(&data.join("e/f/z"), &data.join("skip/z"));
    random_file(&data.join("g/solo"), 3 * MIB, 4);
    sync();

    let h = Harvester::start(
        &case.join("run"),
        &format!(
            "\
host_root: {}
live:
  btrfs_poll_interval: 1s
defaults:
  baseline_interval: 1h
  report_depth: 2
  sharing_interval: 1h
  exclude: ['**/skip/**']
targets:
  - name: data
    path: /srv/data
",
            yaml_quote(&root)
        ),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    let info = loop {
        let info = json(&h, "/api/info");
        if !info["targets"][0]["sharing"].is_null() {
            break info;
        }
        assert!(
            Instant::now() < deadline,
            "no sharing pass:\n{}",
            h.log_tail(30)
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    assert_eq!(info["live"]["source"], "btrfs", "{}", h.log_tail(30));
    let sharing = &info["targets"][0]["sharing"];
    let mut out = Mismatches::default();
    // Unique extents: a/x (shared with b/x), c/y (two links), e/f/z (shared with skip/), g.
    out.check("disk", sharing["disk"].as_u64(), Some(10 * MIB));
    out.check("outside", sharing["outside"].as_u64(), Some(MIB));
    let pair = |a: &str, b: &str| {
        sharing["pairs"]
            .as_array()
            .unwrap()
            .iter()
            .find_map(|pair| {
                let ends = (pair["a"].as_str().unwrap(), pair["b"].as_str().unwrap());
                (ends == (a, b) || ends == (b, a)).then(|| pair["bytes"].as_u64().unwrap())
            })
    };
    out.check(
        "a/b pair",
        pair("/srv/data/a", "/srv/data/b"),
        Some(4 * MIB),
    );
    out.check(
        "c/d pair",
        pair("/srv/data/c", "/srv/data/d"),
        Some(2 * MIB),
    );

    let tree = json(&h, "/api/tree?target=data&depth=8&limit=1000&min_bytes=1")["node"].clone();
    out.check("logical total", tree["t"].as_u64(), Some(14 * MIB));
    // What deleting each directory frees: only what nothing outside it references.
    for (path, freed) in [
        (vec![], 9 * MIB),
        (vec!["a"], 0),
        (vec!["b"], 0),
        (vec!["e"], 0),
        (vec!["g"], 3 * MIB),
    ] {
        out.check(
            format!("freed by deleting /{}", path.join("/")),
            find(&tree, &path)["x"].as_u64(),
            Some(freed),
        );
    }
    // The hard-linked file's allocation counts in whichever of c/ and d/ its link hashes lower
    // in; the other is empty and not listed. Deleting either frees nothing.
    for name in ["c", "d"] {
        if let Some(dir) = tree["c"]
            .as_array()
            .unwrap()
            .iter()
            .find(|child| child["n"] == name)
        {
            out.check(
                format!("freed by deleting /{name}"),
                dir["x"].as_u64(),
                Some(0),
            );
        }
    }
    out.assert_none("sharing pass");

    // A change reaches the event stream from generation polling, without a scan.
    let mut stream = TcpStream::connect(("127.0.0.1", h.port)).unwrap();
    write!(stream, "GET /api/events HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut append = OpenOptions::new()
        .append(true)
        .open(data.join("g/solo"))
        .unwrap();
    append.write_all(&vec![9u8; MIB as usize]).unwrap();
    drop(append);
    sync();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut line = String::new();
    loop {
        assert!(
            Instant::now() < deadline,
            "no btrfs change event:\n{}",
            h.log_tail(30)
        );
        line.clear();
        if reader.read_line(&mut line).is_err() {
            continue;
        }
        let Some(data) = line.trim_end().strip_prefix("data: ") else {
            continue;
        };
        let event: Value = serde_json::from_str(data).unwrap();
        if event["path"] == "/srv/data/g" && event["src"] == "btrfs" {
            assert!(event["db"].as_i64().unwrap() >= MIB as i64, "{event}");
            break;
        }
    }

    // A new hard link to a plain file: polling re-reads both directories, so it counts once.
    let total = || {
        json(&h, "/api/tree?target=data&depth=1")["node"]["t"]
            .as_u64()
            .unwrap()
    };
    let before = total();
    random_file(&data.join("p/plain"), 2 * MIB, 5);
    fs::create_dir_all(data.join("q")).unwrap();
    sync();
    let deadline = Instant::now() + Duration::from_secs(30);
    let with_plain = before + 2 * MIB;
    while total() != with_plain {
        assert!(
            Instant::now() < deadline,
            "plain file not seen: {}",
            total()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    fs::hard_link(data.join("p/plain"), data.join("q/plain")).unwrap();
    sync();
    // Both directories are re-read within a poll or two; then it must still count once.
    std::thread::sleep(Duration::from_secs(6));
    assert_eq!(total(), with_plain, "a new hard link counted twice");

    drop(h);
    let _ = fs::remove_dir_all(&case);
}
