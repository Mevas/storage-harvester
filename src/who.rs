//! Who changed a directory: the process behind a fanotify event, named from `/proc`.
//!
//! fanotify reports the PID of the process that caused each event, or 0 when that process is
//! outside the harvester's PID namespace: in a container without `pid: host` the harvester sees
//! only itself. The process is looked up as its event arrives, since a short-lived writer may be
//! gone by the time its directory is re-read: its `comm`, and from its cgroup the container it
//! runs in, if any. Lookups run on their own thread, so a slow `/proc` read (older kernels take
//! the global cgroup lock to list a process's cgroups) never holds up the event reader, whose
//! queue would overflow. Each PID is looked up at most once per [`TTL`].

// fanotify, and `/proc`, are Linux only; elsewhere nothing fills a lookup.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::sync::mpsc::{self, SyncSender};
#[cfg(target_os = "linux")]
use std::sync::Arc;
use std::sync::{Condvar, Mutex, PoisonError};
#[cfg(target_os = "linux")]
use std::time::Duration;
use std::time::Instant;

use serde_json::{json, Value};

/// A process, as a `change` event names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Who {
    /// Its `comm`: the executable's name, cut to 15 bytes by the kernel.
    pub comm: String,
    /// The container it runs in: `lxc/<vmid>`, or a Docker or containerd ID cut to 12 hex
    /// digits.
    pub container: Option<String>,
}

impl Who {
    /// Adds `who`, and `ctr` when in a container, to a `change` event (a JSON object).
    pub fn annotate(&self, event: &mut Value) {
        event["who"] = json!(self.comm);
        if let Some(container) = &self.container {
            event["ctr"] = json!(container);
        }
    }
}

/// One PID's lookup, shared by every directory its events touched until it is re-read.
#[derive(Debug, Default)]
pub struct Lookup {
    /// `None` until the lookup thread gets to it; then the process, if `/proc` still had it.
    done: Mutex<Option<Option<Who>>>,
    filled: Condvar,
}

impl Lookup {
    pub fn fill(&self, who: Option<Who>) {
        *self.done.lock().unwrap_or_else(PoisonError::into_inner) = Some(who);
        self.filled.notify_all();
    }

    /// The process, waiting for the lookup thread until `deadline` at most. It is usually
    /// done long before: a directory is re-read after its event was read.
    pub fn wait_until(&self, deadline: Instant) -> Option<Who> {
        let mut done = self.done.lock().unwrap_or_else(PoisonError::into_inner);
        while done.is_none() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            done = self
                .filled
                .wait_timeout(done, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        done.clone().flatten()
    }
}

/// How long a PID's lookup is reused. Short, so a recycled PID is not named after the
/// process that had it before.
#[cfg(target_os = "linux")]
const TTL: Duration = Duration::from_secs(2);
/// PIDs remembered at once.
#[cfg(target_os = "linux")]
const CACHED: usize = 256;
/// Lookups waiting for the lookup thread. Past that, events go unnamed.
#[cfg(target_os = "linux")]
const QUEUED: usize = 64;

/// The event reader's side: a cache of recent lookups, and the lookup thread's queue.
#[cfg(target_os = "linux")]
pub struct Resolver {
    own: u32,
    cache: HashMap<u32, (Instant, Arc<Lookup>)>,
    /// `None` when the lookup thread could not start.
    queue: Option<SyncSender<(u32, Arc<Lookup>)>>,
}

#[cfg(target_os = "linux")]
impl Resolver {
    /// Starts the lookup thread.
    pub fn start() -> Self {
        let (queue, lookups) = mpsc::sync_channel::<(u32, Arc<Lookup>)>(QUEUED);
        let spawned = std::thread::Builder::new()
            .name("harvester-who".to_string())
            .spawn(move || {
                for (pid, lookup) in lookups {
                    lookup.fill(read(pid));
                }
            });
        Self {
            own: std::process::id(),
            cache: HashMap::new(),
            queue: spawned.ok().map(|_| queue),
        }
    }

    /// The lookup of the process behind an event: `None` for PID 0 (not visible from here), for
    /// the harvester itself (reading or writing its own files), or when the lookup thread is
    /// behind. Never waits.
    pub fn lookup(&mut self, pid: i32) -> Option<Arc<Lookup>> {
        let pid = u32::try_from(pid)
            .ok()
            .filter(|&pid| pid != 0 && pid != self.own)?;
        let now = Instant::now();
        if let Some((at, lookup)) = self.cache.get(&pid) {
            if now.duration_since(*at) < TTL {
                return Some(Arc::clone(lookup));
            }
        }
        let lookup = Arc::new(Lookup::default());
        self.queue
            .as_ref()?
            .try_send((pid, Arc::clone(&lookup)))
            .ok()?;
        if self.cache.len() >= CACHED {
            self.cache
                .retain(|_, (at, _)| now.duration_since(*at) < TTL);
            if self.cache.len() >= CACHED {
                // Hundreds of new processes within the TTL: start over rather than grow.
                self.cache.clear();
            }
        }
        self.cache.insert(pid, (now, Arc::clone(&lookup)));
        Some(lookup)
    }
}

/// Reads one process from `/proc`; `None` once it is gone.
#[cfg(target_os = "linux")]
fn read(pid: u32) -> Option<Who> {
    let comm = comm(&std::fs::read(format!("/proc/{pid}/comm")).ok()?)?;
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
    Some(Who {
        comm,
        container: container(&cgroup),
    })
}

/// A `/proc/<pid>/comm` without its newline.
fn comm(raw: &[u8]) -> Option<String> {
    let name = raw.strip_suffix(b"\n").unwrap_or(raw);
    (!name.is_empty()).then(|| String::from_utf8_lossy(name).into_owned())
}

/// The container a process runs in, from its `/proc/<pid>/cgroup` (cgroup v1 or v2): a Proxmox
/// LXC guest as `lxc/<vmid>`, otherwise the first 12 hex digits of a Docker, containerd, CRI-O
/// or Podman container ID. The outermost wins, so Docker inside an LXC guest names the guest,
/// the container the host can tell apart. `None` for a host process, and for every process
/// when the harvester sees only its own cgroup namespace (`0::/`).
pub fn container(cgroup: &str) -> Option<String> {
    cgroup.lines().find_map(|line| {
        // `hierarchy:controllers:path`; the path may itself hold colons.
        let path = line.splitn(3, ':').nth(2)?;
        container_in(path)
    })
}

fn container_in(path: &str) -> Option<String> {
    let mut parts = path.split('/').filter(|part| !part.is_empty());
    while let Some(part) = parts.next() {
        // LXC 4+ puts a guest's processes in `lxc.payload.<name>` (its monitor, a host
        // process, in `lxc.monitor.<name>`); older ones in `lxc/<name>`.
        let guest = match part.strip_prefix("lxc.payload.") {
            Some(name) => Some(name),
            None if part == "lxc" || part == "lxc.payload" => parts.next(),
            None => None,
        };
        if let Some(name) = guest {
            return (!name.is_empty()).then(|| format!("lxc/{name}"));
        }
        // `<id>`, `docker-<id>.scope`, `cri-containerd-<id>.scope`, `libpod-<id>.scope`...
        if let Some(id) = part
            .split(['-', '.', '_'])
            .find(|token| is_container_id(token))
        {
            return Some(id[..12].to_string());
        }
    }
    None
}

fn is_container_id(token: &str) -> bool {
    token.len() == 64
        && token
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "4f8c2a1be0d3c5f7a9b8e6d4c2a0f1e3d5c7b9a8f6e4d2c0b1a3f5e7d9c8b6a4";

    #[test]
    fn names_docker_and_containerd_containers() {
        let cases = [
            // cgroup v2, systemd driver (Docker's default on systemd hosts).
            (format!("0::/system.slice/docker-{ID}.scope\n"), "docker v2"),
            // cgroup v2, cgroupfs driver.
            (format!("0::/docker/{ID}\n"), "docker v2, cgroupfs"),
            // cgroup v1: one line per hierarchy, all naming the container.
            (
                format!(
                    "12:pids:/docker/{ID}\n11:memory:/docker/{ID}\n\
                     1:name=systemd:/docker/{ID}\n0::/\n"
                ),
                "docker v1",
            ),
            // cgroup v1 with a host's systemd hierarchy listed first.
            (
                format!("13:misc:/\n4:cpu,cpuacct:/system.slice/docker-{ID}.scope\n"),
                "docker v1, systemd driver",
            ),
            // containerd under Kubernetes, systemd and cgroupfs drivers; nerdctl.
            (
                format!(
                    "0::/kubepods.slice/kubepods-besteffort.slice/\
                     kubepods-besteffort-pod1d2c3b4a_5e6f_7a8b_9c0d_1e2f3a4b5c6d.slice/\
                     cri-containerd-{ID}.scope\n"
                ),
                "containerd, systemd",
            ),
            (
                format!("0::/kubepods/besteffort/pod1d2c3b4a-5e6f-7a8b-9c0d-1e2f3a4b5c6d/{ID}\n"),
                "containerd, cgroupfs",
            ),
            (format!("0::/default/{ID}\n"), "nerdctl"),
            (
                format!("0::/machine.slice/libpod-{ID}.scope/container\n"),
                "podman",
            ),
        ];
        for (cgroup, case) in cases {
            assert_eq!(container(&cgroup).as_deref(), Some(&ID[..12]), "{case}");
        }
    }

    #[test]
    fn names_proxmox_lxc_guests() {
        for (cgroup, case) in [
            ("0::/lxc/106/ns/init.scope\n", "lxc 3, v2"),
            ("0::/lxc.payload.106/init.scope\n", "lxc 4+"),
            ("0::/lxc.payload/106/system.slice/cron.service\n", "lxc 4.0"),
            (
                "12:memory:/lxc/106/ns/user.slice\n1:name=systemd:/lxc/106/ns/init.scope\n",
                "lxc, v1",
            ),
        ] {
            assert_eq!(container(cgroup).as_deref(), Some("lxc/106"), "{case}");
        }
        // Docker inside the guest: the guest is what the host knows.
        let nested = format!("0::/lxc.payload.106/system.slice/docker-{ID}.scope\n");
        assert_eq!(container(&nested).as_deref(), Some("lxc/106"));
    }

    #[test]
    fn host_processes_have_no_container() {
        for cgroup in [
            "0::/user.slice/user-1000.slice/session-3.scope\n",
            "0::/system.slice/smbd.service\n",
            // The daemons themselves, and LXC's monitor, run on the host.
            "0::/system.slice/docker.service\n",
            "0::/system.slice/containerd.service\n",
            "0::/lxc.monitor.106\n",
            "0::/init.scope\n",
            // The harvester's own cgroup namespace: everything looks like its root.
            "0::/\n",
            "12:pids:/\n1:name=systemd:/init.scope\n",
            // Too short, uppercase, or not hex: not an ID.
            "0::/docker/4f8c2a1be0d3\n",
            "0::/docker/4F8C2A1BE0D3C5F7A9B8E6D4C2A0F1E3D5C7B9A8F6E4D2C0B1A3F5E7D9C8B6A4\n",
            "0::/lxc\n",
            "",
        ] {
            assert_eq!(container(cgroup), None, "{cgroup:?}");
        }
    }

    #[test]
    fn reads_comm_without_its_newline() {
        assert_eq!(comm(b"rsync\n").as_deref(), Some("rsync"));
        assert_eq!(comm(b"kworker/u8:2").as_deref(), Some("kworker/u8:2"));
        assert_eq!(comm(b"\n"), None);
        assert_eq!(comm(b""), None);
    }

    #[test]
    fn adds_who_and_ctr_only_when_known() {
        let mut event = json!({"path": "/data"});
        let host = Who {
            comm: "smbd".into(),
            container: None,
        };
        host.annotate(&mut event);
        assert_eq!(event, json!({"path": "/data", "who": "smbd"}));
        let contained = Who {
            comm: "qbittorrent-nox".into(),
            container: Some(ID[..12].into()),
        };
        contained.annotate(&mut event);
        assert_eq!(event["ctr"], &ID[..12]);
    }

    #[test]
    fn a_lookup_waits_for_its_answer_but_not_past_the_deadline() {
        let pending = Lookup::default();
        let soon = Instant::now() + std::time::Duration::from_millis(20);
        assert_eq!(pending.wait_until(soon), None);
        let who = Who {
            comm: "cp".into(),
            container: None,
        };
        pending.fill(Some(who.clone()));
        assert_eq!(pending.wait_until(Instant::now()), Some(who));
        let gone = Lookup::default();
        gone.fill(None);
        assert_eq!(gone.wait_until(Instant::now()), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolves_a_visible_process_and_skips_the_harvester() {
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let mut resolver = Resolver::start();
        let lookup = resolver.lookup(child.id() as i32).expect("queued");
        let soon = Instant::now() + Duration::from_secs(5);
        let who = lookup.wait_until(soon).expect("the child is alive");
        assert_eq!(who.comm, "sleep");
        let again = resolver.lookup(child.id() as i32).unwrap();
        assert!(Arc::ptr_eq(&lookup, &again), "cached");
        assert!(resolver.lookup(0).is_none(), "not in our PID namespace");
        assert!(
            resolver.lookup(std::process::id() as i32).is_none(),
            "ourselves"
        );
        child.kill().unwrap();
        child.wait().unwrap();
    }
}
