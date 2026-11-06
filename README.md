# Storage Harvester

Rust MVP for a per-host storage exporter. It scans configured local paths in the background with Linux block accounting and exposes cached Prometheus metrics.

## Run Locally

```bash
cargo run -- --config examples/config.yaml
```

Validate a config without starting the HTTP server:

```bash
cargo run -- --config examples/nuc.yaml --check-config
```

For deployment, provide your own `config.yaml` beside the Compose file. The repository only includes `examples/config.yaml`.
`examples/nuc.yaml` is a NUC-oriented starting point based on the observed local paths on `nuc-ubuntu`.

For host-path scanning in Docker, mount the host root read-only at `/host` and keep config paths written as host paths:

```yaml
host_root: /host
targets:
  - name: var_log
    path: /var/log
```

The service resolves `/var/log` to `/host/var/log` internally but keeps `/var/log` in labels.

## Testing

```bash
cargo test                      # unit tests + black-box suites (CI runs this)
cargo test -- --ignored         # known bugs, if any: each fails until fixed
cargo test --release --test perf -- --nocapture
```

The black-box suites in `tests/` run the real binary through a `host_root` mount, the way the
container runs, and read what it exports over HTTP. Expected values come from an independent
walk of the same tree (`tests/support`), not from the scanner.

- `tests/accuracy.rs`: a generated tree with vendored dependencies, VCS metadata, logs, a sparse
  image, symlinks of every kind, a 15-level chain, and hostile file names. Checks every reported
  size, entry count and scan counter; agreement with `du -sk`; rescans after real growth and
  deletion; explicit depth caps; unreadable directories; and Prometheus exposition validity.
  A defect found before its fix is recorded as an `#[ignore = "known bug: ..."]` test that
  asserts the *correct* behaviour; the change that fixes it removes the `ignore`.
- `tests/perf.rs`: scan time and µs per entry (cold when `HARVESTER_PERF_DROP_CACHES=1` and
  `sudo -n` work), compared against the independent walk on the same machine, plus memory and
  `/metrics` size and series count. Fails if a warm scan exceeds `HARVESTER_PERF_MAX_RATIO`
  (default 1×) of that baseline, or if the walk was incomplete. The report goes to
  `target/tmp/perf-report.json`. Size the tree with `HARVESTER_PERF_FILES` (default 20000).
- `tests/atlas.rs`: `/api/tree` against the independent walk at every depth, best-first
  pruning, `/api/files`, `/api/info`, CORS, and a change on disk reaching `/api/events`.
- `tests/pictures.rs`: `/api/thumb` with a stand-in ffmpeg (the walk's rules, made once,
  no CORS) and with the real one when installed, and `/api/posters` and `/api/poster` against a
  stand-in Plex server.
- `tests/btrfs.rs`: opt-in (`HARVESTER_BTRFS_DIR`, root). Reflinks, a hard link and an
  excluded reflink on a real btrfs: what deleting each directory frees, the sharing pairs, and
  a change seen by generation polling. CI runs it on a loopback btrfs.
- `tests/live.rs`: opt-in. Compares a deployed harvester with `find` run on its host, using the
  depth the config *intends*:

  ```bash
  HARVESTER_LIVE_SSH=nuc \
  HARVESTER_LIVE_CONFIG=../storage-harvester-komodo/configs/nuc.yaml \
    cargo test --test live -- --nocapture
  ```

## Docker Compose

Every push to `main` that passes CI publishes `ghcr.io/mevas/storage-harvester:latest` and
`:<short sha>` (linux/amd64).

The example `compose.yaml` expects deployment-owned configuration at `./config.yaml`:

```yaml
volumes:
  - /:/host:ro
  - ./config.yaml:/etc/storage-harvester/config.yaml:ro
```

## Endpoints

- `GET /`: redirects to `/atlas`.
- `GET /status`: lightweight HTML status UI backed by cached scan state.
- `GET /status/fragment`: partial HTML used by the live-updating status UI.
- `GET /metrics`: Prometheus text exposition from the cached snapshot store only.
- `GET /-/health`: process health.
- `GET /-/ready`: ready after each configured target has completed at least one scan.
- `GET /atlas`: the Storage Atlas, a dashboard of every harvester's storage (see below), and
  `/atlas/manifest.webmanifest` and its icons, so a phone can install it as an app.
- `GET /api/info`, `GET /api/tree`, `GET /api/files`, `GET /api/thumb`, `GET /api/posters`,
  `GET /api/poster`, `GET /api/events`: what the atlas reads (see below).
- `GET /api/peer/<i>/api/{info,tree,files,thumb,posters,poster,events}`,
  `GET /api/metrics/api/v1/...`: the relay.

## Storage Atlas

`/atlas` shows the storage of every machine running a harvester on one page: capacity and
growth per filesystem, a heatmap of which directories changed when, a block map of every
directory on every machine, and which directories share blocks.
It reads `/api/*` from this harvester and from each of `atlas.peers`, and history from
`atlas.metrics_url`:

```yaml
host: nuc-ubuntu            # the `host` label your scraper adds; absent: the hostname
display_name: NUC           # what the atlas calls this machine; absent: host
atlas:
  peers: ['http://nas.lan:9799']
  metrics_url: http://victoriametrics.lan:8428   # Prometheus HTTP API with this data
  capacity_queries:         # optional: older history for a filesystem, from other metrics
    - path: /volume1
      used: 'my_disk_used_bytes{volume="1"}'
      size: 'my_disk_size_bytes{volume="1"}'
```

`/api/*` is read-only and allows any origin, except pictures: another site may show them but
not read them. The harvester serving the page also relays `/api/peer/<i>/...` to
`atlas.peers[i]` (`/api/info`, `/api/tree`, `/api/files`, `/api/thumb`, `/api/posters`,
`/api/poster` and `/api/events` only,
event streams included) and `/api/metrics/...` to `atlas.metrics_url` (`query`,
`query_range`, `series`, `labels` and label values only), so the page talks to one origin.
That is what lets it work over HTTPS behind a reverse proxy with single sign-on, where the
browser would block plain-HTTP peers on the LAN. Relayed peers must be `http://`. A relayed
answer ends after 45 s without data (event streams send a keepalive every 15 s), a finite one
after 2 minutes in all, and at most 64 are relayed at once.

`/api/info` also says which machine this is (`machine.uuid`, the SMBIOS product UUID) and which
whole disks each filesystem sits on (`filesystems[].disks`: a QEMU disk reports
`drive-scsi0`). A Proxmox harvester reports the same for each VM, so the atlas draws a VM's
harvester inside that VM's disks.

**Machines are physical.** The atlas draws the physical boxes at the top: a harvester inside a
hypervisor's guest is that guest (`NUC · VM 100`), in its hypervisor's colour, never a machine
of its own. `machine.virt` (`qemu`, `vmware`, …, from DMI and the CPU's hypervisor flag) says a
harvester runs in a VM even when its host is not reporting. Every guest shows what the atlas can
know of it: folders and live changes (a harvester inside), folders (a container walked from the
host), filesystems (the guest agent, or a stopped container's superblock), or blocks only.

**Nothing is one opaque box.** What no walked folder holds is split into named pieces, from:
- `machine.disks`: each whole disk under this machine's filesystems, partition by partition
  (`use`: `fs` with `overhead`, the filesystem's own metadata; `swap` with `swap_used`;
  `holder` for LVM or md; `thin_pool`). A VM's disk then shows its other filesystems, swap,
  metadata, and what is left: blocks freed inside it and not trimmed yet.
- `targets[].skips`: targets inside another by path that its walk never reaches (an excluded
  folder, another btrfs subvolume). They are drawn beside it, and filesystem totals count them.
- `filesystems[].btrfs`: btrfs's own split of the devices (`device_size`, `unallocated`, `data`,
  `metadata` and `system` with their `copies`), and `unwalked`, the subvolumes no target walks
  grouped by folder (Docker's btrfs layers, snapshots). df counts none of the metadata.
- Filesystem totals count shared blocks once where a sharing pass has run (a root's `x`).
- An iSCSI LUN a guest uses (its `remote_fs[].serial`, `36001405` + the LUN's id) is drawn as
  that guest's filesystem inside the LUN's file on the machine serving it.

### Block map

Every block is a directory, sized by the blocks it holds. Two layouts:
- **Cells**, the default: a weighted Voronoi treemap you zoom into like a map. Each group of
  siblings settles in a few milliseconds to within 1% of its true areas, and after that its
  cells keep their places: a size change of 1% or more re-fits the weights only, so a folder
  grows or shrinks in place and pushes its neighbours aside; a new folder starts as a speck
  next to where it came from and grows. Zoomed in, the camera holds on to the group in view,
  and lenses, a resized window and tree reloads keep the zoom and the layout.
  A group shows at most 24 cells; the smallest are drawn together as one grained "+N" cell,
  which is not a level: zoomed in, its children show in place as if they sat in its parent.
- **Files**: zoomed into a folder's "files here" cell, its files are cells too, from
  `/api/files` (below); the side panel lists the files of the folder in view.
- **Pictures** (on unless switched off; never in wall mode): an image or video file of a
  target with `thumbnails: true` shows its picture, and a folder of a Plex library its poster
  (below). A picture covers its cell, with the lens's colour as its rim, and stands in for the
  name. An open folder keeps its poster behind its children, which tint it like glass. Only
  cells at least 44 px across ask, nearest the middle first, four at a time.
- **Blocks**: a squarified treemap.

At the top level, machines are drawn at the cube root of their bytes (Balanced) by default, so
a small, busy machine stays visible. Inside a machine, area is true bytes.

Lenses:
- **Live**: hot cores grow with bytes changed over the last 20 s and with block writes. Busy
  cells tremble and ripple as changes arrive, and walls glow when something inside is busy.
  A folder whose newest change (`m`) is 30+ days old is frosted.
- **Change**: growth or shrinkage over the chosen range.
- **Growth rings**: bytes added in the last day, week and month (outermost is newest), from
  30 days of folder history in `metrics_url`.
- **Time machine**: from 30 days back to 180 days ahead. Free space follows each filesystem's
  df trend (90 days, fit over 30), and folders follow their own history and trend. A filesystem
  turns red on the day it fills.
- **Hard links**: from the btrfs sharing pass, each folder's shared part is hatched and what
  deleting it frees is solid. Threads join folders that share blocks.
- **Reclaim**: what could come back. Each candidate has its command, and ticking it previews
  the result on the map and in the time machine. The candidates:
  - blocks freed inside a guest and not trimmed yet: `pct fstrim <vmid>` for a container,
    `fstrim` inside a VM, and `fstrim` of an iSCSI LUN's filesystem inside the guest using it
    (which returns blocks to the machine serving the LUN);
  - folders of at least 8 GiB (and 0.4% of their filesystem) unchanged for 120 days, or
    download and cache folders unchanged for 30.
- **Kind** and **Machine**: colour by what the folder looks like, or by machine.

The side panel folds the event stream into one line per folder per minute, with a reason
guessed from the path and the kind of event, and the process behind it (`who`, `ctr`) when
the harvester can see it. **Raw** shows every event. **Wall mode** fills the screen with the
Live lens, hides leaf names, drifts slowly so a screen left on does not hold one image, and
keeps the screen awake.

### Proxmox thin pools

```yaml
targets:
  - name: local_lvm
    type: lvm_thin
    path: /local-lvm          # the tree's root path; nothing is read from it
    pool: pve/data            # volume group / thin pool
    pve_config: /etc/pve      # default
```

The tree is the pool, then each guest with a disk in it (`NUC (100)`), then its disks
(`scsi0`, `rootfs`, `efidisk0`; volumes no guest refers to go under `Unattached`). A disk's
size is its allocated thin blocks: what it costs the pool, not what the guest sees. A running
container's root disk also holds the container's directories, walked from the host at each
scan: its root is opened once through the container's init process, checked to be on the
container's own volume (so a recycled PID cannot point the walk at the host), and walked through
that descriptor, staying on that filesystem. If the container frees and trims blocks below what
the walk found, the disk shows as one opaque block of its allocation until the next scan. Between scans, device-mapper's status (what `dmsetup status` prints, read
by ioctl: under 1 ms, against 9 ms for running `dmsetup`) and `/sys/block/dm-*/stat` are
read every `live.block_poll_interval` (1 s), including volumes activated since the scan:
allocation changes become `change` events with
`src: "lvm"`, and disks doing I/O get an `io` event with bytes/s read and written, sent live
only (not replayed).

`/api/tree` nodes gain `v` (`pool`, `guest`, `disk`); guests `vmid`, `g` (`qemu`, `lxc`) and
`on`; disks `key`, `p` (provisioned bytes), `w`/`rd` (bytes/s), `u` (allocated bytes no
walked file accounts for) and `est` (sized by an estimate). `/api/info` lists the pool as a
filesystem (`type: lvmthin`, with `provisioned` and thin `meta`) and the target's `guests`, with
each VM's SMBIOS UUID.

Each disk in `guests[].disks[].fs` lists the filesystems on it and their use, without logging in
anywhere:
- **VMs** with `agent: 1`: the QEMU guest agent's `get-fsinfo` (`qm guest cmd <vmid>
  get-fsinfo`, at each scan; `from: "agent"`). Filesystems on disks outside the pool, such as an
  iSCSI LUN the guest logs in to, go in `guests[].remote_fs` with the disk's `serial`. `agent`
  says whether it answered.
- **Running containers**: `statvfs` of the walked root (`from: "walk"`, with `overhead`).
- **Stopped containers**: the ext4 superblock of each volume, read without mounting, so a start
  is never blocked (`from: "superblock"`; `used` includes metadata).

An inactive volume's allocation cannot be read until it is activated. If the pool holds no thin
snapshots, the pool's use that no active volume accounts for is shared out among the inactive
ones by provisioned size (`estimated`, and the tree's `est`), so the pool adds up.

It needs the host: run the harvester there as root (it only reads), not in a container. `lvs`
and `dmsetup` are killed after 15 s, `qm` after 15 s.

### Trees

Each scan keeps every directory it walks in memory, up to `tree_max_directories` per target
(default 500,000, about 200 bytes each; 0 keeps only the reported directories). Reported
directories, and so `/metrics`, are unchanged.

`GET /api/tree?target=NAME[&path=/abs/path][&limit=2500][&depth=8][&min_bytes=N]` returns a
pruned subtree, best first: the largest listed directory is expanded next, until `limit`
directories are listed or none within `depth` levels holds `min_bytes` (default: the root's
total / 4000). Each node: `n` name, `t` total bytes, `a` apparent bytes, `f`/`d`/`l` files,
directories and symlinks below it, `o` bytes of files directly in it, `k` subdirectories,
`m` the newest modification time in it (unix seconds: its own, its subdirectories', and every
file and symlink the scan stat'ed below it), `r` bytes of subdirectories not listed, `c`
listed subdirectories, and `x` (btrfs, below) the bytes deleting it would free. Live changes
raise `m` of the directory and its ancestors to the change's time at least and never lower it
(a deletion leaves it), so it is the last activity seen. A thin pool's own nodes (the pool,
guests, and disks not walked) have no `m`.

### Files

`GET /api/files?target=NAME&path=/abs/path[&limit=400]` lists the files directly in one
directory the target's tree holds (not its subdirectories), biggest first, read from disk when
asked and under the walk's rules (excludes, `no_cross_filesystem`, `follow_symlinks`): names,
sizes, times and link counts, never contents. `files`: up to `limit` (at most 5000) of `n`
name, `b` allocated bytes, `a` apparent bytes, `m` modification time (unix seconds), `l` hard
links, `s` symlink; `count`, `bytes` and `apparent` cover every entry, and `partial` is set when
a directory with more than 200,000 entries was read in part. A path the tree does not hold, or
a thin pool's node, is a 404.

### Pictures

`GET /api/thumb?target=NAME&path=/abs/folder&name=FILE[&w=128|256|512]` answers a JPEG at least
`w` on its short side (other widths round up): of an image file (JPEG, PNG, WebP, GIF, BMP,
TIFF, HEIC, AVIF, DNG), or of the key frame at or before 15% into a video (at most 90 s in, else
its first frame). Only for targets with `thumbnails: true` (default off: it reads file
contents, which nothing else does), only for a regular file in a folder the tree holds, under
the walk's rules (excludes, `no_cross_filesystem`, `follow_symlinks`); anything else is a 404.
ffmpeg reads the file the harvester opened, at a low priority, and (on Linux) is the first
process the kernel kills when memory runs out; an image takes one of `jobs` slots, a video all
of them. A request waits up to
8 s for a slot and making the picture may take 20 s, so a relayed one fits the relay's 30 s;
past either it is a 503, tried again next time. Pictures are kept in `cache_dir` by the file's path,
size, modification time and inode, oldest made first out past `cache_mib`; a file ffmpeg
cannot read is remembered too. Answers carry an `ETag`, are private for a week, and have no
`Access-Control-Allow-Origin`.

`GET /api/posters?target=NAME` lists the target's folders (`paths`) that a Plex library has a
poster for, and `GET /api/poster?target=NAME&path=/abs/folder[&w=...]` fetches one, scaled by
Plex and kept like thumbnails. A movie's poster goes on the folder its file is in, a show's on
its folders, and a season's on `Season 01` (or `Season 1`, `Specials` for season 0) inside
them, the show's again when the season has none. Plex's libraries are read in the background at
startup and every 15 minutes (a minute after a failure); until the first read, both answer 503.

```yaml
atlas:
  thumbnails:                # all optional
    cache_dir: /var/cache/storage-harvester
    cache_mib: 512
    ffmpeg: ffmpeg
    ffprobe: ffprobe
    jobs: 2
  plex:                      # optional
    url: http://plex.lan:32400
    token_env: PLEX_TOKEN    # the variable holding the token (default)
    paths:                   # Plex's path: this harvester's
      /data/media: /volume1/data/media
targets:
  - name: photos
    path: /volume1/photos
    thumbnails: true
```

`/api/info` says per target whether it makes thumbnails (`thumbs`) and whether Plex's libraries
reach into it (`posters`). The image includes ffmpeg.

### Live changes

Between scans, the harvester follows changes and re-reads only the directories that changed:

- **fanotify** (Linux 5.9+): one mark per filesystem reports each directory whose entries or
  files changed, by file handle.
- **btrfs generation polling** (any kernel): every `live.btrfs_poll_interval` (3 s), a
  metadata search for blocks newer than the last poll names the changed directories. btrfs
  writes inode updates at commit, so a change can take up to the commit interval (30 s by
  default) to show.
- **synotify** (Synology DSM, x86_64): DSM's kernel has no fanotify, but Synology added its
  own notifier, whose events name each changed entry by full path. On DSM, btrfs targets are
  followed by it as well as by polling, which stays on to catch what it misses (writes through
  `mmap`, reflinks, an overflowed queue). Writes and deletions then show within a re-read
  (measured on a DS1821+: a buffered write 12 s → 0.1 s, a deletion 23 s → 0.0 s). A mark
  covers one mount, and writes are reported only through the mount the file was opened
  through, so the harvester marks every mount of the targets' filesystems in every mount
  namespace, other containers' included, and looks for new ones every 2 s. In a container
  that needs `pid: host` and `cap_add: [SYS_ADMIN, SYS_PTRACE]`; without them only its own
  mounts are marked. `live.synotify: false` turns it off.

A file with several hard links counts once, in one directory; when that link goes, another
directory holding one takes it over. A *new* hard link to a file that had one link is reported
by fanotify only to the new link's directory, so walks of fanotify targets also record which
directory each singly linked file is in (8 bytes per file); the directory the file was counted
in is then re-read as well. btrfs polling reports both directories itself. Where the tree is
already approximate (that directory is sealed, or the new link sits in a new subtree past
`tree_max_directories`), the harvester asks for an early scan instead: at most one a minute,
and never scanning more than a tenth of the time
(`storage_harvester_live_rescans_requested_total`).

All need `CAP_SYS_ADMIN` (`cap_add: [SYS_ADMIN]`). Without it, or with `live.enabled: false`
or a target's `live: false`, trees change at each scan only. A directory is re-read 50 ms after
its first change (so files that live only milliseconds, like lock files and atomic saves, come
and go unseen), then at most once per `live.min_relist_interval` (250 ms), and less often the
longer it takes to read.

`GET /api/events` is a Server-Sent Events stream. `change` events carry the directory's
`path`, `db` (the change in bytes, which every ancestor shares), `da`, `df` (files), `b` (its
new total) and `src` (`fanotify`, `synotify`, `btrfs`, `lvm`, or `scan` for a difference found by a scan). A
`scan` event follows each scan. New clients get the last 200 changes first, marked `replay`.

With fanotify or synotify, a change also names the last process seen changing the directory: `who` (its
`comm`, such as `rsync` or `smbd`) and, when it runs in a container, `ctr` (`lxc/<vmid>` for
a Proxmox guest, else the first 12 hex digits of the Docker or containerd ID; Docker inside a
guest names the guest). fanotify gives the PID only of processes in the harvester's PID
namespace: run in a container without `pid: host`, the harvester sees none but itself, and its
own events are not named. synotify gives host PIDs, which are used only with `pid: host`; NFS
writes show as `nfsd`. Both fields are left out when the process is unknown or gone before
`/proc` was read.

### What deleting a directory frees (btrfs)

On btrfs, files can share blocks: reflink copies, deduplication, cross-seeded torrents, hard
links. A directory's size then overstates what deleting it frees. With `sharing_interval`
set (for example `6h`), the harvester reads the subvolume's extent metadata (about 1 GB of
it for a 50 TiB share, in under 30 s) and settles each extent on the lowest directory holding
every reference to it. Summed over a subtree, that is exactly what deleting the subtree would
free within the subvolume. Snapshots and other subvolumes are not looked at, so those can keep
more alive.

- `/api/tree` nodes gain `x`; `/api/info` targets gain `sharing` with `logical` (what the
  files add up to), `disk` (unique bytes on disk), `outside` (bytes also referenced by files
  outside the tree) and the directory `pairs` sharing the most bytes.
- Metrics: `storage_harvester_exclusive_size_bytes` per reported directory,
  `storage_harvester_target_disk_bytes`, `storage_harvester_sharing_duration_seconds`.

Other new metrics: `storage_harvester_filesystem_{size,used,avail}_bytes` per target (a thin
pool's own usage for `lvm_thin` targets),
`storage_harvester_live_{relists,changes,rescans_requested,signals,overflows}_total`, and for
thin pools `storage_harvester_thin_{metadata_size,metadata_used,provisioned}_bytes` and
`storage_harvester_block_{read,written}_bytes_total` per disk (`path`).

## MVP Scope

- YAML config.
- Native Linux scanner using `st_blocks * 512`.
- `no_cross_filesystem` support.
- Symlinks not followed by default.
- Glob excludes.
- Per-target scan interval and timeout.
- Depth-based directory reporting with `tree` and `leaves` modes.
- Separate own and child-directory size metrics for each reported node.
- `blocks` and `apparent` size modes.
- Cached background scans.
- Core scan health metrics.
- Lightweight status web UI.
- Structured scan lifecycle logs with issue breakdowns.

Deferred: Docker API metadata, textfile output, and advanced child-label parsing.

## Architecture

The implementation follows the planned module boundaries so later phases can plug in without rewriting the core loop:

```text
src/config.rs                 YAML config and target normalization
src/registry.rs               target registry assembled from collectors
src/collector/filesystem.rs   configured filesystem target collector
src/scheduler.rs              background scan timing, timeouts, and task ownership
src/scanner/mod.rs            scanner trait and backend factory
src/scanner/native.rs         parallel getdents64/fstatat walker using block accounting
src/tree.rs                   the directory tree a scan leaves, pruned views of it, diffs
src/live.rs                   live updates: fanotify, btrfs polling, re-reads, events
src/btrfs.rs                  btrfs metadata search: sharing pass, generation watcher
src/fsinfo.rs                 which filesystem a target is on (mountinfo), statvfs
src/atlas.rs, src/atlas.html  /atlas and /api/*
src/cache.rs                  cached target snapshots read by exporters/API
src/exporter/prometheus.rs    Prometheus text exposition renderer
src/api.rs                    HTTP routes and graceful shutdown
```

Core flow:

```text
config -> filesystem collector -> target registry -> scheduler -> scanner -> snapshot cache -> API/exporter
```

`/metrics` only reads `SnapshotStore`; it never scans synchronously.

## How a Scan Works

A scan is a parallel walk that does a constant amount of work per entry:

- Each entry costs one `fstatat` relative to its directory's open descriptor. On Linux, names
  come from `getdents64` into a reused buffer, so nothing per entry is allocated or looked up.
- Sizes and counts are summed per directory, then added once to the directory's node, or to
  its nearest tracked ancestor's past `tree_max_directories`. Memory is bounded by that cap.
- `scan_threads` workers share directories through one stack. Each worker keeps descending
  into one child and hands the others out, so a walk stays roughly depth-first.
- A multiply-linked file counts once, at the link whose path hashes lowest. Its allocation
  therefore lands in the same directory on every scan, whatever order the workers took.

More threads help a warm walk up to about the number of CPUs. On a cold cache they also keep
more reads in flight, which is what a large tree on SSD needs. Lower `scan_threads` to keep a
scan from competing with the host's other work.

## Reporting Config

Defaults and targets support the same reporting controls:

```yaml
defaults:
  report_mode: tree          # tree or leaves
  report_depth: 1            # emit root plus nodes up to this relative depth
  max_depth: null            # optional traversal cap; null scans full tree
  scan_threads: 8            # walker threads per scan; absent: one per CPU, up to 16
  size_modes:
    - blocks                 # blocks, apparent
  exclude:                   # inherited by every target
    - '**/.git/**'
    - '**/.cache/**'
    - '**/node_modules/**'
    - '**/target/**'
```

Size components:

- `storage_harvester_own_size_bytes`: bytes for the reported node itself.
- `storage_harvester_children_size_bytes`: bytes under the reported node, including direct files and child directories.

Total size for a node is `own_size + children_size`.

Entry components mirror the size model:

- `storage_harvester_own_entries`: direct files, directories, and symlinks owned by this node.
- `storage_harvester_children_entries`: recursive files, directories, and symlinks under child directories.
Total entries for a node are `own_entries + children_entries` grouped by `entry_type`.

Metric groups:

- Data: `storage_harvester_own_size_bytes`, `storage_harvester_children_size_bytes`, `storage_harvester_own_entries`, `storage_harvester_children_entries`.
- Build: `storage_harvester_build_info` with the crate `version` label.
- Scan health: `storage_harvester_scan_success`, `storage_harvester_scan_running`, `storage_harvester_scan_running_seconds`, `storage_harvester_scan_duration_seconds`, `storage_harvester_scan_timestamp_seconds`, `storage_harvester_target_stale_seconds`, `storage_harvester_scan_count_total`, `storage_harvester_scan_errors_total`, `storage_harvester_scan_issue_count`.
- Cardinality/output: `storage_harvester_reported_nodes`, `storage_harvester_scanned_directories`, `storage_harvester_scanned_files`, `storage_harvester_scanned_symlinks`, `storage_harvester_max_observed_depth`, `storage_harvester_depth_limit_hits`.
