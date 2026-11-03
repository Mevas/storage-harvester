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
cargo test -- --ignored         # known bugs: each fails until its fix lands
cargo test --release --test perf -- --nocapture
```

The black-box suites in `tests/` run the real binary through a `host_root` mount, the way the
container runs, and read what it exports over HTTP. Expected values come from an independent
walk of the same tree (`tests/support`), not from the scanner.

- `tests/accuracy.rs`: a generated tree with vendored dependencies, VCS metadata, logs, a sparse
  image, symlinks of every kind, a 15-level chain, and hostile file names. Checks every reported
  size, entry count and scan counter; agreement with `du -sk`; rescans after real growth and
  deletion; explicit depth caps; unreadable directories; and Prometheus exposition validity.
  Tests named `known_bug_*` are `#[ignore]`d and assert the *correct* behaviour for documented
  defects. Un-ignore each one in the change that fixes it.
- `tests/perf.rs`: scan time and µs per entry (cold when `HARVESTER_PERF_DROP_CACHES=1` and
  `sudo -n` work), compared against the independent walk on the same machine, plus memory and
  `/metrics` size and series count. Fails if a warm scan exceeds `HARVESTER_PERF_MAX_RATIO`
  (default 4×) of that baseline, or if the walk was incomplete. The report goes to
  `target/tmp/perf-report.json`. Size the tree with `HARVESTER_PERF_FILES` (default 20000).
- `tests/live.rs`: opt-in. Compares a deployed harvester with `find` run on its host, using the
  depth the config *intends*:

  ```bash
  HARVESTER_LIVE_SSH=nuc \
  HARVESTER_LIVE_CONFIG=../storage-harvester-komodo/configs/nuc.yaml \
    cargo test --test live -- --nocapture
  ```

## Docker Compose

The example `compose.yaml` expects deployment-owned configuration at `./config.yaml`:

```yaml
volumes:
  - /:/host:ro
  - ./config.yaml:/etc/storage-harvester/config.yaml:ro
```

## Endpoints

- `GET /` or `GET /status`: lightweight HTML status UI backed by cached scan state.
- `GET /status/fragment`: partial HTML used by the live-updating status UI.
- `GET /metrics`: Prometheus text exposition from the cached snapshot store only.
- `GET /-/health`: process health.
- `GET /-/ready`: ready after each configured target has completed at least one scan.

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

Deferred: inotify, Docker API metadata, textfile output, deep snapshots, and advanced child-label parsing.

## Architecture

The implementation follows the planned module boundaries so later phases can plug in without rewriting the core loop:

```text
src/config.rs                 YAML config and target normalization
src/registry.rs               target registry assembled from collectors
src/collector/filesystem.rs   configured filesystem target collector
src/scheduler.rs              background scan timing, timeouts, and task ownership
src/scanner/mod.rs            scanner trait and backend factory
src/scanner/native.rs         Linux stat walker using block accounting
src/cache.rs                  cached target snapshots read by exporters/API
src/exporter/prometheus.rs    Prometheus text exposition renderer
src/api.rs                    HTTP routes and graceful shutdown
```

Core flow:

```text
config -> filesystem collector -> target registry -> scheduler -> scanner -> snapshot cache -> API/exporter
```

`/metrics` only reads `SnapshotStore`; it never scans synchronously.

## Reporting Config

Defaults and targets support the same reporting controls:

```yaml
defaults:
  report_mode: tree          # tree or leaves
  report_depth: 1            # emit root plus nodes up to this relative depth
  max_depth: null            # optional traversal cap; null scans full tree
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
