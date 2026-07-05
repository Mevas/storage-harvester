# Storage Harvester

Rust MVP for a per-host storage hotspot exporter. It scans configured local paths in the background with Linux block accounting and exposes cached Prometheus metrics.

## Run Locally

```bash
cargo run -- --config examples/config.yaml
```

For deployment, provide your own `config.yaml` beside the Compose file. The repository only includes `examples/config.yaml`.

For host-path scanning in Docker, mount the host root read-only at `/host` and keep config paths written as host paths:

```yaml
host_root: /host
targets:
  - name: var_log
    path: /var/log
```

The service resolves `/var/log` to `/host/var/log` internally but keeps `/var/log` in labels.

## Docker Compose

The example `compose.yaml` expects deployment-owned configuration at `./config.yaml`:

```yaml
volumes:
  - /:/host:ro
  - ./config.yaml:/etc/storage-harvester/config.yaml:ro
```

## Endpoints

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
- `inclusive`, `exclusive`, and `breakdown` rollups.
- `blocks` and `apparent` size modes.
- Cached background scans.
- Core scan health metrics.

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
  sum_remaining: true        # roll deeper bytes into nearest reported ancestor
  rollups:
    - breakdown              # breakdown, inclusive, exclusive
  size_modes:
    - blocks                 # blocks, apparent
```

Rollups:

- `inclusive`: directory plus all descendants.
- `exclusive`: entries directly in that directory only.
- `breakdown`: direct entries plus unreported deeper descendants when `sum_remaining` is enabled; useful for additive Grafana breakdowns.

Metric groups:

- Data: `storage_hotspot_size_bytes`, `storage_hotspot_entries`.
- Scan health: `storage_harvester_scan_success`, `storage_harvester_scan_duration_seconds`, `storage_harvester_scan_timestamp_seconds`, `storage_harvester_target_stale_seconds`, `storage_harvester_scan_count_total`, `storage_harvester_scan_errors_total`, `storage_harvester_scan_issue_count`.
- Cardinality/output: `storage_harvester_reported_nodes`, `storage_harvester_scanned_directories`, `storage_harvester_scanned_files`, `storage_harvester_scanned_symlinks`, `storage_harvester_max_observed_depth`, `storage_harvester_depth_limit_hits`.
