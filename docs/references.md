# Fact references

## Configuration options

### Environment variables

* `FACT_PATHS`: List of file paths to monitor.

* `FACT_LOGLEVEL`: At which level produce log messages.

* `FACT_CRI_SOCKET`: Absolute Unix socket path in Fact's filesystem for optional
  CRI `ContainerStatus` diagnostics. Requires a build with Cargo feature
  `runtime-metadata` and `FACT_LOGLEVEL=debug`. For a host mounted at `/host`,
  examples are `/host/run/crio/crio.sock` and
  `/host/run/containerd/containerd.sock`. The socket must be accessible to Fact.
  An unset variable disables lookups. Replay events do not trigger lookups.

  Diagnostics log the full container ID, name and attempt, state, lifecycle
  timestamps, exit code/reason, and image name/reference. Timestamps are CRI
  nanoseconds since Unix epoch; zero start/finish values mean unspecified, and
  exit code is meaningful only after finish. Each record is a runtime snapshot
  at lookup time, not the container state at the original file event's time.

  Lookups run in a background worker with a 128-ID queue, a one-second RPC
  deadline, and at most 1,024 distinct IDs per 30-second lookup window. Successful
  and failed lookups are retried only when a later event arrives after that
  window. Excess diagnostics are dropped; file-event delivery does not wait.
  Only `ContainerStatus` with `verbose=false` is called; no arbitrary labels,
  annotations, or runtime-specific verbose data are exported.

  Local standard and OTEL image builds enable `runtime-metadata`. A direct
  Cargo build requires `--features runtime-metadata`; Konflux release builds
  leave the feature disabled. These diagnostics only add debug logs.

### Commandline options

* `--skip-pre-flight`: Do not perform pre-flight checks. Before starting up
  Fact tries to verify if needed LSM hooks are available, but in some
  environments this might not be robust enough. In such cases one can disable
  those checks.

* `-p, --paths`: List of file paths to monitor. This option could be used
  multiple times, instructing Fact to monitor multiple files.
