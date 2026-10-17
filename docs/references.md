# Fact references

## Configuration options

### Environment variables

* `FACT_PATHS`: List of file paths to monitor.

* `FACT_LOGLEVEL`: At which level produce log messages.

* `FACT_CRI_SOCKET`: Absolute Unix socket path in Fact's filesystem for optional
  container image enrichment. Requires Cargo feature `runtime-metadata`.
  For a host mounted at `/host`, examples are `/host/run/crio/crio.sock` and
  `/host/run/containerd/containerd.sock`. The socket must be accessible to Fact.
  An unset variable disables lookups; debug logging is not required.

  JSON and OTEL events include optional `process.container_image`: CRI `image_id`
  when nonempty, otherwise `image_ref`. The value is passed through unchanged;
  a node-local image ID is not necessarily a pullable image reference. If both
  are empty, the field is omitted. Sensor protobuf output is unchanged.

  The first event schedules a background lookup and is delivered without image
  metadata. Later events use the cached result. A cache miss, failed lookup, or
  saturated queue leaves the field absent and never waits for a runtime RPC.
  Replay preserves recorded image metadata and does not trigger lookups.

  The module owns a 128-ID queue, a one-second RPC deadline, and a cache limited
  to 1,024 containers. Cache entries (including failures) expire 30 seconds
  after scheduling; a later event can request a refresh. Only `ContainerStatus`
  with `verbose=false` is called. Full container ID output, mounts, and labels
  are reserved for three separate follow-up PRs.

  Local standard and OTEL image builds enable `runtime-metadata`. A direct
  Cargo build requires `--features runtime-metadata`; Konflux release builds
  leave the feature disabled.

### Commandline options

* `--skip-pre-flight`: Do not perform pre-flight checks. Before starting up
  Fact tries to verify if needed LSM hooks are available, but in some
  environments this might not be robust enough. In such cases one can disable
  those checks.

* `-p, --paths`: List of file paths to monitor. This option could be used
  multiple times, instructing Fact to monitor multiple files.
