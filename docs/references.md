# Fact references

## Configuration options

### Environment variables

* `FACT_PATHS`: List of file paths to monitor.

* `FACT_LOGLEVEL`: At which level produce log messages.

* `FACT_CRI_SOCKET`: Optional absolute path to the host CRI v1 gRPC socket. By
  default, Fact checks the host's CRI-O socket and then the containerd CRI
  plugin socket. Fact also reads CRI-O's on-disk OCI `config.json` when
  available, which provides process, capability, and rootfs details that the
  portable CRI status API does not expose. The socket is reached through the
  configured `FACT_HOST_MOUNT`; the standard host-root mount already covers it.

* `FACT_RUNTIME_METADATA_SOURCE`: Select `auto` (default), `json`, or `cri`.
  Auto reads the OCI JSON file first and falls back to CRI gRPC; the other
  values force one provider.

* `FACT_OCI_RUNTIME_SPEC_DEBUG`: Development-only OCI runtime-spec
  diagnostics. When `true`, Fact adds a curated subset of `config.json`,
  including the root, configured process, capabilities, namespaces, and
  matching mount, to debug logs and `container.oci.*` OpenTelemetry
  attributes. When OCI JSON is unavailable, CRI status can provide container
  identity, labels, annotations, image, and mounts; it does not invent values
  for process details or security settings the CRI response does not expose.
  Runtime metadata is not read when this option is `false`.
  Diagnostics never filter events or change the Sensor gRPC message. The
  equivalent top-level YAML setting is `oci_runtime_spec_debug: true`.
  This option is compiled into Fact only with Cargo feature
  `runtime-metadata`; local standard and OTEL image builds enable that feature.
  Konflux release builds leave it disabled.

  The supported diagnostic modes are:

  - default: Sensor gRPC output with no OCI diagnostics;
  - OCI debug: unchanged Sensor output plus debug-log diagnostics;
  - OCI debug with `FACT_OTEL_ENDPOINT`: unchanged Sensor output plus the same
    diagnostics in debug logs and OpenTelemetry.

  Debug-log records include the Fact version and build SHA. OpenTelemetry
  resources include `service.version` and, when the image was built with
  `FACT_BUILD_SHA`, `fact.build.sha`, so records can be tied to an exact build.

### Commandline options

* `--skip-pre-flight`: Do not perform pre-flight checks. Before starting up
  Fact tries to verify if needed LSM hooks are available, but in some
  environments this might not be robust enough. In such cases one can disable
  those checks.

* `-p, --paths`: List of file paths to monitor. This option could be used
  multiple times, instructing Fact to monitor multiple files.

* `--oci-runtime-spec-debug`: Equivalent to `FACT_OCI_RUNTIME_SPEC_DEBUG`;
  accepts `true` or `false`.

## Feature design

Feature modules own their provider state and format-specific enrichment. Core
event handling should require only a registration point and the smallest event
identity needed by a feature. This keeps event streams independent and makes
new streams or transformations easy to add without passing shared mutable state
between feature modules.
