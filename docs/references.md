# Fact references

## Configuration options

### Environment variables

* `FACT_PATHS`: List of file paths to monitor.

* `FACT_LOGLEVEL`: At which level produce log messages.

* `FACT_OCI_RUNTIME_SPEC_DEBUG`: Development-only OCI runtime-spec
  diagnostics. When `true`, Fact adds a curated subset of `config.json`,
  including the root, configured process, capabilities, namespaces, and
  matching mount, to debug logs and `container.oci.*` OpenTelemetry
  attributes. OCI configuration is not read when this option is `false`.
  Diagnostics never filter events or change the Sensor gRPC message. The
  equivalent top-level YAML setting is `oci_runtime_spec_debug: true`.

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
