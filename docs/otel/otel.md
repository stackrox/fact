# `fact` OpenTelemetry output

`fact` can optionally push file activity events as
[OTLP](https://opentelemetry.io/docs/specs/otlp/) log records over
HTTP (protobuf encoding) to any OTLP-compatible endpoint such as
[Grafana Loki](https://grafana.com/oss/loki/),
[Grafana Alloy](https://grafana.com/docs/alloy/), or a standard
[OpenTelemetry Collector](https://opentelemetry.io/docs/collector/).

This feature is gated behind the `otel` Cargo feature flag and is not
included in the default build.

## Building with OTel support

### Local build

```sh
cargo build --release --features otel
```

### Container image

```sh
make image-otel
```

This invokes the regular `image` target with `CARGO_ARGS=--features otel`.
If you use podman instead of docker, set `DOCKER=podman`:

```sh
make image-otel DOCKER=podman
```

## Configuration

The OTel output requires a single setting: the OTLP HTTP endpoint URL
where log records will be pushed. It can be configured in three ways
(later entries override earlier ones):

| Method | Example |
|---|---|
| YAML config file | `otel:` block with `endpoint:` key (see below) |
| Environment variable | `FACT_OTEL_ENDPOINT=http://loki:3100/otlp/v1/logs` |
| CLI flag | `--otel-endpoint http://loki:3100/otlp/v1/logs` |

YAML example:

```yaml
otel:
  endpoint: http://loki:3100/otlp/v1/logs
```

The endpoint value is the full OTLP HTTP logs URL exposed by your
backend. Common values:

| Backend | Endpoint |
|---|---|
| Grafana Loki | `http://<host>:3100/otlp/v1/logs` |
| OTel Collector | `http://<host>:4318/v1/logs` |

When no endpoint is configured the OTel client is idle and consumes no
resources.

## Technical details

- Events are serialized as structured OTLP `LogRecord` attributes
  using the native OpenTelemetry `AnyValue` map format.
- Transport is HTTP with binary protobuf encoding.
- Records are batched automatically by the OpenTelemetry SDK before
  export. Batch parameters can be tuned via standard
  [OTLP environment variables](https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/#batch-log-record-processor)
  such as `OTEL_BLRP_SCHEDULE_DELAY` and
  `OTEL_BLRP_MAX_EXPORT_BATCH_SIZE`.
- The OTLP resource `service.name` is set to `fact`.
- All records are emitted with severity `Info`.
- The endpoint supports hot-reload: sending `SIGHUP` to reload the
  configuration will reconnect the OTel client to a new endpoint
  without restarting the process.

## Example: pushing events to Loki with Grafana

This walkthrough sets up a minimal Loki instance with Grafana for
visualization, then runs `fact` with the OTel output pointing at
Loki's OTLP ingestion endpoint.

All commands below use `docker` but work identically with `podman`.

### 1. Create a network

```sh
docker network create fact-loki
```

### 2. Start Loki

This directory contains a minimal Loki configuration in
[loki-config.yaml](loki-config.yaml). Mount it into the container:

```sh
docker run -d --name loki \
  --network fact-loki \
  -p 127.0.0.1:3100:3100 \
  -v ./docs/otel/loki-config.yaml:/etc/loki/config.yaml:ro,z \
  docker.io/grafana/loki:3.7.3
```

Loki exposes its OTLP ingestion endpoint at `/otlp/v1/logs` on port
3100.

### 3. Start Grafana

Grafana is pre-configured with a Loki datasource
([grafana-datasource.yaml](grafana-datasource.yaml)) and a small
dashboard ([grafana-fact-dashboard.json](grafana-fact-dashboard.json))
via provisioning files:

```sh
docker run -d --name grafana \
  --network fact-loki \
  -p 127.0.0.1:3000:3000 \
  -e GF_AUTH_ANONYMOUS_ENABLED=true \
  -e GF_AUTH_ANONYMOUS_ORG_ROLE=Admin \
  -v ./docs/otel/grafana-datasource.yaml:/etc/grafana/provisioning/datasources/loki.yaml:ro,z \
  -v ./docs/otel/grafana-dashboard-provider.yaml:/etc/grafana/provisioning/dashboards/default.yaml:ro,z \
  -v ./docs/otel/grafana-fact-dashboard.json:/var/lib/grafana/dashboards/fact.json:ro,z \
  docker.io/grafana/grafana:13.1.0
```

### 4. Run `fact`

#### Option A: container image

Build the OTel image first (if you haven't already):

```sh
make image-otel
```

Then run it on the same network so it can reach Loki by name:

```sh
docker run --rm -it \
  --privileged \
  --network fact-loki \
  -e FACT_OTEL_ENDPOINT=http://loki:3100/otlp/v1/logs \
  -e FACT_PATHS='/etc:/etc/**/*' \
  -e FACT_HOST_MOUNT=/host \
  -v /:/host:ro \
  "$(make image-name)"
```

#### Option B: local binary

Since the binary runs on the host, reach Loki via the published port:

```sh
cargo build --release --features otel
sudo -E FACT_OTEL_ENDPOINT=http://localhost:3100/otlp/v1/logs \
  ./target/release/fact -p /etc
```

### 5. View events in Grafana

Open <http://localhost:3000/dashboards> and select the **fact - File
Activity** dashboard. It contains four panels:

- **Event rate** — a time series showing the number of events per
  minute.
- **Events by type** — a donut chart breaking down events by type
  (open, creation, chmod, etc.).
- **Events by file** — a donut chart breaking down events by filename.
- **Events** — a log stream of all file activity events with full
  attribute details.

You can also query events directly in **Explore**
(<http://localhost:3000/explore>) using LogQL, for example:

```logql
{service_name="fact"}
```

### Cleanup

```sh
docker rm -f loki grafana
docker network rm fact-loki
```
