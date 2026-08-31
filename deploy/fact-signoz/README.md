# FACT operator + SigNoz experiment

This directory records the deployment validated on the OpenShift cluster
`rc-dev-cluster` on 2026-08-31. It is intentionally a short runbook for a
future agent, not a supported installer.

## Tested inputs

- FACT source: `1ddd654120`
- StackRox submodule source: `8a9c85b426`
- Mauro's operator source: `origin/mauro/feat/fact-operator` at `651a9e7383`
- OTel FACT image:
  `quay.io/rcochran/scratch@sha256:846110c1455070e0d28594b0567b60488427a0c82e8495e549373b0c12657be9`
- Operator image:
  `quay.io/rcochran/scratch@sha256:a6730235378f7b150c7c827f4c9c44f8a4e94c292e851f865241bd073fb8988b`
- SigNoz chart `signoz/signoz` version `0.139.0`

The images were built as `linux/amd64`. When rebuilding, construct a clean
source archive from the recorded gitlink revisions. Do not copy the currently
checked-out `third_party/stackrox`: a different StackRox revision failed to
compile because the ACL/xattr protobuf definitions did not match FACT.

Build FACT with `CARGO_ARGS=--features otel`. Use descriptive, deep Quay tags,
for example:

```text
quay.io/rcochran/scratch:fact-otel-<fact-sha>-src-<stackrox-sha>-linux-amd64-<timestamp>
quay.io/rcochran/scratch:fact-operator-mauro-<operator-sha>-linux-amd64-<timestamp>
```

Deploy by digest after pushing. Copy a Quay pull secret into `fact-system` and
`fact-operator-test`, then link it to the `fact-operator` and `default` service
accounts respectively. Never commit registry credentials.

## Deploy

Set `KUBECONFIG` to the infractl-downloaded kubeconfig, then:

```sh
oc apply -f deploy/fact-signoz/signoz-scc.yaml

helm repo add signoz https://charts.signoz.io
helm repo update signoz
helm upgrade --install signoz signoz/signoz \
  --namespace observability --create-namespace \
  --version 0.139.0 \
  --set global.storageClass=ssd-csi \
  --set clickhouse.installCustomStorageClass=true \
  --wait --timeout 30m

oc apply -f deploy/fact-signoz/signoz-route.yaml
oc apply -f deploy/fact-signoz/operator.yaml
oc apply -f deploy/fact-signoz/fact.yaml
oc adm policy add-scc-to-user privileged -z default -n fact-operator-test
```

The SigNoz chart initially let OpAMP replace the collector pipelines with
`nop` pipelines before first-user onboarding. Force the tested collector to use
the chart's static configuration:

```sh
oc -n observability patch deployment signoz-otel-collector --type=json \
  -p='[{"op":"replace","path":"/spec/template/spec/containers/0/args","value":["--config=/conf/otel-collector-config.yaml"]}]'
oc -n observability rollout status deployment/signoz-otel-collector
```

This patch is outside Helm state and must be checked after a Helm upgrade.
Confirm ports 4317/4318 are listening before testing FACT.

The operator-generated DaemonSet uses the `default` service account and needs
the privileged SCC. It performs an initial host scan; files created later are
not necessarily tracked without a configured periodic scan. For deterministic
testing, create seed files under `/tmp/fact-operator-validation` before the
FACT pod starts, then modify/chmod/rename/unlink them.

Open <https://signoz-observability.apps.rc-dev-cluster.ocp.infra.rox.systems>,
create the first account, and use Logs Explorer. Filter on
`service.name = fact`; the useful fields are `body`, `hostname`, `file`, and
`process`. The validated marker was `fact-live-20260831T201728Z`.
