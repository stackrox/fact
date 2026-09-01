# ACS-controlled FACT validation lab

This is a development lab for comparing raw FACT events with RHACS file
activity policy results. RHACS policies are the only source of monitored paths;
do not edit the generated `stackrox/fact-config` ConfigMap.

See [RESULTS-2026-09-01.md](RESULTS-2026-09-01.md) for the captured validation
counts and conclusions.

The deployment was validated on `rc-dev-cluster` on 2026-09-01 with:

- StackRox source `d5255a30c33` and Roxie `v0.4.9`
- development main image `quay.io/rcochran/main:4.12.x-529-gc619d5385e`
- FACT source `96190289b3f4d0233ae62f231c4614fbcde0f2b3`
- FACT image `quay.io/rcochran/scratch@sha256:4e6968b475595baf96425bbe04f45e005a398ff7babb762cdbc6a9c0d0f95655`
- SigNoz chart `0.139.0` from the earlier `deploy/fact-signoz` lab

The Roxie overlay selects FACT's third operating mode:

1. Sensor output only: normal ACS configuration.
2. Sensor plus OCI diagnostics: add `FACT_OCI_RUNTIME_SPEC_DEBUG=true`.
3. Sensor plus OCI diagnostics plus OTLP: also add `FACT_OTEL_ENDPOINT`.

OCI diagnostics and OTLP are additive. FACT remains connected to Sensor and the
diagnostic feature does not change event selection or filtering.

## Deploy

Prerequisites are `oc`, `jq`, `curl`, the adjacent `stackrox/stackrox` checkout,
an existing SigNoz deployment in `observability`, and registry credentials for
the private development images. Do not commit the registry config or Roxie
environment file.

```sh
export KUBECONFIG=/path/to/infractl-cluster-artifacts/kubeconfig
export DOCKER_CONFIG_JSON=/path/to/registry/config.json
export ROXIE_ENVRC=/tmp/roxie-fact-lab.envrc

deploy/acs-fact-lab/setup-acs.sh
deploy/acs-fact-lab/configure-lab.sh
deploy/acs-fact-lab/run-experiments.sh
```

If SigNoz needs to be rebuilt, follow `deploy/fact-signoz/README.md` through the
SigNoz installation and static collector configuration, but do not deploy the
old standalone FACT operator or `Fact` custom resource.

The setup script creates the `quay-rcochran` pull secret from the supplied
registry config before Roxie deploys Central. The environment file contains the
generated ACS password and CA path; keep it private.

## What the experiment proves

The controlled container sequence emits create, writable open, permission
change, two renames, and unlink. The exact same sequence runs against container
rootfs and an EmptyDir mounted at `/tmp`.

| Case | Raw FACT identity | ACS result |
|---|---|---|
| container rootfs | empty `host_path`; OCI `no_mount_match` | deployment alert; empty `actualPath` |
| EmptyDir | empty `host_path`; OCI matched bind mount from `kubernetes.io~empty-dir` | deployment alert unless excluded |
| direct `oc debug node` host write | populated `host_path`; `openshift.debug=true`; container ID present | deployment alert attributed to the transient debug pod |
| host `systemd-run` write | populated `host_path`; no container ID | node alert attributed to the node |

The process policy (`Process Name=chmod`) and operation policy (`File
Operation=open`) each select only their matching event while the raw OTLP stream
retains the complete sequence. The exclusion policy suppresses the EmptyDir
deployment only; it does not alter FACT collection or OTLP.

Node versus deployment evaluation is currently determined by Sensor enrichment:
a nonempty deployment ID is a deployment event. It is not determined by whether
`host_path` is populated. This is why `oc debug node` is visible as a deployment
event while a detached host systemd unit is a node event.

The OCI mount match for a chrooted debug process is currently `no_mount_match`:
the observed path is `/var/tmp/...` after chroot while the OCI mount destination
is `/host`. The independent inode mapping still supplies the correct host path.

## Inspect

Open the SigNoz Logs Explorer and filter on `service.name = fact`. Useful fields
are:

```text
fact.build.sha
file.path
file.host_path
process.executable.path
k8s.namespace.name
k8s.pod.name
openshift.debug
container.oci.config.status
container.oci.mount.status
container.oci.mount.destination
container.oci.mount.source
```

For terminal output:

```sh
SINCE_UTC=2026-09-01T16:00:00Z deploy/acs-fact-lab/query-otel.sh
deploy/acs-fact-lab/query-alerts.sh
oc -n stackrox get configmap fact-config -o jsonpath='{.data.fact\.yml}'
```

The ACS UI shows the same results under Violations. Central and Sensor logs are
also available with `oc -n stackrox logs deployment/central` and
`oc -n stackrox logs deployment/sensor`.

## Tear down

The default removes only the six lab policies, workloads, and isolated host
marker. Add `--acs` to remove Roxie-deployed ACS. Add `--signoz` only when its
persistent telemetry data should also be deleted.

```sh
deploy/acs-fact-lab/teardown.sh
deploy/acs-fact-lab/teardown.sh --acs
deploy/acs-fact-lab/teardown.sh --acs --signoz
```
