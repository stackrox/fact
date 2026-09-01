#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
FACT_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
STACKROX_DIR=${STACKROX_DIR:-"${FACT_ROOT}/../stackrox"}
ROXIE_ENVRC=${ROXIE_ENVRC:-/tmp/roxie-fact-lab.envrc}
DOCKER_CONFIG_JSON=${DOCKER_CONFIG_JSON:-}

# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib.sh"
require_command oc
require_command jq
require_command curl
require_kubeconfig

if [[ ! -x "${STACKROX_DIR}/scripts/roxie.sh" ]]; then
  echo "StackRox Roxie wrapper not found at ${STACKROX_DIR}/scripts/roxie.sh" >&2
  exit 1
fi
if [[ -z "${DOCKER_CONFIG_JSON}" || ! -f "${DOCKER_CONFIG_JSON}" ]]; then
  echo "set DOCKER_CONFIG_JSON to a registry config authorized for quay.io/rcochran" >&2
  exit 1
fi
if ! oc -n observability get service signoz-otel-collector >/dev/null 2>&1; then
  echo "SigNoz OTLP service observability/signoz-otel-collector is not available" >&2
  echo "deploy it with deploy/fact-signoz before enabling FACT_OTEL_ENDPOINT" >&2
  exit 1
fi

oc create namespace stackrox --dry-run=client -o yaml | oc apply -f -
oc -n stackrox create secret generic quay-rcochran \
  --type=kubernetes.io/dockerconfigjson \
  --from-file=.dockerconfigjson="${DOCKER_CONFIG_JSON}" \
  --dry-run=client -o yaml | oc apply -f -

(
  cd "${STACKROX_DIR}"
  ./scripts/roxie.sh \
    --skip-user-config \
    --config "${SCRIPT_DIR}/roxie.yaml" \
    deploy both \
    --deploy-operator \
    --envrc "${ROXIE_ENVRC}"
)

oc -n stackrox rollout status deployment/central --timeout=10m
oc -n stackrox rollout status deployment/sensor --timeout=10m
oc -n stackrox rollout status daemonset/collector --timeout=10m

fact_image=$(oc -n stackrox get daemonset collector -o json | jq -r '.spec.template.spec.containers[] | select(.name == "fact") | .image')
fact_env=$(oc -n stackrox get daemonset collector -o json | jq -r '.spec.template.spec.containers[] | select(.name == "fact") | .env[] | select(.name == "FACT_OCI_RUNTIME_SPEC_DEBUG" or .name == "FACT_OTEL_ENDPOINT") | "\(.name)=\(.value)"')

printf 'Roxie environment: %s\n' "${ROXIE_ENVRC}"
printf 'FACT image: %s\n' "${fact_image}"
printf '%s\n' "${fact_env}"
