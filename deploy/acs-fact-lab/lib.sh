#!/usr/bin/env bash

set -euo pipefail

LAB_NAMESPACE=acs-file-activity-lab
ROXIE_ENVRC=${ROXIE_ENVRC:-/tmp/roxie-fact-lab.envrc}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "required command not found: $1" >&2
    exit 1
  }
}

require_kubeconfig() {
  if [[ -z "${KUBECONFIG:-}" || ! -f "${KUBECONFIG}" ]]; then
    echo "set KUBECONFIG to the downloaded cluster kubeconfig" >&2
    exit 1
  fi
}

load_roxie_env() {
  if [[ ! -f "${ROXIE_ENVRC}" ]]; then
    echo "Roxie environment file not found: ${ROXIE_ENVRC}" >&2
    exit 1
  fi
  set -a
  # shellcheck disable=SC1090
  source "${ROXIE_ENVRC}"
  set +a
  : "${ROX_ENDPOINT:?ROX_ENDPOINT is missing from the Roxie environment}"
  : "${ROX_USERNAME:?ROX_USERNAME is missing from the Roxie environment}"
  : "${ROX_ADMIN_PASSWORD:?ROX_ADMIN_PASSWORD is missing from the Roxie environment}"
  : "${ROX_CA_CERT_FILE:?ROX_CA_CERT_FILE is missing from the Roxie environment}"
}

rox_api() {
  local method=$1
  local api_path=$2
  local data_file=${3:-}
  local endpoint_host=${ROX_ENDPOINT%:*}
  local args=(
    --silent --show-error --fail-with-body --noproxy '*'
    --resolve "central.stackrox:443:${endpoint_host}"
    --user "${ROX_USERNAME}:${ROX_ADMIN_PASSWORD}"
    --cacert "${ROX_CA_CERT_FILE}"
    --request "${method}"
  )
  if [[ -n "${data_file}" ]]; then
    args+=(--header 'Content-Type: application/json' --data-binary "@${data_file}")
  fi
  curl "${args[@]}" "https://central.stackrox${api_path}"
}

policy_ids_by_name() {
  local policy_name=$1
  local query
  query=$(jq -rn --arg value "Policy:${policy_name}" '$value|@uri')
  rox_api GET "/v1/policies?query=${query}" | jq -r --arg name "${policy_name}" '.policies[]? | select(.name == $name) | .id'
}

wait_for_fact_paths() {
  local config
  for _ in $(seq 1 90); do
    config=$(oc -n stackrox get configmap fact-config -o jsonpath='{.data.fact\.yml}' 2>/dev/null || true)
    if grep -q '/tmp/acs-fact-lab-marker' <<<"${config}" && grep -q '/var/tmp/acs-fact-host-marker' <<<"${config}"; then
      return 0
    fi
    sleep 2
  done
  echo "timed out waiting for Sensor to compile the lab paths into fact-config" >&2
  return 1
}

lab_node() {
  local node
  node=$(oc -n "${LAB_NAMESPACE}" get configmap fact-lab-state -o jsonpath='{.data.node}' 2>/dev/null || true)
  if [[ -z "${node}" ]]; then
    node=$(oc get nodes -l node-role.kubernetes.io/worker -o jsonpath='{.items[0].metadata.name}')
  fi
  printf '%s\n' "${node}"
}
