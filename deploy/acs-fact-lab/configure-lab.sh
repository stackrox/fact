#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib.sh"
require_command oc
require_command jq
require_command curl
require_kubeconfig
load_roxie_env

oc apply -f "${SCRIPT_DIR}/workloads.yaml"
oc -n "${LAB_NAMESPACE}" rollout status deployment/rootfs-writer --timeout=5m
oc -n "${LAB_NAMESPACE}" rollout status deployment/emptydir-writer --timeout=5m

node=$(oc get nodes -l node-role.kubernetes.io/worker -o jsonpath='{.items[0].metadata.name}')
oc -n "${LAB_NAMESPACE}" create configmap fact-lab-state \
  --from-literal=node="${node}" \
  --dry-run=client -o yaml | oc apply -f -

# Seed the exact host inode before the policy reaches FACT. This makes host
# scanner behavior deterministic and limits all host writes to /var/tmp.
oc -n "${LAB_NAMESPACE}" debug "node/${node}" -- \
  chroot /host sh -c 'touch /var/tmp/acs-fact-host-marker && chmod 600 /var/tmp/acs-fact-host-marker'

while IFS= read -r policy_name; do
  while IFS= read -r policy_id; do
    [[ -z "${policy_id}" ]] || rox_api DELETE "/v1/policies/${policy_id}" >/dev/null
  done < <(policy_ids_by_name "${policy_name}")
done < <(jq -r '.[].name' "${SCRIPT_DIR}/policies.json")

policy_dir=$(mktemp -d)
trap 'rm -rf "${policy_dir}"' EXIT
policy_count=$(jq 'length' "${SCRIPT_DIR}/policies.json")
for index in $(seq 0 $((policy_count - 1))); do
  policy_file="${policy_dir}/policy-${index}.json"
  jq ".[${index}]" "${SCRIPT_DIR}/policies.json" >"${policy_file}"
  rox_api POST /v1/policies "${policy_file}" | jq -r '"created policy: \(.name) [\(.id)]"'
done

wait_for_fact_paths
oc -n stackrox get configmap fact-config -o jsonpath='{.data.fact\.yml}'

for deployment in rootfs-writer emptydir-writer; do
  query=$(jq -rn --arg value "Deployment:${deployment}" '$value|@uri')
  for _ in $(seq 1 60); do
    count=$(rox_api GET "/v1/deployments?query=${query}" | jq --arg name "${deployment}" '[.deployments[]? | select(.name == $name)] | length')
    [[ "${count}" -gt 0 ]] && break
    sleep 2
  done
  [[ "${count}" -gt 0 ]] || {
    echo "ACS did not inventory deployment ${deployment}" >&2
    exit 1
  }
done

echo "lab policies, workloads, host marker, and FACT paths are ready"
