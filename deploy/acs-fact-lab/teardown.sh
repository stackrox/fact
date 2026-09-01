#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
FACT_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
STACKROX_DIR=${STACKROX_DIR:-"${FACT_ROOT}/../stackrox"}
TEARDOWN_ACS=false
TEARDOWN_SIGNOZ=false

for arg in "$@"; do
  case "${arg}" in
    --acs) TEARDOWN_ACS=true ;;
    --signoz) TEARDOWN_SIGNOZ=true ;;
    *) echo "usage: $0 [--acs] [--signoz]" >&2; exit 2 ;;
  esac
done

# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib.sh"
require_command oc
require_command jq
require_command curl
require_kubeconfig

if [[ -f "${ROXIE_ENVRC}" ]]; then
  load_roxie_env
  while IFS= read -r policy_name; do
    while IFS= read -r policy_id; do
      [[ -z "${policy_id}" ]] || rox_api DELETE "/v1/policies/${policy_id}" >/dev/null
    done < <(policy_ids_by_name "${policy_name}")
  done < <(jq -r '.[].name' "${SCRIPT_DIR}/policies.json")
fi

if oc get namespace "${LAB_NAMESPACE}" >/dev/null 2>&1; then
  node=$(lab_node)
  oc -n "${LAB_NAMESPACE}" debug "node/${node}" -- chroot /host rm -f /var/tmp/acs-fact-host-marker || true
  oc delete namespace "${LAB_NAMESPACE}" --wait=true
fi

if [[ "${TEARDOWN_ACS}" == true ]]; then
  (
    cd "${STACKROX_DIR}"
    ./scripts/roxie.sh --skip-user-config --config "${SCRIPT_DIR}/roxie.yaml" teardown both
    ./scripts/roxie.sh --skip-user-config --config "${SCRIPT_DIR}/roxie.yaml" teardown operator
  )
fi

if [[ "${TEARDOWN_SIGNOZ}" == true ]]; then
  oc delete namespace observability --wait=true
  oc delete securitycontextconstraints signoz-scc --ignore-not-found
fi
