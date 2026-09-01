#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib.sh"
require_command jq
require_command curl
load_roxie_env

while IFS= read -r policy_name; do
  query=$(jq -rn --arg value "Policy:${policy_name}" '$value|@uri')
  response=$(rox_api GET "/v1/alerts?query=${query}")
  count=$(jq --arg name "${policy_name}" '[.alerts[]? | select(.policy.name == $name)] | length' <<<"${response}")
  printf '\n%s: %s alert(s)\n' "${policy_name}" "${count}"
  while IFS= read -r alert_id; do
    rox_api GET "/v1/alerts/${alert_id}" | jq '{
      id,
      policy: .policy.name,
      deployment: (.deployment.name // null),
      namespace: (.deployment.namespace // null),
      node: (.node.name // null),
      violations: [.violations[] | {
        operation: .fileAccess.operation,
        effectivePath: .fileAccess.file.effectivePath,
        actualPath: .fileAccess.file.actualPath,
        process: .fileAccess.process.signal.name,
        executable: .fileAccess.process.signal.execFilePath,
        containerId: .fileAccess.process.signal.containerId,
        pod: .fileAccess.process.podId,
        hostname: .fileAccess.hostname
      }]
    }'
  done < <(jq -r --arg name "${policy_name}" '.alerts[]? | select(.policy.name == $name) | .id' <<<"${response}")
done < <(jq -r '.[].name' "${SCRIPT_DIR}/policies.json")
