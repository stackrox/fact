#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib.sh"
require_command oc
require_kubeconfig

SINCE_UTC=${SINCE_UTC:-1970-01-01T00:00:00Z}
clickhouse_pod=$(oc -n observability get pod -l clickhouse.altinity.com/chi=signoz-clickhouse -o jsonpath='{.items[0].metadata.name}')
since_sql=${SINCE_UTC/T/ }
since_sql=${since_sql%Z}

query="SELECT
  formatDateTime(fromUnixTimestamp64Nano(timestamp), '%FT%T.%fZ') AS time,
  attributes_string['event.name'] AS operation,
  attributes_string['file.path'] AS effective_path,
  attributes_string['file.host_path'] AS host_path,
  attributes_string['process.command'] AS process,
  attributes_string['process.executable.path'] AS executable,
  attributes_string['container.id'] AS container_id,
  attributes_string['k8s.namespace.name'] AS namespace,
  attributes_string['k8s.pod.name'] AS pod,
  attributes_bool['openshift.debug'] AS openshift_debug,
  attributes_string['container.oci.config.status'] AS oci_status,
  attributes_string['container.oci.mount.status'] AS mount_status,
  attributes_string['container.oci.mount.destination'] AS mount_destination,
  attributes_string['container.oci.mount.source'] AS mount_source,
  resources_string['fact.build.sha'] AS fact_build_sha
FROM signoz_logs.distributed_logs_v2
WHERE timestamp >= toUnixTimestamp64Nano(toDateTime64('${since_sql}', 9, 'UTC'))
  AND resources_string['service.name'] = 'fact'
  AND (attributes_string['file.path'] LIKE '%acs-fact-%'
       OR attributes_string['file.host_path'] LIKE '%acs-fact-%')
ORDER BY timestamp
FORMAT PrettyCompactMonoBlock"

oc -n observability exec "${clickhouse_pod}" -- clickhouse-client --query "${query}"
