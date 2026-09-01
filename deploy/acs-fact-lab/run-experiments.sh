#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib.sh"
require_command oc
require_kubeconfig
load_roxie_env

start_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
node=$(lab_node)

exercise_container_path() {
  local deployment=$1
  oc -n "${LAB_NAMESPACE}" exec "deployment/${deployment}" -- sh -c '
    printf create > /tmp/acs-fact-lab-marker
    printf append >> /tmp/acs-fact-lab-marker
    chmod 640 /tmp/acs-fact-lab-marker
    mv /tmp/acs-fact-lab-marker /tmp/acs-fact-lab-marker.moved
    mv /tmp/acs-fact-lab-marker.moved /tmp/acs-fact-lab-marker
    rm /tmp/acs-fact-lab-marker
  '
}

echo "experiment start: ${start_utc}"
echo "rootfs: six operations"
exercise_container_path rootfs-writer
echo "EmptyDir: same six operations"
exercise_container_path emptydir-writer

echo "oc debug: containerized writes to a monitored host inode"
oc -n "${LAB_NAMESPACE}" debug "node/${node}" -- \
  chroot /host sh -c 'printf debug-write >> /var/tmp/acs-fact-host-marker; chmod 600 /var/tmp/acs-fact-host-marker'

echo "host systemd unit: non-containerized writes to the same host inode"
oc -n "${LAB_NAMESPACE}" debug "node/${node}" -- \
  chroot /host systemd-run --wait --collect --unit=acs-fact-lab-host-write \
  /bin/sh -c 'printf host-write >> /var/tmp/acs-fact-host-marker; chmod 640 /var/tmp/acs-fact-host-marker'

echo "waiting for Sensor and Central to persist the results"
sleep 10

echo
echo "Raw FACT OTEL events since ${start_utc}"
SINCE_UTC=${start_utc} "${SCRIPT_DIR}/query-otel.sh"

echo
echo "ACS alerts"
"${SCRIPT_DIR}/query-alerts.sh"
