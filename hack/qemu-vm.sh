#!/usr/bin/env bash
# Boot a cloud image in QEMU/KVM for integration testing.
#
# Designed to work both locally and in CI (GitHub Actions).  The script
# takes a pre-downloaded qcow2 cloud image, injects cloud-init config,
# boots the VM, waits until it is ready, and prints SSH connection
# details.
#
# Usage:
#   hack/qemu-vm.sh start   [options]   — boot the VM
#   hack/qemu-vm.sh ssh     [options]   — open an SSH session to the VM
#   hack/qemu-vm.sh stop    [options]   — kill the VM
#
# Options:
#   --image PATH          path to the base qcow2 image (required for start)
#   --cloud-init PATH     cloud-init user-data template (required for start)
#   --vm-dir DIR          working directory for VM files (default: /tmp/fact-vm)
#   --ssh-port PORT       host port forwarded to guest 22 (default: 2222)
#   --cpu N               vCPUs (default: all host CPUs)
#   --mem SIZE            memory, e.g. 8G (default: 75% of host RAM)
#   --host-mount DIR      directory to share with the VM via virtiofs at /host
#
# Cloud-init templates:
#   The --cloud-init file is a standard #cloud-config YAML with one
#   special placeholder: __SSH_PUBKEY__ is replaced with the VM's
#   ephemeral SSH public key.  See hack/cloud-init/ for examples.
#
# The VM state (image overlay, cloud-init ISO, SSH keys, PID file) lives
# entirely under --vm-dir and can be cleaned up by removing that directory.

set -euo pipefail

: "${IMAGE:=}"
: "${CLOUD_INIT:=}"
: "${VM_DIR:=/tmp/fact-vm}"
: "${SSH_PORT:=2222}"
: "${CPU:=$(nproc)}"
: "${MEM:=$(awk '/^MemTotal/{printf "%dG", int($2/1024/1024*0.75)}' /proc/meminfo)}"
: "${HOST_MOUNT:=}"

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

usage() {
    sed -n '2,/^$/s/^# \{0,1\}//p' "$0"
    exit 1
}

log() { printf '==> %s\n' "$*" >&2; }

EXTRA_ARGS=()

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --image)        IMAGE="$2";        shift 2;;
            --cloud-init)   CLOUD_INIT="$2";   shift 2;;
            --vm-dir)       VM_DIR="$2";       shift 2;;
            --ssh-port)     SSH_PORT="$2";     shift 2;;
            --cpu)          CPU="$2";          shift 2;;
            --mem)          MEM="$2";          shift 2;;
            --host-mount)   HOST_MOUNT="$2";   shift 2;;
            -h|--help)      usage;;
            --)             shift; EXTRA_ARGS+=("$@"); return;;
            *)              EXTRA_ARGS+=("$@"); return;;
        esac
    done
}

create_overlay() {
    local base
    base="$(realpath "${IMAGE}")"
    local overlay="${VM_DIR}/disk.qcow2"
    if [[ -f "${overlay}" ]]; then
        log "Overlay already exists, removing stale one"
        rm -f "${overlay}"
    fi
    log "Creating qcow2 overlay"
    qemu-img create -f qcow2 -b "${base}" -F qcow2 "${overlay}" 20G >/dev/null
}

generate_ssh_key() {
    local key="${VM_DIR}/id_ed25519"
    if [[ -f "${key}" ]]; then
        return
    fi
    log "Generating ephemeral SSH key"
    ssh-keygen -t ed25519 -f "${key}" -N "" -q
}

create_cloud_init_iso() {
    local iso="${VM_DIR}/seed.iso"
    local pubkey
    pubkey="$(cat "${VM_DIR}/id_ed25519.pub")"

    local ci_dir="${VM_DIR}/cloud-init"
    mkdir -p "${ci_dir}"

    cat > "${ci_dir}/meta-data" <<EOF
instance-id: fact-test-vm
local-hostname: fact-test-vm
EOF

    log "Generating user-data from ${CLOUD_INIT}"
    sed "s|__SSH_PUBKEY__|${pubkey}|g" "${CLOUD_INIT}" > "${ci_dir}/user-data"

    log "Creating cloud-init seed ISO"
    genisoimage -output "${iso}" -volid cidata -joliet -rock \
        "${ci_dir}/user-data" "${ci_dir}/meta-data" 2>/dev/null
}

find_virtiofsd() {
    local bin
    bin="$(command -v virtiofsd 2>/dev/null)" && { echo "${bin}"; return; }
    for p in /usr/libexec/virtiofsd /usr/lib/virtiofsd; do
        [[ -x "${p}" ]] && { echo "${p}"; return; }
    done
    echo "error: virtiofsd not found" >&2
    return 1
}

start_virtiofsd() {
    local sock="${VM_DIR}/virtiofsd.sock"
    local bin
    bin="$(find_virtiofsd)"
    log "Starting virtiofsd for ${HOST_MOUNT}"
    "${bin}" \
        --socket-path="${sock}" \
        --shared-dir="${HOST_MOUNT}" \
        --cache=always &
    echo $! > "${VM_DIR}/virtiofsd.pid"

    local i
    for i in $(seq 1 30); do
        if [[ -S "${sock}" ]]; then
            log "virtiofsd ready after ${i}s"
            return 0
        fi
        sleep 1
    done
    log "virtiofsd socket did not appear after 30s"
    return 1
}

build_qemu_args() {
    # shellcheck disable=SC2054 # commas are inside quoted QEMU option values
    local args=(
        -nodefaults
        -display none
        -daemonize
        -pidfile "${VM_DIR}/qemu.pid"
        -enable-kvm
        -cpu host
        -smp "${CPU}"
        -m "${MEM}"
        -drive "file=${VM_DIR}/disk.qcow2,if=virtio,format=qcow2"
        -drive "file=${VM_DIR}/seed.iso,if=virtio,format=raw,readonly=on"
        -netdev "user,id=net0,hostfwd=tcp::${SSH_PORT}-:22"
        -device virtio-net-pci,netdev=net0
        -serial "file:${VM_DIR}/console.log"
    )

    if [[ -n "${HOST_MOUNT}" ]]; then
        args+=(
            -object "memory-backend-memfd,id=mem,size=${MEM},share=on"
            -numa "node,memdev=mem"
            -chardev "socket,id=char0,path=${VM_DIR}/virtiofsd.sock"
            -device "vhost-user-fs-pci,chardev=char0,tag=host_mount"
        )
    fi

    printf '%s\n' "${args[@]}"
}

vm_ssh() {
    ssh -p "${SSH_PORT}" -i "${VM_DIR}/id_ed25519" "${SSH_OPTS[@]}" root@localhost "$@"
}

wait_for_ssh() {
    log "Waiting for SSH (port ${SSH_PORT})..."
    local i
    for i in $(seq 1 180); do
        if vm_ssh true 2>/dev/null; then
            log "SSH ready after ${i}s"
            return 0
        fi
        sleep 1
    done
    log "SSH failed to become ready after 180s"
    [[ -f "${VM_DIR}/console.log" ]] && cat "${VM_DIR}/console.log" >&2
    return 1
}

wait_for_cloud_init() {
    log "Waiting for cloud-init to finish..."
    local i
    for i in $(seq 1 300); do
        if vm_ssh "test -f /var/lib/cloud/instance/boot-finished-user" 2>/dev/null; then
            log "cloud-init finished after ${i}s"
            return 0
        fi
        sleep 1
    done
    log "cloud-init did not finish within 300s"
    vm_ssh "cat /var/log/cloud-init-output.log" 2>/dev/null >&2 || true
    return 1
}

cmd_start() {
    if [[ -z "${IMAGE}" ]]; then
        echo "error: --image is required for start" >&2
        exit 1
    fi
    if [[ ! -f "${IMAGE}" ]]; then
        echo "error: image not found: ${IMAGE}" >&2
        exit 1
    fi
    if [[ -z "${CLOUD_INIT}" ]]; then
        echo "error: --cloud-init is required for start" >&2
        exit 1
    fi
    if [[ ! -f "${CLOUD_INIT}" ]]; then
        echo "error: cloud-init template not found: ${CLOUD_INIT}" >&2
        exit 1
    fi

    mkdir -p "${VM_DIR}"
    create_overlay
    generate_ssh_key
    create_cloud_init_iso

    if [[ -n "${HOST_MOUNT}" ]]; then
        start_virtiofsd
    fi

    log "Starting QEMU (cpu=${CPU}, mem=${MEM}, ssh_port=${SSH_PORT})"
    touch "${VM_DIR}/console.log"
    local qemu_args
    mapfile -t qemu_args < <(build_qemu_args)
    qemu-system-x86_64 "${qemu_args[@]}"

    wait_for_ssh
    wait_for_cloud_init

    log "Rebooting for BPF LSM kernel cmdline change..."
    vm_ssh "reboot" 2>/dev/null || true
    sleep 5
    wait_for_ssh

    log "Verifying BPF LSM is active"
    local lsm
    lsm="$(vm_ssh "cat /sys/kernel/security/lsm")"
    if [[ "${lsm}" != *bpf* ]]; then
        log "ERROR: bpf not found in LSM list: ${lsm}"
        return 1
    fi
    log "LSM list: ${lsm}"

    log "Verifying Docker is running"
    vm_ssh "docker info" >/dev/null

    if [[ -n "${HOST_MOUNT}" ]]; then
        log "Mounting host filesystem inside VM"
        vm_ssh "mkdir -p /host && mount -t virtiofs host_mount /host"
    fi

    log "VM is ready"
    log "  SSH: ssh -p ${SSH_PORT} -i ${VM_DIR}/id_ed25519 ${SSH_OPTS[*]} root@localhost"
}

cmd_ssh() {
    vm_ssh "${EXTRA_ARGS[@]}"
}

kill_pid_file() {
    local pidfile="$1" label="$2"
    if [[ -f "${pidfile}" ]]; then
        local pid
        pid="$(cat "${pidfile}")"
        log "Stopping ${label} (pid ${pid})"
        kill "${pid}" 2>/dev/null || true
        rm -f "${pidfile}"
    fi
}

cmd_stop() {
    kill_pid_file "${VM_DIR}/qemu.pid" "VM"
    kill_pid_file "${VM_DIR}/virtiofsd.pid" "virtiofsd"
}

main() {
    local cmd="${1:-help}"
    shift || true
    parse_args "$@"

    case "${cmd}" in
        start) cmd_start;;
        ssh)   cmd_ssh;;
        stop)  cmd_stop;;
        *)     usage;;
    esac
}

main "$@"
