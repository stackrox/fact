#!/usr/bin/env bash
# Boot a cloud image in QEMU/KVM for integration testing.
#
# Designed to work both locally and in CI (GitHub Actions).  The script
# takes a pre-downloaded qcow2 cloud image, injects cloud-init or
# Ignition config, boots the VM, waits until it is ready, and prints
# SSH connection details.
#
# Usage:
#   ci/qemu-vm.sh start   [options]   — boot the VM
#   ci/qemu-vm.sh ssh     [options]   — open an SSH session to the VM
#   ci/qemu-vm.sh stop    [options]   — kill the VM
#
# Options:
#   --image PATH          path to the base qcow2 image (required for start)
#   --cloud-init PATH     cloud-init user-data template (one of
#                         --cloud-init/--ignition is required for start)
#   --ignition PATH       Ignition config template, for CoreOS-based
#                         images such as RHCOS (see --cloud-init)
#   --vm-dir DIR          working directory for VM files (default: /tmp/fact-vm)
#   --ssh-port PORT       host port forwarded to guest 22 (default: 2222)
#   --ssh-user USER       remote user to SSH as (default: root). Commands
#                         are automatically run via "sudo" when this is
#                         not root (e.g. RHCOS's "core" user).
#   --runtime NAME        container runtime running in the guest, used
#                         only to sanity-check it is up (default: podman)
#   --cpu N               vCPUs (default: all host CPUs)
#   --mem SIZE            memory, e.g. 8G (default: 75% of host RAM)
#   --host-mount DIR      directory to share with the VM via virtiofs at
#                         /mnt/host
#   --expect-reboot       wait for the VM to reboot once cloud-init
#                         finishes, before continuing (needed for
#                         cloud-init templates that update the kernel —
#                         see ci/cloud-init/fedora.yml — and
#                         reboot into it via a "power_state" directive).
#                         Only meaningful with --cloud-init; ignored
#                         with --ignition.
#
# Cloud-init / Ignition templates:
#   The --cloud-init/--ignition file has one special placeholder:
#   __SSH_PUBKEY__ is replaced with the VM's ephemeral SSH public key.
#   See ci/cloud-init/ and ci/ignition/ for examples.
#
# The VM state (image overlay, seed config, SSH keys, PID file) lives
# entirely under --vm-dir and can be cleaned up by removing that directory.

set -euo pipefail

: "${IMAGE:=}"
: "${CLOUD_INIT:=}"
: "${IGNITION:=}"
: "${VM_DIR:=/tmp/fact-vm}"
: "${SSH_PORT:=2222}"
: "${SSH_USER:=root}"
: "${RUNTIME:=podman}"
: "${CPU:=$(nproc)}"
: "${MEM:=$(awk '/^MemTotal/{printf "%dG", int($2/1024/1024*0.75)}' /proc/meminfo)}"
: "${HOST_MOUNT:=}"
: "${EXPECT_REBOOT:=0}"

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

usage() {
    sed -n '2,/^$/s/^# \{0,1\}//p' "$0"
    exit 1
}

log() { printf '==> %s\n' "$*" >&2; }

die() {
    echo >&2 "$1"
    exit 1
}

EXTRA_ARGS=()

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --image)        IMAGE="$2";        shift 2;;
            --cloud-init)   CLOUD_INIT="$2";   shift 2;;
            --ignition)     IGNITION="$2";     shift 2;;
            --vm-dir)       VM_DIR="$2";       shift 2;;
            --ssh-port)     SSH_PORT="$2";     shift 2;;
            --ssh-user)     SSH_USER="$2";     shift 2;;
            --runtime)      RUNTIME="$2";      shift 2;;
            --cpu)          CPU="$2";          shift 2;;
            --mem)          MEM="$2";          shift 2;;
            --host-mount)   HOST_MOUNT="$2";   shift 2;;
            --expect-reboot) EXPECT_REBOOT=1;  shift;;
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

create_ignition_config() {
    local pubkey
    pubkey="$(cat "${VM_DIR}/id_ed25519.pub")"

    log "Generating Ignition config from ${IGNITION}"
    sed "s|__SSH_PUBKEY__|${pubkey}|g" "${IGNITION}" > "${VM_DIR}/ignition.json"
}

find_virtiofsd() {
    local bin
    bin="$(command -v virtiofsd 2>/dev/null)" && { echo "${bin}"; return; }
    for p in /usr/libexec/virtiofsd /usr/lib/virtiofsd; do
        [[ -x "${p}" ]] && { echo "${p}"; return; }
    done
    die "error: virtiofsd not found"
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
        -netdev "user,id=net0,hostfwd=tcp::${SSH_PORT}-:22"
        -device virtio-net-pci,netdev=net0
        -serial "file:${VM_DIR}/console.log"
    )

    if [[ -n "${CLOUD_INIT}" ]]; then
        args+=(-drive "file=${VM_DIR}/seed.iso,if=virtio,format=raw,readonly=on")
    else
        args+=(-fw_cfg "name=opt/com.coreos/config,file=${VM_DIR}/ignition.json")
    fi

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
    if [[ $# -eq 0 ]]; then
        if [[ "${SSH_USER}" == "root" ]]; then
            ssh -p "${SSH_PORT}" -i "${VM_DIR}/id_ed25519" "${SSH_OPTS[@]}" "${SSH_USER}@localhost"
        else
            ssh -t -p "${SSH_PORT}" -i "${VM_DIR}/id_ed25519" "${SSH_OPTS[@]}" "${SSH_USER}@localhost" sudo -n -i
        fi
        return
    fi

    # ssh naively space-joins multiple trailing arguments before sending
    # them to the remote shell, which loses quoting boundaries (e.g. a
    # multi-line "bash -c '...'" script gets corrupted). Shell-quote and
    # join them ourselves into a single argument so ssh passes it
    # through untouched.
    local remote_cmd
    remote_cmd="$(printf '%q ' "$@")"

    # Non-root users (e.g. RHCOS's "core") need sudo for anything that
    # touches the host (mounting virtiofs, talking to a rootful
    # container runtime socket, etc). Wrap transparently so call sites
    # don't need to know which user they're running as.
    if [[ "${SSH_USER}" != "root" ]]; then
        remote_cmd="sudo -n -- sh -c $(printf '%q' "${remote_cmd}")"
    fi

    ssh -p "${SSH_PORT}" -i "${VM_DIR}/id_ed25519" "${SSH_OPTS[@]}" "${SSH_USER}@localhost" "${remote_cmd}"
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
    if ! vm_ssh cloud-init status --wait >/dev/null 2>&1; then
        log "cloud-init did not finish successfully"
        vm_ssh cloud-init status --long 2>/dev/null >&2 || true
        return 1
    fi
    log "cloud-init finished"
}

wait_for_reboot() {
    local old_boot_id="$1"
    local timeout=300

    log "Waiting for kernel-update reboot..."
    local i new_boot_id
    for i in $(seq 1 "${timeout}"); do
        new_boot_id="$(vm_ssh cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)"
        if [[ -n "${new_boot_id}" && "${new_boot_id}" != "${old_boot_id}" ]]; then
            log "Reboot detected after ${i}s"
            return 0
        fi
        sleep 1
    done
    log "VM did not reboot within ${timeout}s"
    return 1
}

cmd_start() {
    if [[ -z "${IMAGE}" ]]; then
        die "error: --image is required for start"
    fi
    if [[ ! -f "${IMAGE}" ]]; then
        die "error: image not found: ${IMAGE}"
    fi
    if [[ -z "${CLOUD_INIT}" && -z "${IGNITION}" ]]; then
        die "error: one of --cloud-init or --ignition is required for start"
    fi
    if [[ -n "${CLOUD_INIT}" && -n "${IGNITION}" ]]; then
        die "error: --cloud-init and --ignition are mutually exclusive"
    fi
    if [[ -n "${CLOUD_INIT}" && ! -f "${CLOUD_INIT}" ]]; then
        die "error: cloud-init template not found: ${CLOUD_INIT}"
    fi
    if [[ -n "${IGNITION}" && ! -f "${IGNITION}" ]]; then
        die "error: Ignition template not found: ${IGNITION}"
    fi

    mkdir -p "${VM_DIR}"
    create_overlay
    generate_ssh_key
    if [[ -n "${CLOUD_INIT}" ]]; then
        create_cloud_init_iso
    else
        create_ignition_config
    fi

    if [[ -n "${HOST_MOUNT}" ]]; then
        start_virtiofsd
    fi

    log "Starting QEMU (cpu=${CPU}, mem=${MEM}, ssh_port=${SSH_PORT})"
    touch "${VM_DIR}/console.log"
    local qemu_args
    mapfile -t qemu_args < <(build_qemu_args)
    qemu-system-x86_64 "${qemu_args[@]}"

    wait_for_ssh

    if [[ -n "${CLOUD_INIT}" ]]; then
        if [[ "${EXPECT_REBOOT}" == "1" ]]; then
            local pre_update_boot_id
            pre_update_boot_id="$(vm_ssh cat /proc/sys/kernel/random/boot_id)"
            wait_for_reboot "${pre_update_boot_id}"
        else
            wait_for_cloud_init
        fi
    fi

    if [[ -n "${HOST_MOUNT}" ]]; then
        log "Mounting host filesystem inside VM"
        vm_ssh sh -c 'mkdir -p /mnt/host && mount -t virtiofs host_mount /mnt/host'
    fi

    log "Checking ${RUNTIME} is up in the VM"
    vm_ssh "${RUNTIME}" info >/dev/null

    log "VM is ready"
    log "  SSH: ssh -p ${SSH_PORT} -i ${VM_DIR}/id_ed25519 ${SSH_OPTS[*]} ${SSH_USER}@localhost"
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
