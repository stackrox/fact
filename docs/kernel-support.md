# `fact` kernel support

At its current stage, `fact` uses features in the kernel that are quite
new in order to make development easier and faster at the cost of some
diminished compatibility. At a bare minimum, the kernel `fact` runs on
needs:
- Access to [BTF symbols](https://docs.ebpf.io/concepts/btf/) for
  relocation.
- BPF support for [LSM hooks](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_LSM/),
  which might need to be enabled at boot time.
- Support for [BPF trampolines](https://docs.ebpf.io/linux/concepts/trampolines/),
  since this is how LSM hooks are attached.
- Support for some newer BPF helpers and features like `bpf_loop`,
  `BPF_MAP_TYPE_RINGBUF`, etc.

Nailing down a specific list of kernels `fact` supports at this time is
difficult, but the following distributions are actively tested against
and expected to work on:

| Distro Name | Versions | Architecture |
|---|---|---|
| Fedora CoreOS | 43 | amd64, arm64 |
| RHCOS | 4.16+ | amd64 |
| RHEL | 9.6+, 10.0+ | amd64 |
| RHEL | 10.0+ | arm64 |
