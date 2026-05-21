# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

fact (File ACTivity) is a file integrity monitoring tool designed for PCI DSS compliance. It's implemented as a BPF agent that:
- Attaches BPF programs to LSM (Linux Security Module) hooks in the kernel
- Receives file system events from the kernel via ring buffers
- Enriches events with process and file metadata
- Outputs events via gRPC or JSON for further processing
- Supports hot-reload of configuration via SIGHUP
- Exposes Prometheus metrics

The project requires modern kernel features (BTF symbols, LSM hooks, BPF trampolines) and is tested on RHEL 9.6+/10+, RHCOS 4.16+, and Fedora CoreOS 43.

## Workspace Structure

This is a Cargo workspace with three main crates:

- **fact**: Main binary that loads BPF programs, processes events, and handles output
  - `src/bpf/`: Rust code for loading and managing BPF programs (uses aya library)
  - `src/event/`: Event processing and enrichment logic
  - `src/config/`: Configuration parsing and hot-reload via `Reloader`
  - `src/output/`: gRPC and JSON output handlers
  - `src/metrics/`: Prometheus metrics exporter
  - `src/host_scanner.rs`: Scans host for existing files on startup

- **fact-api**: gRPC API definitions generated from protobuf files in `third_party/stackrox/proto`

- **fact-ebpf**: BPF program implementation
  - `src/bpf/*.c`: C code for BPF programs that attach to LSM hooks
  - `src/lib.rs`: Rust bindings and types for BPF maps/events
  - Build script compiles C code to BPF bytecode

## Key Architecture Patterns

### Event Flow
1. Kernel LSM hooks trigger BPF programs (in `fact-ebpf/src/bpf/main.c`)
2. BPF programs write events to ring buffer
3. `Bpf` worker (in `fact/src/bpf/mod.rs`) reads from ring buffer, sends to channel
4. `HostScanner` (in `fact/src/host_scanner.rs`) enriches events with process info
5. Output handlers (in `fact/src/output/`) send to gRPC or stdout as JSON

### Build Integration
- Cargo build scripts (`build.rs` files) automatically compile BPF C code
- BPF object files are embedded in the Rust binary
- No manual BPF compilation needed for normal development

### Configuration
- Config loaded from YAML files or environment variables/CLI args
- `Reloader` monitors for SIGHUP and reloads config without restart
- Paths to monitor can be specified via `--paths` or `FACT_PATHS`

## Common Commands

### Building
```sh
# Standard build
cargo build

# Release build (optimized)
cargo build --release

# Check without building
cargo check
```

### Running
```sh
# Run with sudo (required for BPF)
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'

# With path monitoring
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- -p /etc -p /var/log

# Skip pre-flight checks (if LSM hook detection fails)
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --skip-pre-flight
```

### Testing

**For agents/automated testing, prefer using pytest integration tests** (no sudo required):

```sh
# Set up Python virtual environment (first time only)
python3 -m venv .venv
source .venv/bin/activate
pip install -r tests/requirements.txt

# Build container image first
make image

# Run integration tests with pytest (recommended for agents)
cd tests/
pytest --image="<image-tag>"  # e.g., pytest --image="quay.io/stackrox-io/fact:latest"

# Run specific test file
pytest test_file_open.py --image="<image-tag>"
```

**Rust unit tests** (for development):

```sh
# Run Rust unit tests (excludes BPF tests, no sudo needed)
cargo test

# Run BPF-specific unit tests (requires sudo, avoid in automated workflows)
cargo test --config 'target."cfg(all())".runner="sudo -E"' --features=bpf-test
```

**Other test targets**:

```sh
# Run integration tests via Make (uses ansible, requires VMs)
make integration-tests

# Run performance tests
make performance-tests
```

### Formatting
```sh
# Format Rust and C code
make format

# Check formatting without modifying files
make format-check
```

### Container Image
```sh
# Build container image
make image

# Build mock server for testing
make mock-server
```

### IDE Support for BPF C Code
Generate `compile_commands.json` for clangd on x86_64:
```sh
bear -- clang -target bpf -O2 -g -c -Wall -Werror -D__TARGET_ARCH_x86_64 fact-ebpf/src/bpf/main.c -o /dev/null
```
For arm64, use `-D__TARGET_ARCH_aarch64` instead.

## Development Workflow

### Making Changes to BPF Code
1. Edit C files in `fact-ebpf/src/bpf/`
2. Follow existing patterns in `main.c` for LSM hook attachments
3. Format with `make -C fact-ebpf format`
4. Test with `cargo test --features=bpf-test` (requires sudo)

### Making Changes to Event Processing
1. Event definitions are in `fact-ebpf/src/bpf/events.h` (C) and `fact-ebpf/src/lib.rs` (Rust bindings)
2. Processing logic is in `fact/src/event/mod.rs` and `fact/src/event/process.rs`
3. Changes to event structure require updates to both C and Rust definitions

### Configuration Changes
1. Configuration schema is in `fact/src/config/mod.rs`
2. Hot-reload logic is in `fact/src/config/reloader.rs`
3. Add unit tests in `fact/src/config/tests.rs`

## Important Notes

- **Preferred testing for agents**: Use pytest integration tests in `tests/` directory (no sudo required)
- **Python environment**: All Python dependencies must be installed in a virtual environment at `.venv`
- All BPF operations require root/sudo privileges (avoid in automated testing when possible)
- The `bpf-test` feature gates tests that load actual BPF programs and requires sudo
- Build scripts handle BPF compilation automatically - no need to run clang manually
- Pytest integration tests require a built container image (use `make image` first)
- The project uses `sudo -E` to preserve environment variables when running with elevated privileges
- SIGHUP triggers configuration reload without restarting the process
