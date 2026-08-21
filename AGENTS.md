# AGENTS.md

## Project Overview

fact (File ACTivity) is a BPF-based file integrity monitoring tool for PCI DSS compliance. It attaches to kernel LSM hooks, receives file system events via ring buffers, enriches them, and outputs via gRPC, OTLP, or JSON. Supports hot-reload via SIGHUP and exposes Prometheus metrics.

Requires: BTF symbols, LSM hooks, BPF trampolines. Tested on RHEL 9.6+/10+, RHCOS 4.16+, Fedora CoreOS 43.

## Workspace Structure

Cargo workspace with three crates (`default-members = ["fact"]`, so bare `cargo build` only builds the main crate):

- **fact** (edition 2024): Main binary — BPF loading (aya), event processing, config, output, metrics
- **fact-api** (edition 2021): gRPC API generated from protos in `third_party/stackrox/proto` (git submodule)
- **fact-ebpf** (edition 2021): BPF C programs (`src/bpf/main.c`, `checks.c`) + Rust bindings via bindgen

### Build system dependencies

`libbpf-dev`, `protobuf-compiler`, `clang` (for BPF compilation), `make`, `git` (build.rs runs `make version` to embed git tag).

Proto submodule: `git submodule update --init` after fresh clone.

## Commands

### Build & check
```sh
cargo build              # builds only `fact` (default member)
cargo build --release
cargo check
```

### Lint
```sh
make lint                # cargo clippy --all-targets --all-features -- -D warnings + tests/
cargo clippy --all-targets --all-features -- -D warnings  # Rust only
```

### Format
```sh
make format              # cargo fmt + clang-format (BPF C/H) + ruff format tests/
make format-check        # check only, no modifications
```

### Test

**Rust unit tests** (no sudo needed):
```sh
cargo test
```

**BPF unit tests** (requires sudo, avoid in automated workflows):
```sh
cargo test --config 'target."cfg(all())".runner="sudo -E"' --features=bpf-test
```

**Integration tests** (require Docker, a built image, and proto codegen):
```sh
make image                                    # build container image first
python3 -m venv .venv                         # create venv (first time)
source .venv/bin/activate                     # activate venv
pip install -r tests/requirements.txt         # install deps (first time)
cd tests/
make grpc-gen                                 # generate Python proto stubs
pytest --image="<image-tag>"                  # run all tests
pytest test_file_open.py --image="<image-tag>"  # single file
pytest --output=otlp --image="<image-tag>"    # test OTLP output
```

Integration tests use the Docker Python SDK — they launch `fact` in a privileged container with `--network=host`, bind-mount `/` as `/host`, and communicate via gRPC/OTLP mock servers + health check endpoint. Python linting: `ruff check . && pyright .` (from `tests/`).

### Run locally (requires sudo)
```sh
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- -p /etc -p /var/log
```

## Key Architecture Notes

### Event flow
1. Kernel LSM hooks → BPF programs (`fact-ebpf/src/bpf/main.c`) → ring buffer
2. `Bpf` worker (`fact/src/bpf/mod.rs`) reads ring buffer → channel
3. `HostScanner` (`fact/src/host_scanner.rs`) does periodic inode scanning
4. Rate limiting (`fact/src/rate_limiter.rs`) → output (gRPC/OTLP/JSON)

### Dual-language event definitions
Event structs are defined in both C (`fact-ebpf/src/bpf/events.h`, `types.h`) and Rust (`fact-ebpf/src/lib.rs` via bindgen). Changes to event structure require updates to both sides.

### BPF build integration
`fact-ebpf/build.rs` compiles `main.c` and `checks.c` with clang targeting BPF, then runs bindgen on `types.h`. BPF objects are embedded in the binary. No manual clang invocation needed.

### Config
- Schema: `fact/src/config/mod.rs`
- Hot-reload: `fact/src/config/reloader/mod.rs` (polls every 10s + SIGHUP trigger)
- Config tests: `fact/src/config/tests.rs` and `fact/src/config/reloader/tests.rs`
- Config loaded from YAML files, env vars, or CLI args

### Feature flags
- `bpf-test`: gates tests that load actual BPF programs (requires sudo)
- `otel`: enables OpenTelemetry/OTLP output (`fact/Cargo.toml`)

## Gotchas

- `config.toml` at workspace root sets `rustflags = ["-C", "force-frame-pointers=yes"]` — this affects all builds
- `fact/build.rs` shells out to `make -sC .. version` to embed the git version string — builds fail without `make` and a valid git repo
- `CLANG_FMT` defaults to `clang-format`; CI uses `clang-format-18`. Override via env if your system name differs
- `CLAUDE.md` exists alongside this file with identical content — `AGENTS.md` is canonical
- Prometheus metrics use prefix `stackrox_fact`
