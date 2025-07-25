# fact

## Prerequisites

1. stable rust toolchains.
1. clang and libbpf headers for the C eBPF probe.
1. protoc and the Google protobuf definitions for gRPC.

On Fedora, you can install all the dependencies with the following
commands:

```sh
sudo dnf install -y \
    clang \
    libbpf-devel \
    protobuf-compiler \
    protobuf-devel \
    rustup
rustup toolchain install stable
```

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

Cargo build scripts are used to automatically build the eBPF correctly
and include it in the program.

## License

With the exception of eBPF code, fact is distributed under the terms
of the [Apache License] (version 2.0).

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this project by you, as defined in the GPL-2
license, shall be dual licensed as above, without any additional terms
or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
