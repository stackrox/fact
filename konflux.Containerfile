FROM registry.access.redhat.com/ubi8/ubi:latest AS builder

RUN dnf install --enablerepo=crb -y \
        clang-20.1.8-1.el8 \
        libbpf-devel \
        protobuf-compiler \
        protobuf-devel \
        cargo-1.84.1 \
        rust-1.84.1 && \
    mkdir /app

WORKDIR /app

COPY . .

RUN cargo build --release

FROM registry.access.redhat.com/ubi8/ubi-micro:latest

COPY --from=builder /app/target/release/fact /usr/local/bin

ENTRYPOINT ["fact"]
