FROM quay.io/centos/centos:stream9 AS builder

RUN dnf install --enablerepo=crb -y \
        clang-19.1.7 \
        libbpf-devel \
        protobuf-compiler \
        protobuf-devel \
        cargo-1.84.1 \
        rust-1.84.1

WORKDIR /app

COPY . .

ARG FACT_VERSION
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    cp target/release/fact fact

FROM registry.access.redhat.com/ubi9/ubi-micro:latest

COPY --from=builder /app/fact /usr/local/bin

ENTRYPOINT ["fact"]
