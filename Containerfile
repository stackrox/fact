FROM quay.io/centos/centos:stream9 AS builder

ARG RUST_VERSION=stable

RUN dnf install --enablerepo=crb -y \
        clang \
        libbpf-devel \
        openssl-devel \
        protobuf-compiler \
        protobuf-devel && \
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
            sh -s -- -y --default-toolchain $RUST_VERSION --profile minimal

ENV PATH=/root/.cargo/bin:${PATH}

WORKDIR /app

COPY . .

FROM builder AS build

ARG FACT_VERSION
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    cp target/release/fact fact

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

RUN microdnf install -y openssl-libs && \
    microdnf clean all && \
    rpm --verbose -e --nodeps $( \
        rpm -qa 'curl' '*rpm*' '*dnf*' '*libsolv*' '*hawkey*' 'yum*' 'libyaml*' 'libarchive*' \
    ) && \
    rm -rf /var/cache/yum

COPY --from=build /app/fact /usr/local/bin

ENTRYPOINT ["fact"]
