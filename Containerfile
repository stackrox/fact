FROM registry.access.redhat.com/ubi9/ubi-micro:latest AS ubi-micro-base

FROM registry.access.redhat.com/ubi9/ubi:latest AS package_installer

COPY --from=ubi-micro-base / /out/

RUN dnf install -y \
    --installroot=/out/ \
    --releasever=9 \
    --setopt=install_weak_deps=False \
    --nodocs \
    ca-certificates \
    crypto-policies-scripts \
    gzip \
    less \
    openssl-libs \
    tar && \
    dnf clean all --installroot=/out/ && \
    rm -rf /out/var/cache/dnf /out/var/cache/yum

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

FROM ubi-micro-base

ARG FACT_VERSION
LABEL name="fact" \
      vendor="StackRox" \
      maintainer="support@stackrox.com" \
      summary="File activity data collection for the StackRox Kubernetes Security Platform" \
      description="This image supports file activity data collection in the StackRox Kubernetes Security Platform." \
      io.stackrox.fact.version="${FACT_VERSION}"

COPY --from=package_installer /out/ /

COPY --from=build /app/fact /usr/local/bin

COPY LICENSE-APACHE LICENSE-MIT LICENSE-GPL2 /licenses/

RUN update-crypto-policies --set DEFAULT:PQ

ENTRYPOINT ["fact"]
