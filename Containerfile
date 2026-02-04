FROM quay.io/centos/centos:stream9 AS builder

ARG RUST_VERSION=stable

RUN dnf install --enablerepo=crb -y \
        clang \
        make \
        elfutils-libelf-devel \
        zlib-devel \
        openssl-devel \
        protobuf \
        protobuf-devel \
        protobuf-compiler && \
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
            sh -s -- -y --default-toolchain $RUST_VERSION --profile minimal

ENV PATH=/root/.cargo/bin:${PATH}

WORKDIR /app

# Build vendored dependencies
COPY builder/install builder/install
COPY builder/third_party builder/third_party

RUN builder/install/install-dependencies.sh
RUN echo -e '/usr/local/lib\n/usr/local/lib64' > /etc/ld.so.conf.d/usrlocallib.conf && ldconfig

# Set up environment to use vendored libbpf
ENV PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig:/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
ENV LD_LIBRARY_PATH=/usr/local/lib64:/usr/local/lib:$LD_LIBRARY_PATH
ENV C_INCLUDE_PATH=/usr/local/include:$C_INCLUDE_PATH

COPY . .

FROM builder AS build

ARG FACT_VERSION
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    cp target/release/fact fact

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

ARG FACT_VERSION
LABEL name="fact" \
      vendor="StackRox" \
      maintainer="support@stackrox.com" \
      summary="File activity data collection for the StackRox Kubernetes Security Platform" \
      description="This image supports file activity data collection in the StackRox Kubernetes Security Platform." \
      io.stackrox.fact.version="${FACT_VERSION}"

RUN microdnf install -y openssl-libs && \
    microdnf clean all && \
    rpm --verbose -e --nodeps $( \
        rpm -qa 'curl' '*rpm*' '*dnf*' '*libsolv*' '*hawkey*' 'yum*' 'libyaml*' 'libarchive*' \
    ) && \
    rm -rf /var/cache/yum

COPY --from=build /app/fact /usr/local/bin

COPY LICENSE-APACHE LICENSE-MIT LICENSE-GPL2 /licenses/

ENTRYPOINT ["fact"]
