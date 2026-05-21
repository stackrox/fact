FROM registry.access.redhat.com/ubi9/ubi-micro@sha256:4b45a7cbeab6b02e6db359ce007439ce612b296c29d9d0fb688a9d24d3b56f02 AS ubi-micro-base

FROM registry.access.redhat.com/ubi9/ubi@sha256:151fc1b2c976f198779d740851436544fdf4e9449ccb4a47e2d0faad34f1733b AS package_installer

COPY --from=ubi-micro-base / /out/

RUN dnf install -y \
    --installroot=/out/ \
    --releasever=9 \
    --setopt=install_weak_deps=False \
    --setopt=reposdir=/etc/yum.repos.d \
    --nodocs \
    ca-certificates \
    crypto-policies-scripts \
    gzip \
    less \
    openssl-libs \
    tar && \
    dnf clean all --installroot=/out/ && \
    rm -rf /out/var/cache/dnf /out/var/cache/yum

FROM registry.access.redhat.com/ubi9/ubi@sha256:151fc1b2c976f198779d740851436544fdf4e9449ccb4a47e2d0faad34f1733b AS builder

ARG FACT_TAG
RUN echo "Checking required FACT_TAG"; [[ "${FACT_TAG}" != "" ]]

RUN dnf install --allowerasing -y \
        clang \
        libbpf-devel \
        openssl-devel \
        protobuf-compiler \
        protobuf-devel \
        cargo \
        rust

WORKDIR /app

COPY . .

RUN cargo build --release

FROM ubi-micro-base

ARG FACT_TAG

LABEL \
    com.redhat.component="rhacs-fact-container" \
    com.redhat.license_terms="https://www.redhat.com/agreements" \
    description="This image supports file activity data collection for Red Hat Advanced Cluster Security for Kubernetes" \
    distribution-scope="public" \
    io.k8s.description="This image supports file activity data collection for Red Hat Advanced Cluster Security for Kubernetes" \
    io.k8s.display-name="fact" \
    io.openshift.tags="rhacs,fact,stackrox" \
    maintainer="Red Hat, Inc." \
    name="advanced-cluster-security/rhacs-fact-rhel9" \
    # Custom Snapshot creation in `operator-bundle-pipeline` depends on source-location label to be set correctly.
    source-location="https://github.com/stackrox/fact" \
    summary="File activity data collection for Red Hat Advanced Cluster Security for Kubernetes" \
    url="https://catalog.redhat.com/software/container-stacks/detail/60eefc88ee05ae7c5b8f041c" \
    vendor="Red Hat, Inc." \
    # We must set version label for EC and to prevent inheriting value set in the base stage.
    version="${FACT_TAG}" \
    # Release label is required by EC although has no practical semantics.
    # We also set it to not inherit one from a base stage in case it's RHEL or UBI.
    release="1"

COPY --from=package_installer /out/ /

COPY --from=builder /app/target/release/fact /usr/local/bin

COPY LICENSE-APACHE LICENSE-MIT LICENSE-GPL2 /licenses/

RUN update-crypto-policies --set DEFAULT:PQ

ENTRYPOINT ["fact"]
