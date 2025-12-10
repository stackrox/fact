FROM registry.access.redhat.com/ubi9/ubi@sha256:d4feb579a84ead49894ec71fe54f14300992e202f3491d9bb22b62cc57affd49 AS builder

ARG FACT_TAG
RUN echo "Checking required FACT_TAG"; [[ "${FACT_TAG}" != "" ]]

RUN dnf install -y \
        clang \
        libbpf-devel \
        protobuf-compiler \
        protobuf-devel \
        cargo \
        rust

WORKDIR /app

COPY . .

RUN cargo build --release

FROM registry.access.redhat.com/ubi9/ubi-micro@sha256:e14a8cbcaa0c26b77140ac85d40a47b5e910a4068686b02ebcad72126e9b5f86

ARG FACT_TAG

LABEL \
    com.redhat.license_terms="https://www.redhat.com/agreements" \
    description="This image supports file activity data collection for Red Hat Advanced Cluster Security for Kubernetes" \
    distribution-scope="public" \
    io.k8s.description="This image supports file activity data collection for Red Hat Advanced Cluster Security for Kubernetes" \
    io.openshift.tags="rhacs,fact,stackrox" \
    maintainer="Red Hat, Inc." \
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

COPY --from=builder /app/target/release/fact /usr/local/bin

ENTRYPOINT ["fact"]
