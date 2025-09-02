FROM registry.access.redhat.com/ubi9/ubi@sha256:7ff0b510498fa9f368a58e735e0c57f3497fd3205dbc2ea5e6e8ddf84f48752f AS builder

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

FROM registry.access.redhat.com/ubi9/ubi-micro@sha256:f5c5213d2969b7b11a6666fc4b849d56b48d9d7979b60a37bb853dff0255c14b

ARG FACT_TAG
RUN echo "Checking required FACT_TAG"; [[ "${FACT_TAG}" != "" ]]

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
