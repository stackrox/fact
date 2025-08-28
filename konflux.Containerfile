FROM registry.access.redhat.com/ubi9/ubi:latest AS builder

ARG FACT_TAG
RUN if [[ "$FACT_TAG" == "" ]]; then >&2 echo "error: required FACT_TAG arg is unset"; exit 6; fi

RUN dnf install -y \
        clang \
        libbpf-devel \
        protobuf-compiler \
        protobuf-devel \
        cargo \
        rust && \
    mkdir /app

WORKDIR /app

COPY . .

RUN cargo build --release

FROM registry.access.redhat.com/ubi9/ubi-micro:latest

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
