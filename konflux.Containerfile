FROM registry.access.redhat.com/ubi9/ubi@sha256:dbc1e98d14a022542e45b5f22e0206d3f86b5bdf237b58ee7170c9ddd1b3a283 AS builder

ARG FACT_TAG
RUN echo "Checking required FACT_TAG"; [[ "${FACT_TAG}" != "" ]]

RUN dnf install -y \
        clang \
        libbpf-devel \
        protobuf-compiler \
        protobuf-devel \
        cargo \
        rust \
        # aws-lc FIPS requirements
        golang \
        perl \
        cmake

WORKDIR /app

COPY . .

RUN cargo build --release

FROM registry.access.redhat.com/ubi9/ubi-micro@sha256:f45ee3d1f8ea8cd490298769daac2ac61da902e83715186145ac2e65322ddfc8

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
