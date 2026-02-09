FROM registry.access.redhat.com/ubi8/ubi@sha256:a2874895561a0f52e84c78c9c8b504922cd0dd03dc19d682a51c935d29330c55 AS builder

ARG FACT_TAG
RUN echo "Checking required FACT_TAG"; [[ "${FACT_TAG}" != "" ]]

RUN dnf install -y \
        clang \
        make \
        elfutils-libelf-devel \
        zlib-devel \
        openssl-devel \
        protobuf \
        protobuf-devel \
        protobuf-compiler \
        cargo \
        rust

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

RUN cargo build --release

FROM registry.access.redhat.com/ubi8/ubi-minimal@sha256:de46044c1c8d595193316655c441f196cf885bda9fb97244679b458327c19142

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
    name="advanced-cluster-security/rhacs-fact-rhel8" \
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

RUN microdnf install -y openssl-libs && \
    microdnf clean all && \
    rpm --verbose -e --nodeps $( \
        rpm -qa 'curl' '*rpm*' '*dnf*' '*libsolv*' '*hawkey*' 'yum*' 'libyaml*' 'libarchive*' \
    ) && \
    rm -rf /var/cache/yum

COPY --from=builder /app/target/release/fact /usr/local/bin

COPY LICENSE-APACHE LICENSE-MIT LICENSE-GPL2 /licenses/

ENTRYPOINT ["fact"]
