FROM registry.access.redhat.com/ubi9/ubi:latest AS builder

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

COPY --from=builder /app/target/release/fact /usr/local/bin

ENTRYPOINT ["fact"]
