#!/usr/bin/env bash

set -e

cd builder/third_party/libbpf

mkdir -p src/build
make BUILD_STATIC_ONLY=y OBJDIR=build PREFIX=/usr/local "LDFLAGS=-Wl,-Bstatic" "CFLAGS=-fPIC ${EXTRA_CFLAGS_DEBUG:-}" \
     ${NPROCS:+-j ${NPROCS}} -C src install install_uapi_headers
