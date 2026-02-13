RUST_VERSION ?= 1.92

FACT_TAG ?= $(shell git describe --always --tags --abbrev=10 --dirty)
FACT_VERSION ?= $(FACT_TAG)
FACT_REGISTRY ?= quay.io/stackrox-io/fact
FACT_IMAGE_NAME ?= $(FACT_REGISTRY):$(FACT_TAG)

CLANG_FMT ?= $(shell which clang-format)

DOCKER ?= docker
