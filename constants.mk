FACT_TAG ?= $(shell git describe --always --tags --abbrev=10 --dirty)
FACT_VERSION ?= $(FACT_TAG)
FACT_REGISTRY ?= quay.io/stackrox-io/fact
FACT_IMAGE_NAME ?= $(FACT_REGISTRY):$(FACT_TAG)
FACT_RHACS_ENG_REGISTRY ?= quay.io/rhacs-eng/fact
FACT_RHACS_ENG_IMAGE_NAME ?= $(FACT_RHACS_ENG_REGISTRY):$(FACT_TAG)

CLANG_FMT ?= $(shell which clang-format)
