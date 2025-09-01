FACT_ARCH ?= amd64
FACT_TAG ?= $(shell git describe --always --tags --abbrev=10 --dirty)
FACT_REGISTRY ?= quay.io/stackrox-io/fact
FACT_IMAGE_NAME ?= $(FACT_REGISTRY):$(FACT_TAG)-$(FACT_ARCH)
