FACT_TAG ?= $(shell git describe --always --tags --abbrev=10 --dirty)
FACT_IMAGE_NAME ?= quay.io/rhacs-eng/fact:$(FACT_TAG)
