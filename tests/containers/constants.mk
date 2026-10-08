REPO_ROOT := $(shell git rev-parse --show-toplevel)

include $(REPO_ROOT)/constants.mk

# PLATFORM can be a comma separated list of platforms of the form linux/<arch>
# it is passed to buildx, which will build for each one (this is important
# for pushing multi-arch images because `buildx --push` will push a manifest list
# containing all the relevant platforms)
PLATFORM ?= linux/amd64

# Path needs to be absolute so subdirectories don't fail when they include this
# file.
FACT_QA_TAG ?= $(shell cat "$(REPO_ROOT)/tests/containers/QA_TAG")
