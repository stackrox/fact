include ../constants.mk

FACT_QA_EDITORS_TAG := fact-editors-$(FACT_QA_TAG)

all: build

run:
	$(DOCKER) buildx build $(BUILD_ARGS) --platform $(PLATFORM) \
		-t quay.io/rhacs-eng/qa-multi-arch:$(FACT_QA_EDITORS_TAG) \
		-f Containerfile \
		$(CURDIR)

build: BUILD_ARGS = --load
build: run

build-and-push: BUILD_ARGS = --push
build-and-push: run

.PHONY: build build-and-push all run
