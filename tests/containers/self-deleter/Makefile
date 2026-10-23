include ../constants.mk

FACT_QA_SELF_DELETER_TAG := fact-self-deleter-$(FACT_QA_TAG)

all: build

run:
	$(DOCKER) buildx build $(BUILD_ARGS) --platform $(PLATFORM) \
		-t quay.io/rhacs-eng/qa-multi-arch:$(FACT_QA_SELF_DELETER_TAG) \
		-f Containerfile \
		$(CURDIR)

build: BUILD_ARGS = --load
build: run

build-and-push: BUILD_ARGS = --push
build-and-push: run

exists:
	$(DOCKER) manifest inspect quay.io/rhacs-eng/qa-multi-arch:$(FACT_QA_SELF_DELETER_TAG) &>/dev/null

.PHONY: build build-and-push all run exists
