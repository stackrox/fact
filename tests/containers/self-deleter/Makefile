include ../constants.mk

FACT_QA_SELF_DELETER_TAG := fact-self-deleter

ifneq ($(FACT_QA_TAG),)
FACT_QA_SELF_DELETER_TAG=fact-self-deleter-$(FACT_QA_TAG)
endif

.PHONY: all
all: build

.PHONY: build
build:
	@$(DOCKER) buildx build --load --platform $(PLATFORM) \
		-t quay.io/rhacs-eng/qa-multi-arch:$(FACT_QA_SELF_DELETER_TAG) .

.PHONY: build-and-push
build-and-push:
	@$(DOCKER) buildx build --push --platform $(PLATFORM) \
		-t quay.io/rhacs-eng/qa-multi-arch:$(FACT_QA_SELF_DELETER_TAG) .
