ifeq ($(FACT_TAG),)
FACT_TAG=$(shell git describe --always --tags --abbrev=10 --dirty)
endif

ifeq ($(FACT_IMAGE_NAME),)
FACT_IMAGE_NAME=quay.io/rhacs-eng/fact:$(FACT_TAG)
endif

tag:
	@echo "$(FACT_TAG)"

image-name:
	@echo "$(FACT_IMAGE_NAME)"

mock-server:
	make -C mock-server

image:
	docker build \
		-f Containerfile \
		-t $(FACT_IMAGE_NAME) \
		$(CURDIR)

integration-tests:
	make -C tests

.PHONY: tag mock-server integration-tests image image-name
