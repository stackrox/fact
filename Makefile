include constants.mk

tag:
	@echo "$(FACT_TAG)"

version:
	@echo "$(FACT_VERSION)"

image-name:
	@echo "$(FACT_IMAGE_NAME)"

image-name-rhacs-eng:
	@echo "$(FACT_RHACS_ENG_IMAGE_NAME)"

mock-server:
	make -C mock-server

image:
	docker build \
		-f Containerfile \
		--build-arg FACT_VERSION=$(FACT_VERSION) \
		-t $(FACT_IMAGE_NAME) \
		$(CURDIR)

retag-image:
	docker tag $(FACT_IMAGE_NAME) $(FACT_RHACS_ENG_IMAGE_NAME)

integration-tests:
	make -C tests

clean:
	make -C tests clean

format-check:
	cargo fmt --check
	make -C fact-ebpf format-check

format:
	cargo fmt
	make -C fact-ebpf format

.PHONY: tag mock-server integration-tests image image-name clean
