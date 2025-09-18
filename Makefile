include constants.mk

tag:
	@echo "$(FACT_TAG)"

image-name:
	@echo "$(FACT_IMAGE_NAME)"

mock-server:
	make -C mock-server

image:
	docker build \
		-f Containerfile \
		--build-arg FACT_TAG=$(FACT_TAG) \
		-t $(FACT_IMAGE_NAME) \
		$(CURDIR)

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
