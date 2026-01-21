include constants.mk

tag:
	@echo "$(FACT_TAG)"

version:
	@echo "$(FACT_VERSION)"

image-name:
	@echo "$(FACT_IMAGE_NAME)"

mock-server:
	make -C mock-server

image:
	docker build \
		-f Containerfile \
		--build-arg FACT_VERSION=$(FACT_VERSION) \
		--build-arg RUST_VERSION=$(RUST_VERSION) \
		-t $(FACT_IMAGE_NAME) \
		$(CURDIR)

licenses:THIRD_PARTY_LICENSES.html

THIRD_PARTY_LICENSES.html:Cargo.lock
	cargo install cargo-about
	cargo about generate --format handlebars -o THIRD_PARTY_LICENSES.html about_html.hbs

integration-tests:
	make -C tests

performance-tests:
	make -C performance-tests

clean:
	make -C tests clean

format-check:
	cargo fmt --check
	make -C fact-ebpf format-check

format:
	cargo fmt
	make -C fact-ebpf format

.PHONY: tag mock-server integration-tests image image-name licenses clean
