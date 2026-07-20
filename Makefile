include constants.mk

tag:
	@echo "$(FACT_TAG)"

version:
	@echo "$(FACT_VERSION)"

image-name:
	@echo "$(FACT_IMAGE_NAME)"

operator-name:
	@echo "$(FACT_OPERATOR_NAME)"

mock-server:
	make -C mock-server

BUILD_TARGET ?= fact
IMAGE_NAME ?= $(FACT_IMAGE_NAME)

image:
	$(DOCKER) build \
		-f Containerfile \
		--build-arg FACT_VERSION=$(FACT_VERSION) \
		--build-arg RUST_VERSION=$(RUST_VERSION) \
		--build-arg CARGO_ARGS="$(CARGO_ARGS)" \
		--target $(BUILD_TARGET) \
		-t $(IMAGE_NAME) \
		$(CURDIR)

image-otel: CARGO_ARGS = --features otel
image-otel: image

operator: BUILD_TARGET = fact-operator
operator: IMAGE_NAME = $(FACT_OPERATOR_NAME)
operator: image

licenses:THIRD_PARTY_LICENSES.html

THIRD_PARTY_LICENSES.html:Cargo.lock
	$(if $(shell command -v cargo-about),,$(error cargo-about not found, you can install it with 'cargo install cargo-about --features=cli'))
	cargo about generate --format handlebars -o THIRD_PARTY_LICENSES.html about_html.hbs

integration-tests:
	make -C tests

performance-tests:
	make -C performance-tests

coverage:
	cargo llvm-cov --workspace --codecov --output-path codecov.json

clean:
	make -C tests clean
	rm -f THIRD_PARTY_LICENSES.html
	rm -f codecov.json

lint:
	cargo clippy --all-targets --all-features -- -D warnings
	make -C tests lint

format-check:
	cargo fmt --check
	make -C fact-ebpf format-check
	ruff format --diff tests/

format:
	cargo fmt
	make -C fact-ebpf format
	ruff format tests/

.PHONY: tag mock-server integration-tests image image-otel image-name
.PHONY: operator operator-name licenses coverage lint clean
