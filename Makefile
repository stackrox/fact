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
		-t $(FACT_IMAGE_NAME) \
		$(CURDIR)

integration-tests:
	make -C tests

.PHONY: tag mock-server integration-tests image image-name
