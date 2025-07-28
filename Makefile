mock-server:
	make -C mock-server

image:
	docker build -f Containerfile -t fact:latest .

integration-tests:
	make -C tests

.PHONY: mock-server integration-tests image
