include ../constants.mk

all: image performance-tests

image:
	# note that FACT_VERSION on a PR would be the branch name
	docker build \
		-f Containerfile \
		--build-arg FACT_VERSION=$(FACT_TAG) \
		--build-arg BERSERKER_VERSION=$(BERSERKER_VERSION) \
		-t performance-test \
		$(CURDIR)

performance-tests: data_dir user_space_cpu

data_dir:
	mkdir -p data

user_space_cpu:
	docker run --rm -it --privileged \
		-v ./data:/data \
		-v ./workloads:/workloads \
		performance-test:latest \
        user_space_cpu ignored_and_monitored 10 \
        --output-file=/data/perf.json \
        --workloads-path=/workloads \
        --fact-cmdline='--skip-pre-flight --paths /tmp/test /tmp/test1'

make push-data:

clean:
	rm -rf logs/
	rm -rf logs.tar.gz
	rm -f results.xml

.PHONY: all performance-tests clean
