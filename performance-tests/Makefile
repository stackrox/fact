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

performance-tests: data_dir user_space_cpu user_space_mem kernel_space_cpu kernel_space_mem

data_dir:
	mkdir -p data

user_space_cpu:
	for workload in ignored_and_monitored monitored ignored ; do \
		docker run --rm -it --privileged \
			-v ./data:/data \
			-v ./workloads:/workloads \
			performance-test:latest \
			user_space_cpu $$workload 10 \
			--output-file=/data/user.cpu.$$workload.json \
			--workloads-path=/workloads \
			--fact-cmdline='--skip-pre-flight --paths /tmp/test /tmp/test1' ; \
	done

user_space_mem:
	for workload in ignored_and_monitored monitored ignored ; do \
		docker run --rm -it --privileged \
			-v ./data:/data \
			-v ./workloads:/workloads \
			performance-test:latest \
			user_space_mem $$workload 10 \
			--output-file=/data/user.mem.$$workload.json \
			--workloads-path=/workloads \
			--fact-cmdline='--skip-pre-flight --paths /tmp/test /tmp/test1' ; \
	done

kernel_space_cpu:
	for workload in ignored_and_monitored monitored ignored ; do \
		docker run --rm -it --privileged \
			-v ./data:/data \
			-v ./workloads:/workloads \
			performance-test:latest \
			kernel_space_cpu $$workload 10 \
			--output-file=/data/kernel.cpu.$$workload.json \
			--workloads-path=/workloads \
			--fact-cmdline='--skip-pre-flight --paths /tmp/test /tmp/test1' ; \
	done

kernel_space_mem:
	for workload in ignored_and_monitored monitored ignored ; do \
		docker run --rm -it --privileged \
			-v ./data:/data \
			-v ./workloads:/workloads \
			performance-test:latest \
			kernel_space_mem $$workload 10 \
			--output-file=/data/kernel.mem.$$workload.json \
			--workloads-path=/workloads \
			--fact-cmdline='--skip-pre-flight --paths /tmp/test /tmp/test1' ; \
	done

make push-data:
	for file in `ls data/*.json` ; do \
		python store.py $$file fact ; \
	done

clean:
	rm -rf logs/
	rm -rf logs.tar.gz
	rm -f results.xml

.PHONY: all performance-tests clean
