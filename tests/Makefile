include ../constants.mk

all: pytest

pytest: grpc-gen
	pytest --tag="${FACT_TAG}" --junit-xml=results.xml

PYOUT = $(CURDIR)

ARTIFACTS=
ARTIFACTS += ../third_party/stackrox/proto/internalapi/sensor/collector.proto
ARTIFACTS += ../third_party/stackrox/proto/internalapi/sensor/sfa.proto
ARTIFACTS += ../third_party/stackrox/proto/internalapi/sensor/sfa_iservice.proto

grpc-gen: ${ARTIFACTS}
	python3 -m grpc_tools.protoc \
		-I../third_party/stackrox/proto \
		--python_out=${PYOUT} \
		--pyi_out=${PYOUT} \
		--grpc_python_out=${PYOUT} \
		${ARTIFACTS}

clean:
	rm -rf logs/
	rm -rf logs.tar.gz
	rm -f results.xml

.PHONY: all pytest grpc-gen clean
