all: mock-server

mock-server: grpc-gen
	./server.py

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

.PHONY: all mock-server grpc-gen
