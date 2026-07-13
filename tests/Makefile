include ../constants.mk

all: pytest

pytest: grpc-gen
	pytest --image="${FACT_IMAGE_NAME}" --output=grpc --junit-xml=results.xml

pytest-otlp: grpc-gen
	pytest --image="${FACT_IMAGE_NAME}" --output=otlp --junit-xml=results.xml

pytest-all: grpc-gen
	pytest --image="${FACT_IMAGE_NAME}-otel" --output=all --junit-xml=results.xml

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

lint: grpc-gen
	ruff check .
	pyright .

clean:
	rm -rf logs/
	rm -rf logs.tar.gz
	rm -f results.xml

.PHONY: all pytest pytest-otlp pytest-all grpc-gen lint clean
