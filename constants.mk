ifeq ($(FACT_TAG),)
FACT_TAG=$(shell git describe --always --tags --abbrev=10 --dirty)
endif

ifeq ($(FACT_IMAGE_NAME),)
FACT_IMAGE_NAME=quay.io/rhacs-eng/fact:$(FACT_TAG)
endif
