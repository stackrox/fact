include constants.mk

TARGETS := build build-and-push image-names
DIRS := $(wildcard ./*/)

$(TARGETS): $(DIRS)
$(DIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY: $(TARGETS) $(DIRS)
