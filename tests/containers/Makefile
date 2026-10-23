include constants.mk

TARGETS := build build-and-push exists
DIRS := $(wildcard ./*/)

$(TARGETS): $(DIRS)
$(DIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY: $(TARGETS) $(DIRS)
