include constants.mk

TARGETS := build build-and-push
DIRS := $(wildcard ./*/)

$(TARGETS): $(DIRS)
$(DIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY: $(TARGETS) $(DIRS)
