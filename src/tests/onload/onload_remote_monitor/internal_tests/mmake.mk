# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2014-2019 Xilinx, Inc.

TARGETS := test_ftl

SRCS := ../../../tap/tap.c
TEST_SRCS := test_ftl.c

OBJS := $(patsubst %.c,%.o,$(SRCS))
OBJS += $(patsubst %.c,%.o,$(TEST_SRCS))

TESTS := $(patsubst %.c,./%,$(TEST_SRCS))

%.o: %.c
	$(MMakeCompileC)

$(TARGETS): $(OBJS)
	$(MMakeLinkCApp)

all: $(TARGETS)
test: $(TARGETS)

targets:
	@echo $(TARGETS)

clean:
	@$(MakeClean)


ifdef UNIT_TEST_OUTPUT
PROVE_FLAGS += --merge --timer
UNIT_TEST_OUTPUT_DIR = $(UNIT_TEST_OUTPUT)
PROVE_REDIRECT = >> $(UNIT_TEST_OUTPUT)

test: $(UNIT_TEST_OUTPUT_DIR)

$(UNIT_TEST_OUTPUT_DIR):
	mkdir -p $$(dirname $(UNIT_TEST_OUTPUT_DIR))
	touch $(UNIT_TEST_OUTPUT_DIR)
endif # UNIT_TEST_OUTPUT

HARNESS_TIME_OUT=240

.PHONY: test
test:
	/usr/bin/timeout $(HARNESS_TIME_OUT) prove --exec ' ' \
	$(PROVE_FLAGS) $(TESTS) $(PROVE_REDIRECT)
