# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2026 Advanced Micro Devices, Inc.
SUBDIRS := tests

TARGETS := oo_nics_test

MMAKE_LIBS += $(LINK_CITOOLS_LIB) $(LINK_KCOMPAT_LIB)
MMAKE_LIB_DEPS += $(CITOOLS_LIB_DEPEND) $(KCOMPAT_LIB_DEPENDS)

SRCS := ../../tap/tap.c oo_nics_test.c stubs.c oo_nics.c
TEST_SRCS := tests/basic.c tests/multiarch_datapath.c \
	tests/whitelist_blacklist.c
HDRS := oo_nics_test.h stubs.h oo_nics_deps.h onload_kernel_compat.h

OBJS := $(patsubst %,%.o,$(SRCS))
OBJS += $(patsubst %,%.o,$(TEST_SRCS))

TESTS := $(patsubst tests/%.c,"./oo_nics_test %",$(TEST_SRCS))

%.c.o: %.c $(HDRS)
	$(MMakeCompileC)

$(TARGETS): $(OBJS) $(MMAKE_LIB_DEPS)
	@(libs="$(MMAKE_LIBS)"; $(MMakeLinkCApp))

all: $(TARGETS)

targets:
	@echo $(TARGETS)

clean:
	@$(MakeClean)

ifdef UNIT_TEST_OUTPUT
PROVE_FLAGS += --merge --timer
UNIT_TEST_OUTPUT_DIR = $(UNIT_TEST_OUTPUT)
PROVE_REDIRECT = >> $(UNIT_TEST_OUTPUT)

tests: $(UNIT_TEST_OUTPUT_DIR)

$(UNIT_TEST_OUTPUT_DIR):
	mkdir -p $$(dirname $(UNIT_TEST_OUTPUT_DIR))
	touch $(UNIT_TEST_OUTPUT_DIR)
endif # UNIT_TEST_OUTPUT

HARNESS_TIME_OUT=240

.PHONY: tests
tests:
	/usr/bin/timeout $(HARNESS_TIME_OUT) prove --exec ' ' \
	$(PROVE_FLAGS) $(TESTS) $(PROVE_REDIRECT)
