# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc.
SUBDIRS := tests

TARGETS := oof_test

MMAKE_LIBS += $(LINK_CITOOLS_LIB) $(LINK_KCOMPAT_LIB)
MMAKE_LIB_DEPS += $(CITOOLS_LIB_DEPEND) $(KCOMPAT_LIB_DEPENDS)

SRCS := ../../tap/tap.c oof_test.c oof_interface.c \
	oof_filters.c tcp_filters.c efrm_interface.c stack_interface.c \
	stack.c cplane.c efrm.c oof_onload.c oof_nat.c
TEST_SRCS := tests/sanity.c tests/multicast_sanity.c tests/namespace_sanity.c \
	tests/namespace_macvlan_move.c
HDRS := cplane.h oof_impl.h stack_interface.h driverlink_interface.h  \
	oof_test.h tcp_filters_deps.h efrm_interface.h oo_hw_filter.h \
	tcp_filters_internal.h onload_kernel_compat.h stack.h utils.h \
	efrm.h oof_tproxy_ipproto.h oof_onload_types.h

OBJS := $(patsubst %,%.o,$(SRCS))
OBJS += $(patsubst %,%.o,$(TEST_SRCS))

TESTS := $(patsubst tests/%.c,"./oof_test %",$(TEST_SRCS))
# Add the local include directory before the standard include path to allow
# us to replace system includes where needed.
MMAKE_INCLUDE := -I$(TOPPATH)/$(CURRENT)/include $(MMAKE_INCLUDE)

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
PROVE_FLAGS += --merge --timer --formatter TAP::Formatter::JUnit
UNIT_TEST_OUTPUT_DIR = $(UNIT_TEST_OUTPUT)
PROVE_REDIRECT = > $(UNIT_TEST_OUTPUT)/$@.xml

tests: $(UNIT_TEST_OUTPUT_DIR)

$(UNIT_TEST_OUTPUT_DIR):
	mkdir -p $(UNIT_TEST_OUTPUT_DIR)
	rm -rf $(UNIT_TEST_OUTPUT)/*.xml
endif # UNIT_TEST_OUTPUT

HARNESS_TIME_OUT=240

.PHONY: tests
tests:
	/usr/bin/timeout $(HARNESS_TIME_OUT) prove --exec ' ' \
	$(PROVE_FLAGS) $(TESTS) $(PROVE_REDIRECT)
