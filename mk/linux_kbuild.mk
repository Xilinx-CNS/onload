# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc.
MMAKE_IN_KBUILD	:= 1

include $(TOPPATH)/mk/platform/$(PLATFORM).mk
include $(TOPPATH)/mk/site/funcs.mk

EXTRA_CPPFLAGS += -I$(TOPPATH)/src/include -I$(BUILDPATH)/include \
		-I$(BUILDPATH) -I$(TOPPATH)/$(CURRENT) -D__ci_driver__
ifdef NDEBUG
EXTRA_CPPFLAGS += -DNDEBUG
endif
ifndef MMAKE_LIBERAL
EXTRA_CFLAGS += -Werror
endif # MMAKE_LIBERAL

ifdef W_NO_STRING_TRUNCATION
EXTRA_CFLAGS += -Wno-stringop-truncation
endif

ifndef NDEBUG
EXTRA_CFLAGS += -g
endif

TRANSPORT_CONFIG_OPT_HDR ?= ci/internal/transport_config_opt_extra.h
EXTRA_CFLAGS += -DTRANSPORT_CONFIG_OPT_HDR='<$(TRANSPORT_CONFIG_OPT_HDR)>'

EXTRA_CFLAGS += $(MMAKE_CFLAGS) $(EXTRA_CPPFLAGS)
EXTRA_AFLAGS += $(EXTRA_CPPFLAGS)

# Linux 4.6 added some object-file validation, which was also merged into
# RHEL 7.3.  Unfortunately, it assumes that all functions that don't end with
# a return or a jump are recorded in a hard-coded table inside objtool.  That
# is not of much use to an out-of-tree driver, and we have far too many such
# functions to rewrite them, so we turn off the checks.
OBJECT_FILES_NON_STANDARD := y
