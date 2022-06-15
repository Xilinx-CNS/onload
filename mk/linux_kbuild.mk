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

AUX_BUS_PATH ?= $(TOPPATH)/../cns-auxiliary-bus
HAVE_CNS_AUX := $(or $(and $(wildcard $(AUX_BUS_PATH)),1),0)
EXTRA_CFLAGS += -DCI_HAVE_CNS_AUX=$(HAVE_CNS_AUX)
ifneq ($(HAVE_CNS_AUX),0)
EXTRA_CFLAGS += -DCI_AUX_HEADER='"$(AUX_BUS_PATH)/include/linux/auxiliary_bus.h"'
EXTRA_CFLAGS += -DCI_AUX_MOD_HEADER='"$(AUX_BUS_PATH)/drivers/base/mod_devicetable_auxiliary.h"'
else
ifneq (,$(wildcard /lib/modules/$(KVER)/updates/auxiliary.symvers))
KBUILD_EXTRA_SYMBOLS += "/lib/modules/$(KVER)/updates/auxiliary.symvers"
endif
endif

X3_NET_HDR := linux/net/xilinx/xlnx_efct.h
X3_NET_PATH ?= $(TOPPATH)/../x3-net-linux
ifneq ($(wildcard $(X3_NET_PATH)/include/$(X3_NET_HDR)),)
 HAVE_X3_NET := 1
 EXTRA_CFLAGS += -DCI_XLNX_EFCT_HEADER='"$(X3_NET_PATH)/include/$(X3_NET_HDR)"'
else
 ifneq ($(wildcard include/$(X3_NET_HDR)),)
  HAVE_X3_NET := 1
  EXTRA_CFLAGS += -DCI_XLNX_EFCT_HEADER='"$(X3_NET_HDR)"'
 else
  HAVE_X3_NET := 0
 endif
endif
EXTRA_CFLAGS += -DCI_HAVE_X3_NET=$(HAVE_X3_NET)

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
