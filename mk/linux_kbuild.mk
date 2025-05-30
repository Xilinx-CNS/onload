# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc.
MMAKE_IN_KBUILD	:= 1

include $(TOPPATH)/mk/platform/$(PLATFORM).mk
include $(TOPPATH)/mk/site/funcs.mk

ifdef KPATH
KDIR ?= $(KPATH)
ifndef KVER
KVER := $(shell sed -r 's/^\#define UTS_RELEASE "(.*)"/\1/; t; d' $(KDIR)/include/generated/utsrelease.h $(KDIR)/include/linux/utsrelease.h $(KDIR)/include/linux/version.h 2>/dev/null)
ifeq ($(KVER),)
$(error Failed to find kernel version for $(KDIR))
endif
endif # !KVER
endif # KPATH

ifndef KVER
KVER := $(shell uname -r)
endif
KDIR ?= /lib/modules/$(KVER)/build
export KDIR KVER


EXTRA_CPPFLAGS += -I$(TOPPATH)/src/include -I$(BUILDPATH)/include \
		-I$(BUILDPATH) -I$(TOPPATH)/$(CURRENT) -D__ci_driver__
ifdef NDEBUG
EXTRA_CPPFLAGS += -DNDEBUG
endif
ifndef MMAKE_LIBERAL
EXTRA_CFLAGS += -Werror
endif # MMAKE_LIBERAL

# TODO Address these in the source code.
EXTRA_CFLAGS += -Wno-missing-prototypes -Wno-missing-declarations

ifdef W_NO_STRING_TRUNCATION
EXTRA_CFLAGS += -Wno-stringop-truncation
endif

ifndef NDEBUG
EXTRA_CFLAGS += -g
endif

HAVE_EFCT ?=

ifeq ($(HAVE_EFCT),0)
else ifneq ($(wildcard $(dir $(KPATH))/*/include/linux/net/xilinx/xlnx_efct.h),)
HAVE_KERNEL_EFCT := 1
else
X3_NET_PATH ?= $(TOPPATH)/../x3-net-linux
HAVE_CNS_EFCT := $(or $(and $(wildcard $(X3_NET_PATH)/include/linux/net/xilinx/xlnx_efct.h),1),0)
endif

ifeq ($(or $(filter 1, $(HAVE_KERNEL_EFCT) $(HAVE_CNS_EFCT)),0),1)
  EXTRA_CFLAGS += -DCI_HAVE_EFCT_AUX=1
  ifneq ($(HAVE_CNS_EFCT),0)
    EXTRA_CFLAGS += -I$(X3_NET_PATH)/include
  endif
else
  ifneq ($(HAVE_EFCT),1)
    EXTRA_CFLAGS += -DCI_HAVE_EFCT_AUX=0
  else
    $(error Unable to build Onload with EFCT or AUX bus support)
  endif
endif

HAVE_EF10CT ?= 1
ifeq ($(HAVE_EF10CT),0)
  EXTRA_CFLAGS += -DCI_HAVE_EF10CT=0
else
  EXTRA_CFLAGS += -DCI_HAVE_EF10CT=1
endif

HAVE_SDCI ?= 0
ifeq ($(HAVE_SDCI),1)
	EXTRA_CFLAGS += -DCI_HAVE_SDCI=1
else
	EXTRA_CFLAGS += -DCI_HAVE_SDCI=0
endif

HAVE_SFC ?= 1
ifeq ($(HAVE_SFC),1)
  EXTRA_CFLAGS += -DCI_HAVE_SFC=1
else
  EXTRA_CFLAGS += -DCI_HAVE_SFC=0
endif

TRANSPORT_CONFIG_OPT_HDR ?= ci/internal/transport_config_opt_extra.h
EXTRA_CFLAGS += -DTRANSPORT_CONFIG_OPT_HDR='<$(TRANSPORT_CONFIG_OPT_HDR)>'

EXTRA_CFLAGS += $(MMAKE_CFLAGS) $(EXTRA_CPPFLAGS)
EXTRA_AFLAGS += $(EXTRA_CPPFLAGS)

ifdef M_NO_OUTLINE_ATOMICS
EXTRA_CFLAGS += -mno-outline-atomics
endif
