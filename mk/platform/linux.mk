# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
ifndef KPATH
$(shell echo >&2 "KPATH is not set.")
$(error KPATH is not set.)
endif

LINUX		   := 1

LINUX_VERSION_3	   := $(shell cat $(KPATH)/include/{linux/utsrelease.h,generated/utsrelease.h,linux/version.h} 2>/dev/null | sed 's/^\#define UTS_RELEASE \"\([0-9]\+\.[0-9]\+\.[0-9]\+\).*/\1/; t; d')

DRIVER		   := 1
MMAKE_USE_KBUILD   := 1
MMAKE_NO_RULES	   := 1

# Itanium on linux2.6 is very strict that for a given library/module,
# all objects must be compiled with the same flags. For some reason
# the linux kbuild environment doesn't satisfy this condition
include $(KPATH)/.config
ifdef CONFIG_IA64
CFLAGS_KERNEL :=
endif

ifdef CONFIG_ARM64
EXTRA_CFLAGS += -mcmodel=large
endif

# To build without -g set CONFIG_DEBUG_INFO to empty string
# (-g does make kernel modules quite big, but only on disk).
ifdef NO_DEBUG_INFO
MMAKE_KBUILD_ARGS_DBG := CONFIG_DEBUG_INFO=
endif

# Setting KBUILD_VERBOSE=1 is quite useful here
MMAKE_KBUILD_ARGS_CONST := -C $(KPATH) NDEBUG=$(NDEBUG) GCOV=$(GCOV) CC=$(CC)
MMAKE_KBUILD_ARGS = $(MMAKE_KBUILD_ARGS_CONST) $(MMAKE_KBUILD_ARGS_DBG)

