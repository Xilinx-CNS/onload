# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2004-2020 Xilinx, Inc.
GNU	    := 1
MMAKE_CARCH ?= -mtune=native
MMAKE_CARCH := -m64 $(MMAKE_CTUNE)

MMAKE_RELOCATABLE_LIB := -z combreloc

include $(TOPPATH)/mk/linux_gcc.mk
