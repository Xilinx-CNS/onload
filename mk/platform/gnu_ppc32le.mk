# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2015-2020 Xilinx, Inc.

GNU := 1
ifndef MMAKE_CTUNE
 MMAKE_CTUNE := -mtune=native
endif
MMAKE_CARCH := -m32 -mcpu=native $(MMAKE_CTUNE)

MMAKE_RELOCATABLE_LIB := -mrelocatable-lib

include $(TOPPATH)/mk/linux_gcc.mk
