# SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
GNU	    := 1
MMAKE_CTUNE ?= -msse -march=core2 -mtune=native
MMAKE_CARCH := -m32 $(MMAKE_CTUNE)

MMAKE_RELOCATABLE_LIB := -z combreloc

include $(TOPPATH)/mk/linux_gcc.mk
