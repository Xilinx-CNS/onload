# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
GNU := 1

#Following is how we optimised for PPC64 BE, which I doubt is optimal here,
#TBD: work out best tuning settings for PPC64 LE
#ifndef MMAKE_CTUNE
# MMAKE_CTUNE := -mtune=native
# ifneq ($(shell grep -i power8 /proc/cpuinfo),)
#  MMAKE_CTUNE += -mpower8-fusion -O6
# endif
#endif
#MMAKE_CARCH := -m64 -mcpu=native $(MMAKE_CTUNE)

MMAKE_CTUNE :=
MMAKE_CARCH := -m64 $(MMAKE_CTUNE)

MMAKE_RELOCATABLE_LIB := -mrelocatable-lib

include $(TOPPATH)/mk/linux_gcc.mk
