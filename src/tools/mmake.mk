# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc.

ifeq ($(LINUX),1)
SUBDIRS		:=

# 32-bit x86 kernels are not suppported, so we don't need the 32-bit control
# plane.
ifneq ($(PLATFORM),gnu)
SUBDIRS		+= cplane
endif

SUBDIRS		+= onload_helper ip \
		   solar_clusterd onload_remote_monitor \
		   onload_mibdump shrub_controller

endif

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)
