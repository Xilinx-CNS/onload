# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc.

DRIVER_SUBDIRS	     := lib driver

ifeq ($(GNU),1)
SUBDIRS              := include lib app driver tools tests
endif

ifeq ($(LINUX),1)
DRIVER_SUBDIRS	     := lib driver
OTHER_DRIVER_SUBDIRS := tests
endif

ifeq ($(SPECIAL_TOP_RULES),1)

all:    special_top_all

clean:    special_top_clean

else

all:
ifeq ($(LINUX),1)
ifneq ($(GNU),1)
	# Build both autocompat.h files: linux_net and linux_resource.
	$(MAKE) -C driver/linux_net
	$(MAKE) -C driver/linux_resource
endif
endif
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)
endif
