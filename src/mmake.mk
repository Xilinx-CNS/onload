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

AUTOCOMPAT := driver/linux_resource/autocompat.h
all:
	+@$(MakeSubdirs)

ifeq ($(LINUX),1)
ifneq ($(GNU),1)
all: $(AUTOCOMPAT)

LINUX_RESOURCE := $(SRCPATH)/driver/linux_resource
$(AUTOCOMPAT): $(LINUX_RESOURCE)/kernel_compat.sh $(LINUX_RESOURCE)/kernel_compat_funcs.sh
	@mkdir -p $(@D)
	$< -k $(KPATH) $(if $(filter 1,$(V)),-v,-q) > $@
endif
endif

clean:
	@$(MakeClean)
	rm -f $(AUTOCOMPAT)
endif
