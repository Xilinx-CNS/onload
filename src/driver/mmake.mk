# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc.
# For linux_net/util
ifeq ($(LINUX),1)
SUBDIRS         += linux_net
endif

MMAKE_NO_DEPS	:= 1

ifeq ($(LINUX),1)

# DRIVER_SUBDIRS must be ordered according to inter-driver dependencies

# Always include linux_net when mmakebuildtree is running, to allow
# user to switch sfc build at 'make' time.
ifeq ($(MMAKEBUILDTREE),1)
DRIVER_SUBDIRS  += linux_net
else ifeq ($(HAVE_SFC),1)
DRIVER_SUBDIRS  += linux_net
else
endif

DRIVER_SUBDIRS	+= linux_resource linux_char linux_onload linux

endif # ifeq ($(LINUX),1)

all: passthruparams := "CI_FROM_DRIVER=1"
all:
	+@(target=all ; $(MakeSubdirs))

clean:
	@$(MakeClean)

