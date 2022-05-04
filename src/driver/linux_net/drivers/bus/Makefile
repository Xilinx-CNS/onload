# SPDX-License-Identifier: GPL-2.0
################################################################################
#
# Driver for Solarflare and Xilinx network controllers and boards
# Copyright 2019 Solarflare Communications Inc.
# Copyright 2019-2020 Xilinx Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation, incorporated herein by reference.
#
################################################################################

ifdef KERNELRELEASE
# kbuild part of makefile
ifndef CONFIG_VIRTUAL_BUS
TOPDIR := $(src)/../..
include $(TOPDIR)/scripts/Makefile.common
export CONFIG_VIRTUAL_BUS := m

obj-m += virtual_bus.o

ifndef EFX_UPSTREAM
$(obj)/virtual_bus.o: $(obj)/.kpath $(obj)/autocompat.h
endif # !EFX_UPSTREAM
endif
else
# normal makefile
TOPDIR := ../..
include $(TOPDIR)/scripts/Makefile.common

all modules:
	$(MAKE) -C $(KDIR) $(EXTRA_MAKEFLAGS) M=$$(pwd) modules

ifndef EFX_UPSTREAM
# Do not overwrite the existing in-tree driver.
export:
	test -f $(KDIR)/drivers/bus/virtual_bus.c || \
		$(EXPORT_CMD) -s drivers/bus $(KDIR) virtual_bus.c

export-srpm:
	test -f $(KDIR)/drivers/bus/virtual_bus.c || \
		$(EXPORT_CMD) -o -s drivers/bus $(KDIR) virtual_bus.c kernel_compat.h kernel_compat.sh $(TOPDIR)/scripts/kernel_compat_funcs.sh
endif # !EFX_UPSTREAM
#
modules_install:
	mkdir -p $(INSTALL_MOD_PATH)/lib/modules/$(KVER)/$(INSTALL_MOD_DIR)
	$(MAKE) -C $(KDIR) $(EXTRA_MAKEFLAGS) M=$$(pwd) INSTALL_MOD_DIR=$(INSTALL_MOD_DIR) modules_install

clean:
	$(MAKE) -C $(KDIR) $(EXTRA_MAKEFLAGS) M=$$(pwd) $@
ifndef EFX_UPSTREAM
	@$(RM) .kpath autocompat.h

.PHONY : export export-srpm
endif # !EFX_UPSTREAM
endif
