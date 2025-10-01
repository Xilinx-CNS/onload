# SPDX-License-Identifier: GPL-2.0
################################################################################
#
# Driver for Solarflare and Xilinx network controllers and boards
# Copyright 2021 Xilinx Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation, incorporated herein by reference.
#
################################################################################
ifndef EFX_UPSTREAM

# Check config dependencies under Kbuild.  We should only do this if
# .config has actually been included (it isn't when cleaning), so test
# for config symbol CONFIG_NET that should always be defined.
ifdef KERNELRELEASE
# Out-of-tree kernel config
export CONFIG_SFC_SIENA := m
override CONFIG_SFC_SRIOV :=
override CONFIG_SFC_DRIVERLINK :=
override CONFIG_SFC_VDPA :=

# For CONFIG_SFC_TRACING includes via linux <include/trace/define_trace.h>
ccflags-y += -I$(src)

ifdef EFX_FOR_UPSTREAM
# match UNIFDEF_DEFINES in export.sh
override CONFIG_SFC_DEBUGFS :=
else
ifndef CONFIG_DEBUG_FS
override CONFIG_SFC_DEBUGFS :=
ifdef CONFIG_NET
$(warning Kernel does not support DEBUG_FS)
$(warning => Some diagnostic information will be unavailable)
endif
else
override CONFIG_SFC_DEBUGFS := y
endif
endif

ifdef CONFIG_MTD
override CONFIG_SFC_MTD := y
else
override CONFIG_SFC_MTD :=
ifdef CONFIG_NET
$(warning Kernel does not support MTD)
$(warning => Firmware update will be unavailable)
endif
endif

ifdef CONFIG_HWMON
override CONFIG_SFC_MCDI_MON := y
else
override CONFIG_SFC_MCDI_MON :=
ifdef CONFIG_NET
$(warning Kernel does not support HWMON)
$(warning => Temperature and voltage reporting will be disabled)
endif
endif

override CONFIG_SFC_PTP := y
override CONFIG_SFC_DUMP := y
endif # !KERNELRELEASE
endif # !EFX_UPSTREAM

# Select source files wanted
sfc-siena-y := farch.o siena.o
sfc-siena-y += efx.o efx_common.o efx_channels.o nic.o \
	       tx.o tx_common.o tx_tso.o rx.o rx_common.o \
	       selftest.o ethtool_common.o ethtool.o \
	       mcdi.o mcdi_port.o mcdi_port_common.o mcdi_functions.o \
	       mcdi_filters.o xdp.o efx_devlink.o
ifndef EFX_NO_KCOMPAT
ifneq ($(MAKECMDGOALS),export)
sfc-siena-y += kernel_compat.o
ifndef EFX_FOR_UPSTREAM
sfc-siena-y += ioctl.o ioctl_common.o sfctool.o
CFLAGS_efx.o = -DEFX_USE_PRIVATE_IOCTL
endif
endif
endif # !EFX_NO_KCOMPAT
sfc-siena-$(CONFIG_SFC_DEBUGFS) += debugfs.o
sfc-siena-$(CONFIG_SFC_MTD) += mtd.o
sfc-siena-$(CONFIG_SFC_PTP) += ptp.o
sfc-siena-$(CONFIG_SFC_MCDI_MON) += mcdi_mon.o
sfc-siena-$(CONFIG_SFC_DUMP) += dump.o

obj-$(CONFIG_SFC_SIENA)	+= sfc-siena.o
ifndef EFX_UPSTREAM
ifndef EFX_DISABLE_GRO
ccflags-y += -DEFX_USE_GRO
endif
ifdef KERNELRELEASE
# Kernel build
TOPDIR := $(src)/../../../../..
include $(TOPDIR)/scripts/Makefile.common

# Generate config.h
define filechk_config.h
	printf "$(foreach name,SFC_DEBUGFS SFC_DUMP SFC_MCDI_MON SFC_MTD SFC_SIENA SFC_SRIOV SFC_PTP SFC_PPS SFC_TRACING SFC_MCDI_LOGGING SFC_BUSYPOLL,#undef CONFIG_$(name)\n$(if $(filter y m,$(CONFIG_$(name))),#define CONFIG_$(name) $(CONFIG_$(name))\n))"
endef

$(obj)/config.h: $(src)/Makefile FORCE
	$(call filechk,config.h)

$(addprefix $(obj)/,$(sfc-siena-y)): \
	$(obj)/.kpath $(obj)/autocompat.h $(obj)/config.h
else
# normal makefile
TOPDIR := ../../../../..
include $(TOPDIR)/scripts/Makefile.common

all modules:
	$(MAKE) -C $(KDIR) $(EXTRA_MAKEFLAGS) M=$$(pwd) modules

modules_install:
	mkdir -p $(INSTALL_MOD_PATH)/lib/modules/$(KVER)/$(INSTALL_MOD_DIR)
	$(MAKE) -C $(KDIR) $(EXTRA_MAKEFLAGS) M=$$(pwd) INSTALL_MOD_DIR=$(INSTALL_MOD_DIR) modules_install

clean:
	$(MAKE) -C $(KDIR) $(EXTRA_MAKEFLAGS) M=$$(pwd) $@
	@$(RM) .kpath autocompat.h config.h

# Export into kernel tree
export:
	$(EXPORT_CMD) -s drivers/net/ethernet/sfc/siena $(KDIR) $(sfc-siena-y:%.o=%.c)
endif
endif # !EFX_UPSTREAM
