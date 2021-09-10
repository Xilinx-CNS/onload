################################################################################
#
# Driver for Solarflare network controllers and boards
# Copyright 2019 Solarflare Communications Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation, incorporated herein by reference.
#
################################################################################

ifndef EFX_UPSTREAM

# The EFX_UPSTREAM variable is never defined.  Sections of the Makefile
# that are only needed for an out-of-tree build are guarded by
# "ifndef EFX_UPSTREAM" and removed using sed when it is exported to a
# kernel tree.

# The KERNELRELEASE variable is defined by kbuild.  Some parts of the
# Makefile should only be included when this is the top-level Makefile
# and not when it is included by kbuild; these are guarded by
# "ifndef KERNELRELEASE".

# Configuration
ifndef KERNELRELEASE
export CONFIG_NET_VENDOR_SOLARFLARE := y
export CONFIG_SFC := m
ifdef EFX_FOR_UPSTREAM
# match UNIFDEF_DEFINES in export.sh
export CONFIG_SFC_DEBUGFS :=
else
export CONFIG_SFC_DEBUGFS := y
endif
export CONFIG_SFC_DUMP := y
export CONFIG_SFC_MCDI_MON := y
export CONFIG_SFC_MTD := y
export CONFIG_SFC_SRIOV := y
export CONFIG_SFC_PTP := y
export CONFIG_SFC_PPS := y
export CONFIG_SFC_TRACING :=
export CONFIG_SFC_MCDI_LOGGING := y
export CONFIG_SFC_SIENA := y
export CONFIG_SFC_DRIVERLINK := m
export CONFIG_SFC_AOE := $(subst m,y,$(CONFIG_SFC_DRIVERLINK))
export CONFIG_SFC_BUSYPOLL := n
export CONFIG_SFC_VDPA := y
endif

ifdef KSRCDIR
$(error KSRCDIR has been replaced with KDIR)
endif

ifdef KERNELRELEASE

# Check config dependencies under Kbuild.  We should only do this if
# .config has actually been included (it isn't when cleaning), so test
# for a config symbol that should always be defined.
ifdef CONFIG_NET
ifndef CONFIG_X86
ifndef CONFIG_ARCH_DMA_ADDR_T_64BIT
$(error Unsupported architecture)
endif
endif
ifndef CONFIG_MTD
ifdef CONFIG_SFC_MTD
override CONFIG_SFC_MTD :=
endif
endif
ifdef CONFIG_SFC_FALCON
$(warning SFE4001/Falcon is no longer supported)
endif
ifdef CONFIG_SFC_MCDI_MON
ifndef CONFIG_HWMON
$(warning Kernel does not support HWMON)
override CONFIG_SFC_MCDI_MON :=
endif
endif # CONFIG_SFC_MCDI_MON
ifndef CONFIG_SFC_MCDI_MON
$(warning => Temperature and voltage reporting for SFC9000-family boards will be disabled)
endif
ifdef CONFIG_SFC_SRIOV
ifndef CONFIG_PCI_IOV
$(warning Kernel does not support PCI_IOV)
override CONFIG_SFC_SRIOV :=
$(warning => SR-IOV functionality will be disabled)
endif
endif
ifdef CONFIG_SFC_TRACING
ifndef CONFIG_EVENT_TRACING
$(error Kernel does not support EVENT_TRACING)
endif
endif
ifdef CONFIG_SFC_DEBUGFS
ifndef CONFIG_DEBUG_FS
$(warning Kernel does not support DEBUG_FS)
override CONFIG_SFC_DEBUGFS :=
$(warning => Some diagnostic information will be unavailable)
endif
endif
ifndef CONFIG_SFC_MCDI_LOGGING
$(warning => MCDI tracing will not be supported)
endif
ifdef CONFIG_SFC_VDPA
ifndef CONFIG_VDPA
$(warning Kernel does not support vDPA)
override CONFIG_SFC_VDPA :=
$(warning => vDPA functionality will be disabled)
endif
endif

ifndef CONFIG_VIRTUAL_BUS
# Pick up exported symbols of our build of virtual_bus.ko
KBUILD_EXTRA_SYMBOLS += $(KBUILD_EXTMOD)/../../../bus/Module.symvers

$(KBUILD_EXTMOD)/../../../bus/Module.symvers:
	make -C ../../../bus
endif
endif # CONFIG_NET

else # !KERNELRELEASE ###### The following is for the standalone Makefile case

TOPDIR = ../../../..
include $(TOPDIR)/scripts/Makefile.common

ifneq ($(MAKECMDGOALS),export-srpm)

KVERPARTS = $(subst -, ,$(subst ., ,$(KVER)))
ifeq ($(word 1,$(KVERPARTS)),2)
ifneq ($(word 2,$(KVERPARTS)),6)
$(error Kernel version $(KVER) is not supported; minimum version is 2.6.16)
endif
ifneq ($(filter 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15,$(word 3,$(KVERPARTS))),)
$(error Kernel version $(KVER) is not supported; minimum version is 2.6.16)
endif
endif

endif # export-srpm

endif # !KERNELRELEASE

endif # !EFX_UPSTREAM
#
sfc-y			:= efx.o efx_common.o efx_channels.o nic.o ef10.o \
			   tx.o tx_common.o rx.o rx_common.o \
			   selftest.o ethtool_common.o ethtool.o \
			   mcdi.o mcdi_port.o mcdi_port_common.o mcdi_functions.o \
			   mcdi_filters.o ef10_sriov.o tx_tso.o \
			   efx_devlink.o xdp.o efx_virtbus.o \
			   ef100.o ef100_nic.o ef100_netdev.o ef100_ethtool.o \
			   ef100_rx.o ef100_tx.o ef100_sriov.o ef100_rep.o \
			   tc.o mae.o ef100_bsp.o efx_reflash.o

sfc_driverlink-y	:= driverlink.o

sfc-$(CONFIG_SFC_SIENA)	+= farch.o siena.o
sfc-$(CONFIG_SFC_SRIOV)	+= sriov.o
sfc-$(CONFIG_SFC_MCDI_MON) += mcdi_mon.o
sfc-$(CONFIG_SFC_PTP)	+= ptp.o
sfc-$(CONFIG_SFC_MTD)	+= mtd.o
sfc-$(CONFIG_SFC_VDPA) += ef100_vdpa.o ef100_vdpa_ops.o mcdi_vdpa.o \
			  ef100_iova.o
ifndef EFX_NO_KCOMPAT
ifneq ($(MAKECMDGOALS),export)
ifndef EFX_FOR_UPSTREAM
sfc-y			+= ioctl.o ioctl_common.o
CFLAGS_efx.o		= -DEFX_USE_PRIVATE_IOCTL
endif
sfc-y			+= kernel_compat.o
endif
endif # !EFX_NO_KCOMPAT
ifndef EFX_UPSTREAM
ifeq ($(filter export export-xen,$(MAKECMDGOALS)),)
ifndef EFX_FOR_UPSTREAM
sfc-y			+= linux_mdio.o sfctool.o ef100_dump.o
sfc-$(CONFIG_SFC_AOE)	+= aoe.o
sfc-$(CONFIG_SFC_DEBUGFS) += debugfs.o
endif # !EFX_FOR_UPSTREAM
sfc-$(CONFIG_SFC_DUMP) += dump.o
endif
endif # !EFX_UPSTREAM

obj-$(CONFIG_SFC)	+= sfc.o
obj-$(CONFIG_SFC_DRIVERLINK) += sfc_driverlink.o

#
ifndef EFX_UPSTREAM

# Compiler flags
EXTRA_CFLAGS += -I$(src) -DWITH_MCDI_V2

ifdef KMP_RELEASE
EXTRA_CFLAGS += -DKMP_RELEASE
endif

ifdef EFX_NOT_EXPORTED
ifdef GCOV
sfc_gcov-y		+= gcov.o
obj-m			+= sfc_gcov.o
EXTRA_CFLAGS += -fprofile-arcs -ftest-coverage -DEFX_GCOV
endif
endif # EFX_NOT_EXPORTED

ifndef EFX_DISABLE_GRO
EXTRA_CFLAGS += -DEFX_USE_GRO
endif
ifndef EFX_DISABLE_SFC_LRO
EXTRA_CFLAGS += -DEFX_USE_SFC_LRO
endif
ifndef EFX_DISABLE_OVERLAY_TX_CSUM
EXTRA_CFLAGS += -DEFX_USE_OVERLAY_TX_CSUM
endif

all_sfc_ko = $(subst .o,.ko,$(obj-m))

ifdef KERNELRELEASE
TOPDIR = $(src)/../../../..
include $(TOPDIR)/scripts/Makefile.common

define filechk_config.h
	printf "$(foreach name,SFC_DEBUGFS SFC_DUMP SFC_MCDI_MON SFC_MTD SFC_SIENA SFC_SRIOV SFC_PTP SFC_PRIVATE_MDIO SFC_AOE SFC_PPS SFC_TRACING SFC_MCDI_LOGGING SFC_DRIVERLINK SFC_BUSYPOLL SFC_VDPA,#undef CONFIG_$(name)\n$(if $(filter y m,$(CONFIG_$(name))),#define CONFIG_$(name) $(CONFIG_$(name))\n))"
endef

$(obj)/config.h: $(src)/Makefile FORCE
	$(call filechk,config.h)

$(addprefix $(obj)/,$(sfc-y) $(sfc_driverlink-y)): \
	$(obj)/.kpath $(obj)/autocompat.h $(obj)/config.h

# Select the right warnings - complicated by working out which options work
ifndef try-run
try-run = $(shell set -e;		\
	TMP="$(obj)/.$$$$.tmp";		\
	TMPO="$(obj)/.$$$$.o";		\
	if ($(1)) >/dev/null 2>&1;	\
	then echo "$(2)";		\
	else echo "$(3)";		\
	fi;				\
	rm -f "$$TMP" "$$TMPO")
endif
ifndef cc-disable-warning
cc-disable-warning = $(call try-run,\
	$(CC) $(KBUILD_CPPFLAGS) $(KBUILD_CFLAGS) -W$(strip $(1)) -c -xc /dev/null -o "$$TMP",-Wno-$(strip $(1)))
endif
override EXTRA_CFLAGS += $(call cc-disable-warning, unused-but-set-variable) \
			 $(call cc-disable-warning, format-zero-length)

else # !KERNELRELEASE

# Some distribution packages of 2.6.16 fail to define KERNELRELEASE
# when compiling out-of-tree modules.
ifneq ($(filter 2.6.16-% 2.6.16.%,$(KVER)),)
EXTRA_MAKEFLAGS := KERNELRELEASE=$(KVER)
endif

default : top

top:
	$(MAKE) -C ../../../.. all

all : modules
ifdef BUILD_INKERNEL_TESTS
	! [ -d unittest_filters ] || $(MAKE) -C unittest_filters $(EXTRA_MAKEFLAGS)
endif

modules :
	$(MAKE) -C $(KDIR) $(EXTRA_MAKEFLAGS) M=$$(pwd)
# strip objects
ifdef NDEBUG
	$(CROSS_COMPILE)strip --strip-debug $(all_sfc_ko)
endif
ifdef EFX_NOT_EXPORTED
	@echo "module sizes are:"
	@ls -l $(all_sfc_ko)
endif # EFX_NOT_EXPORTED

modules_install :
	mkdir -p $(INSTALL_MOD_PATH)/lib/modules/$(KVER)/$(INSTALL_MOD_DIR)
	$(MAKE) -C $(KDIR) $(EXTRA_MAKEFLAGS) M=$$(pwd) INSTALL_MOD_DIR=$(INSTALL_MOD_DIR) modules_install

clean : clean_modules clean_tests

clean_tests:
	! [ -d unittest_filters ] || $(MAKE) -C unittest_filters clean

clean_modules :
	rm -f *.o *.s *.ko *.mod.c *.symvers config.h autocompat.h .kpath
	$(MAKE) -C $(KDIR) $(EXTRA_MAKEFLAGS) M=$$(pwd) clean

.PHONY : all modules modules_install clean clean_modules top FORCE

ifdef EFX_NOT_EXPORTED

all : util

clean : clean_doc clean_util

# Misc

cscope : $(obj-m)
	 @cscope -bkR -s.

# Documentation (using kernel-doc)

INTRANET_DOC_PATH = /project/intranet/live/html/efab/soft/linux_net/html
intranet : doc
	rm -rf $(INTRANET_DOC_PATH)
	cp -a doc/html $(INTRANET_DOC_PATH)

doc :
	$(MAKE) -C doc

clean_doc :
	$(MAKE) -C doc clean

# For recursion into util subdirectory
util:
	$(MAKE) -C util

clean_util:
	$(MAKE) -C util clean

endif # EFX_NOT_EXPORTED

# Export into kernel tree
export:
	$(EXPORT_CMD) $(KDIR) $(sfc_driverlink-y:%.o=%.c) $(sfc-y:%.o=%.c)

export-resolve-kcompat:
	$(EXPORT_CMD) -k -kk $(KDIR) $(sfc-y:%.o=%.c)

# Export into a Xen kernel tree
export-xen:
	$(EXPORT_CMD) -k -kk --suffix=xen $(KDIR) $(sfc_driverlink-y:%.o=%.c) $(sfc-y:%.o=%.c)

# Export for SRPM
export-srpm:
	mkdir -p $(KDIR)/mtd
	$(EXPORT_CMD) -o $(KDIR) $(sfc_driverlink-y:%.o=%.c) $(sfc-y:%.o=%.c) mtd/mtd-abi.h trace/events/sfc.h kernel_compat.sh $(TOPDIR)/scripts/kernel_compat_funcs.sh

.PHONY : intranet doc clean_doc util clean_util export export-xen export-srpm

endif # !KERELRELEASE
endif # !EFX_UPSTREAM
