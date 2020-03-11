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
export CONFIG_SFC_EF100 := m
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
endif

ifdef KSRCDIR
$(error KSRCDIR has been replaced with KPATH)
endif

ifdef KERNELRELEASE

# Check config dependencies under Kbuild.  We should only do this if
# .config has actually been included (it isn't when cleaning), so test
# for a config symbol that should always be defined.
ifdef CONFIG_NET
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
endif # CONFIG_NET

else # !KERNELRELEASE ###### The following is for the standalone Makefile case

ifneq ($(MAKECMDGOALS),export-srpm)
# Get kernel version and source directory.  Either may be specified and
# we work out the other automatically.  If neither is specified then we
# assume the current kernel version.
ifdef KPATH
ifndef KVER
KVER := $(shell sed -r 's/^\#define UTS_RELEASE "(.*)"/\1/; t; d' $(KPATH)/include/generated/utsrelease.h $(KPATH)/include/linux/utsrelease.h $(KPATH)/include/linux/version.h 2>/dev/null)
ifeq ($(KVER),)
$(error Failed to find kernel version for $(KPATH))
endif
endif
else # !KPATH
ifndef KVER
KVER := $(shell uname -r)
endif
KPATH := /lib/modules/$(KVER)/build
endif # KPATH

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
#
ifneq ($(findstring 2.6.32-573,$(KPATH)),)
# RedHat 6.7 kbuild is missing a patch to build multiple modules
override CONFIG_SFC_EF100 :=
endif
# RedHat 6.8 and later only need separate builds if dynamic debugging is enabled
ifneq ($(findstring .el6,$(KPATH)),)
  EFX_BUILD_SEPARATE_MODULES := y
endif

endif # !EFX_UPSTREAM
#
sfc-y			:= efx.o efx_common.o efx_channels.o nic.o ef10.o \
			   tx.o tx_common.o rx.o rx_common.o \
			   selftest.o ethtool_common.o ethtool.o \
			   mcdi.o mcdi_port.o mcdi_port_common.o mcdi_functions.o \
			   mcdi_filters.o ef10_sriov.o tx_tso.o tc-stub.o \
			   efx_devlink.o

sfc_ef100-y             := mcdi.o ef100.o efx_common.o efx_channels.o \
                           ef100_nic.o nic.o ef100_netdev.o ef100_ethtool.o \
                           ef100_rx.o rx_common.o ef100_tx.o tx_common.o \
			   ethtool_common.o mcdi_port_common.o mcdi_functions.o \
			   mcdi_filters.o ef100_sriov.o ef100_rep.o tc.o mae.o \
			   efx_devlink.o selftest.o

sfc_driverlink-y	:= driverlink.o

sfc-$(CONFIG_SFC_SIENA)	+= farch.o siena.o
sfc-$(CONFIG_SFC_SRIOV)	+= sriov.o
sfc-$(CONFIG_SFC_MCDI_MON) += mcdi_mon.o
sfc-$(CONFIG_SFC_PTP)	+= ptp.o
sfc_ef100-$(CONFIG_SFC_PTP)	+= ptp.o
sfc-$(CONFIG_SFC_MTD)	+= mtd.o
ifndef EFX_NO_KCOMPAT
ifneq ($(MAKECMDGOALS),export)
ifndef EFX_FOR_UPSTREAM
sfc-y			+= ioctl.o ioctl_common.o
CFLAGS_efx.o		= -DEFX_USE_PRIVATE_IOCTL
sfc_ef100-y		+= ioctl_common.o
endif
sfc-y			+= kernel_compat.o
endif
endif # !EFX_NO_KCOMPAT
ifndef EFX_UPSTREAM
ifeq ($(filter export export-xen,$(MAKECMDGOALS)),)
ifndef EFX_FOR_UPSTREAM
sfc-y			+= linux_mdio.o sfctool.o
sfc_ef100-y		+= sfctool.o
sfc-$(CONFIG_SFC_AOE)	+= aoe.o
sfc-$(CONFIG_SFC_DEBUGFS) += debugfs.o
sfc_ef100-$(CONFIG_SFC_DEBUGFS) += debugfs.o
endif # !EFX_FOR_UPSTREAM
sfc-$(CONFIG_SFC_DUMP) += dump.o
sfc_ef100-$(CONFIG_SFC_DUMP) += dump.o
endif
endif # !EFX_UPSTREAM

ifndef EFX_NO_KCOMPAT
ifneq ($(MAKECMDGOALS),export)
sfc_ef100-y             += kernel_compat.o
endif
endif # !EFX_NO_KCOMPAT

obj-$(CONFIG_SFC)	+= sfc.o
obj-$(CONFIG_SFC_EF100) += sfc_ef100.o
obj-$(CONFIG_SFC_DRIVERLINK) += sfc_driverlink.o

#
ifndef EFX_UPSTREAM

# Compiler flags
EXTRA_CFLAGS += -I$(src) -Wall -Wno-deprecated-declarations -DEFX_USE_KCOMPAT=1 -DWITH_MCDI_V2
ifdef EFX_FOR_UPSTREAM
EXTRA_CFLAGS += -include config.h
else
EXTRA_CFLAGS += -DEFX_NOT_UPSTREAM=1
endif
ifdef KMP_RELEASE
EXTRA_CFLAGS += -DKMP_RELEASE
endif

ifdef EFX_NOT_EXPORTED
EXTRA_CFLAGS += -DEFX_NOT_EXPORTED

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
ifdef EFX_C_MODEL
EXTRA_CFLAGS += -DEFX_C_MODEL
endif

ifndef NOWERROR
EXTRA_CFLAGS += -Werror
endif # NOWERROR

# Debugging-enabled builds
ifndef NDEBUG
EXTRA_CFLAGS += -DDEBUG -g
endif

all_sfc_ko = $(subst .o,.ko,$(obj-m))

ifdef KERNELRELEASE

# Define filechk if necessary
ifndef filechk
define filechk
	$(Q)set -e;				\
	$(if Q,echo '  CHK     $@';)		\
	mkdir -p $(dir $@);			\
	$(filechk_$(1)) < $< > $@.tmp;		\
	if [ -r $@ ] && cmp -s $@ $@.tmp; then	\
		rm -f $@.tmp;			\
	else					\
		$(if Q,echo '  UPD     $@';)	\
		mv -f $@.tmp $@;		\
	fi
endef
endif

# autocompat.h depends on the kernel compiled against.
# However, there is nothing stopping the user compiling on multiple
# machines in the same directory. The .kpath target provides a simple
# dependency check for this.
#
# Module(s).symvers also depends on the kernel compiled against, but
# can simply be deleted here.  However mmake does some more complicated
# management of Module.symvers and does not allow changing the kernel
# path, so don't touch it when invoked from an mmake tree.
$(obj)/.kpath: FORCE
	@if ! [ -f $@ ] || [ $$(cat $@) != $(objtree) ]; then		\
		echo $(objtree) >$@;					\
		$(if $(MMAKE_IN_KBUILD),,rm -f $(obj)/*.symvers;)	\
	fi

ifdef KBUILD_SRC
define filechk_autocompat.h
	$(src)/kernel_compat.sh -k $(KBUILD_SRC) -o "$(CURDIR)" $(if $(filter 1,$(V)),-v,-q)
endef
else
define filechk_autocompat.h
	$(src)/kernel_compat.sh -k "$(CURDIR)" -o "$(CURDIR)" $(if $(filter 1,$(V)),-v,-q)
endef
endif

$(obj)/autocompat.h: $(obj)/.kpath $(src)/kernel_compat.sh $(src)/kernel_compat_funcs.sh
	+$(call filechk,autocompat.h)
	@touch $@

define filechk_config.h
	printf "$(foreach name,SFC_DEBUGFS SFC_DUMP SFC_MCDI_MON SFC_MTD SFC_SIENA SFC_SRIOV SFC_PTP SFC_PRIVATE_MDIO SFC_AOE SFC_PPS SFC_TRACING SFC_MCDI_LOGGING SFC_DRIVERLINK SFC_BUSYPOLL,#undef CONFIG_$(name)\n$(if $(filter y m,$(CONFIG_$(name))),#define CONFIG_$(name) $(CONFIG_$(name))\n))"
endef

$(obj)/config.h: $(src)/Makefile FORCE
	$(call filechk,config.h)

$(addprefix $(obj)/,$(sfc-y) $(sfc_ef100-y) $(sfc_driverlink-y)): \
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
ifeq ($(origin CC),default)
ifneq ($(CROSS_COMPILE),)
CC=$(CROSS_COMPILE)gcc
endif
endif
ifneq ($(CC),)
EXTRA_MAKEFLAGS += CC="$(CC)"
endif
ifneq ($(C),)
EXTRA_MAKEFLAGS += C="$(C)"
endif
ifdef KMP_RELEASE
EXTRA_MAKEFLAGS += KMP_RELEASE=1
endif

ifeq ($(INSTALL_MOD_DIR),)
INSTALL_MOD_DIR := updates
endif

default : all

all : modules
ifdef BUILD_INKERNEL_TESTS
	! [ -d unittest_filters ] || $(MAKE) -C unittest_filters $(EXTRA_MAKEFLAGS)
endif

modules :
ifdef EFX_BUILD_SEPARATE_MODULES
  # The kernel is too old to build multiple modules in 1 build
  ifdef CONFIG_SFC
	$(MAKE) -C $(KPATH) $(EXTRA_MAKEFLAGS) M=$$(pwd) CONFIG_SFC_EF100=
  endif
  ifdef CONFIG_SFC_EF100
	$(MAKE) -C $(KPATH) $(EXTRA_MAKEFLAGS) M=$$(pwd) CONFIG_SFC=
  endif
else
	$(MAKE) -C $(KPATH) $(EXTRA_MAKEFLAGS) M=$$(pwd)
endif
# strip objects
ifdef NDEBUG
	$(CROSS_COMPILE)strip --strip-debug $(all_sfc_ko)
endif
ifdef EFX_NOT_EXPORTED
	@echo "module sizes are:"
	@ls -l $(all_sfc_ko)
endif # EFX_NOT_EXPORTED

modules_install :
  # See bug 35865 for discussion on updates vs. extra location
	echo INSTALL_MOD_PATH=$(INSTALL_MOD_PATH)
	echo INSTALL_MOD_DIR=$(INSTALL_MOD_DIR)
	mkdir -p $(INSTALL_MOD_PATH)/lib/modules/$(KVER)/$(INSTALL_MOD_DIR)
	$(MAKE) -C $(KPATH) $(EXTRA_MAKEFLAGS) M=$$(pwd) INSTALL_MOD_DIR=$(INSTALL_MOD_DIR) modules_install

clean : clean_modules clean_tests

clean_tests:
	! [ -d unittest_filters ] || $(MAKE) -C unittest_filters clean

clean_modules :
	rm -f *.o *.s *.ko *.mod.c *.symvers config.h autocompat.h .kpath
	$(MAKE) -C $(KPATH) $(EXTRA_MAKEFLAGS) M=$$(pwd) clean

.PHONY : all modules modules_install clean clean_modules FORCE

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
	./export.sh $(KPATH) $(sfc_driverlink-y:%.o=%.c) $(sfc-y:%.o=%.c) $(sfc_ef100-y:%.o=%.c)

export-resolve-kcompat:
	./export.sh -k -kk $(KPATH) $(sfc-y:%.o=%.c)

# Export into a Xen kernel tree
export-xen:
	./export.sh -k -kk --suffix=xen $(KPATH) $(sfc_driverlink-y:%.o=%.c) $(sfc-y:%.o=%.c) $(sfc_ef100-y:%.o=%.c)

# Export for SRPM
export-srpm:
	mkdir -p $(KPATH)/mtd
	./export.sh -o $(KPATH) $(sfc_driverlink-y:%.o=%.c) $(sfc-y:%.o=%.c) $(sfc_ef100-y:%.o=%.c) mtd/mtd-abi.h trace/events/sfc.h kernel_compat.sh kernel_compat_funcs.sh

.PHONY : intranet doc clean_doc util clean_util export export-xen export-srpm

endif # !KERELRELEASE
endif # !EFX_UPSTREAM
