# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc.
############################
# 
# EtherFabric linux kernel drivers 
#
#	sfc_resource
#
############################

RESOURCE_SRCS	:= resource_driver.c \
	iopage.c kernel_proc.c filter.c \
	bt_stats.c compat_pat_wc.c port_sniff.c nondl_resource.c sysfs.c \
	nondl_driver.c sfcaffinity.c nic_notifier.c \
	aux_driver.c aux_efct.c efct_superbuf.c

EFHW_SRCS	:= nic.c eventq.c af_xdp.c ethtool_rxclass.c \
		ethtool_flow.c efct.c

EFHW_HDRS	:= ef10_mcdi.h ethtool_rxclass.h ethtool_flow.h ef10_ef100.h \
		efct.h

EFRM_SRCS	:=			\
		assert_valid.c		\
		efrm_vi_set.c		\
		efrm_pd.c		\
		efrm_pio.c		\
		efrm_slice_ext.c	\
		efrm_efct_rxq.c		\
		resource_manager.c	\
		resources.c		\
		vi_resource_alloc.c	\
		vi_resource_event.c	\
		vi_resource_flush.c	\
		vi_resource_manager.c	\
		vi_resource_info.c	\
		vi_allocator.c		\
		buddy.c			\
		bt_manager.c		\
		driver_object.c		\
		licensing.c

EFRM_HDRS	:= efrm_internal.h efrm_vi.h efrm_vi_set.h \
		efrm_pd.h efrm_pio.h bt_manager.h

UTILS_HDRS	:= hugetlb.h
UTILS_SRCS	:= hugetlb.c

ifeq ($(HAVE_SFC),1)
RESOURCE_SRCS += driverlink_new.c
EFHW_SRCS += ef10.c ef100.c
endif

IMPORT		:= $(EFHW_SRCS:%=../../lib/efhw/%) \
		   $(EFHW_HDRS:%=../../lib/efhw/%) \
		   $(EFRM_SRCS:%=../../lib/efrm/%) \
		   $(EFRM_HDRS:%=../../lib/efrm/%) \
		   $(UTILS_SRCS:%=../../lib/kernel_utils/%) \
		   $(UTILS_HDRS:%=../../include/kernel_utils/%) \
		   ../linux_net/drivers/net/ethernet/sfc/driverlink_api.h


RESOURCE_TARGET	:= sfc_resource.o
RESOURCE_TARGET_SRCS := $(RESOURCE_SRCS) $(EFHW_SRCS) $(EFRM_SRCS) $(UTILS_SRCS)

TARGETS		:= $(RESOURCE_TARGET)

x86_TARGET_SRCS   := syscall_x86.o

arm64_TARGET_SRCS := syscall_aarch64.o


######################################################
# linux kbuild support
#

ifeq ($(HAVE_SFC),1)
KBUILD_EXTRA_SYMBOLS := $(BUILDPATH)/driver/linux_net/drivers/net/ethernet/sfc/Module.symvers
endif

ifndef CONFIG_AUXILIARY_BUS
ifneq ($(HAVE_CNS_AUX),0)
KBUILD_EXTRA_SYMBOLS += $(AUX_BUS_PATH)/drivers/base/Module.symvers
else
ifneq (,$(wildcard /lib/modules/$(KVER)/updates/auxiliary.symvers))
KBUILD_EXTRA_SYMBOLS += /lib/modules/$(KVER)/updates/auxiliary.symvers
endif
endif
endif

all: $(KBUILD_EXTRA_SYMBOLS)
	$(MAKE) $(MMAKE_KBUILD_ARGS) M=$(CURDIR)
	cp -f sfc_resource.ko $(BUILDPATH)/driver/linux
ifndef CI_FROM_DRIVER
	$(warning "Due to build order sfc.ko may be out-of-date. Please build in driver/linux_net")
endif

clean:
	@$(MakeClean)
	rm -rf *.ko Module.symvers .*.cmd


ifdef MMAKE_IN_KBUILD

obj-m := $(RESOURCE_TARGET) 

sfc_resource-objs := $(RESOURCE_TARGET_SRCS:%.c=%.o) $($(ARCH)_TARGET_SRCS:%.c=%.o)

endif # MMAKE_IN_KBUILD
