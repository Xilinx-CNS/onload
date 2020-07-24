# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
############################
# 
# EtherFabric linux kernel drivers 
#
#	sfc_resource
#
############################

RESOURCE_SRCS	:= resource_driver.c \
	iopage.c driverlink_new.c kernel_proc.c filter.c \
	bt_stats.c compat_pat_wc.c port_sniff.c nondl_resource.c sysfs.c \
	nondl_driver.c sfcaffinity.c nic_notifier.c

EFHW_SRCS	:= nic.c eventq.c ef10.c ef100.c af_xdp.c

EFHW_HDRS	:= ef10_mcdi.h

EFRM_SRCS	:=			\
		assert_valid.c		\
		efrm_vi_set.c		\
		efrm_pd.c		\
		efrm_pio.c		\
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
		driver_object.c         \
		licensing.c

EFRM_HDRS	:= efrm_internal.h efrm_vi.h efrm_vi_set.h \
		efrm_pd.h efrm_pio.h bt_manager.h


IMPORT		:= $(EFHW_SRCS:%=../../lib/efhw/%) \
		   $(EFHW_HDRS:%=../../lib/efhw/%) \
		   $(EFRM_SRCS:%=../../lib/efrm/%) \
		   $(EFRM_HDRS:%=../../lib/efrm/%) \
		   ../linux_net/drivers/net/ethernet/sfc/driverlink_api.h

RESOURCE_TARGET	:= sfc_resource.o
RESOURCE_TARGET_SRCS := $(RESOURCE_SRCS) $(EFHW_SRCS) $(EFRM_SRCS)

TARGETS		:= $(RESOURCE_TARGET)

x86_TARGET_SRCS   := syscall_x86.o

arm64_TARGET_SRCS := syscall_aarch64.o


######################################################
# linux kbuild support
#

KBUILD_EXTRA_SYMBOLS := $(BUILDPATH)/driver/linux_net/drivers/net/ethernet/sfc/Module.symvers

all: $(KBUILD_EXTRA_SYMBOLS)
	$(MAKE) $(MMAKE_KBUILD_ARGS) M=$(CURDIR)
	cp -f sfc_resource.ko $(BUILDPATH)/driver/linux
ifndef CI_FROM_DRIVER
	$(warning "Due to build order sfc.ko may be out-of-date. Please build in driver/linux_net")
endif

clean:
	@$(MakeClean)
	rm -rf *.ko Module.symvers .*.cmd autocompat.h


ifdef MMAKE_IN_KBUILD

obj-m := $(RESOURCE_TARGET) 

sfc_resource-objs := $(RESOURCE_TARGET_SRCS:%.c=%.o) $($(ARCH)_TARGET_SRCS:%.c=%.o)

ifdef KBUILD_SRC
define filechk_autocompat.h
	$(src)/kernel_compat.sh -k $(KBUILD_SRC) -o "$(CURDIR)" $(if $(filter 1,$(V)),-v,-q)
endef
else
define filechk_autocompat.h
	$(src)/kernel_compat.sh -k "$(CURDIR)" -o "$(CURDIR)" $(if $(filter 1,$(V)),-v,-q)
endef
endif

$(obj)/autocompat.h: $(src)/kernel_compat.sh $(src)/kernel_compat_funcs.sh
	+$(call filechk,autocompat.h)
	@touch $@

$(addprefix $(obj)/,$(sfc_resource-objs)): $(obj)/autocompat.h

endif # MMAKE_IN_KBUILD
