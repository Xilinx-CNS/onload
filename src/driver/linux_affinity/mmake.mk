# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
SFCAFF_SRCS	:= sfcaffinity.c

SFCAFF_TARGET	:= sfc_affinity.o
SFCAFF_TARGET_SRCS := $(SFCAFF_SRCS)

TARGETS		:= $(SFCAFF_TARGET)

IMPORT		:= ../linux_net/drivers/net/ethernet/sfc/driverlink_api.h


######################################################
# linux kbuild support
#

KBUILD_EXTRA_SYMBOLS := $(BUILDPATH)/driver/linux_net/drivers/net/ethernet/sfc/Module.symvers

all: $(KBUILD_EXTRA_SYMBOLS)
	$(MAKE) $(MMAKE_KBUILD_ARGS) M=$(CURDIR)
	cp -f sfc_affinity.ko $(BUILDPATH)/driver/linux
ifndef CI_FROM_DRIVER
	$(warning "Due to build order sfc.ko may be out-of-date. Please build in driver/linux_net")
endif

clean:
	@$(MakeClean)
	rm -rf *.ko Module.symvers .*.cmd


ifdef MMAKE_IN_KBUILD

dummy := $(shell echo>&2 "MMAKE_IN_KBUILD")

obj-m := $(SFCAFF_TARGET) 

sfc_affinity-objs := $(SFCAFF_TARGET_SRCS:%.c=%.o)

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

$(obj)/$(sfc_affinity-objs): $(obj)/autocompat.h

endif # MMAKE_IN_KBUILD
