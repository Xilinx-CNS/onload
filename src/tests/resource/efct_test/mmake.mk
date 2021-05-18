# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc.

EFCT_TEST_SRCS	:= efct_test_driver.c efct_test_device.c efct_test_ops.c \
		sysfs.c

EFCT_TEST_TARGET	:= efct_test.o
EFCT_TEST_TARGET_SRCS := $(EFCT_TEST_SRCS)

TARGETS		:= $(EFCT_TEST_TARGET)

# FIXME IMPORT is applied relative to TOPPATH, should fix this
# to not rely on a repo in a fixed relative location.
IMPORT		:=
IMPORT		+= ../../../../../x3-net-linux/include/linux/net/sfc/sfc_efct.h


######################################################
# linux kbuild support
#

ifndef CONFIG_AUXILIARY_BUS
ifneq ($(HAVE_CNS_AUX),0)
KBUILD_EXTRA_SYMBOLS := $(AUX_BUS_PATH)/drivers/base/Module.symvers
else
$(warning "Aux bus is needed for efct_test")
endif
endif

all: $(KBUILD_EXTRA_SYMBOLS)
	$(MAKE) $(MMAKE_KBUILD_ARGS) M=$(CURDIR)

clean:
	@$(MakeClean)
	rm -rf *.ko Module.symvers .*.cmd


ifdef MMAKE_IN_KBUILD

obj-m := $(EFCT_TEST_TARGET)

efct_test-objs := $(EFCT_TEST_TARGET_SRCS:%.c=%.o)

endif # MMAKE_IN_KBUILD
