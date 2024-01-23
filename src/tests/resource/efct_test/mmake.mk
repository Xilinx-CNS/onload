# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc.

EFCT_TEST_SRCS	:= efct_test_driver.c efct_test_device.c efct_test_ops.c \
		configfs.c efct_test_tx.c efct_test_rx.c

EFCT_TEST_TARGET	:= efct_test.o
EFCT_TEST_TARGET_SRCS := $(EFCT_TEST_SRCS)

TARGETS		:= $(EFCT_TEST_TARGET)

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

ifeq ($(HAVE_X3_NET),0)
$(warning "X3 net driver is needed for efct_test")
endif

all: $(KBUILD_EXTRA_SYMBOLS)
	$(MAKE) $(MMAKE_KBUILD_ARGS) M=$(CURDIR)
	cp -f efct_test.ko $(BUILDPATH)/driver/linux

clean:
	@$(MakeClean)
	rm -rf *.ko Module.symvers .*.cmd


ifdef MMAKE_IN_KBUILD

obj-m := $(EFCT_TEST_TARGET)

efct_test-objs := $(EFCT_TEST_TARGET_SRCS:%.c=%.o)

endif # MMAKE_IN_KBUILD
