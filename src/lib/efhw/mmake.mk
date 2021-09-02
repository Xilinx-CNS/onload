# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc.

TARGET		:= $(EFHW_LIB)
MMAKE_TYPE	:= LIB

LIB_SRCS	:= nic.c \
		   eeprom.c \
		   eventq.c \
		   ef10.c \
		   ef100.c \
		   efct.c \
		   af_xdp.c \
		   ethtool_rxclass.c \
		   ethtool_flow.c


ifndef MMAKE_NO_RULES

MMAKE_OBJ_PREFIX := ef_hw_
LIB_OBJS	 := $(LIB_SRCS:%.c=$(MMAKE_OBJ_PREFIX)%.o)

all: $(TARGET)

lib: $(TARGET)

clean:
	@$(MakeClean)

$(TARGET): $(LIB_OBJS)
	$(MMakeLinkStaticLib)
endif


######################################################
# linux kbuild support
#
ifdef MMAKE_USE_KBUILD
all:
	 $(MAKE) $(MMAKE_KBUILD_ARGS) KBUILD_EXTMOD=$(BUILDPATH)/lib/efhw
clean:
	@$(MakeClean)
	rm -f lib.a
endif

ifdef MMAKE_IN_KBUILD
LIB_OBJS := $(LIB_SRCS:%.c=%.o)
lib-y    := $(LIB_OBJS)
endif
