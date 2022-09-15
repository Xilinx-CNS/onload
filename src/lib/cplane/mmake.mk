# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2015-2020 Xilinx, Inc.
TARGET		:= $(CPLANE_LIB)
MMAKE_TYPE	:= LIB

LIB_SRCS	:= mib.c mib_fwd.c services.c onload.c version.c onload_version.c
LIB_OBJS	:= $(LIB_SRCS:%.c=$(MMAKE_OBJ_PREFIX)%.o)

ALL		:= $(TARGET)


ifndef MMAKE_NO_RULES

all: $(ALL)

lib: $(TARGET)

clean:
	@$(MakeClean)

$(LIB_OBJS): $(CP_INTF_VER_HDR)

$(TARGET): $(LIB_OBJS)
	$(MMakeLinkStaticLib)

endif

ifdef MMAKE_USE_KBUILD
  objd	:= $(obj)/
  EXTRA_CFLAGS += $(CP_INTF_VER_CFLAGS)
else
  objd	:=
  MMAKE_CFLAGS += $(CP_INTF_VER_CFLAGS) -I../..
endif

######################################################
# linux kbuild support
#
ifdef MMAKE_USE_KBUILD

lib_obj = cplane_lib.o
lib_obj_path = $(BUILDPATH)/lib/cplane

lib_obj_cmd = $(LD) -r $(LIB_SRCS:%.c=%.o) -o $(lib_obj)
all: $(CP_INTF_VER_HDR)
	$(MAKE) $(MMAKE_KBUILD_ARGS) KBUILD_BUILTIN=1 KBUILD_EXTMOD=$(lib_obj_path)
	$(lib_obj_cmd)
	echo "cmd_$(lib_obj_path)/$(lib_obj) := $(lib_obj_cmd)" > .$(lib_obj).cmd
clean:
	@$(MakeClean)
	rm -f cplane_lib.o
endif

ifdef MMAKE_IN_KBUILD
LIB_OBJS  := $(LIB_SRCS:%.c=%.o)
obj-y     := $(LIB_OBJS)

# This normally gets included via mk/site/mmake.mk, but we do not include
# that file when MAKE_IN_KBUILD is set, so we need an explicit include
# here to get the CP_INTF_VER variables
include $(TOPPATH)/mk/site/cplane.mk
ccflags-y := $(CP_INTF_VER_CFLAGS)
endif

