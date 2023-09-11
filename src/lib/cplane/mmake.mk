# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2015-2020 Xilinx, Inc.
TARGETS		:= $(CPLANE_LIB) $(CPLANE_API_SHARED_REALNAME) $(CPLANE_API_SHARED_SONAME) $(CPLANE_API_SHARED_LINKNAME)
MMAKE_TYPE	:= LIB

LIB_SRCS	:= mib.c mib_fwd.c services.c onload.c version.c onload_version.c
LIB_OBJS	:= $(LIB_SRCS:%.c=$(MMAKE_OBJ_PREFIX)%.o)
UAPI_LIB_OBJS := uapi_top.o uapi_llap.o uapi_resolve.o

ALL		:= $(TARGETS)

MMAKE_CFLAGS += -fvisibility=hidden

ifndef MMAKE_NO_RULES

all: $(ALL)

lib: $(TARGETS)

clean:
	@$(MakeClean)

$(LIB_OBJS): $(CP_INTF_VER_HDR)

$(CPLANE_LIB): $(LIB_OBJS)
	$(MMakeLinkStaticLib)

$(UAPI_LIB_OBJS) : $(CP_INTF_VER_HDR)
$(CPLANE_API_SHARED_REALNAME): $(UAPI_LIB_OBJS) $(CPLANE_LIB)
	@(soname="$(CPLANE_API_SHARED_SONAME)" libs="$(LINK_CPLANE_LIB) $(LINK_CITOOLS_LIB)"; $(MMakeLinkDynamicLib))

$(CPLANE_API_SHARED_SONAME): $(CPLANE_API_SHARED_REALNAME)
	ln -fs $(<F) $@

$(CPLANE_API_SHARED_LINKNAME): $(CPLANE_API_SHARED_REALNAME)
	ln -fs $(<F) $@

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
	$(MAKE) $(MMAKE_KBUILD_ARGS) KBUILD_BUILTIN=1 KBUILD_EXTMOD=$(lib_obj_path) $(KBUILD_LIB_MAKE_TRG)
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

