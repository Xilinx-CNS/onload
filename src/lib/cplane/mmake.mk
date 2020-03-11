# SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
TARGET		:= $(CPLANE_LIB)
MMAKE_TYPE	:= LIB

LIB_SRCS	:= mib.c mib_fwd.c services.c onload.c version.c
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
  MMAKE_CFLAGS += $(CP_INTF_VER_CFLAGS)
endif

######################################################
# linux kbuild support
#
ifdef MMAKE_USE_KBUILD
all: $(CP_INTF_VER_HDR)
	 $(MAKE) $(MMAKE_KBUILD_ARGS) KBUILD_EXTMOD=$(BUILDPATH)/lib/cplane
	 $(LD) -r $(LIB_SRCS:%.c=%.o) -o cplane_lib.o
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

