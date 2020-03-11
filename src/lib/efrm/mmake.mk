# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc

TARGET		:= $(EFRM_LIB)
MMAKE_TYPE	:= LIB

LIB_SRCS	:= assert_valid.c \
		   buffer_table.c \
		   efrm_vi_set.c \
		   efrm_pd.c \
		   efrm_pio.c \
		   iobufset_resource.c \
		   resource_manager.c \
		   resources.c \
		   vi_resource_alloc.c \
		   vi_resource_event.c \
		   vi_resource_flush.c \
		   vi_resource_manager.c \
		   vi_resource_info.c \
		   vi_allocator.c \
		   buddy.c \
		   driver_object.c \
		   licensing.c


ifndef MMAKE_NO_RULES

MMAKE_OBJ_PREFIX := ef_rm_
LIB_OBJS	 := $(LIB_SRCS:%.c=$(MMAKE_OBJ_PREFIX)%.o)

all: $(TARGET)

lib: $(TARGET)

clean:
	@$(MakeClean)

$(TARGET): $(LIB_OBJS) $(LIB_OBJS1)
	$(MMakeLinkStaticLib)
endif


######################################################
# linux kbuild support
#
ifdef MMAKE_USE_KBUILD
all:
	 $(MAKE) $(MMAKE_KBUILD_ARGS) KBUILD_EXTMOD=$(BUILDPATH)/lib/efrm
clean:
	@$(MakeClean)
	rm -f lib.a
endif

ifdef MMAKE_IN_KBUILD
LIB_OBJS := $(LIB_SRCS:%.c=%.o)
lib-y    := $(LIB_OBJS)
endif
