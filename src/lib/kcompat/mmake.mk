# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
TARGET		:= $(KCOMPAT_LIB)
MMAKE_TYPE	:= LIB

LIB_SRCS	:= compat_stubs.c
LIB_OBJS	:= $(LIB_SRCS:%.c=$(MMAKE_OBJ_PREFIX)%.o)

ALL		:= $(TARGET)


ifndef MMAKE_NO_RULES

all: $(ALL)

lib: $(TARGET)

clean:
	@$(MakeClean)

$(TARGET): $(LIB_OBJS)
	$(MMakeLinkStaticLib)

endif

