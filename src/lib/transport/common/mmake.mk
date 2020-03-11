# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
TARGET		:= $(CITPCOMMON_LIB)
MMAKE_TYPE	:= LIB

LIB_SRCS	:=		\
		log.c		\
		netif_init.c	\
		lock.c

MMAKE_OBJ_PREFIX := ci_tp_common_
LIB_OBJS	:= $(LIB_SRCS:%.c=$(MMAKE_OBJ_PREFIX)%.o)

all: $(TARGET)

lib: $(TARGET)

clean:
	@$(MakeClean)

$(TARGET): $(LIB_OBJS)
	$(MMakeLinkStaticLib)
