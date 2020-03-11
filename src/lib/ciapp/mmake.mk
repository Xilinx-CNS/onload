# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc

TARGET		:= $(CIAPP_LIB)
MMAKE_TYPE	:= LIB

LIB_SRCS	:= \
		testapp.c \
		net.c \
		bytepattern.c \
		ctimer.c \
		stats.c \
		iarray_mean_and_limits.c \
		iarray_median.c \
		iarray_mode.c \
		iarray_variance.c \
		qsort_compare_int.c \
		testpattern.c \
		select.c \
		errno.c \
		read_exact.c \
		write_exact.c \
		recv_exact.c \
		getinput.c \
		put_record.c \
		get_record.c \
		testethpkt.c \
		rawpkt.c \
		fork_filter.c \
		dump_select_set.c \
		rate_thread.c \
		sys_info.c \
		dummy_work.c \
		dump_tcp_info.c \
		onload_info.c

ifeq ($(LINUX),1)
LIB_SRCS	+= ifindex.c
endif


MMAKE_OBJ_PREFIX := ci_app_
LIB_OBJS	 := $(LIB_SRCS:%.c=$(MMAKE_OBJ_PREFIX)%.o)


all: $(TARGET)

lib: $(TARGET)

clean:
	@$(MakeClean)


$(TARGET): $(LIB_OBJS)
	$(MMakeLinkStaticLib)

