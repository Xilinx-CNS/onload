# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc.

TARGET		:= $(CITOOLS_LIB)
MMAKE_TYPE	:= LIB

LIB_SRCS	:= \
		buddy.c \
		buffer.c \
		bufrange.c \
		crc16.c \
		crc32.c \
		toeplitz.c \
		dllist.c \
		eth_addr.c \
		fail.c \
		fifo_grow_lock.c \
		hex_dump.c \
		hex_dump_to_raw.c \
		ipcsum.c \
		ip_csum_partial.c \
		memchk.c \
		icmp_checksum.c \
		log.c \
		log_nonl.c \
		log_buffer.c \
		log_nth.c \
		log_unique.c \
		parse_eth_addr.c \
		sys_fail.c \
		pktdump.c \
		ip_addr.c \
		csum_copy2.c \
		csum_copy_iovec.c \
		csum_copy_to_iovec.c \
		copy_iovec.c \
		copy_to_iovec.c \
		ip_csum_precompute.c \
		tcp_csum_precompute.c \
		udp_csum_precompute.c \
		ippacket.c \
		namespace.c

ifeq ($(DRIVER),1)
LIB_SRCS	+= drv_log_fn.c memleak_debug.c
else
LIB_SRCS	+= get_cpu_khz.c log_fn.c log_file.c
LIB_SRCS	+= glibc_version.c
endif


ifndef MMAKE_NO_RULES

MMAKE_OBJ_PREFIX := ci_tools_
LIB_OBJS	 := $(LIB_SRCS:%.c=$(MMAKE_OBJ_PREFIX)%.o)

ifeq (${PLATFORM},gnu_x86_64)
MMAKE_CFLAGS	+= -mpclmul -msse4.1
endif

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

lib_obj = citools_lib.o
lib_obj_path = $(BUILDPATH)/lib/citools

lib_obj_cmd = $(LD) -r $(LIB_SRCS:%.c=%.o) -o $(lib_obj)
all:
	$(MAKE) $(MMAKE_KBUILD_ARGS) KBUILD_BUILTIN=1 KBUILD_EXTMOD=$(lib_obj_path) $(KBUILD_LIB_MAKE_TRG)
	$(lib_obj_cmd)
	echo "cmd_$(lib_obj_path)/$(lib_obj) := $(lib_obj_cmd)" > .$(lib_obj).cmd

clean:
	@$(MakeClean)
	rm -f citools_lib.o
endif

ifdef MMAKE_IN_KBUILD
LIB_OBJS := $(LIB_SRCS:%.c=%.o)
obj-y    := $(LIB_OBJS)
endif
