# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc.
############################
# 
# EtherFabric linux kernel drivers 
#
#	onload_ip
#
############################


ONLOAD_SRCS	:= driver.c timesync.c \
		tcp_sendpage.c driverlink_ip.c linux_stats.c \
		shmbuf.c oo_shmbuf.c compat.c \
		ossock_calls.c mmap.c \
		epoll_device.c onloadfs.c \
		dshm.c cplane.c cplane_prot.c

# This is a kernel makefile, so gets re-called by kbuild with 'src' set
src ?= .

EFTHRM_SRCS	:= eplock_resource_manager.c \
		tcp_helper_endpoint.c tcp_helper_resource.c \
		tcp_helper_ioctl.c tcp_helper_sleep.c \
		tcp_helper_endpoint_move.c \
		tcp_filters.c oof_filters.c oof_onload.c oof_nat.c \
		driverlink_filter.c ip_protocols.c \
		onload_nic.c id_pool.c dump_to_user.c iobufset.c \
		tcp_helper_cluster.c oof_interface.c tcp_helper_stats_dump.c

EFTHRM_HDRS	:= oo_hw_filter.h oof_impl.h tcp_filters_internal.h \
		tcp_helper_resource.h tcp_filters_deps.h oof_tproxy_ipproto.h \
		oof_onload_types.h tcp_helper_stats_dump.h

ifeq ($(LINUX),1)
EFTHRM_SRCS	+= tcp_helper_linux.c
endif

# Build host
CPPFLAGS += -DCI_BUILD_HOST=$(HOSTNAME)

IMPORT		:= $(EFTHRM_SRCS:%=../../lib/efthrm/%) \
		$(EFTHRM_HDRS:%=../../lib/efthrm/%)

IP_TARGET      := onload.o
IP_TARGET_SRCS := $(ONLOAD_SRCS) $(EFTHRM_SRCS)

TARGETS		:= $(IP_TARGET)

x86_TARGET_SRCS    := x86_linux_trampoline.o

arm64_TARGET_SRCS := aarch64_linux_trampoline.o


######################################################
# linux kbuild support
#

KBUILD_EXTRA_SYMBOLS := $(BUILDPATH)/driver/linux_char/Module.symvers
ifeq ($(shell grep -s efrm_syscall_table $(KBUILD_EXTRA_SYMBOLS)),)
# Linux-5.8 does not include resource symbols into char's symvers file.
KBUILD_EXTRA_SYMBOLS += $(BUILDPATH)/driver/linux_resource/Module.symvers
endif

all: $(KBUILD_EXTRA_SYMBOLS)
	$(MAKE) $(MMAKE_KBUILD_ARGS) M=$(CURDIR) \
		DO_EFAB_IP=1
	cp -f onload.ko $(BUILDPATH)/driver/linux


clean:
	@$(MakeClean)
	rm -rf *.ko Module.symvers .*.cmd


ifdef MMAKE_IN_KBUILD

obj-m := $(IP_TARGET)

ifeq ($(ARCH),powerpc)
# RHEL5/PPC requires you to pass this, because by default its userspace
# is 32-bit, but its kernel was built with a 64-bit compiler!
EXTRA_CFLAGS+= -m64
endif

ifeq ($(ARCH),arm64)
# HACK: to circumvent build error on newever gcc/kernels on ARM (?)
EXTRA_CFLAGS+= -Wno-error=discarded-qualifiers
endif

onload-objs  := $(IP_TARGET_SRCS:%.c=%.o) $($(ARCH)_TARGET_SRCS:%.c=%.o)
onload-objs  += $(BUILD)/lib/transport/ip/ci_ip_lib.o	\
		$(BUILD)/lib/cplane/cplane_lib.o \
		$(BUILD)/lib/citools/citools_lib.o	\
		$(BUILD)/lib/ciul/ci_ul_lib.o

endif # MMAKE_IN_KBUILD
