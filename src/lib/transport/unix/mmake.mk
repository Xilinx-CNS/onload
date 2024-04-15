# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc.
ifeq ($(ISA),amd64)
BUILD_TREE_COPY	:= mapfile.lp64
endif

ifeq ($(ISA),i386)
BUILD_TREE_COPY	:= mapfile.ilp32
endif

TARGET		:= libcitransport0.so
MMAKE_TYPE	:= DLL

LDEP	:= $(CITPCOMMON_LIB_DEPEND) $(CIIP_LIB_DEPEND) $(CPLANE_LIB_DEPEND) \
	$(CITOOLS_LIB_DEPEND) $(CIUL_LIB_DEPEND)

LLNK	:= $(LINK_CITPCOMMON_LIB) $(LINK_CIIP_LIB) $(LINK_CPLANE_LIB) \
	$(LINK_CITOOLS_LIB) $(LINK_CIUL_LIB)

LIB_SRCS	:=			\
		startup.c		\
		log_fn.c		\
		sys.c			\
		sockcall_intercept.c	\
		onload_ext_intercept.c	\
		zc_intercept.c          \
		tmpl_intercept.c	\
		stackname.c		\
		stackopt.c		\
		fdtable.c		\
		protocol_manager.c	\
		closed_fd.c		\
		tcp_fd.c		\
		udp_fd.c		\
		pipe_fd.c		\
		nonsock.c		\
		epoll_fd.c		\
		epoll_fd_b.c		\
		netif_init.c		\
		exec.c			\
		environ.c		\
		common_fcntl.c		\
		wqlock.c		\
		poll_select.c		\
		passthrough_fd.c	\
		utils.c

MMAKE_OBJ_PREFIX := ci_tp_unix_
LIB_OBJS	:= $(LIB_SRCS:%.c=$(MMAKE_OBJ_PREFIX)%.o)
LIB_OBJS	+= $(MMAKE_OBJ_PREFIX)vfork_intercept.o

MMAKE_CFLAGS 	+= -DONLOAD_EXT_VERSION_MAJOR=$(ONLOAD_EXT_VERSION_MAJOR)
MMAKE_CFLAGS 	+= -DONLOAD_EXT_VERSION_MINOR=$(ONLOAD_EXT_VERSION_MINOR)
MMAKE_CFLAGS 	+= -DONLOAD_EXT_VERSION_MICRO=$(ONLOAD_EXT_VERSION_MICRO)


# Overwrite standard rule for startup.c: add -fno-stack-protector
# to execute the library as a binary
cflags_for_startup := -fno-stack-protector
$(MMAKE_OBJ_PREFIX)startup.o: $(TOPPATH)/src/lib/transport/unix/startup.c
	(cflags="$(cflags_for_startup)"; $(MMakeCompileC))

all: $(TARGET)

lib: $(TARGET)

clean:
	@$(MakeClean)

# This tells the linker which symbols to include in the dynamic symbol
# table.  It is useful to omit this to see whether the "hidden" attribute
# is being used appropriately.  Just do "make EXPMAP="
EXPMAP := -Wl,--version-script=$(TOPPATH)/src/lib/transport/unix/exports.map

$(TARGET): $(LIB_OBJS) $(LDEP) exports.map
	(libs="$(LLNK) -e onload_version_msg $(EXPMAP)"; \
	$(MMakeLinkPreloadLib))
