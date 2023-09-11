# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc.
lib_ver   := 0
lib_name  := cplane
lib_where := lib/cplane
CPLANE_LIB	:= $(MMakeGenerateLibTarget)
CPLANE_LIB_DEPEND	:= $(MMakeGenerateLibDepend)
LINK_CPLANE_LIB	:= $(MMakeGenerateLibLink)

# This is the set of cplane header files that define the cplane interface.
# The cp server, client and kernel must all agree on the interface version,
# which is defined as the md5sum hash of the contents of these files.
_CP_INTF_HDRS :=   \
    cplane.h       \
    create.h       \
    ioctl.h        \
    mib.h          \
    mibdump_sock.h \
    mmap.h         \
    server.h       \

CP_INTF_HDRS := $(_CP_INTF_HDRS:%=$(SRCPATH)/include/cplane/%)

CP_INTF_VER_HDR := $(BUILDPATH)/cp_intf_ver.h
CP_INTF_VER_CFLAGS := -include $(CP_INTF_VER_HDR)

$(CP_INTF_VER_HDR): $(CP_INTF_HDRS)
	@md5=$$(cat $(CP_INTF_HDRS) | md5sum | sed 's/ .*//'); \
	echo "#define OO_CP_INTF_VER $$md5" >"$@"

lib_maj   := 1
lib_min   := 0
lib_mic   := 0
lib_name  := efcp
lib_where := lib/cplane
CPLANE_API_SHARED_REALNAME	:= $(MMakeGenerateDllRealname)
CPLANE_API_SHARED_SONAME	:= $(MMakeGenerateDllSoname)
CPLANE_API_SHARED_LINKNAME	:= $(MMakeGenerateDllLinkname)
CPLANE_API_SHARED_LINK		:= $(MMakeGenerateDllLink)
CPLANE_API_SHARED_DEPEND	:= $(MMakeGenerateDllDepend)
