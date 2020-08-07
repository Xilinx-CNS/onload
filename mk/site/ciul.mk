# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc.
# The libciul static library.
lib_ver   := 1
ifeq ($(DRIVER),1)
lib_name  := ciul-drv
else
lib_name  := ciul
endif
lib_where := lib/ciul
CIUL_LIB		:= $(MMakeGenerateLibTarget)
CIUL_LIB_DEPEND		:= $(MMakeGenerateLibDepend)
LINK_CIUL_LIB		:= $(MMakeGenerateLibLink)

# The libciul dynamic library.
#
# As things stand, it is very difficult to make libciul compatible between
# releases, because the internals of the data structures are exposed.  That
# means that almost any non-trivial change to ef_vi should cause the MAJOR
# version number to be incremented.
lib_maj := 1
lib_min := 1
lib_mic := 1
CIUL_REALNAME		:= $(MMakeGenerateDllRealname)
CIUL_SONAME		:= $(MMakeGenerateDllSoname)
CIUL_LINKNAME		:= $(MMakeGenerateDllLinkname)
LINK_CIUL_DLIB		:= $(MMakeGenerateDllLink)

lib_name  := efvi
lib_where := lib/efvi
EFVI_LIB		:= $(MMakeGenerateLibTarget)
EFVI_LIB_DEPEND		:= $(MMakeGenerateLibDepend)
LINK_EFVI_LIB		:= $(MMakeGenerateLibLink)
