# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc.

# Major: Increment when making a change that is not backwards compatible.
ONLOAD_EXT_VERSION_MAJOR := 2

# Minor: Increment when extending existing interfaces such that if caller
# uses the new feature they must have a contemporary version of Onload for
# it to work.  Do *not* increment when adding a new symbol, since linker
# will detect that.  Reset to zero when major is bumped.
ONLOAD_EXT_VERSION_MINOR := 0

# Micro: Incremented for any change.  Reset to zero when minor is bumped.
ONLOAD_EXT_VERSION_MICRO := 0

lib_name  := onload_ext
lib_where := lib/onload_ext
lib_maj		:= $(ONLOAD_EXT_VERSION_MAJOR)
lib_min		:= $(ONLOAD_EXT_VERSION_MINOR)
lib_mic		:= $(ONLOAD_EXT_VERSION_MICRO)
ONLOAD_EXT_REALNAME	:= $(MMakeGenerateDllRealname)
ONLOAD_EXT_SONAME	:= $(MMakeGenerateDllSoname)
ONLOAD_EXT_LINKNAME	:= $(MMakeGenerateDllLinkname)
# By default use the static library - as onload_install doesn't install .so
lib_ver	:=
ONLOAD_EXT_LIB_DEPEND	:= $(MMakeGenerateLibDepend)
LINK_ONLOAD_EXT_LIB	:= $(MMakeGenerateLibLink) -ldl # for dlsym

lib_ver   := 0
lib_name  := spektor
lib_where := lib/spektor
SPEKTOR_LIB		:= $(MMakeGenerateLibTarget)
SPEKTOR_LIB_DEPEND	:= $(MMakeGenerateLibDepend)
LINK_SPEKTOR_LIB	:= $(MMakeGenerateLibLink)

# Minimal emulations of kernel functions, for testing purposes
lib_ver   := 0
lib_name  := kcompat
lib_where := lib/kcompat
KCOMPAT_LIB		:= $(MMakeGenerateLibTarget)
KCOMPAT_LIB_DEPEND	:= $(MMakeGenerateLibDepend)
LINK_KCOMPAT_LIB	:= $(MMakeGenerateLibLink)
