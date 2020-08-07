# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2006-2020 Xilinx, Inc.
lib_ver   := 0
lib_name  := citpcommon
lib_where := lib/transport/common
CITPCOMMON_LIB		:= $(MMakeGenerateLibTarget)
CITPCOMMON_LIB_DEPEND	:= $(MMakeGenerateLibDepend)
LINK_CITPCOMMON_LIB	:= $(MMakeGenerateLibLink)
