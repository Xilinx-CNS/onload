# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
lib_ver   := 1
lib_name  := efrm
lib_where := lib/efrm
EFRM_LIB		:= $(MMakeGenerateLibTarget)
EFRM_LIB_DEPEND		:= $(MMakeGenerateLibDepend)
LINK_EFRM_LIB		:= $(MMakeGenerateLibLink)
