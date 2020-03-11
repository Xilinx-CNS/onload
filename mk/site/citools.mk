# SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc

lib_ver   := 1

ifeq ($(DRIVER),1)
lib_name  := citools-drv
else
lib_name  := citools
endif

lib_where := lib/citools
CITOOLS_LIB		:= $(MMakeGenerateLibTarget)
CITOOLS_LIB_DEPEND	:= $(MMakeGenerateLibDepend)
LINK_CITOOLS_LIB	:= $(MMakeGenerateLibLink)
