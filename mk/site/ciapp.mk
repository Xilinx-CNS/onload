# SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc

lib_ver   := 1
lib_name  := ciapp
lib_where := lib/ciapp
CIAPP_LIB		:= $(MMakeGenerateLibTarget)
CIAPP_LIB_DEPEND	:= $(MMakeGenerateLibDepend)
LINK_CIAPP_LIB		:= $(MMakeGenerateLibLink)

