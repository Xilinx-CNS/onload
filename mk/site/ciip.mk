# SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
lib_ver   := 0
lib_name  := ciip
lib_where := lib/transport/ip
CIIP_LIB	:= $(MMakeGenerateLibTarget)
CIIP_LIB_DEPEND	:= $(MMakeGenerateLibDepend)
LINK_CIIP_LIB	:= $(MMakeGenerateLibLink)

