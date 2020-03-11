# SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
lib_ver   := 1
lib_name  := ciiscsi
lib_where := lib/iscsi
CIISCSI_LIB		:= $(MMakeGenerateLibTarget)
CIISCSI_LIB_DEPEND	:= $(MMakeGenerateLibDepend)
LINK_CIISCSI_LIB	:= $(MMakeGenerateLibLink)

