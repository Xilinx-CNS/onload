# SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
lib_ver   := 1
lib_name  := sfgpxe
lib_where := lib/sfgpxe

SFGPXE_LIB		:= $(MMakeGenerateLibTarget)
SFGPXE_LIB_DEPEND	:= $(MMakeGenerateLibDepend)
LINK_SFGPXE_LIB		:= $(MMakeGenerateLibLink)

