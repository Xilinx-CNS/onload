# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
APPS	:= sfcaffinity_tool

TARGETS	:= $(APPS:%=$(AppPattern))


MMAKE_LIBS	:= $(LINK_CIAPP_LIB) $(LINK_CITOOLS_LIB) $(LINK_CIUL_LIB)
MMAKE_LIB_DEPS	:= $(CIAPP_LIB_DEPEND) $(CITOOLS_LIB_DEPEND) $(CIUL_LIB_DEPEND)


all: $(TARGETS)

clean:
	@$(MakeClean)
