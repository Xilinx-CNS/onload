# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2019 Xilinx, Inc.

ifeq ($(call GetTransportConfigOpt,CI_CFG_UL_INTERRUPT_HELPER),1)

APPS := onload_helper

TARGETS	:= $(APPS:%=$(AppPattern))

onload_helper := $(patsubst %,$(AppPattern),onload_helper)

MMAKE_LIBS	:= $(LINK_CIIP_LIB) $(LINK_CIAPP_LIB) \
		   $(LINK_CITOOLS_LIB) $(LINK_CIUL_LIB) \
		   $(LINK_CPLANE_LIB)
MMAKE_LIB_DEPS	:= $(CIIP_LIB_DEPEND) $(CIAPP_LIB_DEPEND) \
		   $(CITOOLS_LIB_DEPEND) $(CIUL_LIB_DEPEND) \
		   $(CPLANE_LIB_DEPEND)

$(onload_helper): main.o $(MMAKE_LIB_DEPS)
	(libs="$(MMAKE_LIBS) $(MMAKE_STACKDUMP_LIBS)"; $(MMakeLinkCApp))


TARGETS	:= $(APPS:%=$(AppPattern))
all: $(TARGETS)

endif
