# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc.
TRANSPORT_CONFIG_OPT_HDR ?= ci/internal/transport_config_opt_extra.h
AUX_BUS_PATH ?= $(TOPPATH)/../cns-auxiliary-bus
include $(BUILD)/config.mk
include $(BUILDPATH)/options_config.mk
include $(TOPPATH)/mk/before.mk
include $(TOPPATH)/mk/platform/$(PLATFORM).mk
ifneq ($(MMAKEBUILDTREE),1)
include $(TOPPATH)/mk/site/funcs.mk
include $(TOPPATH)/mk/site/citools.mk
include $(TOPPATH)/mk/site/ciapp.mk
include $(TOPPATH)/mk/site/ciul.mk
include $(TOPPATH)/mk/site/ciip.mk
include $(TOPPATH)/mk/site/cplane.mk
include $(TOPPATH)/mk/site/citpcommon.mk
include $(TOPPATH)/mk/site/efrm.mk
include $(TOPPATH)/mk/site/efthrm.mk
include $(TOPPATH)/mk/site/libs.mk
include $(TOPPATH)/mk/site/sfgpxe.mk
include $(TOPPATH)/mk/site/efhw.mk
endif
include $(TOPPATH)/mk/middle.mk
