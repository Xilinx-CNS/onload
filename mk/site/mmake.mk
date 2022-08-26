# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc.
TRANSPORT_CONFIG_OPT_HDR ?= ci/internal/transport_config_opt_extra.h
AUX_BUS_PATH ?= $(TOPPATH)/../cns-auxiliary-bus
HAVE_CNS_AUX := $(or $(and $(wildcard $(AUX_BUS_PATH)),1),0)
X3_NET_PATH ?= $(TOPPATH)/../x3-net-linux
HAVE_X3_NET := $(or $(and $(wildcard $(X3_NET_PATH)),1),0)
HAVE_SFC ?= 1
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
include $(TOPPATH)/mk/site/libs.mk
endif
include $(TOPPATH)/mk/middle.mk
