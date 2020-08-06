# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc

# GetTransportConfigOpt is a function to return the value of a variable in
# the transport_config_opt_extra.h (or substitute as defined by the
# TRANSPORT_CONFIG_OPT environment variable).
# Call it as (for example):
#    ifeq ($(call GetTransportConfigOpt,CI_CFG_BPF),1)
#      ...do stuff...
#    endif

# The implementation is rigged to call gcc iff the function is called (to
# avoid the cost of spawning gcc for the majority of make invocations which
# don't use it).

# Note that this function doesn't work at mmakebuildtree time, so can't be
# used to exclude entire subdirectories from building (but can be used to
# exclude anything from being done in that subdirectory)

# after this, _CFG_OPTS_CACHE will contain (e.g.)
#  "CI_CFG_L3XUDP=0 CI_CFG_TCP_TOA=0 CI_CFG_DECLUSTER=0 ..."
define _InitTransportConfigOpt
ifndef _CFG_OPTS_CACHE
_CFG_OPTS_CACHE := $(shell $(CC) -dM -E $(CFLAGS) \
                           -I$(TOPPATH)/src/include -I$(BUILD)/include \
                           $(TOPPATH)/src/include/$(TRANSPORT_CONFIG_OPT_HDR) \
                           | awk '/#define CI_CFG_/ {print $$2 "=" $$3}')
endif
endef

GetTransportConfigOpt = $(eval $(_InitTransportConfigOpt))$(patsubst $(strip $(1))=%,%,$(filter $(1)=%,$(_CFG_OPTS_CACHE)))
