# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
TARGETS	:= rx_timestamping tx_timestamping cpacket_send

ifneq ($(strip $(USEONLOADEXT)),)
CFLAGS += -DONLOADEXT_AVAILABLE
MMAKE_LIBS += $(LINK_ONLOAD_EXT_LIB)
MMAKE_LIB_DEPS += $(ONLOAD_EXT_LIB_DEPEND)
endif

# Use the kernel timestamping headers for definition, unless they don't exist
# in which case we will fall back to our own definitions.
# We need both these two files to exist:
ts_missing =
  ifeq (,$(wildcard /usr/include/linux/net_tstamp.h))
    ts_missing = yes
  endif
  ifeq (,$(wildcard /usr/include/linux/sockios.h))
    ts_missing = yes
  endif
ifdef ts_missing
  CFLAGS += -DNO_KERNEL_TS_INCLUDE
endif

all: $(TARGETS)

targets:
	@echo $(TARGETS)

clean:
	@$(MakeClean)
