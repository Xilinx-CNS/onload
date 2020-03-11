# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
# Only build if USEONLOADEXT is defined
ifneq ($(strip $(USEONLOADEXT)),)

TARGETS := wire_order_client wire_order_server

MMAKE_LIBS += $(LINK_ONLOAD_EXT_LIB)
MMAKE_LIB_DEPS += $(ONLOAD_EXT_LIB_DEPEND)
CFLAGS += -DONLOADEXT_AVAILABLE

all: $(TARGETS)

targets:
	@echo $(TARGETS)

clean:
	@$(MakeClean)

endif
