# SPDX-License-Identifier: BSD-2-Clause
# SPDX-FileCopyrightText: (c) Copyright 2015-2024 Advanced Micro Devices, Inc.
TARGETS	:= rx_timestamping tx_timestamping cpacket_send

ifneq ($(strip $(USEONLOADEXT)),)
CFLAGS += -DONLOADEXT_AVAILABLE
MMAKE_LIBS += $(LINK_ONLOAD_EXT_LIB)
MMAKE_LIB_DEPS += $(ONLOAD_EXT_LIB_DEPEND)
endif

all: $(TARGETS)

targets:
	@echo $(TARGETS)

clean:
	@$(MakeClean)
