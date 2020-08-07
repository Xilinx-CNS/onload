# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2018-2020 Xilinx, Inc.

TEST_APPS	:= exchange \
		trader_onload_ds_efvi

TARGETS		:= $(TEST_APPS:%=$(AppPattern))


all: $(TARGETS)

clean:
	@$(MakeClean)


exchange: exchange.o utils.o
exchange: MMAKE_LIBS     += $(LINK_ONLOAD_EXT_LIB)
exchange: MMAKE_LIB_DEPS += $(ONLOAD_EXT_LIB_DEPEND)

trader_onload_ds_efvi: trader_onload_ds_efvi.o utils.o
trader_onload_ds_efvi: \
	MMAKE_LIBS     += $(LINK_ONLOAD_EXT_LIB) $(LINK_CIUL_LIB)
trader_onload_ds_efvi: \
	MMAKE_LIB_DEPS += $(ONLOAD_EXT_LIB_DEPEND) $(CIUL_LIB_DEPEND)
