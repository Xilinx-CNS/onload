# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2016-2019 Xilinx, Inc.

TEST_APPS	:= rtt
TARGETS		:= $(TEST_APPS:%=$(AppPattern))


all: $(TARGETS)

clean:
	@$(MakeClean)


MMAKE_LIBS	:= $(LINK_CIAPP_LIB) $(LINK_CITOOLS_LIB) $(LINK_CIUL_LIB)
MMAKE_LIB_DEPS	:= $(CIAPP_LIB_DEPEND) $(CITOOLS_LIB_DEPEND) $(CIUL_LIB_DEPEND)


rtt: rtt.o rtt_socket.o rtt_efvi.o
