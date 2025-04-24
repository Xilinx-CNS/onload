# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2003-2019 Xilinx, Inc.

EFSEND_APPS := efsend efsend_timestamping efsend_warming efsend_cplane
TEST_APPS	:= efforward efrss efsink \
		   efsink_packed eflatency stats \
		   $(EFSEND_APPS)

TARGETS		:= $(TEST_APPS:%=$(AppPattern))


MMAKE_LIBS	:= $(LINK_CIUL_LIB) $(CPLANE_API_SHARED_LINK)
MMAKE_LIB_DEPS	:= $(CIUL_LIB_DEPEND) $(CPLANE_API_SHARED_DEPEND)


all: $(TARGETS)

clean:
	@$(MakeClean)


eflatency: eflatency.o utils.o

$(EFSEND_APPS): utils.o efsend_common.o

efsink: efsink.o utils.o

efsink_packed: efsink_packed.o utils.o

stats: stats.py
	cp $< $@
