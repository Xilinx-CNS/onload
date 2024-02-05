# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2003-2019 Xilinx, Inc.

EFSEND_APPS := efsend efsend_pio efsend_timestamping efsend_warming \
               efsend_cplane
TEST_APPS	:= efforward efrss efsink \
		   efsink_packed efforward_packed eflatency efexclusivity stats \
		   efjumborx $(EFSEND_APPS)

ifeq (${PLATFORM},gnu_x86_64)
	TEST_APPS += efrink_controller efrink_consumer
endif

TARGETS		:= $(TEST_APPS:%=$(AppPattern))


MMAKE_LIBS	:= $(LINK_CIUL_LIB) $(LINK_CIAPP_LIB) $(CPLANE_API_SHARED_LINK)
MMAKE_LIB_DEPS	:= $(CIUL_LIB_DEPEND) $(CIAPP_LIB_DEPEND) $(CPLANE_API_SHARED_DEPEND)


all: $(TARGETS)

clean:
	@$(MakeClean)


eflatency: eflatency.o utils.o

efexclusivity: efexclusivity.o utils.o

$(EFSEND_APPS): utils.o efsend_common.o

efsink: efsink.o utils.o

efjumborx: efjumborx.o utils.o

efsink_packed: efsink_packed.o utils.o

efforward_packed: efforward_packed.o utils.o

efpingpong: MMAKE_LIBS     := $(LINK_CITOOLS_LIB) $(MMAKE_LIBS)
efpingpong: MMAKE_LIB_DEPS := $(CITOOLS_LIB_DEPEND) $(MMAKE_LIB_DEPS)

$(EFSEND_APPS): MMAKE_LIBS := $(LINK_CITOOLS_LIB) $(MMAKE_LIBS)
$(EFSEND_APPS): MMAKE_LIB_DEPS := $(CITOOLS_LIB_DEPEND) $(MMAKE_LIB_DEPS)

eflatency: MMAKE_LIBS     := $(LINK_CITOOLS_LIB) $(MMAKE_LIBS)
eflatency: MMAKE_LIB_DEPS := $(CITOOLS_LIB_DEPEND) $(MMAKE_LIB_DEPS)


efexclusivity: MMAKE_LIBS     := $(LINK_CITOOLS_LIB) $(MMAKE_LIBS)
efexclusivity: MMAKE_LIB_DEPS := $(CITOOLS_LIB_DEPEND) $(MMAKE_LIB_DEPS)

efrink_controller: efrink_controller.o utils.o

stats: stats.py
	cp $< $@
