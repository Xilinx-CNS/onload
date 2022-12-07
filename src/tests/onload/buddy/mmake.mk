# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2004-2020 Xilinx, Inc.
APPS := pio_buddy_test
TARGETS := $(APPS:%=$(AppPattern))

pio_buddy_test := $(patsubst %,$(AppPattern),pio_buddy_test)

ifeq ($(shell CC="${CC}" CFLAGS="${CFLAGS} ${MMAKE_CFLAGS}" check_library_presence pcap.h pcap 2>/dev/null),1)
MMAKE_LIBS_LIBPCAP=-lpcap
endif

MMAKE_LIBS := $(LINK_CIIP_LIB) $(LINK_CIAPP_LIB) \
              $(LINK_CITOOLS_LIB) $(LINK_CIUL_LIB) \
              $(LINK_CPLANE_LIB) $(MMAKE_LIBS_LIBPCAP)

MMAKE_LIB_DEPS := $(CIIP_LIB_DEPEND) $(CIAPP_LIB_DEPEND) \
                  $(CITOOLS_LIB_DEPEND) $(CIUL_LIB_DEPEND) \
                  $(CPLANE_LIB_DEPEND)

all: $(TARGETS)

MMAKE_CFLAGS += -I$(TOPPATH)/src/tools/ip/

$(pio_buddy_test): pio_buddy_test.o $(BUILDPATH)/tools/ip/libstack.o $(MMAKE_LIB_DEPS)
	(libs="$(MMAKE_LIBS)"; $(MMakeLinkCApp) )

clean:
	@$(MakeClean)
