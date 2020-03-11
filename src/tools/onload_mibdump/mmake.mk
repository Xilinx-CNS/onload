# SPDX-License-Identifier: Solarflare-Binary
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
APPS := onload_mibdump

TARGETS	:= $(APPS:%=$(AppPattern))

MIBDUMP_OBJS := mibdump.o dump_tables.o

$(MIBDUMP_OBJS):  $(CP_INTF_VER_HDR)

onload_mibdump := $(patsubst %,$(AppPattern),onload_mibdump)

MMAKE_LIBS	:= $(LINK_CPLANE_LIB) $(LINK_CIAPP_LIB) $(LINK_CITOOLS_LIB) $(LINK_CIUL_LIB)
MMAKE_LIB_DEPS	:= $(CIAPP_LIB_DEPEND) $(CITOOLS_LIB_DEPEND) $(CIUL_LIB_DEPEND) $(CPLANE_LIB_DEPEND)

MMAKE_CFLAGS += $(CP_INTF_VER_CFLAGS)

# ffsll needs _GNU_SOURCE
MMAKE_CPPFLAGS += -D_GNU_SOURCE

$(onload_mibdump): $(MIBDUMP_OBJS) $(MMAKE_LIB_DEPS)
	(libs="$(MMAKE_LIBS)"; $(MMakeLinkCApp))

all: $(TARGETS)
clean:
	rm -f *.o $(TARGETS)
