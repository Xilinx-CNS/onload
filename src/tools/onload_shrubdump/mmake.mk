# SPDX-License-Identifier: BSD-2-Clause
/* SPDX-FileCopyrightText: (c) Copyright 2025 Advanced Micro Devices, Inc. */

APPS := onload_shrubdump

TARGETS	:= $(APPS:%=$(AppPattern))

SHRUBDUMP_OBJS := shrubdump.o

$(SHRUBDUMP_OBJS):  $(CP_INTF_VER_HDR)

onload_shrubdump := $(patsubst %,$(AppPattern),onload_shrubdump)

MMAKE_LIBS	:= $(LINK_CPLANE_LIB) $(LINK_CIAPP_LIB) $(LINK_CITOOLS_LIB)
MMAKE_LIB_DEPS	:= $(CIAPP_LIB_DEPEND) $(CITOOLS_LIB_DEPEND) $(CPLANE_LIB_DEPEND)

MMAKE_CFLAGS += $(CP_INTF_VER_CFLAGS)

# ffsll needs _GNU_SOURCE
MMAKE_CPPFLAGS += -D_GNU_SOURCE

$(onload_shrubdump): $(SHRUBDUMP_OBJS) $(MMAKE_LIB_DEPS)
	(libs="$(MMAKE_LIBS)"; $(MMakeLinkCApp))

all: $(TARGETS)
clean:
	rm -f *.o $(TARGETS)
