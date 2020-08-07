# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2006-2020 Xilinx, Inc.

CC	:= mpicc
CFLAGS	:= -Wall -g $(INCLUDES)
CXX	:= mpiCC
CXXFLAGS:= $(CFLAGS)
LIBS    := $(addprefix -L,$(dir $(LIBS))) $(addprefix -l,$(notdir $(basename $(LIBS))))

%: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $^ $(LIBS) -o $@

