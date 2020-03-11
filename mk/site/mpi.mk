# SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc

CC	:= mpicc
CFLAGS	:= -Wall -g $(INCLUDES)
CXX	:= mpiCC
CXXFLAGS:= $(CFLAGS)
LIBS    := $(addprefix -L,$(dir $(LIBS))) $(addprefix -l,$(notdir $(basename $(LIBS))))

%: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $^ $(LIBS) -o $@

