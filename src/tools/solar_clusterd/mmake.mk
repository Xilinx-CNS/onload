# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2013-2019 Xilinx, Inc.

CWARNINGS	:= -Wall -Wundef -Wstrict-prototypes -Wpointer-arith \
		   -Wnested-externs

PYTHON_VER	:= $(shell python3 -V 2>&1 | \
			sed 's/Python \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/')
PYTHON_VER_MAJOR:= $(shell python3 -V 2>&1 | \
			sed 's/Python \([0-9][0-9]*\)\.[0-9][0-9]*.*/\1/')
PYTHON_CFLAGS	+= $(shell python3-config --cflags 2>/dev/null)
PYTHON_LIBS	:= $(shell python3-config --libs 2>/dev/null)

ifeq ($(PYTHON_CFLAGS),)
PYTHON_CFLAGS	:= -fno-strict-aliasing -fPIC -I/usr/include/python$(PYTHON_VER)
PYTHON_LIBS	:= -lpython$(PYTHON_VER)
endif

# On SLES11, '$ python-config --cflags' doesn't include -fPIC but it
# is needed to properly compile PYTHON_SRCS.
PYTHON_CFLAGS   += -fPIC
ifeq ($(PYTHON_VER_MAJOR),2)
PYTHON_VERDEF	:= -DPYTHON2
endif

CFLAGS += $(PYTHON_CFLAGS) $(PYTHON_VERDEF)
CFLAGS += -Werror $(CWARNINGS) -g -O2 -DNDEBUG
LIBS   += $(PYTHON_LIBS)

SRCS := filter_string cluster_protocol

OBJS := $(patsubst %,%.o,$(SRCS))

%.o: %.c
	$(CC) $(CFLAGS) $(MMAKE_INCLUDE) -c $< -o $@

# 32 bits cluster_protocol.so cannot be built on on a 64 bits system
# as the system is missing the required 32 bits python libraries so we
# disallow building on 32 bits all together.
buildplatform=$(shell mmaketool --buildplatform)
BUILD_SC := 0
ifeq ($(buildplatform),gnu_x86_64)
BUILD_SC := 1
endif
ifeq ($(buildplatform),gnu_ppc64)
BUILD_SC := 1
endif
ifeq ($(buildplatform),gnu_ppc64le)
BUILD_SC := 1
endif

# Don't build cluster_protocol.so if python-devel is not present.  The
# way we detect this is by checking if Python.h is present.
ifeq (,$(wildcard /usr/include/python$(PYTHON_VER)*/Python.h))
BUILD_SC := 0
endif

ifeq ($(BUILD_SC),1)
all: cluster_protocol.so
else
all:
endif

cluster_protocol.so: $(OBJS) $(CIUL_LIB_DEPEND)
	$(CC) -shared -g -Wl,-E $^ $(MMAKE_LIBS) $(PYTHON_LIBS) \
	$(LINK_CIUL_LIB) -o $@

clean:
	@$(MakeClean)
	rm -f *.o *.so *.pyc
