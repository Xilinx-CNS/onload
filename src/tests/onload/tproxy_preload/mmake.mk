# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2015 Xilinx, Inc.

TARGETS := tproxy_preload.so

SRCS := tproxy_preload.c

CFLAGS += -fPIC

all: $(TARGETS)

clean:
	@$(MakeClean)


OBJS := $(patsubst %,%.o,$(SRCS))


%.c.o: %.c
	$(CC) $(mmake_c_compile) $(MMAKE_INCLUDE) -c $< -o $@


$(TARGETS): $(OBJS)
	$(CC) $(mmake_c_compile) -shared -g -Wl,-E $^ $(MMAKE_LIBS) $(BUILD)/lib/citools/libcitools1.a -ldl -o $@

targets:
	@echo $(TARGETS)
