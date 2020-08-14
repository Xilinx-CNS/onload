# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2015-2017 Xilinx, Inc.

TARGETS := sync_preload.so

SRCS := sync_preload.c

CFLAGS += -fPIC

all: $(TARGETS)

clean:
	@$(MakeClean)


OBJS := $(patsubst %,%.o,$(SRCS))


%.c.o: %.c
	$(CC) $(mmake_c_compile) $(MMAKE_INCLUDE) -c $< -o $@


$(TARGETS): $(OBJS)
	$(CC) $(mmake_c_compile) -shared -g -Wl,-E $^ $(MMAKE_LIBS) $(BUILD)/lib/citools/libcitools1.a -ldl -lrt -o $@

targets:
	@echo $(TARGETS)
