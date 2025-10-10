# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2015-2019 Xilinx, Inc.
TARGETS		:= libpthread_intercept.so.1.0.0.1 \
				onload_fd_stat \
				onload_is_present \
				onload_move_fd \
				onload_recv_filter \
				onload_set_stackname \
				onload_stack_opt \
				onload_thread_set_spin \
				libpthread_test


MMAKE_CFLAGS	:= -g -I../../../include/ -fPIC
MMAKE_LIB	:= -g -shared
MMAKE_EXTLIBS	:= -L../../../../build/gnu_x86_64/lib/onload_ext/		\
				-L../../../../build/gnu_x86/lib/onload_ext/		\
				-lonload_ext -lpthread
CC		:= gcc

%.o: %.c
	@$(CC) $(MMAKE_CFLAGS) -c $^


libpthread_intercept.so.1.0.0.1: libpthread_intercept.o
	@$(CC) $(MMAKE_LIB) -Wl,-soname,v.so.1 -ldl -o $@ libpthread_intercept.o

libpthread_test:
	@$(CC) libpthread_test.c $(MMAKE_EXTLIBS) $(MMAKE_CFLAGS) -g -o $@

onload_fd_stat: onload_fd_stat.c
	@$(CC) $^ $(MMAKE_EXTLIBS) -o$@
onload_is_present: onload_is_present.c
	@$(CC) $^ $(MMAKE_EXTLIBS) -o$@
onload_move_fd: onload_move_fd.c
	@$(CC) $^ $(MMAKE_EXTLIBS) -o$@
onload_recv_filter: onload_recv_filter.c
	@$(CC) $^ $(MMAKE_EXTLIBS) -o$@
onload_set_stackname: onload_set_stackname.c
	@$(CC) $^ $(MMAKE_EXTLIBS) -o$@
onload_stack_opt: onload_stack_opt.c
	@$(CC) $^ $(MMAKE_EXTLIBS) -o$@
onload_thread_set_spin: onload_thread_set_spin.c
	@$(CC) $^ $(MMAKE_EXTLIBS) -o$@


test: $(TARGETS)
	@onload ./onload_is_present
	@LPI_INTERCEPT_CONFIG_FILE="./.onload_intercept"             \
	 LD_PRELOAD="./libpthread_intercept.so.1.0.0.1 libonload.so" \
	 ./libpthread_test

all: $(TARGETS)

targets:
	@echo $(TARGETS) test

clean:
	@rm *.o $(TARGETS)
