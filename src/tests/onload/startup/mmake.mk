# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2023 Xilinx, Inc.

LIB_TARGET := libdtor.so
LIB_SRCS := dtor_lib.cpp

TARGET := dtor_test
SRCS := dtor_test.cpp

all: $(TARGET)

$(TARGET): $(SRCS) $(LIB_TARGET)
	g++ -g $^ -o $@

$(LIB_TARGET): $(LIB_SRCS)
	g++ -shared -fPIC -g $^ -o $@

clean:
	@$(MakeClean)
