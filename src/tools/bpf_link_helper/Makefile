# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2022 Xilinx, Inc.

APP = bpf-link-helper

all: $(APP)

$(APP): $(APP).c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
