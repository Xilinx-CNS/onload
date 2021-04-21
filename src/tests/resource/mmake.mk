# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 002-2020 Xilinx, Inc.

DRIVER_SUBDIRS	:= efct_test

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)

