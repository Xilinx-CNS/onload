# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc.

DRIVER_SUBDIRS := linux

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)
