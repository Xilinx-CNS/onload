# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2002-2019 Xilinx, Inc.
SUBDIRS	:= ip common unix
DRIVER_SUBDIRS := ip


all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)

