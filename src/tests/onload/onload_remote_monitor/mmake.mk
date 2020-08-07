# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2002-2019 Xilinx, Inc.
SUBDIRS	:= internal_tests

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)

