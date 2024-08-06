# SPDX-License-Identifier: GPL-2.0
# SPDX-FileCopyrightText: (c) Copyright 2002-2020 Advanced Micro Devices, Inc.

DRIVER_SUBDIRS	:= efct_test

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)

