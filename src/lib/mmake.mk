# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc.

SUBDIRS		:= citools ciapp

ifeq ($(LINUX),1)
DRIVER_SUBDIRS	:= citools ciul cplane transport
SUBDIRS		+= onload_ext
endif

ifeq ($(GNU),1)
# N.B.: The order matters here.
SUBDIRS		+= ciul kcompat
SUBDIRS		+= cplane transport
endif


all:
	+@(export MMAKE_NO_CSTYLE=1; $(MakeSubdirs))

clean:
	@$(MakeClean)

