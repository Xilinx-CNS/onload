# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc.
SUBDIRS	:= wire_order tproxy_preload hwtimestamping \
           sync_preload l3xudp_preload

ifneq ($(ONLOAD_ONLY),1)
# These tests have dependency on kernel_compat lib,
# tests/tap, libmnl that are !ONLOAD_ONLY
SUBDIRS += oof onload_remote_monitor
ifneq ($(NO_TEAMING),1)
ifneq ($(NO_NETLINK),1)
SUBDIRS += cplane_unit cplane_sysunit
endif # NO_NETLINK
endif # NO_TEAMING
ifeq ($(GNU),1)
SUBDIRS += buddy
endif # GNU
endif # ONLOAD_ONLY


all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)

