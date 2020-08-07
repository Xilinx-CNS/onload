# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc.

# These object files are built into both the control plane server and the unit
# tests.
SERVER_OBJS := server.o netlink.o llap.o route.o services.o teambond.o team.o \
	debug.o bond.o ip_prefix_list.o dump.o print.o mibdump.o \
	epoll.o agent.o

CLIENT_OBJS := client.o

MMAKE_CFLAGS += -fno-strict-aliasing

