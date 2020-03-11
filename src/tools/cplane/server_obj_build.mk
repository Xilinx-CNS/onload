# SPDX-License-Identifier: Solarflare-Binary
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc

# These object files are built into both the control plane server and the unit
# tests.
SERVER_OBJS := server.o netlink.o llap.o route.o services.o teambond.o team.o \
	debug.o bond.o ip_prefix_list.o dump.o print.o mibdump.o \
	epoll.o agent.o

CLIENT_OBJS := client.o

MMAKE_CFLAGS += -fno-strict-aliasing

