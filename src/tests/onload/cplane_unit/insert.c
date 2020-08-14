/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2018 Xilinx, Inc. */

#include "cplane_unit.h"
#include <cplane/server.h>

void
cp_unit_insert_route(struct cp_session* s, in_addr_t dest, int dest_prefix,
                     in_addr_t pref_src, int ifindex)
{
  CP_TEST(dest != 0);
  CP_TEST(pref_src != 0);
  cp_unit_nl_handle_route_msg(s, dest, dest_prefix, 0, 0, pref_src, 0, ifindex,
			      0, 0);
}


void
cp_unit_insert_gateway(struct cp_session* s, in_addr_t gateway, in_addr_t dest,
                       int prefix, int ifindex)
{
  CP_TEST(gateway != 0);
  cp_unit_nl_handle_route_msg(s, dest, prefix, 0, 0, 0, gateway, ifindex, 0, 0);
}


void
cp_unit_insert_resolution(struct cp_session* s, in_addr_t dest, in_addr_t src,
                          in_addr_t pref_src, in_addr_t next_hop, int ifindex)
{
  CP_TEST((src == 0) != (pref_src == 0));
  cp_unit_nl_handle_route_msg(s, dest, 32, src, src ? 32 : 0, pref_src,
			      next_hop, ifindex, CP_UNIT_NL_PID,
			      CP_FWD_FLAG_REQ);
}


void
cp_unit_insert_neighbour(struct cp_session* s, int ifindex, in_addr_t dest,
                         const uint8_t *macaddr)
{
  CP_TEST((dest != 0) && (macaddr != 0));
  cp_unit_nl_handle_neigh_msg(s, ifindex, RTM_NEWNEIGH, NUD_REACHABLE,
                              dest, macaddr, 1, CP_UNIT_NL_PID, 0);
}


void
cp_unit_remove_neighbour(struct cp_session* s, int ifindex, in_addr_t dest,
                         const uint8_t *macaddr)
{
  CP_TEST((dest != 0) && (macaddr != 0));
  cp_unit_nl_handle_neigh_msg(s, ifindex, RTM_DELNEIGH, NUD_REACHABLE,
                              dest, macaddr, 1, CP_UNIT_NL_PID, 0);
}
