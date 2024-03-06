/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2019 Xilinx, Inc. */

#include <stdlib.h>
#include <string.h>


#include "../../../tools/cplane/private.h"
#include <ci/tools.h>

#include <cplane/cplane.h>


#define CP_TRY(x)                                                         \
  do {                                                                    \
    int __rc = (x);                                                       \
    if( __rc < 0 ) {                                                      \
      ci_log("ERROR: %s: CP_TRY(%s) failed", __func__, #x);               \
      ci_log("ERROR: at %s:%d", __FILE__, __LINE__);                      \
      ci_log("ERROR: rc=%d errno=%d (%s)", __rc, errno, strerror(errno)); \
      abort();                                                            \
    };                                                                    \
  } while( 0 )


#define CP_TEST(x)                                                    \
  do {                                                                \
    if( ! (x) ) {                                                     \
      ci_log("ERROR: %s: CP_TEST(%s) failed", __func__, #x);          \
      ci_log("ERROR: at %s:%d", __FILE__, __LINE__);                  \
      abort();                                                        \
    };                                                                \
  } while( 0 )


#define CP_UNIT_NL_PID 22222


static inline uint32_t rand32(void)
{
  uint32_t r1 = rand();
  r1 = r1 << 1;
  r1 ^= rand();
  return r1;
}

static inline void cp_unit_init(void)
{
  /* Prevent logging from the control plane from interfering with the TAP
   * stream. */
  ci_set_log_prefix("# ");

  /* Re-assignments */
  ci_sys_ioctl = (void*) cplane_ioctl;
}

/* General functions. */

extern void cp_unit_init_session(struct cp_session*);
extern void cp_unit_destroy_session(struct cp_session*);
extern void
cp_unit_init_cp_handle(struct oo_cplane_handle*, struct cp_session*);
extern void
cp_unit_set_main_cp_handle(struct cp_session*, struct cp_session* s_main);
extern void cp_unit_dump_cplane_tables(struct cp_session*);
extern void __cp_team_print(struct cp_session* s, cicp_bond_row_t* bond_table);

/* Time handling functions. */

extern void cp_time_elapse(ci_uint64 ticks);
extern void cp_timer_expire(struct cp_timer* which, int type);

/* Netlink functions. */

extern void
cp_unit_nl_handle_link_msg(struct cp_session* s, uint16_t nlmsg_type,
			   int ifindex, const char* name, const char* mac);

extern void
cp_unit_nl_handle_macvlan_link_msg(struct cp_session* s, uint16_t nlmsg_type,
		                   int ifindex, const char* name,
				   const char* mac, int link_ifindex);

extern void
cp_unit_nl_handle_veth_link_msg(struct cp_session* s, uint16_t nlmsg_type,
                                int ifindex, int peer_ifindex, const char* name,
                                const char* mac);

extern void
cp_unit_nl_handle_team_link_msg(struct cp_session* s, uint16_t nlmsg_type,
		                int ifindex, const char* name, const char* mac);

extern void
cp_unit_nl_handle_teamslave_link_msg(struct cp_session* s, uint16_t nlmsg_type,
		                     int ifindex, const char* name,
				     const char* mac);

extern void
cp_unit_nl_handle_route_msg(struct cp_session*, in_addr_t dest,
			    int dest_prefix, in_addr_t src,
			    in_addr_t src_prefix, in_addr_t pref_src,
			    in_addr_t gateway, int ifindex, int iif_ifindex,
			    uint32_t nlmsg_pid, uint32_t nlmsg_seq);

extern void
cp_unit_nl_handle_neigh_msg(struct cp_session* s, int ifindex, int type,
                            int state, in_addr_t dest, const uint8_t* macaddr,
                            int reachable_ms, uint32_t nlmsg_pid,
                            uint32_t nlmsg_seq);

extern void
cp_unit_nl_handle_addr_msg(struct cp_session* s, in_addr_t laddr, int ifindex,
                           int prefixlen, int scope);

/* Functions for inserting simulated netlink replies. */
extern void
cp_unit_insert_route(struct cp_session* s, in_addr_t dest, int dest_prefix,
                     in_addr_t pref_src, int ifindex);

extern void
cp_unit_insert_gateway(struct cp_session* s, in_addr_t gateway, in_addr_t dest,
                       int prefix, int ifindex);

extern void
cp_unit_insert_resolution(struct cp_session* s, in_addr_t dest, in_addr_t src,
                          in_addr_t pref_src, in_addr_t next_hop, int ifindex);

extern void
cp_unit_insert_resolution_xns(struct cp_session* s, in_addr_t dest,
                              in_addr_t src, in_addr_t pref_src,
                              in_addr_t next_hop, int ifindex, int iif_ifindex);

extern void
cp_unit_insert_neighbour(struct cp_session* s, int ifindex, in_addr_t dest,
                         const uint8_t *macaddr);

extern void
cp_unit_remove_neighbour(struct cp_session* s, int ifindex, in_addr_t dest,
                         const uint8_t *macaddr);
