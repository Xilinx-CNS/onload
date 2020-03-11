/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __ONLOAD_OOF_SOCKET_H__
#define __ONLOAD_OOF_SOCKET_H__

#include <ci/net/ipvx.h>

struct oof_local_port;


/* Per-socket state for the filtering module.
 *
 * All fields are protected by [oof_manager::lock].
 */
struct oof_socket {

  /* If NULL then no packets are filtered to this socket. */
  struct oof_local_port* sf_local_port;

  /* List of [struct oof_mcast_member]s. */
  ci_dllist sf_mcast_memberships;

/* sf_flags field can be nonzero only when sf_local_port != NULL
 * and when socket is fully deleted all flags are cleared. */
#define OOF_SOCKET_MCAST_FULL_SW_FILTER   0x00000001
#define OOF_SOCKET_SW_FILTER_WAS_REMOVED  0x00000002
#define OOF_SOCKET_CLUSTERED              0x00000004
/* socket is inserted but not armed */
#define OOF_SOCKET_DUMMY                  0x00000008
/* a dummy socket that has no stack (no endpoint association) */
#define OOF_SOCKET_NO_STACK               0x00000010
/* full socket will not share filter of a semi-wild one */
#define OOF_SOCKET_NO_SHARING             0x00000020
/* No unicast filters sw or hw should be installed.
 * Note: this means these sockets should be ignored in all
 * filter related searches.  Exception being an installation of
 * NO_STACK DUMMY socket in search of presence of an existing cluster */
#define OOF_SOCKET_NO_UCAST               0x00000040
  unsigned  sf_flags;

  /* All other fields are only valid when [sf_local_port] is not NULL */
  struct oo_hw_filter sf_full_match_filter;

  int af_space;

  ci_addr_t sf_laddr;
  ci_addr_t sf_raddr;

  int       sf_rport;
  /* See [sf_local_port] for local port and protocol. */

  /* If this is a socket accepted on a NAT-ed address, and the local port
   * before NAT is different from the port after NAT, then this is the former.
   * In all other cases, the field is equal to zero. */
  int       sf_lport_prenat;

  /* Index of the relevant oof_local_port_addr structure within sf_local_port.
   * Negative for wild sockets.  For semi-wild and full-match sockets, this is
   * typically equal to oof_manager_addr_find(..., sf_laddr), but this doesn't
   * hold true when the socket's local address is subject to NAT.
   *   Note that this index is stable for a given address as long as there at
   * least one oof_socket referencing that address, so storing the index here
   * is valid. */
  int       sf_la_i;

  /* Link for one of:
   * - [oof_local_port::lp_wild_socks]
   * - [oof_local_port_addr::lpa_semi_wild_socks]
   * - [oof_local_port_addr::lpa_full_socks]
   * - [oof_manager::fm_mcast_laddr_socks]
   */
  ci_dllink sf_lp_link;

};

#endif  /* __ONLOAD_OOF_SOCKET_H__ */
