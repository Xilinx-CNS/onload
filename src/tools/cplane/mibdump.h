/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __TOOLS_CPLANE_MIBDUMP_H__
#define __TOOLS_CPLANE_MIBDUMP_H__

/* Bits for AF_UNIX message when asking to print the sp_server internal
 * state:
 * (1 << CP_SERVER_PRINT_STATE_FOO) | (1 << CP_SERVER_PRINT_STATE_BAR) | ...
 * 0 is considered to be equal to all-ones except STAT_DOC.
 */
#define CP_SERVER_PRINT_STATE_BASE  0
#define CP_SERVER_PRINT_STATE_DST   1
#define CP_SERVER_PRINT_STATE_SRC   2
#define CP_SERVER_PRINT_STATE_LLAP  3
#define CP_SERVER_PRINT_STATE_TEAM  4
#define CP_SERVER_PRINT_STATE_MAC   5
#define CP_SERVER_PRINT_STATE_FWD   6
#define CP_SERVER_PRINT_STATE_STAT  7
#define CP_SERVER_PRINT_STATE_MAC6  8
#define CP_SERVER_PRINT_STATE_DST6  9
#define CP_SERVER_PRINT_STATE_SRC6  10
#define CP_SERVER_PRINT_STATE_ROUTE 11
#define CP_SERVER_PRINT_STATE_ROUTE6 12
#define CP_SERVER_PRINT_STATE_LADDR  13
#define CP_SERVER_PRINT_STATE_STAT_DOC 14 /* This one MUST be the last */

static inline const char*
cp_ifindex2name(struct cp_mibs* mib, ci_ifid_t ifindex)
{
  if( ifindex > 0 )
    return mib->llap[cp_llap_find_row(mib, ifindex)].name;
  else
    return "";
}

#define CP_FWD_DATA_BASE_FMT "src %s via %s %s (%d) mtu %d"
#define CP_FWD_DATA_BASE_ARG(mib, data)         \
  AF_IP_L3((data)->src), AF_IP_L3((data)->next_hop),  \
  cp_ifindex2name(mib, (data)->ifindex), (data)->ifindex, (data)->mtu

#endif /* __TOOLS_CPLANE_MIBDUMP_H__ */
