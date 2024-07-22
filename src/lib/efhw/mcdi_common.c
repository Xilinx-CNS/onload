/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: Copyright (C) 2024, Advanced Micro Devices, Inc. */

#include <ci/driver/efab/hardware.h>
#include <ci/tools/bitfield.h>
#include <ci/efhw/mc_driver_pcol.h>
#include "mcdi_common.h"


#define MC_FILTER_IP_LOCAL (1 << MC_CMD_FILTER_OP_IN_MATCH_DST_IP_LBN |\
                            1 << MC_CMD_FILTER_OP_IN_MATCH_DST_PORT_LBN |\
                            1 << MC_CMD_FILTER_OP_IN_MATCH_ETHER_TYPE_LBN |\
                            1 << MC_CMD_FILTER_OP_IN_MATCH_IP_PROTO_LBN)
#define MC_FILTER_IP_FULL (1 << MC_CMD_FILTER_OP_IN_MATCH_DST_IP_LBN |\
                           1 << MC_CMD_FILTER_OP_IN_MATCH_DST_PORT_LBN |\
                           1 << MC_CMD_FILTER_OP_IN_MATCH_SRC_IP_LBN |\
                           1 << MC_CMD_FILTER_OP_IN_MATCH_SRC_PORT_LBN |\
                           1 << MC_CMD_FILTER_OP_IN_MATCH_ETHER_TYPE_LBN |\
                           1 << MC_CMD_FILTER_OP_IN_MATCH_IP_PROTO_LBN)
#define MC_FILTER_VLAN_IP_WILD (1 << MC_CMD_FILTER_OP_IN_MATCH_DST_IP_LBN |\
                              1 << MC_CMD_FILTER_OP_IN_MATCH_DST_PORT_LBN |\
                              1 << MC_CMD_FILTER_OP_IN_MATCH_ETHER_TYPE_LBN |\
                              1 << MC_CMD_FILTER_OP_IN_MATCH_OUTER_VLAN_LBN |\
                              1 << MC_CMD_FILTER_OP_IN_MATCH_IP_PROTO_LBN)
#define MC_FILTER_ETH_LOCAL (1 << MC_CMD_FILTER_OP_IN_MATCH_DST_MAC_LBN)
#define MC_FILTER_ETH_LOCAL_VLAN (1 << MC_CMD_FILTER_OP_IN_MATCH_DST_MAC_LBN |\
                             1 << MC_CMD_FILTER_OP_IN_MATCH_OUTER_VLAN_LBN)
#define MC_FILTER_UCAST_MISMATCH \
                         (1 << MC_CMD_FILTER_OP_IN_MATCH_UNKNOWN_UCAST_DST_LBN)
#define MC_FILTER_MCAST_MISMATCH \
                         (1 << MC_CMD_FILTER_OP_IN_MATCH_UNKNOWN_MCAST_DST_LBN)
#define MC_FILTER_IP_PROTOCOL (1 << MC_CMD_FILTER_OP_IN_MATCH_ETHER_TYPE_LBN |\
                               1 << MC_CMD_FILTER_OP_IN_MATCH_IP_PROTO_LBN)
#define MC_FILTER_ETHERTYPE (1 << MC_CMD_FILTER_OP_IN_MATCH_ETHER_TYPE_LBN)
#define MC_FILTER_MAC_IP4_PROTO \
                            (1 << MC_CMD_FILTER_OP_IN_MATCH_ETHER_TYPE_LBN |\
                             1 << MC_CMD_FILTER_OP_IN_MATCH_IP_PROTO_LBN |\
                             1 << MC_CMD_FILTER_OP_IN_MATCH_DST_MAC_LBN)


static int
check_supported_filter(ci_dword_t* matches, int len, unsigned filter)
{
  int i;
  for(i = 0; i < len; i++)
    if ( EFHW_MCDI_ARRAY_DWORD(matches,
           GET_PARSER_DISP_INFO_OUT_SUPPORTED_MATCHES, i) == filter )
      return 1;

  return 0;
}


uint64_t
mcdi_parser_info_to_nic_flags(ci_dword_t *out, int num_matches)
{
  uint64_t flags = 0;

  /* We check types of filters that may be used by onload, or ef_vi
   * users.  This information will be exposed by the capabilities API.  */
  if( check_supported_filter(out, num_matches, MC_FILTER_IP_LOCAL) )
    flags |= NIC_FLAG_RX_FILTER_TYPE_IP_LOCAL;
  if( check_supported_filter(out, num_matches, MC_FILTER_IP_FULL) )
    flags |= NIC_FLAG_RX_FILTER_TYPE_IP_FULL;
  if( check_supported_filter(out, num_matches, MC_FILTER_VLAN_IP_WILD) )
    flags |= NIC_FLAG_VLAN_FILTERS;
  if( check_supported_filter(out, num_matches, MC_FILTER_ETH_LOCAL) )
    flags |= NIC_FLAG_RX_FILTER_TYPE_ETH_LOCAL;
  if( check_supported_filter(out, num_matches, MC_FILTER_ETH_LOCAL_VLAN) )
    flags |= NIC_FLAG_RX_FILTER_TYPE_ETH_LOCAL_VLAN;
  if( check_supported_filter(out, num_matches, MC_FILTER_IP_PROTOCOL) )
    flags |= NIC_FLAG_RX_FILTER_IP4_PROTO;
  if( check_supported_filter(out, num_matches, MC_FILTER_ETHERTYPE) )
    flags |= NIC_FLAG_RX_FILTER_ETHERTYPE;
  if( check_supported_filter(out, num_matches, MC_FILTER_MAC_IP4_PROTO) )
    flags |= NIC_FLAG_RX_FILTER_MAC_IP4_PROTO;
  if( check_supported_filter(out, num_matches, MC_FILTER_UCAST_MISMATCH) )
    flags |= NIC_FLAG_RX_FILTER_TYPE_UCAST_MISMATCH;
  if( check_supported_filter(out, num_matches, MC_FILTER_MCAST_MISMATCH) )
    flags |= NIC_FLAG_RX_FILTER_TYPE_MCAST_MISMATCH;

  return flags;
}
