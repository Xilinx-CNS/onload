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


static bool
check_supported_filter(const ci_dword_t* matches, unsigned filter)
{
  int i;
  int len = EFHW_MCDI_DWORD(matches,
                            GET_PARSER_DISP_INFO_OUT_NUM_SUPPORTED_MATCHES);
  for(i = 0; i < len; i++)
    if ( EFHW_MCDI_ARRAY_DWORD(matches,
           GET_PARSER_DISP_INFO_OUT_SUPPORTED_MATCHES, i) == filter )
      return true;

  return false;
}


uint64_t
mcdi_parser_info_to_filter_flags(ci_dword_t *out)
{
  uint64_t flags = 0;

  /* We check types of filters that may be used by onload, or ef_vi
   * users.  This information will be exposed by the capabilities API.  */
  if( check_supported_filter(out, MC_FILTER_IP_LOCAL) )
    flags |= NIC_FILTER_FLAG_RX_TYPE_IP_LOCAL;
  if( check_supported_filter(out, MC_FILTER_IP_FULL) )
    flags |= NIC_FILTER_FLAG_RX_TYPE_IP_FULL;
  if( check_supported_filter(out, MC_FILTER_VLAN_IP_WILD) )
    flags |= NIC_FILTER_FLAG_IPX_VLAN_HW;
  if( check_supported_filter(out, MC_FILTER_ETH_LOCAL) )
    flags |= NIC_FILTER_FLAG_RX_TYPE_ETH_LOCAL;
  if( check_supported_filter(out, MC_FILTER_ETH_LOCAL_VLAN) )
    flags |= NIC_FILTER_FLAG_RX_TYPE_ETH_LOCAL_VLAN;
  if( check_supported_filter(out, MC_FILTER_IP_PROTOCOL) )
    flags |= NIC_FILTER_FLAG_RX_IP4_PROTO;
  if( check_supported_filter(out, MC_FILTER_ETHERTYPE) )
    flags |= NIC_FILTER_FLAG_RX_ETHERTYPE;
  if( check_supported_filter(out, MC_FILTER_MAC_IP4_PROTO) )
    flags |= NIC_FILTER_FLAG_RX_MAC_IP4_PROTO;
  if( check_supported_filter(out, MC_FILTER_UCAST_MISMATCH) )
    flags |= NIC_FILTER_FLAG_RX_TYPE_UCAST_MISMATCH;
  if( check_supported_filter(out, MC_FILTER_MCAST_MISMATCH) )
    flags |= NIC_FILTER_FLAG_RX_TYPE_MCAST_MISMATCH;

  return flags;
}


uint64_t
mcdi_capability_info_to_nic_flags(ci_dword_t *out, size_t out_size)
{
  uint64_t capability_flags = 0;
  unsigned flags;
  int pio_num;

  flags = EFHW_MCDI_DWORD(out, GET_CAPABILITIES_V3_OUT_FLAGS1);
  if (flags & (1u << MC_CMD_GET_CAPABILITIES_V3_OUT_RX_PREFIX_LEN_14_LBN))
    capability_flags |= NIC_FLAG_14BYTE_PREFIX;
  if (flags & (1u << MC_CMD_GET_CAPABILITIES_V3_OUT_TX_MCAST_UDP_LOOPBACK_LBN))
    capability_flags |= NIC_FLAG_MCAST_LOOP_HW;
  if (flags & (1u << MC_CMD_GET_CAPABILITIES_V3_OUT_RX_PACKED_STREAM_LBN))
    capability_flags |= NIC_FLAG_PACKED_STREAM;
  if (flags & (1u << MC_CMD_GET_CAPABILITIES_V3_OUT_RX_RSS_LIMITED_LBN))
    capability_flags |= NIC_FLAG_RX_RSS_LIMITED;
  if (flags & (1u << MC_CMD_GET_CAPABILITIES_V3_OUT_RX_PACKED_STREAM_VAR_BUFFERS_LBN))
    capability_flags |= NIC_FLAG_VAR_PACKED_STREAM;
  if (flags & (1u << MC_CMD_GET_CAPABILITIES_V3_OUT_ADDITIONAL_RSS_MODES_LBN))
    capability_flags |= NIC_FLAG_ADDITIONAL_RSS_MODES;
  if (flags & (1u << MC_CMD_GET_CAPABILITIES_V3_OUT_RX_TIMESTAMP_LBN))
    capability_flags |= NIC_FLAG_HW_RX_TIMESTAMPING;
  if (flags & (1u << MC_CMD_GET_CAPABILITIES_V3_OUT_TX_TIMESTAMP_LBN))
    capability_flags |= NIC_FLAG_HW_TX_TIMESTAMPING;
  if (flags & (1u << MC_CMD_GET_CAPABILITIES_V3_OUT_MCAST_FILTER_CHAINING_LBN))
    capability_flags |= NIC_FLAG_MULTICAST_FILTER_CHAINING;
  if (flags & (1u << MC_CMD_GET_CAPABILITIES_V3_OUT_RX_PREFIX_LEN_0_LBN))
    capability_flags |= NIC_FLAG_ZERO_RX_PREFIX;
  if (flags & (1u << MC_CMD_GET_CAPABILITIES_V3_OUT_RX_BATCHING_LBN))
    capability_flags |= NIC_FLAG_RX_MERGE;
  if (flags & (1u << MC_CMD_GET_CAPABILITIES_V3_OUT_RX_FORCE_EVENT_MERGING_LBN))
    capability_flags |= NIC_FLAG_RX_FORCE_EVENT_MERGING;

  if (out_size >= MC_CMD_GET_CAPABILITIES_V2_OUT_LEN) {
    pio_num = EFHW_MCDI_WORD(out, GET_CAPABILITIES_V3_OUT_NUM_PIO_BUFFS);
    if( pio_num > 0 )
      capability_flags |= NIC_FLAG_PIO;
    flags = EFHW_MCDI_DWORD(out, GET_CAPABILITIES_V3_OUT_FLAGS2);
    if (flags & (1u << MC_CMD_GET_CAPABILITIES_V3_OUT_TX_VFIFO_ULL_MODE_LBN))
      capability_flags |= NIC_FLAG_TX_ALTERNATIVES;
    if (flags & (1u << MC_CMD_GET_CAPABILITIES_V3_OUT_INIT_EVQ_V2_LBN))
      capability_flags |= NIC_FLAG_EVQ_V2;
    if (flags & (1u << MC_CMD_GET_CAPABILITIES_V2_OUT_CTPIO_LBN))
      capability_flags |= NIC_FLAG_TX_CTPIO;
    if (flags & (1u << MC_CMD_GET_CAPABILITIES_V3_OUT_EVENT_CUT_THROUGH_LBN))
      capability_flags |= NIC_FLAG_EVENT_CUT_THROUGH;
    if (flags & (1u << MC_CMD_GET_CAPABILITIES_V3_OUT_RX_CUT_THROUGH_LBN))
      capability_flags |= NIC_FLAG_RX_CUT_THROUGH;
  }
  else {
    EFHW_ERR("%s: ERROR: Unexpectedly failed to read NIC capabilities",
             __FUNCTION__);
  }

  return capability_flags;
}
