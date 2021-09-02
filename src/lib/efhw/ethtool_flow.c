/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */
#include <uapi/linux/ethtool.h>
#include <ci/driver/driverlink_api.h>

static uint32_t combine_ports(uint16_t loc, uint16_t rem)
{
  return htonl(ntohs(loc) | (htons(rem) << 16));
}

int efx_spec_to_ethtool_flow(const struct efx_filter_spec *src,
                             struct ethtool_rx_flow_spec *dst)
{
  int proto = -1;
  uint32_t loc_ip = 0, loc_ip_mask = 0;
  uint16_t loc_port = 0, loc_port_mask = 0;
  uint32_t rem_ip = 0, rem_ip_mask = 0;
  uint16_t rem_port = 0, rem_port_mask = 0;

  memset(dst, 0, sizeof(*dst));
  dst->location = RX_CLS_LOC_ANY;

  if( src->flags & ~(EFX_FILTER_FLAG_RX | EFX_FILTER_FLAG_STACK_ID |
                     EFX_FILTER_FLAG_VPORT_ID | EFX_FILTER_FLAG_RX_SCATTER) )
    return -EPROTONOSUPPORT;

  if( src->match_flags == EFX_FILTER_MATCH_LOC_MAC_IG &&
      src->loc_mac[0] == 1 ) {
    dst->flow_type = UDP_V4_FLOW;
    dst->h_u.udp_ip4_spec.ip4dst = htonl(0xe0000000);
    dst->m_u.udp_ip4_spec.ip4dst = htonl(0xf0000000);
    return 0;
  }

  if( src->match_flags & ~(EFX_FILTER_MATCH_REM_HOST |
                            EFX_FILTER_MATCH_LOC_HOST |
                            EFX_FILTER_MATCH_REM_PORT |
                            EFX_FILTER_MATCH_LOC_PORT |
                            EFX_FILTER_MATCH_IP_PROTO |
                            EFX_FILTER_MATCH_ETHER_TYPE) )
    return -EPROTONOSUPPORT;
  if( (src->match_flags &
       (EFX_FILTER_MATCH_REM_HOST | EFX_FILTER_MATCH_LOC_HOST)) ==
      EFX_FILTER_MATCH_REM_HOST ||
      (src->match_flags &
       (EFX_FILTER_MATCH_REM_PORT | EFX_FILTER_MATCH_LOC_PORT)) ==
      EFX_FILTER_MATCH_REM_PORT )
    return -EPROTONOSUPPORT;
  if( src->match_flags & EFX_FILTER_MATCH_ETHER_TYPE &&
      src->ether_type != htons(ETH_P_IP) )
    return -EPROTONOSUPPORT;

  if( src->match_flags & EFX_FILTER_MATCH_IP_PROTO )
    proto = src->ip_proto;

  if( src->match_flags & EFX_FILTER_MATCH_LOC_HOST ) {
    loc_ip = src->loc_host[0];
    loc_ip_mask = -1;
  }
  if( src->match_flags & EFX_FILTER_MATCH_LOC_PORT ) {
    loc_port = src->loc_port;
    loc_port_mask = -1;
  }
  if( src->match_flags & EFX_FILTER_MATCH_REM_HOST ) {
    rem_ip = src->rem_host[0];
    rem_ip_mask = -1;
  }
  if( src->match_flags & EFX_FILTER_MATCH_REM_PORT ) {
    rem_port = src->rem_port;
    rem_port_mask = -1;
  }
  switch( proto ) {
  case IPPROTO_UDP:
    dst->flow_type = UDP_V4_FLOW;
    dst->h_u.udp_ip4_spec.ip4dst = loc_ip;
    dst->h_u.udp_ip4_spec.pdst = loc_port;
    dst->h_u.udp_ip4_spec.ip4src = rem_ip;
    dst->h_u.udp_ip4_spec.psrc = rem_port;
    dst->m_u.udp_ip4_spec.ip4dst = loc_ip_mask;
    dst->m_u.udp_ip4_spec.pdst = loc_port_mask;
    dst->m_u.udp_ip4_spec.ip4src = rem_ip_mask;
    dst->m_u.udp_ip4_spec.psrc = rem_port_mask;
    break;
  case IPPROTO_TCP:
    dst->flow_type = TCP_V4_FLOW;
    dst->h_u.tcp_ip4_spec.ip4dst = loc_ip;
    dst->h_u.tcp_ip4_spec.pdst = loc_port;
    dst->h_u.tcp_ip4_spec.ip4src = rem_ip;
    dst->h_u.tcp_ip4_spec.psrc = rem_port;
    dst->m_u.tcp_ip4_spec.ip4dst = loc_ip_mask;
    dst->m_u.tcp_ip4_spec.pdst = loc_port_mask;
    dst->m_u.tcp_ip4_spec.ip4src = rem_ip_mask;
    dst->m_u.tcp_ip4_spec.psrc = rem_port_mask;
    break;
  default:
    dst->flow_type = IPV4_USER_FLOW;
    dst->h_u.usr_ip4_spec.proto = proto;
    dst->h_u.usr_ip4_spec.ip4dst = loc_ip;
    dst->h_u.usr_ip4_spec.ip4src = rem_ip;
    dst->h_u.usr_ip4_spec.l4_4_bytes = combine_ports(loc_port, rem_port);
    dst->m_u.usr_ip4_spec.proto = proto < 0 ? 0 : -1;
    dst->m_u.usr_ip4_spec.ip4dst = loc_ip_mask;
    dst->m_u.usr_ip4_spec.ip4src = rem_ip_mask;
    dst->m_u.usr_ip4_spec.l4_4_bytes = combine_ports(loc_port_mask,
                                                     rem_port_mask);
    break;
  }
  return 0;
}
