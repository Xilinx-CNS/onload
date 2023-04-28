/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */
#include <uapi/linux/ethtool.h>
#include <ci/driver/driverlink_api.h>
#include <ci/efhw/debug.h>
#include <ci/driver/kernel_compat.h>

static uint32_t combine_ports(uint16_t loc, uint16_t rem)
{
  return htonl(ntohs(loc) | (htons(rem) << 16));
}

int efx_spec_to_ethtool_flow(const struct efx_filter_spec *src,
                             struct ethtool_rx_flow_spec *dst)
{
  static const __be32 zero[4] = {};
  static const __be32 minus1[4] = {~0u, ~0u, ~0u, ~0u};
  int proto = -1;
  const __be32 *loc_ip = zero, *loc_ip_mask = zero;
  uint16_t loc_port = 0, loc_port_mask = 0;
  const __be32 *rem_ip = zero, *rem_ip_mask = zero;
  uint16_t rem_port = 0, rem_port_mask = 0;

  memset(dst, 0, sizeof(*dst));
  dst->location = RX_CLS_LOC_ANY;

  if( src->flags & ~(EFX_FILTER_FLAG_RX | EFX_FILTER_FLAG_STACK_ID |
                     EFX_FILTER_FLAG_VPORT_ID | EFX_FILTER_FLAG_RX_SCATTER |
                     EFX_FILTER_FLAG_RX_RSS ) )
    return -EPROTONOSUPPORT;

  if( (src->match_flags & ~EFX_FILTER_MATCH_OUTER_VID) == EFX_FILTER_MATCH_LOC_MAC_IG ) {
    dst->flow_type = ETHER_FLOW;

    memset(&(dst->m_u.ether_spec), 0, sizeof(struct ethhdr));
    dst->m_u.ether_spec.h_dest[0] = 1;
    memset(&(dst->h_u.ether_spec), 0, sizeof(struct ethhdr));
    dst->h_u.ether_spec.h_dest[0] = src->loc_mac[0];

    return 0;
  }

  if( src->match_flags & ~(EFX_FILTER_MATCH_REM_HOST |
                            EFX_FILTER_MATCH_LOC_HOST |
                            EFX_FILTER_MATCH_REM_PORT |
                            EFX_FILTER_MATCH_LOC_PORT |
                            EFX_FILTER_MATCH_IP_PROTO |
                            EFX_FILTER_MATCH_ETHER_TYPE |
                            EFX_FILTER_MATCH_OUTER_VID |
                            EFX_FILTER_MATCH_LOC_MAC) )
    return -EPROTONOSUPPORT;
  if( (src->match_flags &
       (EFX_FILTER_MATCH_REM_HOST | EFX_FILTER_MATCH_LOC_HOST)) ==
      EFX_FILTER_MATCH_REM_HOST ||
      (src->match_flags &
       (EFX_FILTER_MATCH_REM_PORT | EFX_FILTER_MATCH_LOC_PORT)) ==
      EFX_FILTER_MATCH_REM_PORT )
    return -EPROTONOSUPPORT;
  if( src->match_flags & EFX_FILTER_MATCH_ETHER_TYPE &&
      src->ether_type != htons(ETH_P_IP) &&
      src->ether_type != htons(ETH_P_IPV6) &&
      src->ether_type != htons(ETH_P_ARP) )
    return -EPROTONOSUPPORT;

  if( src->match_flags & EFX_FILTER_MATCH_IP_PROTO )
    proto = src->ip_proto;

  if( src->match_flags & EFX_FILTER_MATCH_LOC_HOST ) {
    loc_ip = src->loc_host;
    loc_ip_mask = minus1;
  }
  if( src->match_flags & EFX_FILTER_MATCH_LOC_PORT ) {
    loc_port = src->loc_port;
    loc_port_mask = -1;
  }
  if( src->match_flags & EFX_FILTER_MATCH_REM_HOST ) {
    rem_ip = src->rem_host;
    rem_ip_mask = minus1;
  }
  if( src->match_flags & EFX_FILTER_MATCH_REM_PORT ) {
    rem_port = src->rem_port;
    rem_port_mask = -1;
  }
  if( src->ether_type == htons(ETH_P_IPV6) ) {
    switch( proto ) {
    case IPPROTO_UDP:
    case IPPROTO_TCP:
      /* This assert is checking both the location and the type */
      EFHW_ASSERT(&dst->h_u.udp_ip6_spec == &dst->h_u.tcp_ip6_spec);
      dst->flow_type = proto == IPPROTO_UDP ? UDP_V6_FLOW : TCP_V6_FLOW;
      memcpy(dst->h_u.udp_ip6_spec.ip6dst, loc_ip,
             sizeof(dst->h_u.udp_ip6_spec.ip6dst));
      dst->h_u.udp_ip6_spec.pdst = loc_port;
      memcpy(dst->h_u.udp_ip6_spec.ip6src, rem_ip,
             sizeof(dst->h_u.udp_ip6_spec.ip6src));
      dst->h_u.udp_ip6_spec.psrc = rem_port;
      memcpy(dst->m_u.udp_ip6_spec.ip6dst, loc_ip_mask,
             sizeof(dst->m_u.udp_ip6_spec.ip6dst));
      dst->m_u.udp_ip6_spec.pdst = loc_port_mask;
      memcpy(dst->m_u.udp_ip6_spec.ip6src, rem_ip_mask,
             sizeof(dst->m_u.udp_ip6_spec.ip6src));
      dst->m_u.udp_ip6_spec.psrc = rem_port_mask;
      break;
    default:
      dst->flow_type = IPV6_USER_FLOW;
      dst->h_u.usr_ip6_spec.l4_proto = proto;
      memcpy(dst->h_u.usr_ip6_spec.ip6dst, loc_ip,
             sizeof(dst->h_u.usr_ip6_spec.ip6dst));
      memcpy(dst->h_u.usr_ip6_spec.ip6src, rem_ip,
             sizeof(dst->h_u.usr_ip6_spec.ip6src));
      dst->h_u.usr_ip6_spec.l4_4_bytes = combine_ports(loc_port, rem_port);
      dst->m_u.usr_ip6_spec.l4_proto = proto < 0 ? 0 : -1;
      memcpy(dst->m_u.usr_ip6_spec.ip6dst, loc_ip_mask,
             sizeof(dst->m_u.usr_ip6_spec.ip6dst));
      memcpy(dst->m_u.usr_ip6_spec.ip6src, rem_ip_mask,
             sizeof(dst->m_u.usr_ip6_spec.ip6src));
      dst->m_u.usr_ip6_spec.l4_4_bytes = combine_ports(loc_port_mask,
                                                      rem_port_mask);
      break;
    }
  }
  else if( src->ether_type == htons(ETH_P_IP) ) {
    switch( proto ) {
    case IPPROTO_UDP:
    case IPPROTO_TCP:
      /* This assert is checking both the location and the type */
      EFHW_ASSERT(&dst->h_u.udp_ip4_spec == &dst->h_u.tcp_ip4_spec);
      dst->flow_type = proto == IPPROTO_UDP ? UDP_V4_FLOW : TCP_V4_FLOW;
      dst->h_u.tcp_ip4_spec.ip4dst = loc_ip[0];
      dst->h_u.tcp_ip4_spec.pdst = loc_port;
      dst->h_u.tcp_ip4_spec.ip4src = rem_ip[0];
      dst->h_u.tcp_ip4_spec.psrc = rem_port;
      dst->m_u.tcp_ip4_spec.ip4dst = loc_ip_mask[0];
      dst->m_u.tcp_ip4_spec.pdst = loc_port_mask;
      dst->m_u.tcp_ip4_spec.ip4src = rem_ip_mask[0];
      dst->m_u.tcp_ip4_spec.psrc = rem_port_mask;
      break;
    default:
      dst->flow_type = IPV4_USER_FLOW;
      dst->h_u.usr_ip4_spec.proto = proto;
      dst->h_u.usr_ip4_spec.ip4dst = loc_ip[0];
      dst->h_u.usr_ip4_spec.ip4src = rem_ip[0];
      dst->h_u.usr_ip4_spec.l4_4_bytes = combine_ports(loc_port, rem_port);
      dst->h_u.usr_ip4_spec.ip_ver = ETH_RX_NFC_IP4;
      dst->m_u.usr_ip4_spec.proto = proto < 0 ? 0 : -1;
      dst->m_u.usr_ip4_spec.ip4dst = loc_ip_mask[0];
      dst->m_u.usr_ip4_spec.ip4src = rem_ip_mask[0];
      dst->m_u.usr_ip4_spec.l4_4_bytes = combine_ports(loc_port_mask,
                                                      rem_port_mask);
      dst->m_u.usr_ip4_spec.ip_ver = 0;
      break;
    }
#ifdef EFRM_HAVE_FLOW_RSS
    if( src->flags & EFX_FILTER_FLAG_RX_RSS ) {
      dst->flow_type |= FLOW_RSS;
    }
#endif
    if( src->match_flags & EFX_FILTER_MATCH_LOC_MAC) {
      dst->flow_type |= FLOW_MAC_EXT;

      memcpy(dst->h_ext.h_dest, src->loc_mac, sizeof(dst->h_ext.h_dest));
      memcpy(dst->m_ext.h_dest, minus1, sizeof(dst->m_ext.h_dest));
    }
  }
  /* This should only be entered when installing an ETHER_FLOW type filter.
   * If the requested filter also includes IP specific things (protocol number,
   * ports, addresses etc.) then the handling of MAC addresses should be done
   * by setting FLOW_MAC_EXT in dst->flow_type and updating dst->h_ext.
   */
  if( (src->match_flags & EFX_FILTER_MATCH_LOC_MAC) &&
     !(src->match_flags & (EFX_FILTER_MATCH_IP_PROTO |
                           EFX_FILTER_MATCH_LOC_HOST |
                           EFX_FILTER_MATCH_LOC_PORT)) ) {
    dst->flow_type = ETHER_FLOW;

    memcpy(dst->h_u.ether_spec.h_dest, src->loc_mac,
      sizeof(dst->h_u.ether_spec.h_dest));
    memcpy(dst->m_u.ether_spec.h_dest, minus1,
      sizeof(dst->m_u.ether_spec.h_dest));

    if( src->match_flags & EFX_FILTER_MATCH_ETHER_TYPE ) {
      dst->h_u.ether_spec.h_proto = src->ether_type;
      dst->m_u.ether_spec.h_proto = (__be16)~0u;
    }
  }
  if( src->match_flags & EFX_FILTER_MATCH_OUTER_VID ) {
    dst->flow_type |= FLOW_EXT;
    dst->h_ext.vlan_tci = src->outer_vid;
    dst->m_ext.vlan_tci = 0xffff;
  }
  return 0;
}
