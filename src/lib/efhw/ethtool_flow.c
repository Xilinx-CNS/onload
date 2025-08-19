/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */
#include <uapi/linux/ethtool.h>
#include <ci/driver/driverlink_api.h>
#include <ci/efhw/debug.h>
#include <ci/driver/kernel_compat.h>

#include <ci/tools/bitfield.h>
#include <ci/efhw/mc_driver_pcol.h>
#include "mcdi_common.h"

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
  if( (src->match_flags & (EFX_FILTER_MATCH_LOC_MAC |
                           EFX_FILTER_MATCH_ETHER_TYPE)) &&
     !(src->match_flags & (EFX_FILTER_MATCH_IP_PROTO |
                           EFX_FILTER_MATCH_LOC_HOST |
                           EFX_FILTER_MATCH_LOC_PORT)) ) {
    dst->flow_type = ETHER_FLOW;

    if( src->match_flags & EFX_FILTER_MATCH_LOC_MAC ) {
      memcpy(dst->h_u.ether_spec.h_dest, src->loc_mac,
        sizeof(dst->h_u.ether_spec.h_dest));
      memcpy(dst->m_u.ether_spec.h_dest, minus1,
        sizeof(dst->m_u.ether_spec.h_dest));
    }

    if( src->match_flags & EFX_FILTER_MATCH_ETHER_TYPE ) {
      dst->h_u.ether_spec.h_proto = src->ether_type;
      dst->m_u.ether_spec.h_proto = (__be16)~0u;
    }
  }
  if( src->match_flags & EFX_FILTER_MATCH_OUTER_VID ) {
    dst->flow_type |= FLOW_EXT;
    dst->h_ext.vlan_tci = src->outer_vid;
    /* VID is the bottom 12 bits of the vlan_tci field */
    dst->m_ext.vlan_tci = htons(0xfff);
  }
  return 0;
}

static bool ipv6_addr_non_null(const __be32 addr[static 4])
{
  int i;
  for (i = 0; i < 4; i++)
    if( addr[i] )
      return true;
  return false;
}

static bool ether_addr_non_null(const u8 addr[static ETH_ALEN])
{
  int i;
  for (i = 0; i < ETH_ALEN; i++)
    if( addr[i] )
      return true;
  return false;
}

static void set_masked_ether_addr(void *dst, const u8 addr[static ETH_ALEN],
                                  const u8 mask[static ETH_ALEN])
{
  u8 masked_addr[ETH_ALEN];
  int i;
  for (i = 0; i < CI_ARRAY_SIZE(masked_addr); i++)
    masked_addr[i] = mask[i] & addr[i];

  memcpy(dst, masked_addr, sizeof(masked_addr));
}

static void set_masked_ipv6_addr(void *dst, const __be32 addr[static 4],
                                 const __be32 mask[static 4])
{
  __be32 masked_addr[4];
  int i;
  for (i = 0; i < CI_ARRAY_SIZE(masked_addr); i++)
    masked_addr[i] = mask[i] & addr[i];

  memcpy(dst, masked_addr, sizeof(masked_addr));
}

void ethtool_flow_to_mcdi_op(ci_dword_t *buf, int rxq, int op,
                             const struct ethtool_rx_flow_spec *filter)
{
  bool multicast = false;
  uint32_t match_fields = 0;
  uint32_t base_flow_type = (filter->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT));
  EFHW_BUILD_ASSERT(sizeof(match_fields) == MC_CMD_FILTER_OP_IN_MATCH_FIELDS_LEN);

  /* Ignore any VLAN or MAC options to start with. We'll add those later. */
  switch (base_flow_type) {
  case TCP_V4_FLOW:
  case UDP_V4_FLOW:
    match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(ETHER_TYPE);
    EFHW_MCDI_SET_WORD(buf, FILTER_OP_IN_ETHER_TYPE, htons(ETH_P_IP));

    match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(IP_PROTO);
    EFHW_MCDI_SET_WORD(buf, FILTER_OP_IN_IP_PROTO,
                       base_flow_type == UDP_V4_FLOW ? IPPROTO_UDP :
                                                       IPPROTO_TCP);

    if (filter->m_u.tcp_ip4_spec.ip4src) {
      match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(SRC_IP);
      EFHW_MCDI_SET_DWORD(buf, FILTER_OP_IN_SRC_IP,
                          filter->h_u.tcp_ip4_spec.ip4src &
                          filter->m_u.tcp_ip4_spec.ip4src);
    }
    if (filter->m_u.tcp_ip4_spec.ip4dst) {
      match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(DST_IP);
      EFHW_MCDI_SET_DWORD(buf, FILTER_OP_IN_DST_IP,
                          filter->h_u.tcp_ip4_spec.ip4dst &
                          filter->m_u.tcp_ip4_spec.ip4dst);

      /* Check for multicast */
      if (base_flow_type == UDP_V4_FLOW &&
          ipv4_is_multicast(filter->h_u.udp_ip4_spec.ip4dst))
        multicast = true;
    }
    if (filter->m_u.tcp_ip4_spec.psrc) {
      match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(SRC_PORT);
      EFHW_MCDI_SET_WORD(buf, FILTER_OP_IN_SRC_PORT,
                         filter->h_u.tcp_ip4_spec.psrc &
                         filter->m_u.tcp_ip4_spec.psrc);
    }
    if (filter->m_u.tcp_ip4_spec.pdst) {
      match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(DST_PORT);
      EFHW_MCDI_SET_WORD(buf, FILTER_OP_IN_DST_PORT,
                         filter->h_u.tcp_ip4_spec.pdst &
                         filter->m_u.tcp_ip4_spec.pdst);
    }
    /* Type of service isn't supported */
    EFHW_ASSERT(filter->m_u.tcp_ip4_spec.tos == 0);
    break;
  case TCP_V6_FLOW:
  case UDP_V6_FLOW:
    match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(ETHER_TYPE);
    EFHW_MCDI_SET_WORD(buf, FILTER_OP_IN_ETHER_TYPE, htons(ETH_P_IPV6));

    match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(IP_PROTO);
    EFHW_MCDI_SET_WORD(buf, FILTER_OP_IN_IP_PROTO,
                       base_flow_type == UDP_V6_FLOW ? IPPROTO_UDP :
                                                       IPPROTO_TCP);

    if (ipv6_addr_non_null(filter->m_u.tcp_ip6_spec.ip6src)) {
      match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(SRC_IP);
      EFHW_BUILD_ASSERT(sizeof(filter->h_u.tcp_ip6_spec.ip6src) == MC_CMD_FILTER_OP_IN_SRC_IP_LEN);
      set_masked_ipv6_addr(EFHW_MCDI_PTR(buf, FILTER_OP_IN_SRC_IP),
                           filter->h_u.tcp_ip6_spec.ip6src,
                           filter->m_u.tcp_ip6_spec.ip6src);
    }
    if (ipv6_addr_non_null(filter->m_u.tcp_ip6_spec.ip6dst)) {
      match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(DST_IP);
      EFHW_BUILD_ASSERT(sizeof(filter->h_u.tcp_ip6_spec.ip6dst) == MC_CMD_FILTER_OP_IN_DST_IP_LEN);
      set_masked_ipv6_addr(EFHW_MCDI_PTR(buf, FILTER_OP_IN_DST_IP),
                           filter->h_u.tcp_ip6_spec.ip6dst,
                           filter->m_u.tcp_ip6_spec.ip6dst);

      /* Check for multicast */
      if (base_flow_type == UDP_V6_FLOW &&
          filter->h_u.udp_ip6_spec.ip6dst[0] == 0xff)
        multicast = true;
    }
    if (filter->m_u.tcp_ip6_spec.psrc) {
      match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(SRC_PORT);
      EFHW_MCDI_SET_WORD(buf, FILTER_OP_IN_SRC_PORT,
                         filter->h_u.tcp_ip6_spec.psrc &
                         filter->m_u.tcp_ip6_spec.psrc);
    }
    if (filter->m_u.tcp_ip6_spec.pdst) {
      match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(DST_PORT);
      EFHW_MCDI_SET_WORD(buf, FILTER_OP_IN_DST_PORT,
                         filter->h_u.tcp_ip6_spec.pdst &
                         filter->m_u.tcp_ip6_spec.pdst);
    }

    EFHW_ASSERT(filter->m_u.tcp_ip6_spec.tclass == 0);
    break;
  case IPV4_USER_FLOW: /* Also includes IP_USER_FLOW */
    match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(ETHER_TYPE);
    EFHW_MCDI_SET_WORD(buf, FILTER_OP_IN_ETHER_TYPE, htons(ETH_P_IP));

    if (filter->m_u.usr_ip4_spec.ip4src) {
      match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(SRC_IP);
      EFHW_MCDI_SET_DWORD(buf, FILTER_OP_IN_SRC_IP,
                          filter->h_u.usr_ip4_spec.ip4src &
                          filter->m_u.usr_ip4_spec.ip4src);
    }
    if (filter->m_u.usr_ip4_spec.ip4dst) {
      match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(DST_IP);
      EFHW_MCDI_SET_DWORD(buf, FILTER_OP_IN_DST_IP,
                          filter->h_u.usr_ip4_spec.ip4dst &
                          filter->m_u.usr_ip4_spec.ip4dst);
    }

    EFHW_ASSERT(filter->m_u.usr_ip4_spec.l4_4_bytes == 0);
    EFHW_ASSERT(filter->m_u.usr_ip4_spec.tos == 0);
    EFHW_ASSERT(filter->h_u.usr_ip4_spec.ip_ver == ETH_RX_NFC_IP4);
    EFHW_ASSERT(filter->m_u.usr_ip4_spec.ip_ver == 0);

    match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(IP_PROTO);

    EFHW_MCDI_SET_WORD(buf, FILTER_OP_IN_IP_PROTO,
                       filter->h_u.usr_ip4_spec.proto);
    break;
  case IPV6_USER_FLOW:
    match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(ETHER_TYPE);
    EFHW_MCDI_SET_WORD(buf, FILTER_OP_IN_ETHER_TYPE, htons(ETH_P_IPV6));

    if (ipv6_addr_non_null(filter->m_u.usr_ip6_spec.ip6src)) {
      match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(SRC_IP);
      EFHW_BUILD_ASSERT(sizeof(filter->h_u.usr_ip6_spec.ip6src) == MC_CMD_FILTER_OP_IN_SRC_IP_LEN);
      set_masked_ipv6_addr(EFHW_MCDI_PTR(buf, FILTER_OP_IN_SRC_IP),
                           filter->h_u.usr_ip6_spec.ip6src,
                           filter->m_u.usr_ip6_spec.ip6src);
    }
    if (ipv6_addr_non_null(filter->m_u.usr_ip6_spec.ip6dst)) {
      match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(DST_IP);
      EFHW_BUILD_ASSERT(sizeof(filter->h_u.usr_ip6_spec.ip6dst) == MC_CMD_FILTER_OP_IN_DST_IP_LEN);
      set_masked_ipv6_addr(EFHW_MCDI_PTR(buf, FILTER_OP_IN_DST_IP),
                           filter->h_u.usr_ip6_spec.ip6dst,
                           filter->m_u.usr_ip6_spec.ip6dst);
    }
    EFHW_ASSERT(filter->m_u.usr_ip6_spec.l4_4_bytes == 0);
    EFHW_ASSERT(filter->m_u.usr_ip6_spec.tclass == 0);

    if (filter->m_u.usr_ip6_spec.l4_proto) {
      match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(IP_PROTO);
      EFHW_MCDI_SET_WORD(buf, FILTER_OP_IN_IP_PROTO,
                         filter->h_u.usr_ip6_spec.l4_proto &
                         filter->m_u.usr_ip6_spec.l4_proto);
    }
    break;
  case ETHER_FLOW:
    if (ether_addr_non_null(filter->m_u.ether_spec.h_source)) {
      match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(SRC_MAC);
      EFHW_BUILD_ASSERT(sizeof(filter->h_u.ether_spec.h_source) == MC_CMD_FILTER_OP_IN_SRC_MAC_LEN);
      EFHW_BUILD_ASSERT(sizeof(filter->h_u.ether_spec.h_source) == ETH_ALEN);
      set_masked_ether_addr(EFHW_MCDI_PTR(buf, FILTER_OP_IN_SRC_MAC),
                                 filter->h_u.ether_spec.h_source,
                                 filter->m_u.ether_spec.h_source);
    }
    if (ether_addr_non_null(filter->m_u.ether_spec.h_dest)) {
      match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(DST_MAC);
      EFHW_BUILD_ASSERT(sizeof(filter->h_u.ether_spec.h_dest) == MC_CMD_FILTER_OP_IN_DST_MAC_LEN);
      EFHW_BUILD_ASSERT(sizeof(filter->h_u.ether_spec.h_dest) == ETH_ALEN);
      set_masked_ether_addr(EFHW_MCDI_PTR(buf, FILTER_OP_IN_DST_MAC),
                                 filter->h_u.ether_spec.h_dest,
                                 filter->m_u.ether_spec.h_dest);
    }
    if (filter->m_u.ether_spec.h_proto) {
      match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(ETHER_TYPE);
      EFHW_MCDI_SET_WORD(buf, FILTER_OP_IN_ETHER_TYPE,
                         filter->h_u.ether_spec.h_proto &
                         filter->m_u.ether_spec.h_proto);
    }
    break;
  case SCTP_V4_FLOW:    /* SCTP over IPv4 */
  case AH_ESP_V4_FLOW:
  case ESP_V4_FLOW:     /* IPSEC ESP over IPv4 */
  case SCTP_V6_FLOW:    /* SCTP over IPv6 */
  case AH_V4_FLOW:      /* IPSEC AH over IPv4 */
  case AH_ESP_V6_FLOW:
  case AH_V6_FLOW:      /* IPSEC AH over IPv6 */
  case ESP_V6_FLOW:     /* IPSEC ESP over IPv6 */
  case IPV4_FLOW:
  case IPV6_FLOW:
    /* Using this as a dumping ground for flow types that don't obviously match
     * fields in match_fields */
    EFHW_ERR("%s Unsupported filter flow_type %u",
              __func__, filter->flow_type);
    break;
  default:
    EFHW_WARN("%s Unknown filter flow_type %u", __func__, filter->flow_type);
    break;
  }

  if (filter->flow_type & FLOW_MAC_EXT) {
    if (ether_addr_non_null(filter->m_ext.h_dest)) {
      match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(DST_MAC);
      EFHW_BUILD_ASSERT(sizeof(filter->h_ext.h_dest) == MC_CMD_FILTER_OP_IN_DST_MAC_LEN);
      EFHW_BUILD_ASSERT(sizeof(filter->h_ext.h_dest) == ETH_ALEN);
      set_masked_ether_addr(EFHW_MCDI_PTR(buf, FILTER_OP_IN_DST_MAC),
                                 filter->h_ext.h_dest, filter->m_ext.h_dest);
    }
  }

  if (filter->flow_type & FLOW_EXT) {
    if (filter->m_ext.vlan_tci) {
      match_fields |= EFHW_MCDI_MATCH_FIELD_BIT(OUTER_VLAN);
      EFHW_MCDI_SET_WORD(buf, FILTER_OP_IN_OUTER_VLAN,
                         filter->h_ext.vlan_tci & filter->m_ext.vlan_tci);
    }

    EFHW_ASSERT(filter->m_ext.vlan_etype == 0);
    EFHW_ASSERT(filter->m_ext.data[0] == 0);
    EFHW_ASSERT(filter->m_ext.data[1] == 0);
  }

  EFHW_ASSERT((op == MC_CMD_FILTER_OP_IN_OP_INSERT) ||
              (op == MC_CMD_FILTER_OP_IN_OP_SUBSCRIBE) ||
              (op == MC_CMD_FILTER_OP_IN_OP_REPLACE));
  EFHW_MCDI_SET_DWORD(buf, FILTER_OP_IN_OP, op);
  EFHW_MCDI_SET_DWORD(buf, FILTER_OP_IN_PORT_ID, EVB_PORT_ID_ASSIGNED);
  EFHW_MCDI_SET_DWORD(buf, FILTER_OP_IN_MATCH_FIELDS, match_fields);
  EFHW_MCDI_SET_DWORD(buf, FILTER_OP_IN_RX_DEST,
                      MC_CMD_FILTER_OP_IN_RX_DEST_HOST);
  EFHW_MCDI_SET_DWORD(buf, FILTER_OP_IN_RX_QUEUE, rxq);
  EFHW_MCDI_SET_DWORD(buf, FILTER_OP_IN_RX_MODE,
                      MC_CMD_FILTER_OP_IN_RX_MODE_SIMPLE);
  EFHW_MCDI_SET_DWORD(buf, FILTER_OP_IN_TX_DEST,
                      MC_CMD_FILTER_OP_IN_TX_DEST_DEFAULT);
}
