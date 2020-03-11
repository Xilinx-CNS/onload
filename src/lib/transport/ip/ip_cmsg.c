/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  Evgeniy Vladimirovich Bobkov <kavri@oktetlabs.ru>
**  \brief  Control messages / ancillary data.
**   \date  2004/12/23
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include <ci/internal/ip_timestamp.h>


#define LPF "IP CMSG "

/* On some glibc versions CMSG_NXTHDR looks into unitialized data and
 * may return null */
#define NEED_A_WORKAROUND_FOR_GLIBC_BUG_13500


/**
 * Put a portion of ancillary data into msg ancillary data buffer.
 *
 * man cmsg says: Use CMSG_FIRSTHDR() on the msghdr to get the first
 * control message and CMSG_NEXTHDR() to get all subsequent ones.  In
 * each control message, initialize cmsg_len (with CMSG_LEN()), the
 * other cmsghdr header fields, and the data portion using
 * CMSG_DATA().  Finally, the msg_controllen field of the msghdr
 * should be set to the sum of the CMSG_SPACE() of the length of all
 * control messages in the buffer.
 */
void ci_put_cmsg(struct cmsg_state *cmsg_state,
                 int level, int type, socklen_t len, const void* data)
{

  int data_space, data_len = len;

  /* Calls to CMSG_FIRSTHDR and CMSG_NEXTHDR already check that there
   * is enough space for the cmsghdr itself, so just need to check
   * that it is != NULL here
   */
  if( *cmsg_state->p_msg_flags & MSG_CTRUNC )
    return;
  if( cmsg_state->cm == NULL ) {
    *cmsg_state->p_msg_flags |= MSG_CTRUNC;
    return;
  }

  data_space = ((unsigned char*)cmsg_state->msg->msg_control + 
                cmsg_state->msg->msg_controllen) - 
    (unsigned char*)CMSG_DATA(cmsg_state->cm);
  if( data_space < 0 ) {
    *cmsg_state->p_msg_flags |= MSG_CTRUNC;
    return;
  }

  if( data_len > data_space ) {
    *cmsg_state->p_msg_flags |= MSG_CTRUNC;
    cmsg_state->cmsg_bytes_used = cmsg_state->msg->msg_controllen;
    data_len = data_space;
  }
  else {
    cmsg_state->cmsg_bytes_used += CMSG_SPACE(data_len);
  }

  cmsg_state->cm->cmsg_len   = CMSG_LEN(data_len);
  cmsg_state->cm->cmsg_level = level;
  cmsg_state->cm->cmsg_type  = type;

  memcpy(CMSG_DATA(cmsg_state->cm), data, data_len);


  if( *cmsg_state->p_msg_flags & MSG_CTRUNC )
    return;

#if !defined(NEED_A_WORKAROUND_FOR_GLIBC_BUG_13500) || defined(__KERNEL__)
  cmsg_state->cm = CMSG_NXTHDR(cmsg_state->msg, cmsg_state->cm);
#else
  /* space has been already checked so just updating ptr */
  cmsg_state->cm = (struct cmsghdr*)(((char*)(cmsg_state->cm))
      + (CMSG_ALIGN(cmsg_state->cm->cmsg_len)));
#endif
}


struct llap_data {
  ci_hwport_id_t hwport;
  ci_uint16 vlan_id;
  const uint8_t* mac;
  int ifindex;
};
static int/*bool*/
llap_vs_pktinfo(struct oo_cplane_handle* cp,
                cicp_llap_row_t* llap,
                void* llap_data)
{
  struct llap_data* l = llap_data;
  if( oo_cp_llap_params_check(llap, l->hwport, l->vlan_id, l->mac) ) {
    l->ifindex = llap->ifindex;
    return 1;
  }
  return 0;
}

ci_ifid_t ci_rx_pkt_ifindex(ci_netif* ni, const ci_ip_pkt_fmt* pkt)
{
  int ifindex = 0;
  struct llap_data l = {
    .hwport = ni->state->intf_i_to_hwport[pkt->intf_i],
    .vlan_id = pkt->vlan,
    .mac = oo_ether_hdr_const(pkt)->ether_dhost,
  };

  if( l.mac[0] == 1 && l.mac[1] == 0 && l.mac[2] == 0x5e )
    l.mac = NULL;

  /* First of all, we look up the local IP address.
   * If the llap_data matches, then we have the answer.
   * It is the only way to handle ipvlan interfaces.  */
  if( ! IS_AF_INET6(oo_pkt_af(pkt)) ) {
    if( oo_cp_find_llap_by_ip(ni->cplane, RX_PKT_DADDR(pkt).ip4,
                              llap_vs_pktinfo, &l) )
      return l.ifindex;
  }
#if CI_CFG_IPV6
  else {
    if( oo_cp_find_llap_by_ip6(ni->cplane, RX_PKT_DADDR(pkt).ip6,
                              llap_vs_pktinfo, &l) )
      return l.ifindex;
  }
#endif

  /* If the local IP address is misleading (it may happen!), then we look
   * up by the llap_data.
   *
   * oo_cp_hwport_vlan_to_ifindex() may provide wrong information for incoming
   * multicast packets when there are multiple macvlan interfaces in the same
   * net namespace, or basic and macvlan interface in the same net namespace.
   * See bug 72886 for details. */
  ifindex = oo_cp_hwport_vlan_to_ifindex(ni->cplane,
                                         l.hwport, l.vlan_id, l.mac);
  if( ifindex <= 0 ) {
    LOG_E(ci_log("%s: oo_cp_hwport_vlan_to_ifindex(intf_i=%d => hwport=%d, "
                 "vlan_id=%d mac="CI_MAC_PRINTF_FORMAT" ) failed",
                 __FUNCTION__, pkt->intf_i, l.hwport, l.vlan_id,
                 CI_MAC_PRINTF_ARGS(l.mac)));
  }

  return ifindex;
}


#ifndef __KERNEL__

/**
 * Put an IP_PKTINFO or IPV6_PKTINFO control message into msg ancillary data buffer.
 */
static void ip_cmsg_recv_pktinfo(ci_netif* netif, ci_udp_state* us,
                                 const ci_ip_pkt_fmt* pkt, int af_info,
                                 struct cmsg_state *cmsg_state)
{
  ci_addr_t addr = RX_PKT_DADDR(pkt);
  int ifindex;

  /* If the last packet was the same, then we can use the caches info */
  if( pkt->intf_i == us->ip_pktinfo_cache.intf_i &&
      pkt->vlan == us->ip_pktinfo_cache.vlan &&
      af_info == us->ip_pktinfo_cache.af &&
      CI_IPX_ADDR_EQ(addr, us->ip_pktinfo_cache.daddr) &&
      memcmp(oo_ether_hdr_const(pkt)->ether_dhost,
             us->ip_pktinfo_cache.dmac, ETH_ALEN) == 0) {
    if( af_info == AF_INET )
      ci_put_cmsg(cmsg_state, IPPROTO_IP, IP_PKTINFO, sizeof(struct in_pktinfo),
                  &us->ip_pktinfo_cache.ipx_pktinfo.ipi);
#if CI_CFG_IPV6
    else
      ci_put_cmsg(cmsg_state, IPPROTO_IPV6, IPV6_PKTINFO,
                  sizeof(struct ci_in6_pktinfo),
                  &us->ip_pktinfo_cache.ipx_pktinfo.ipi6);
#endif
    return;
  }

  ifindex = ci_rx_pkt_ifindex(netif, pkt);

  if( af_info == AF_INET ) {
    struct in_pktinfo info;

    info.ipi_addr.s_addr = addr.ip4;
    info.ipi_ifindex = ifindex;

    /* RFC1122: The specific-destination address is defined to be the
    * destination address in the IP header unless the header contains a
    * broadcast or multicast address, in which case the specific-destination
    * is an IP address assigned to the physical interface on which the
    * datagram arrived.
    *
    * Onload does not work with broadcast (?), so we check for multicast
    * only.
    */
    if( CI_IP_IS_MULTICAST(oo_ip_hdr_const(pkt)->ip_daddr_be32) ) {
      info.ipi_spec_dst.s_addr = oo_cp_ifindex_to_ip(netif->cplane,
                                                    info.ipi_ifindex);
    }
    else
      info.ipi_spec_dst.s_addr = oo_ip_hdr_const(pkt)->ip_daddr_be32;

    ci_put_cmsg(cmsg_state, IPPROTO_IP, IP_PKTINFO, sizeof(info), &info);
    memcpy(&us->ip_pktinfo_cache.ipx_pktinfo.ipi, &info, sizeof(info));
  }
#if CI_CFG_IPV6
  else {
    struct ci_in6_pktinfo info;

    memcpy(info.ipi6_addr.s6_addr, &addr, sizeof(info.ipi6_addr.s6_addr));
    info.ipi6_ifindex = ifindex;
    ci_put_cmsg(cmsg_state, IPPROTO_IPV6, IPV6_PKTINFO, sizeof(info), &info);
    memcpy(&us->ip_pktinfo_cache.ipx_pktinfo.ipi6, &info, sizeof(info));
  }
#endif

  /* Cache the info: */
  us->ip_pktinfo_cache.intf_i = pkt->intf_i;
  us->ip_pktinfo_cache.vlan = pkt->vlan;
  us->ip_pktinfo_cache.daddr = addr;
  us->ip_pktinfo_cache.af = af_info;
  memcpy(&us->ip_pktinfo_cache.dmac, oo_ether_hdr_const(pkt)->ether_dhost,
         ETH_ALEN);
}

/**
 * Put an IP_RECVTTL or IPV6_RECVHOPLIMIT control message into msg ancillary
 * data buffer.
 */
ci_inline void ip_cmsg_recv_ttl_hoplimit(const ci_ip_pkt_fmt *pkt,
                                         unsigned flags,
                                         struct cmsg_state *cmsg_state)
{
  WITH_CI_CFG_IPV6( int af = oo_pkt_af(pkt); )
  int ttl = ipx_hdr_ttl(af, oo_ipx_hdr(pkt));

#if CI_CFG_IPV6
  if( IS_AF_INET6(af) ) {
    if( flags & CI_IPV6_CMSG_HOPLIMIT )
      ci_put_cmsg(cmsg_state, IPPROTO_IPV6, IPV6_HOPLIMIT, sizeof(ttl), &ttl);
  }
  else
#endif
  {
    if( flags & CI_IP_CMSG_TTL )
      ci_put_cmsg(cmsg_state, IPPROTO_IP, IP_TTL, sizeof(ttl), &ttl);
  }
}

/**
 * Put an IP_RECVTOS or IPV6_RECVTCLASS control message into msg ancillary
 * data buffer.
 */
ci_inline void ip_cmsg_recv_tos_tclass(const ci_ip_pkt_fmt *pkt,
                                       unsigned flags,
                                       struct cmsg_state *cmsg_state)
{
  int af = oo_pkt_af(pkt);
  int tos = ipx_hdr_tos_tclass(af, oo_ipx_hdr(pkt));

#if CI_CFG_IPV6
  if( IS_AF_INET6(af) ) {
    if( flags & CI_IPV6_CMSG_TCLASS )
      ci_put_cmsg(cmsg_state, IPPROTO_IPV6, IPV6_TCLASS, sizeof(tos), &tos);
  }
  else
#endif
  {
    if( flags & CI_IP_CMSG_TOS )
      ci_put_cmsg(cmsg_state, IPPROTO_IP, IP_TOS, sizeof(tos), &tos);
  }
}

/**
 * Put a SO_TIMESTAMP control message into msg ancillary data buffer.
 */
void ip_cmsg_recv_timestamp(ci_netif *ni, ci_uint64 timestamp, 
                                      struct cmsg_state *cmsg_state)
{
  struct timespec ts;
  struct timeval tv;

  ci_udp_compute_stamp(ni, timestamp, &ts);
  tv.tv_sec = ts.tv_sec;
  tv.tv_usec = ts.tv_nsec / 1000;

  ci_put_cmsg(cmsg_state, SOL_SOCKET, SO_TIMESTAMP, sizeof(tv), &tv);
}

/**
 * Put a SO_TIMESTAMPNS control message into msg ancillary data buffer.
 */
void ip_cmsg_recv_timestampns(ci_netif *ni, ci_uint64 timestamp, 
                                        struct cmsg_state *cmsg_state)
{
  struct timespec ts;

  ci_udp_compute_stamp(ni, timestamp, &ts);

  ci_put_cmsg(cmsg_state, SOL_SOCKET, SO_TIMESTAMPNS, sizeof(ts), &ts);
}


#if CI_CFG_TIMESTAMPING
/**
 * Put a SO_TIMESTAMPING control message into msg ancillary data buffer.
 */
void ip_cmsg_recv_timestamping(ci_netif *ni, const ci_ip_pkt_fmt *pkt,
                               int flags, struct cmsg_state *cmsg_state)
{
  if( flags & ONLOAD_SOF_TIMESTAMPING_ONLOAD ) {
    struct onload_timestamp ts[ONLOAD_TIMESTAMPING_FLAG_RX_COUNT];
    int n = 0;

    if( flags & ONLOAD_TIMESTAMPING_FLAG_RX_NIC ) {
      ci_assert_lt(n, ONLOAD_TIMESTAMPING_FLAG_RX_COUNT);
      ci_rx_pkt_timestamp_nic(pkt, &ts[n++]);
    }
    if( flags & ONLOAD_TIMESTAMPING_FLAG_RX_CPACKET ) {
      ci_assert_lt(n, ONLOAD_TIMESTAMPING_FLAG_RX_COUNT);
      ci_rx_pkt_timestamp_cpacket(pkt, &ts[n++]);
    }

    ci_put_cmsg(cmsg_state, SOL_SOCKET, ONLOAD_SO_TIMESTAMPING,
                n * sizeof(ts[0]), &ts);
  }
  else if( (flags & (ONLOAD_SOF_TIMESTAMPING_RAW_HARDWARE |
                     ONLOAD_SOF_TIMESTAMPING_SYS_HARDWARE |
                     ONLOAD_SOF_TIMESTAMPING_SOFTWARE)) ) {
    struct {
      struct timespec swtime;
      struct timespec hwtimesys;
      struct timespec hwtimeraw;
    } ts;

    memset(&ts, 0, sizeof(ts));
    if( flags & ONLOAD_SOF_TIMESTAMPING_SOFTWARE && pkt->tstamp_frc != 0 )
      ci_udp_compute_stamp(ni, pkt->tstamp_frc, &ts.swtime);

    struct onload_timestamp ots;
    struct timespec nic;
    ci_rx_pkt_timestamp_nic(pkt, &ots);
    onload_timestamp_to_timespec(&ots, &nic);

    if( flags & ONLOAD_SOF_TIMESTAMPING_SYS_HARDWARE &&
        nic.tv_nsec & CI_IP_PKT_HW_STAMP_FLAG_IN_SYNC )
      ts.hwtimesys = nic;

    if( flags & ONLOAD_SOF_TIMESTAMPING_RAW_HARDWARE )
      ts.hwtimeraw = nic;

    ci_put_cmsg(cmsg_state, SOL_SOCKET, ONLOAD_SO_TIMESTAMPING, sizeof(ts), &ts);
  }
}
#endif

void ci_ip_cmsg_finish(struct cmsg_state* cmsg_state)
{
#ifndef NEED_A_WORKAROUND_FOR_GLIBC_BUG_13500
  /* This is to ensure that a client unaware of the bug
   * will not miss last cmsg.
   */
  if( (cmsg_state->cm) &&
      ( ((char*)((&cmsg_state->cm->cmsg_len) + 1))
          - ((char*)cmsg_state->msg->msg_control)
        <= cmsg_state->msg->msg_controllen ) )
    cmsg_state->cm->cmsg_len = 0;
#endif

  cmsg_state->msg->msg_controllen = cmsg_state->cmsg_bytes_used;
}

/**
 * Fill in the msg ancillary data buffer with all control messages
 * according to cmsg_flags the user has set beforehand.
 */
void ci_ip_cmsg_recv(ci_netif* ni, ci_udp_state* us, const ci_ip_pkt_fmt *pkt,
                     struct msghdr *msg, int netif_locked, int *p_msg_flags)
{
  unsigned flags = us->s.cmsg_flags;
  struct cmsg_state cmsg_state;
  int af = oo_pkt_af(pkt);

  cmsg_state.msg = msg;
  cmsg_state.cmsg_bytes_used = 0;
  cmsg_state.cm = CMSG_FIRSTHDR(msg);
  cmsg_state.p_msg_flags = p_msg_flags;

  if( pkt->flags & CI_PKT_FLAG_INDIRECT )
    pkt = PKT_CHK_NML(ni, pkt->frag_next, netif_locked);

  if( (af == AF_INET) && (flags & CI_IP_CMSG_PKTINFO) ) {
    ++us->stats.n_rx_pktinfo;
    ip_cmsg_recv_pktinfo(ni, us, pkt, af, &cmsg_state);
  }
#if CI_CFG_IPV6
  /* If IPv6 socket with both enabled IP_PKTINFO and IPV6_RECVPKTINFO options
   * receives IPv4 packet, it returns both control messages. The in6_pktinfo
   * message contains IPv4-mapped IPv6 address.
   */
  if( flags & CI_IPV6_CMSG_PKTINFO ) {
    ++us->stats.n_rx_pktinfo;
    ip_cmsg_recv_pktinfo(ni, us, pkt, AF_INET6, &cmsg_state);
  }
#endif

  if( flags & (CI_IP_CMSG_TTL | CI_IPV6_CMSG_HOPLIMIT) )
    ip_cmsg_recv_ttl_hoplimit(pkt, flags, &cmsg_state);

  if( flags & (CI_IP_CMSG_TOS | CI_IPV6_CMSG_TCLASS) )
    ip_cmsg_recv_tos_tclass(pkt, flags, &cmsg_state);

  if( flags & CI_IP_CMSG_TIMESTAMPNS )
    ip_cmsg_recv_timestampns(ni, pkt->tstamp_frc, &cmsg_state);
  else /* SO_TIMESTAMP gets ignored when SO_TIMESTAMPNS one is set */
    if( flags & CI_IP_CMSG_TIMESTAMP )
      ip_cmsg_recv_timestamp(ni, pkt->tstamp_frc, &cmsg_state);

#if CI_CFG_TIMESTAMPING
  if( flags & CI_IP_CMSG_TIMESTAMPING )
    ip_cmsg_recv_timestamping(ni, pkt, us->s.timestamping_flags, &cmsg_state);
#endif

  ci_ip_cmsg_finish(&cmsg_state);
}

#endif /* !__KERNEL__ */


/**
 * Find out all control messages the user has provided with msg.
 *
 * \param info_out    Must be a valid pointer. Contains a pointer to
 * struct in_pktinfo or struct in6_pktinfo.
 */
int ci_ip_cmsg_send(const struct msghdr* msg, void** info_out)
{
  struct cmsghdr *cmsg;

  /* NB. I don't think CMSG_NXTHDR() modifies [*msg], but for some
   * reason it takes a non-const arg.
   */
  for( cmsg = CMSG_FIRSTHDR(msg); cmsg;
       cmsg = CMSG_NXTHDR((struct msghdr*) msg, cmsg) ) {

    if( cmsg->cmsg_len < sizeof(struct cmsghdr) ||
        (socklen_t)(((char*)cmsg - (char*)msg->msg_control)
                    + cmsg->cmsg_len) > msg->msg_controllen )
      return -EINVAL;

#if CI_CFG_IPV6
    if( cmsg->cmsg_level == IPPROTO_IPV6 ) {
      if( cmsg->cmsg_type == IPV6_PKTINFO ) {
        if( cmsg->cmsg_len != CMSG_LEN(sizeof(struct ci_in6_pktinfo)) )
          return -EINVAL;
        *info_out = CMSG_DATA(cmsg);
      }
      else
        return -EINVAL;
    }
    else
#endif
    if( cmsg->cmsg_level == IPPROTO_IP ) {
      if( cmsg->cmsg_type == IP_RETOPTS )
        /* TODO: implementation required */
        return -ENOPROTOOPT;
      if( cmsg->cmsg_type == IP_PKTINFO ) {
        if (cmsg->cmsg_len != CMSG_LEN(sizeof(struct in_pktinfo)))
          return -EINVAL;
        *info_out = CMSG_DATA(cmsg);
      }
      else
        return -EINVAL;
    }
  }

  return 0;
}

/*! \cidoxg_end */
