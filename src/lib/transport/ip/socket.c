/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2010-2020 Xilinx, Inc. */
/************************************************************************** \
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  ci_sock_cmn routines.
**   \date  2010/11/22
**    \cop  (c) Solarflare Communications, Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */
#include "ip_internal.h"


void ci_sock_cmn_reinit(ci_netif* ni, ci_sock_cmn* s)
{
  s->so_error = 0;

  s->tx_errno = EPIPE;
  s->rx_errno = ENOTCONN;
  ci_ip_cache_init(&s->pkt, AF_INET);

  s->s_flags &= ~(CI_SOCK_FLAG_FILTER | CI_SOCK_FLAG_STACK_FILTER |
                  CI_SOCK_FLAG_SCALPASSIVE);
  ci_assert_nflags(s->s_flags, CI_SOCK_FLAG_SCALACTIVE);
}


void oo_sock_cplane_init(struct oo_sock_cplane* cp)
{
  cp->laddr = ip4_addr_any;
  cp->lport_be16 = 0;
  cp->so_bindtodevice = CI_IFID_BAD;
  cp->ip_multicast_if = CI_IFID_BAD;
  cp->ip_multicast_if_laddr_be32 = 0;
  cp->ip_ttl = -1;
  cp->ip_mcast_ttl = 1;
#if CI_CFG_IPV6
  cp->hop_limit = -1;
#endif
  cp->ip_tos = CI_IP_DFLT_TOS;
  cp->sock_cp_flags = 0;
}


void ci_sock_cmn_init(ci_netif* ni, ci_sock_cmn* s, int can_poison)
{
  oo_p sp;

  /* Poison. */
  CI_DEBUG(
  if( can_poison )
    memset(&s->b + 1, 0xf0, (char*) (s + 1) - (char*) (&s->b + 1));
  )

  citp_waitable_reinit(ni, &s->b);
  oo_sock_cplane_init(&s->cp);

#if CI_CFG_IPV6
  s->cp.tclass = CI_IPV6_DFLT_TCLASS;
#endif

  s->s_flags = CI_SOCK_FLAG_CONNECT_MUST_BIND | CI_SOCK_FLAG_PMTU_DO
               WITH_CI_CFG_IPV6( | CI_SOCK_FLAG_IP6_PMTU_DO );
  s->s_aflags = 0u;

  ci_assert_equal( 0, CI_IP_DFLT_TOS );
  s->so_priority = 0;

  /* SO_SNDBUF & SO_RCVBUF.  See also ci_tcp_set_established_state() which
   * may modify these values.
   */
  memset(&s->so, 0, sizeof(s->so));
  s->so.sndbuf = NI_OPTS(ni).tcp_sndbuf_def;
  s->so.rcvbuf = NI_OPTS(ni).tcp_rcvbuf_def;

  s->rx_bind2dev_ifindex = CI_IFID_BAD;
  /* These don't really need to be initialised, as only significant when
   * rx_bind2dev_ifindex != CI_IFID_BAD.  But makes stackdump output
   * cleaner this way...
   */
  s->rx_bind2dev_hwports = 0;
  s->rx_bind2dev_vlan = 0;

  s->cmsg_flags = 0u;
#if CI_CFG_TIMESTAMPING
  s->timestamping_flags = 0u;
#endif
  s->os_sock_status = OO_OS_STATUS_TX;

#if CI_CFG_IPV6
  {
    ci_uint32 auto_flowlabels = NI_OPTS(ni).auto_flowlabels;
    if( auto_flowlabels == CITP_IP6_AUTO_FLOW_LABEL_OPTOUT ||
        auto_flowlabels == CITP_IP6_AUTO_FLOW_LABEL_FORCED )
      s->s_flags |= (CI_SOCK_FLAG_AUTOFLOWLABEL_REQ |
                     CI_SOCK_FLAG_AUTOFLOWLABEL_OPT );
    else
      s->s_flags &= ~(CI_SOCK_FLAG_AUTOFLOWLABEL_REQ |
                      CI_SOCK_FLAG_AUTOFLOWLABEL_OPT );
  }
#endif

  ci_sock_cmn_reinit(ni, s);

  sp = oo_sockp_to_statep(ni, SC_SP(s));
  OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_sock_cmn, reap_link));
  ci_ni_dllist_link_init(ni, &s->reap_link, sp, "reap");
  ci_ni_dllist_self_link(ni, &s->reap_link);

  /* Not functionally necessary, but avoids garbage addresses in stackdump. */
  sock_laddr_be32(s) = sock_raddr_be32(s) = 0;
  sock_lport_be16(s) = sock_rport_be16(s) = 0;
}


void ci_sock_cmn_dump(ci_netif* ni, ci_sock_cmn* s, const char* pf,
                      oo_dump_log_fn_t logger, void* log_arg)
{
  logger(log_arg, "%s  uid=%d"CI_DEBUG(" pid=%d")
         " s_flags: "CI_SOCK_FLAGS_FMT, pf,
         (int) s->uuid CI_DEBUG_ARG((int)s->pid),
         CI_SOCK_FLAGS_PRI_ARG(s));
  logger(log_arg, "%s  rcvbuf=%d sndbuf=%d", pf, s->so.rcvbuf, s->so.sndbuf);
  logger(log_arg, "%s  rcvtimeo_ms=%d sndtimeo_ms=%d sigown=%d "
         "cmsg="OO_CMSG_FLAGS_FMT,
         pf, s->so.rcvtimeo_msec, s->so.sndtimeo_msec, s->b.sigown,
         OO_CMSG_FLAGS_PRI_ARG(s->cmsg_flags));
  logger(log_arg, "%s  bindtodev=%d(%d,0x%x:%d) ttl=%d "OO_SCP_FLAGS_FMT,
         pf, s->cp.so_bindtodevice,
         s->rx_bind2dev_ifindex, s->rx_bind2dev_hwports,
         s->rx_bind2dev_vlan, s->cp.ip_ttl,
         OO_SCP_FLAGS_ARG(s->cp.sock_cp_flags));
  logger(log_arg, "%s  rx_errno=%x tx_errno=%x so_error=%d os_sock=%u%s%s", pf,
         s->rx_errno, s->tx_errno, s->so_error,
         s->os_sock_status >> OO_OS_STATUS_SEQ_SHIFT,
         (s->os_sock_status & OO_OS_STATUS_RX) ? ",RX":"",
         (s->os_sock_status & OO_OS_STATUS_TX) ? ",TX":"");

  if( s->b.ready_lists_in_use != 0 ) {
    ci_uint32 tmp, i;
    CI_READY_LIST_EACH(s->b.ready_lists_in_use, tmp, i)
      logger(log_arg, "%s  epoll3: ready_list_id %d", pf, i);
  }
}


void ci_ipcache_set_saddr(ci_ip_cached_hdrs* ipcache, ci_addr_t addr)
{
#if CI_CFG_IPV6
  if( ipcache_is_ipv6(ipcache) ) {
    memcpy(ipcache->ipx.ip6.saddr, addr.ip6, sizeof(ci_ip6_addr_t));
  } else
#endif
  {
    ipcache->ipx.ip4.ip_saddr_be32 = addr.ip4;
  }
}

void ci_ipcache_set_daddr(ci_ip_cached_hdrs* ipcache, ci_addr_t addr)
{
#if CI_CFG_IPV6
  if( ipcache_is_ipv6(ipcache) ) {
    memcpy(ipcache->ipx.ip6.daddr, addr.ip6, sizeof(ci_ip6_addr_t));
  } else
#endif
  {
    ipcache->ipx.ip4.ip_daddr_be32 = addr.ip4;
  }
}

void ci_sock_set_laddr_port(ci_sock_cmn* s, ci_addr_t addr, ci_uint16 port)
{
  ci_sock_set_laddr(s, addr);
  sock_lport_be16(s) = port;
}

void ci_sock_set_raddr_port(ci_sock_cmn* s, ci_addr_t addr, ci_uint16 port)
{
  ci_sock_set_raddr(s, addr);
  sock_rport_be16(s) = port;
}


ci_addr_t sock_laddr(ci_sock_cmn* s)
{
  return s->laddr;
}


ci_addr_t sock_raddr(ci_sock_cmn* s)
{
#if CI_CFG_IPV6
  if( ipcache_is_ipv6(&s->pkt) ) {
    ci_addr_t addr;
    memcpy(addr.ip6, sock_ip6_raddr(s), sizeof(addr.ip6));
    return addr;
  }
  else
#endif
  {
    return CI_ADDR_FROM_IP4(sock_raddr_be32(s));
  }
}


#if CI_CFG_IPV6
ci_inline void ci_init_ipcache_ipx_hdr(ci_sock_cmn* s, int af_to)
{
  ci_uint8 protocol;
  int af_from = (af_to == AF_INET6) ? AF_INET : AF_INET6;

#ifndef NDEBUG
  if (af_to == AF_INET6)
    ci_assert_equal(ipcache_is_ipv6(&s->pkt), 0);
  else
    ci_assert_nequal(ipcache_is_ipv6(&s->pkt), 0);
#endif

  protocol = ipx_hdr_protocol(af_from, &s->pkt.ipx);

  if (af_to == AF_INET6) {
    s->pkt.ether_type = CI_ETHERTYPE_IP6;
    memset(&s->pkt.ipx.ip6, 0, sizeof(s->pkt.ipx.ip6));
  }
  else {
    s->pkt.ether_type = CI_ETHERTYPE_IP;
    memset(&s->pkt.ipx.ip4, 0, sizeof(s->pkt.ipx.ip4));
  }

  ci_ipx_hdr_init_fixed(&s->pkt.ipx, af_to, protocol,
                        sock_cp_ttl_hoplimit(af_to, &s->cp),
                        sock_tos_tclass(af_to, &s->cp));
}

void ci_init_ipcache_ip4_hdr(ci_sock_cmn* s)
{
  ci_init_ipcache_ipx_hdr(s, AF_INET);
}

void ci_init_ipcache_ip6_hdr(ci_sock_cmn* s)
{
  ci_init_ipcache_ipx_hdr(s, AF_INET6);
}
#endif
