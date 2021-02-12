/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr/ctk
**  \brief  TCP connection routines:
**          accept, bind, close, connect, shutdown, getpeername
**   \date  2003/06/03
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */
  
#include "ip_internal.h"
#include <onload/common.h>
#include <onload/sleep.h>

#ifndef __KERNEL__
#include <ci/internal/efabcfg.h>
#endif

#if OO_DO_STACK_POLL
#define VERB(x)

#define LPF "tcp_connect: "




#if !defined(__KERNEL__) || CI_CFG_ENDPOINT_MOVE
/* TCP connect() implementation is not needed in-kernel except for loopback */

#ifndef __KERNEL__
/*!
 * Tests for valid sockaddr & sockaddr length & AF_INET or AF_INET6.
 */
static int ci_tcp_validate_sa( sa_family_t domain, 
                               const struct sockaddr* sa, socklen_t sa_len )
{
  /*
   * Linux deviates from documented behaviour here;
   * On Linux we return EINVAL if sa and sa_len are NULL and 0 respectively,
   *      and we return EFAULT if sa is NULL and sa_len != 0....
   */
  if( !sa ) {
    LOG_U(ci_log(LPF "invalid sockaddr : sa = %lx, sa_len = %d",
	      (long) sa, sa_len));
    if( sa_len == 0 )
      RET_WITH_ERRNO( EINVAL );
    else
      RET_WITH_ERRNO( EFAULT );
  }

  if( sa_len < sizeof(struct sockaddr_in) 
#if CI_CFG_FAKE_IPV6
      || (domain == AF_INET6 && sa_len < SIN6_LEN_RFC2133)
#endif
      ) {
    LOG_U( ci_log(LPF "struct too short to be sockaddr_in(6)" ));
    RET_WITH_ERRNO( EINVAL );
  }

  /* It should be sa->sa_family, but MS wdm does not understand it,
   * so let's use CI_SIN(sa)->sin_family. */
  if (CI_SIN(sa)->sin_family != domain && 
      CI_SIN(sa)->sin_family != AF_UNSPEC) {
    LOG_U(ci_log(LPF "address family %d does not match "
                 "with socket domain %d", CI_SIN(sa)->sin_family, domain));
    RET_WITH_ERRNO(EAFNOSUPPORT);
  }

#if CI_CFG_FAKE_IPV6 && !CI_CFG_IPV6
  if (sa->sa_family == AF_INET6 && !ci_tcp_ipv6_is_ipv4(sa)) {
    LOG_TC(ci_log(LPF "Pure IPv6 address is not supported"));
    RET_WITH_ERRNO(EAFNOSUPPORT);
  }
#endif 
  return 0;
}
#endif


/* The flags and state associated with bind are complex.  This function
 * provides a basic consistency check on the enabled flags.
 */
ci_inline void ci_tcp_bind_flags_assert_valid(ci_sock_cmn* s)
{
  if( s->s_flags & CI_SOCK_FLAG_DEFERRED_BIND ) {
    /* If we deferred the bind we need to know that we should bind later */
    ci_assert( s->s_flags & CI_SOCK_FLAG_CONNECT_MUST_BIND );

    /* We can only defer bind in cases where the application doesn't bind to
     * a specific port.
     */
    ci_assert( s->s_flags & ~CI_SOCK_FLAG_PORT_BOUND );
  }
}

/* Bind a TCP socket, performing an OS socket bind if necessary.
 * \param ni       Stack
 * \param s        Socket to be bound
 * \param fd       File descriptor (unused in kernel)
 * \param ci_addr_t     Local address to which to bind
 * \param port_be16     [in] requested port [out] assigned port
 * \param may_defer Whether OS socket bind can be deferred
 * \return         0 - success & [port_be16] updated
 *                 CI_SOCKET_HANDOVER, Pass to OS, OS bound ok, (no error)
 *                 CI_SOCKET_ERROR & errno set
 */
int __ci_tcp_bind(ci_netif *ni, ci_sock_cmn *s, ci_fd_t fd,
                  ci_addr_t addr, ci_uint16* port_be16, int may_defer)
{
  int rc = 0;
  ci_uint16 user_port; /* Port number specified by user, not by OS.
                        * See bug 4015 for details */
  union ci_sockaddr_u sa_u;

  ci_assert(s->domain == AF_INET || s->domain == AF_INET6);
  ci_assert( port_be16 );
  ci_assert(s->b.state & CI_TCP_STATE_TCP ||
            s->b.state == CI_TCP_STATE_ACTIVE_WILD);
  ci_tcp_bind_flags_assert_valid(s);

  user_port = *port_be16;

  if( !(s->s_flags & CI_SOCK_FLAG_TPROXY) ) {
#if CI_CFG_TCP_SHARED_LOCAL_PORTS
    /* In active-wild mode we might not want to bind yet. */
    if( !may_defer || !NI_OPTS(ni).tcp_shared_local_ports || user_port != 0 )
#endif
    {
#if CI_CFG_FAKE_IPV6
      ci_assert(s->domain == AF_INET || s->domain == AF_INET6);
      if( s->domain == AF_INET )
        ci_make_sockaddr_from_ip4(&sa_u.sin, user_port, addr.ip4);
      else if( !CI_IS_ADDR_IP6(addr) )
        ci_make_sockaddr_in6_from_ip4(&sa_u.sin6, user_port, addr.ip4);
#if CI_CFG_IPV6
      else {
        ci_make_sockaddr_in6_from_ip6(&sa_u.sin6, user_port, (ci_uint32*)addr.ip6);
        /* Bind to link-local address requires an interface */
        sa_u.sin6.sin6_scope_id = s->cp.so_bindtodevice;
      }
#endif
#else
      ci_assert(s->domain == AF_INET);
      ci_make_sockaddr_from_ip4(&sa_u.sin, user_port, addr.ip4);
#endif

#ifdef __ci_driver__
      rc = efab_tcp_helper_bind_os_sock_kernel(netif2tcp_helper_resource(ni),
                                               SC_SP(s), &sa_u.sa,
                                               sizeof(sa_u), port_be16);
#else
      rc = ci_tcp_helper_bind_os_sock(fd, &sa_u.sa, sizeof(sa_u), port_be16);
#endif
      if( rc == 0 )
        s->s_flags &= ~(CI_SOCK_FLAG_CONNECT_MUST_BIND |
                        CI_SOCK_FLAG_DEFERRED_BIND);
    }
#if CI_CFG_TCP_SHARED_LOCAL_PORTS
    /* We can defer this bind.  We need to make an extra check for the socket
     * already having been bound.  In the non-deferred case this is enforced by
     * the binding of the OS socket, but we don't have that luxury here. */
    else if( s->s_flags & CI_SOCK_FLAG_DEFERRED_BIND ||
             ! (s->s_flags & CI_SOCK_FLAG_CONNECT_MUST_BIND) ) {
      /* Already bound. */
      CI_SET_ERROR(rc, EINVAL);
    }
    else {
      /* CI_SOCK_FLAG_DEFERRED_BIND is clear, so either we never set it
       * (meaning nobody called bind()) or we've since cleared it (meaning that
       * the deferred bind has been performed).  Only in the former case are we
       * allowed to bind now, but the latter case should have been checked by
       * the caller. */
      ci_tcp_state* c = &SOCK_TO_WAITABLE_OBJ(s)->tcp;
      ci_assert_equal(s->b.state, CI_TCP_CLOSED);
      ci_assert(~c->tcpflags & CI_TCPT_FLAG_WAS_ESTAB);
      (void) c;

      s->s_flags |= CI_SOCK_FLAG_DEFERRED_BIND;
      rc = 0;
    }
#endif
  }
  else {
    /* CI_SOCK_FLAG_TPROXY is set.  We don't use OS backing sockets for these,
     * and we don't support deferred binds either.
     */
    ci_assert_nflags(s->s_flags, CI_SOCK_FLAG_DEFERRED_BIND);
    s->s_flags &= ~CI_SOCK_FLAG_CONNECT_MUST_BIND;
  }

  /* bug1781: only do this if the earlier bind succeeded. 
   * check if we can handle this socket */
  if( rc != 0 )
    return rc;
  if( user_port != 0 )
    s->s_flags |= CI_SOCK_FLAG_PORT_BOUND;
  if( !CI_IPX_ADDR_IS_ANY(addr) )
    s->cp.sock_cp_flags |= OO_SCP_BOUND_ADDR;

#ifndef __ci_driver__
  /* We do not call bind() to alien address from in-kernel code */
  if( ! (s->s_flags & CI_SOCK_FLAG_TPROXY) && !CI_IPX_ADDR_IS_ANY(addr) &&
      ! cicp_user_addr_is_local_efab(ni, addr) )
    s->s_flags |= CI_SOCK_FLAG_BOUND_ALIEN;
#endif
  
  ci_tcp_bind_flags_assert_valid(s);
  return rc;
}


static int /*bool*/
ci_tcp_connect_check_local_dst_addr(ci_tcp_socket_listen* tls,
                                    ci_addr_t dst_addr)
{
  if( !CI_IPX_ADDR_IS_ANY(tls->s.laddr) )
    return CI_IPX_ADDR_EQ(tls->s.laddr, dst_addr);
#if CI_CFG_IPV6
  else {
    if( CI_IS_ADDR_IP6(dst_addr) )
      return CI_IS_ADDR_IP6(tls->s.laddr);
    else
      return !(tls->s.s_flags & CI_SOCK_FLAG_V6ONLY);
  }
#endif

  return 1;
}


oo_sp ci_tcp_connect_find_local_peer(ci_netif *ni, int locked,
                                     ci_addr_t dst_addr, int dport_be16)
{
  ci_tcp_socket_listen* tls;
  int i;
  oo_sp sock = OO_SP_NULL;

  if( locked ) {
    /* SW filter table look-up does not find socket in scenarios where client
     * attempts to connect with non-SF IP address to INADDR_ANY bound listening
     * socket */
    /* FIXME: make ci_netif_listener_lookup() work for unlocked stacks */
    /* FIXME: enable IPv6, bug 84048 */
    sock = ci_netif_listener_lookup(ni, CI_IS_ADDR_IP6(dst_addr) ?
                                        AF_SPACE_FLAG_IP6 : AF_SPACE_FLAG_IP4,
                                    dst_addr, dport_be16);
  }

  if( OO_SP_NOT_NULL(sock) ) {
    tls = ID_TO_TCP_LISTEN(ni, sock);
    if( ( ~tls->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN ) &&
        ( tls->s.cp.so_bindtodevice == CI_IFID_BAD ) )
      goto found;
  }

  /* Socket has not been found through SW filter table look-up.
   * Perform full search to cover the case when destination address
   * does not belong to SF interface. */

  for( i = 0; i < (int)ni->state->n_ep_bufs; ++i ) {
    citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(ni, i);
    if( wo->waitable.state != CI_TCP_LISTEN ) continue;
    if( wo->waitable.sb_aflags & CI_SB_AFLAG_ORPHAN ) continue;
    tls = SOCK_TO_TCP_LISTEN(&wo->sock);
    if( tls->s.cp.lport_be16 != dport_be16 ) continue;
    if( !ci_tcp_connect_check_local_dst_addr(tls, dst_addr) ) continue;
    if( tls->s.cp.so_bindtodevice != CI_IFID_BAD ) continue;
    goto found;
  }
  return OO_SP_NULL;

found:
  /* this is our tls - connect to it! */
  if( (int)ci_tcp_acceptq_n(tls) < tls->acceptq_max )
    return tls->s.b.bufid;
  else
    return OO_SP_INVALID;
}


#if CI_CFG_IPV6
static void ci_tcp_init_ipcache_ip4_hdr(ci_tcp_state* ts)
{
  ci_init_ipcache_ip4_hdr(&ts->s);
  memmove(&ts->s.pkt.ipx.ip4 + 1, &ts->s.pkt.ipx.ip6 + 1, sizeof(ci_tcp_hdr));
  ts->outgoing_hdrs_len -= CI_IPX_HDR_SIZE(AF_INET6) - CI_IPX_HDR_SIZE(AF_INET);

  if( CI_IS_ADDR_IP6(ts->s.cp.laddr) ) {
    ci_assert(CI_IPX_ADDR_IS_ANY(ts->s.cp.laddr));
    ts->s.cp.laddr = ip4_addr_any;
  }
}

static void ci_tcp_init_ipcache_ip6_hdr(ci_tcp_state* ts)
{
  memmove(&ts->s.pkt.ipx.ip6 + 1, &ts->s.pkt.ipx.ip4 + 1, sizeof(ci_tcp_hdr));
  ci_init_ipcache_ip6_hdr(&ts->s);
  ts->outgoing_hdrs_len += CI_IPX_HDR_SIZE(AF_INET6) - CI_IPX_HDR_SIZE(AF_INET);

  if( ! CI_IS_ADDR_IP6(ts->s.cp.laddr) ) {
    ci_assert(CI_IPX_ADDR_IS_ANY(ts->s.cp.laddr));
    ts->s.cp.laddr = addr_any;
  }
}

/*
 * Convert ipcache from IPv4 to IPv6 and backwards. We always start with IPv4,
 * but in result of socket reuse (listen+shutdown, failed connect, * etc) we
 * can get a socket in any state.
 */
void ci_tcp_ipcache_convert(int af, ci_tcp_state* ts)
{
  if( IS_AF_INET6(af) ) {
    if( !ipcache_is_ipv6(&ts->s.pkt) )
      ci_tcp_init_ipcache_ip6_hdr(ts);
  }
  else if( ipcache_is_ipv6(&ts->s.pkt) ) {
    ci_tcp_init_ipcache_ip4_hdr(ts);
  }
}
#endif


#ifndef __KERNEL__
/* check that we can handle this destination */
static int ci_tcp_connect_check_dest(citp_socket* ep, ci_addr_t dst,
                                     int dport_be16)
{
  ci_ip_cached_hdrs* ipcache = &ep->s->pkt;
  ci_addr_t src = sock_ipx_laddr(ep->s);

#if CI_CFG_IPV6
  /*
   * Socket was bound to IPv4 and connecting to IPv6 or vice versa - hand it over.
   */
  if( (ep->s->cp.sock_cp_flags & OO_SCP_BOUND_ADDR) &&
      CI_ADDR_AF(dst) != CI_ADDR_AF(ep->s->laddr) ) {
    CITP_STATS_NETIF(++ep->netif->state->stats.tcp_connect_af_mismatch);
    return CI_SOCKET_HANDOVER;
  }
  /* IPV6_V6ONLY prevents from connecting to IPv4 address */
  if( CI_ADDR_AF(dst) == AF_INET && (ep->s->s_flags & CI_SOCK_FLAG_V6ONLY) ) {
    CITP_STATS_NETIF(++ep->netif->state->stats.tcp_connect_af_mismatch);
    return CI_SOCKET_HANDOVER;
  }

  ci_tcp_ipcache_convert(CI_ADDR_AF(dst), SOCK_TO_TCP(ep->s));
#endif

  ci_sock_set_raddr_port(ep->s, dst, dport_be16);
  ci_ip_cache_invalidate(ipcache);
  cicp_user_retrieve(ep->netif, ipcache, &ep->s->cp);

  /* Control plane has selected a source address for us -- remember it. */
  if( ipcache->status != retrrc_noroute &&
      ipcache->status != retrrc_alienroute &&
      CI_IPX_ADDR_IS_ANY(src) ) {
    ci_sock_set_laddr(ep->s, ipcache_laddr(ipcache));
    ep->s->cp.laddr = ep->s->laddr;
  }

  if(CI_LIKELY( ipcache->status == retrrc_success ||
                ipcache->status == retrrc_nomac   ||
                ipcache->status < 0 )) {
    /* Onloadable. */
    if( ipcache->encap.type & CICP_LLAP_TYPE_XMIT_HASH_LAYER4 )
      /* We don't yet have a local port number, so the result of that
       * lookup may be wrong.
       */
      ci_ip_cache_invalidate(ipcache);
    return 0;
  }
#if CI_CFG_ENDPOINT_MOVE
  else if( ipcache->status == retrrc_localroute ) {
    ci_tcp_state* ts = SOCK_TO_TCP(ep->s);

    if( NI_OPTS(ep->netif).tcp_client_loopback == CITP_TCP_LOOPBACK_OFF)
      return CI_SOCKET_HANDOVER;

    ep->s->s_flags |= CI_SOCK_FLAG_BOUND_ALIEN;
    if( NI_OPTS(ep->netif).tcp_server_loopback != CITP_TCP_LOOPBACK_OFF )
      ts->local_peer = ci_tcp_connect_find_local_peer(ep->netif, 1 /* locked */,
                                                      dst, dport_be16);
    else
      ts->local_peer = OO_SP_NULL;

    if( OO_SP_NOT_NULL(ts->local_peer) ||
        NI_OPTS(ep->netif).tcp_client_loopback !=
        CITP_TCP_LOOPBACK_SAMESTACK ) {
      ipcache->flags |= CI_IP_CACHE_IS_LOCALROUTE;
      ipcache->ether_offset = 4; /* lo is non-VLAN */
      ipcache->dport_be16 = dport_be16;
      return 0;
    }
    return CI_SOCKET_HANDOVER;
  }
#endif

  return CI_SOCKET_HANDOVER;
}
#endif

#endif

static int/*bool*/
cicp_check_ipif_ifindex(struct oo_cplane_handle* cp,
                        ci_ifid_t ifindex, void* data)
{
  return ifindex == *(ci_ifid_t*)data;
}


int
ci_tcp_use_mac_filter_listen(ci_netif* ni, ci_sock_cmn* s, ci_ifid_t ifindex)
{
  int mode;

  if( NI_OPTS(ni).scalable_filter_enable == CITP_SCALABLE_FILTERS_DISABLE )
    return 0;

  mode = NI_OPTS(ni).scalable_filter_mode;
  if( (mode & CITP_SCALABLE_MODE_PASSIVE) == 0 )
    return 0;

  /* Listening sockets bound to an IP address on an interface that we have
   * a MAC filter for share that MAC filter.  Clustering setting of listening
   * socket needs to match scalable mode rss-wise. */
  if( ((NI_OPTS(ni).cluster_ignore == 1 ) ||
         ! (s->s_flags & CI_SOCK_FLAG_REUSEPORT)) ==
       !(mode & CITP_SCALABLE_MODE_RSS) ) {
    /* If we've been configured to use scalable filters on all interfaces, then
     * we can do so without further ado. */
    if( NI_OPTS(ni).scalable_filter_ifindex_passive ==
        CITP_SCALABLE_FILTERS_ALL )
      return 1;

    /* based on bind to device we might be using scalable iface */
    if( ifindex <= 0 ) {
      /* Determine which ifindex the IP address being bound to is on. */
        ifindex = NI_OPTS(ni).scalable_filter_ifindex_passive;
        return cicp_find_ifindex_by_ip(ni->cplane, sock_laddr(s),
                                       cicp_check_ipif_ifindex, &ifindex);
    }
    return (NI_OPTS(ni).scalable_filter_ifindex_passive == ifindex);
  }
  return 0;
}


#if !defined(__KERNEL__) || CI_CFG_ENDPOINT_MOVE
int ci_tcp_can_set_filter_in_ul(ci_netif *ni, ci_sock_cmn* s)
{
  if( (s->s_flags & CI_SOCK_FLAGS_SCALABLE) == 0 )
    return 0;
  if( s->b.state == CI_TCP_LISTEN )
    return 0;
  if( (s->s_flags & CI_SOCK_FLAG_REUSEPORT) != 0 )
    return 0;
  if( (s->s_flags & CI_SOCK_FLAG_SCALPASSIVE) != 0 &&
      NI_OPTS(ni).scalable_listen != CITP_SCALABLE_LISTEN_ACCELERATED_ONLY )
    return 0;

  ci_assert_nflags(s->s_flags, CI_SOCK_FLAG_FILTER);
  ci_assert_flags(s->b.state, CI_TCP_STATE_TCP);

  if( ci_tcp_is_pluginized(SOCK_TO_TCP(s)) )
    return 0;

  ci_assert_nequal(s->b.state, CI_TCP_LISTEN);
  ci_assert(!CI_IPX_ADDR_IS_ANY(sock_ipx_laddr(s)));
  ci_assert_nequal(sock_lport_be16(s), 0);
  return 1;
}
#endif


int ci_tcp_sock_set_stack_filter(ci_netif *ni, ci_sock_cmn* s)
{
  int rc;
  oo_sp sock;

  LOG_TC(log( NSS_FMT " %s", NSS_PRI_ARGS(ni, s), __FUNCTION__));
  ci_assert((s->s_flags & CI_SOCK_FLAG_STACK_FILTER) == 0);

  sock = ci_netif_filter_lookup(ni, sock_af_space(s),
                                sock_ipx_laddr(s), sock_lport_be16(s),
                                sock_ipx_raddr(s), sock_rport_be16(s),
                                sock_protocol(s));

  if( OO_SP_NOT_NULL(sock) )
    return -EADDRINUSE;

  rc = ci_netif_filter_insert(ni, SC_ID(s), sock_af_space(s),
                              sock_ipx_laddr(s), sock_lport_be16(s),
                              sock_ipx_raddr(s), sock_rport_be16(s),
                              sock_protocol(s));
  if( rc == 0 ) {
    s->s_flags |= CI_SOCK_FLAG_STACK_FILTER;
    if( (s->s_flags & CI_SOCK_FLAGS_SCALABLE) != 0 )
      CITP_STATS_NETIF_INC(ni, mac_filter_shares);
  }
  return rc;
}


void ci_tcp_sock_clear_stack_filter(ci_netif *ni, ci_tcp_state* ts)
{
  LOG_TC(log( LNT_FMT " %s", LNT_PRI_ARGS(ni, ts), __FUNCTION__));
  ci_assert((ts->s.s_flags & CI_SOCK_FLAG_STACK_FILTER) != 0);
  ci_netif_filter_remove(ni, S_ID(ts), sock_af_space(&ts->s), tcp_ipx_laddr(ts),
                         tcp_lport_be16(ts), tcp_ipx_raddr(ts),
                         tcp_rport_be16(ts), tcp_protocol(ts));
  ts->s.s_flags &= ~CI_SOCK_FLAG_STACK_FILTER;
}


/* Returns true if [a] is older than (i.e. was last used before) [b]. */
ci_inline int /*bool*/
ci_tcp_prev_seq_older(const ci_tcp_prev_seq_t* a, const ci_tcp_prev_seq_t* b)
{
  return ci_ip_time_before(a->expiry, b->expiry);
}


ci_inline ci_uint32
ci_tcp_prev_seq_initial_seqno(ci_netif* ni, const ci_tcp_prev_seq_t* prev_seq)
{
  return ci_tcp_initial_seqno(ni, prev_seq->laddr, prev_seq->lport,
                                  prev_seq->raddr, prev_seq->rport);
}


ci_inline ci_uint32
ci_tcp_prev_seq_future_isn(ci_netif* ni, const ci_tcp_prev_seq_t* prev_seq,
                           ci_iptime_t ticks)
{
  return ci_tcp_future_isn(ni, prev_seq->laddr, prev_seq->lport,
                               prev_seq->raddr, prev_seq->rport, ticks);
}


ci_inline ci_uint32
ci_tcp_prev_seq_hash1(ci_netif* ni, const ci_tcp_prev_seq_t* prev_seq)
{
  return onload_hash1(ni->state->seq_table_entries_n - 1,
                      prev_seq->laddr, prev_seq->lport,
                      prev_seq->raddr, prev_seq->rport,
                      IPPROTO_TCP);
}


ci_inline ci_uint32
ci_tcp_prev_seq_hash2(ci_netif* ni, const ci_tcp_prev_seq_t* prev_seq)
{
  return onload_hash2(prev_seq->laddr, prev_seq->lport,
                      prev_seq->raddr, prev_seq->rport,
                      IPPROTO_TCP);
}


/* Given [prev_seq], which records the last sequence number used by a
 * four-tuple, return whether it would be safe to use the clock-based ISN for
 * a reuse of that four-tuple at all times from now until the peer is
 * guaranteed to have exited TIME_WAIT. */
ci_inline int /*bool*/
ci_tcp_clock_isn_safe(ci_netif* ni, const ci_tcp_prev_seq_t* prev_seq)
{
  ci_uint32 isn_now = ci_tcp_prev_seq_initial_seqno(ni, prev_seq);
  ci_uint32 prev_seq_no = prev_seq->seq_no;
  /* We assume that all peers have 2 MSL <= 240 s.  The argument to this
   * function is in ticks, but a tick is between one and two milliseconds. */
  ci_uint32 isn_after_2msl = ci_tcp_prev_seq_future_isn
    (ni, prev_seq, NI_CONF(ni).tconst_peer2msl_time);
  return SEQ_GT(isn_now, prev_seq_no) && SEQ_GT(isn_after_2msl, prev_seq_no);
}



ci_inline void ci_tcp_prev_seq_from_ts(ci_netif* ni, const ci_tcp_state* ts,
                                       ci_tcp_prev_seq_t* prev_seq /* out */)
{
  prev_seq->laddr = tcp_ipx_laddr(ts);
  prev_seq->raddr = tcp_ipx_raddr(ts);
  prev_seq->lport = tcp_lport_be16(ts);
  prev_seq->rport = tcp_rport_be16(ts);
  prev_seq->seq_no = tcp_enq_nxt(ts) + NI_OPTS(ni).tcp_isn_offset;
  if( prev_seq->seq_no == 0 )
    prev_seq->seq_no = 1;
}


/* Insert [prev_seq_from] (copy 4-tuple and seq_no)
 * into the table at location [prev_seq]. */
ci_inline void ci_tcp_prev_seq_remember_at(ci_netif* ni,
                                           const ci_tcp_prev_seq_t* prev_seq_from,
                                           ci_tcp_prev_seq_t* prev_seq)
{
  ci_uint32 isn_now;
  prev_seq->laddr = prev_seq_from->laddr;
  prev_seq->raddr = prev_seq_from->raddr;
  prev_seq->lport = prev_seq_from->lport;
  prev_seq->rport = prev_seq_from->rport;
  prev_seq->seq_no = prev_seq_from->seq_no;

  prev_seq->expiry = ci_tcp_time_now(ni) +
                     NI_CONF(ni).tconst_peer2msl_time;

  /* In many cases clock based ISN catches with entry's seq_no sooner
   * then nominal expiry time.  Once this happen clock based ISN would be
   * good to use and the entry will no longer be needed */
  /*
                   \/ now                 \/ after_2msl(=4mins)
  isnclock  <------------------------9minutes----------------------->
              /\ after_2msl-0x80000000          /\ now-0x80000000

  possible seq_no locations, where Xs mark the no-go areas:
            XXXX|                            XXXXXXXXXXXXXXXXXXXXXXXX
                  good: new connection created at any time between 'now' and
                  after_2msl will be in the future
            X|                            XXXXXXXXXXXXXXXXXXXXXXXXXXX
               bad: peer might still be in time_wait after the wrap point,
               cannot expire before after_2msl
                                                        XXXXXXXXXXXXX
            XXXXXXXXXXXXXX| bad: mustn't expire until isnclock catches up to
                            here (i.e. in about 30 seconds)
                  XXXXXXXXXXXXXXXXXXXXXXXXXXXX| bad: similar to previous case,
                                                but can expire at after_2msl
                          XXXXXXXXXXXXXXXXXXXXXXXXXXXX| bad: same as case 2
  */
  isn_now = ci_tcp_initial_seqno(ni, prev_seq->laddr, prev_seq->lport,
                                 prev_seq->raddr, prev_seq->rport);
  if( SEQ_GT(prev_seq->seq_no, isn_now) ) {
    ci_uint32 isn_after_2msl = ci_tcp_future_isn
      (ni, prev_seq->laddr, prev_seq->lport,
       prev_seq->raddr, prev_seq->rport,
       NI_CONF(ni).tconst_peer2msl_time);
    if( SEQ_GT(isn_after_2msl, prev_seq->seq_no) ) {
      /* The clock based ISN will catch up with entry between 0 and 2msl.
       * Let's calculate exactly how much earlier this will happen
       * and adjust expiry time accordingly */
      ci_iptime_t expiry_reduce = ci_tcp_isn2tick
          (ni, isn_after_2msl - prev_seq->seq_no);
      ci_assert_ge(NI_CONF(ni).tconst_peer2msl_time, expiry_reduce);
      prev_seq->expiry -= expiry_reduce;

      ni->state->stats.tcp_seq_table_short_expiry++;
    }
  }

  ni->state->stats.tcp_seq_table_insertions++;
}


#define TCP_PREV_SEQ_DEPTH_LIMIT 16


/* Function removes route_count indexes along the look-up path.
 * [prev_seq_val] is used to generate hashes,
 * [prev_seq_entry] is pointer to the hash table entry, we'd got match with
 * [prev_seq_val] 4 tuple. */
static void
__ci_tcp_prev_seq_free(ci_netif* ni, const ci_tcp_prev_seq_t* prev_seq_val,
                                     const ci_tcp_prev_seq_t* prev_seq_entry)
{
  unsigned hash;
  unsigned hash2 = 0;
  int depth = 0;

  hash = ci_tcp_prev_seq_hash1(ni, prev_seq_val);

  do {
    ci_tcp_prev_seq_t* prev_seq = &ni->seq_table[hash];
    ci_assert_lt(hash, ni->state->seq_table_entries_n);

    ci_assert_gt(prev_seq->route_count, 0);
    --prev_seq->route_count;

    if( prev_seq == prev_seq_entry )
      return;
    if( hash2 == 0 )
      hash2 = ci_tcp_prev_seq_hash2(ni, prev_seq_val);
    hash = (hash + hash2) & (ni->state->seq_table_entries_n - 1);
    depth++;
    ci_assert_le(depth, TCP_PREV_SEQ_DEPTH_LIMIT);
    if(CI_UNLIKELY( depth > TCP_PREV_SEQ_DEPTH_LIMIT )) {
      LOG_U(ci_log("%s: reached search depth", __FUNCTION__));
      break;
    }
  } while( 1 );
}


static void
ci_tcp_prev_seq_free(ci_netif* ni, ci_tcp_prev_seq_t* prev_seq) {
  __ci_tcp_prev_seq_free(ni, prev_seq, prev_seq);
  prev_seq->laddr = addr_any;
}


/* Add the final sequence number of [ts] to a hash table so that, when reusing
 * the four-tuple, we can avoid using sequence numbers that overlap with the
 * old connection.  Some peers are more tolerant than others of such apparent
 * overlap -- Linux, for example, will consider TCP timestamps -- but we have
 * to target the lowest common denominator, as it were, meaning that we can't
 * avoid tracking the sequence number in such cases. */
static int /*bool*/
__ci_tcp_prev_seq_remember(ci_netif* ni, const ci_tcp_prev_seq_t* ts_prev_seq)
{
  unsigned hash;
  unsigned hash2 = 0;
  /* Oldest amongst the entries that we've traversed. */
  ci_tcp_prev_seq_t* oldest_seq = NULL;
  ci_tcp_prev_seq_t* prev_seq;
  
  int depth;

  /* If the clock ISN is safe, no need to remember the sequence number. */
  if( ci_tcp_clock_isn_safe(ni, ts_prev_seq) ) {
    ni->state->stats.tcp_seq_table_avoided++;
    return 0;
  }

  hash = ci_tcp_prev_seq_hash1(ni, ts_prev_seq);

  for( depth = 0; depth < TCP_PREV_SEQ_DEPTH_LIMIT; ++depth ) {
    prev_seq = &ni->seq_table[hash];
    ci_assert_lt(hash, ni->state->seq_table_entries_n);

    ci_assert_impl(CI_TCP_PREV_SEQ_IS_TERMINAL(*prev_seq),
                   CI_TCP_PREV_SEQ_IS_FREE(*prev_seq));
    ++prev_seq->route_count;
    ni->state->stats.tcp_seq_table_steps++;

    if( CI_TCP_PREV_SEQ_IS_FREE(*prev_seq) ) {
      /* Free entry.  Use it. */
      ci_tcp_prev_seq_remember_at(ni, ts_prev_seq, prev_seq);
      break;
    }
    else if( ci_ip_time_before(prev_seq->expiry, ci_ip_time_now(ni)) ) {
      /* Expired entry.  Free it and reuse it. */
      ci_tcp_prev_seq_free(ni, prev_seq);
      ci_tcp_prev_seq_remember_at(ni, ts_prev_seq, prev_seq);
      ni->state->stats.tcp_seq_table_expiries++;
      break;
    }
    else if( depth == 0 || ci_tcp_prev_seq_older(prev_seq, oldest_seq) ) {
      /* Entry is live and in use, and the oldest that we've seen so far.
       * Remember it so that we can purge the oldest if we don't find any free
       * or expired entries. */
      oldest_seq = prev_seq;
    }

    if( hash2 == 0 )
      hash2 = ci_tcp_prev_seq_hash2(ni, ts_prev_seq);
    hash = (hash + hash2) & (ni->state->seq_table_entries_n - 1);
  }

  /* If we didn't find any free entries, use the oldest up to the search
   * depth. */
  if( depth >= TCP_PREV_SEQ_DEPTH_LIMIT ) {
    ci_assert_equal(depth, TCP_PREV_SEQ_DEPTH_LIMIT);
    ci_assert(oldest_seq);
    /* rollback all route count updates we made above */
    __ci_tcp_prev_seq_free(ni, ts_prev_seq, prev_seq);
    /* purge the oldest entry */
    ci_tcp_prev_seq_free(ni, oldest_seq);
    ni->state->stats.tcp_seq_table_purgations++;
    /* redo insertion, now it will succeed with free entry */
    __ci_tcp_prev_seq_remember(ni, ts_prev_seq);
  }

  return 1;
}


static ci_tcp_prev_seq_t*
__ci_tcp_prev_seq_lookup(ci_netif* ni, const ci_tcp_prev_seq_t* ts_prev_seq)
{
  unsigned hash = ci_tcp_prev_seq_hash1(ni, ts_prev_seq);
  unsigned hash2 = 0;
  int depth;

  for( depth = 0; depth < TCP_PREV_SEQ_DEPTH_LIMIT; ++depth ) {
    ci_tcp_prev_seq_t* prev_seq = &ni->seq_table[hash];
    ci_assert_lt(hash, ni->state->seq_table_entries_n);

    if( CI_TCP_PREV_SEQ_IS_TERMINAL(*prev_seq) ) {
      return NULL;
    }
    if( CI_IPX_ADDR_EQ(prev_seq->laddr, ts_prev_seq->laddr) &&
        prev_seq->lport == ts_prev_seq->lport &&
        CI_IPX_ADDR_EQ(prev_seq->raddr, ts_prev_seq->raddr) &&
        prev_seq->rport == ts_prev_seq->rport )
      return prev_seq;

    if( hash2 == 0 )
      hash2 = ci_tcp_prev_seq_hash2(ni, ts_prev_seq);
    hash = (hash + hash2) & (ni->state->seq_table_entries_n - 1);
  }

  return NULL;
}


ci_uint32 ci_tcp_prev_seq_lookup(ci_netif* ni, const ci_tcp_state* ts)
{
  ci_tcp_prev_seq_t ts_prev_seq;
  ci_tcp_prev_seq_t* prev_seq;
  ci_uint32 seq_no;
  ci_tcp_prev_seq_from_ts(ni, ts, &ts_prev_seq);
  prev_seq = __ci_tcp_prev_seq_lookup(ni, &ts_prev_seq);
  if( prev_seq == NULL )
    return 0;
  seq_no = prev_seq->seq_no;
  ci_tcp_prev_seq_free(ni, prev_seq);
  ni->state->stats.tcp_seq_table_hits++;
  return seq_no;
}


void ci_tcp_prev_seq_remember(ci_netif* ni, ci_tcp_state* ts)
{
  ci_tcp_prev_seq_t ts_prev_seq;

  if( NI_OPTS(ni).tcp_isn_mode != 1 )
    return;
  if( ! NI_OPTS(ni).tcp_isn_include_passive &&
      ts->tcpflags & CI_TCPT_FLAG_PASSIVE_OPENED )
    return;

  /* We record the final sequence number, so we must have sent a FIN.  If the
   * peer is not in TIME_WAIT, then we don't need to bother remembering the
   * sequence number.  As such, we should call this function precisely when
   * entering LAST_ACK or CLOSING. */
  if( ts->s.b.state != CI_TCP_CLOSING )
    ci_assert_equal(ts->s.b.state, CI_TCP_LAST_ACK);

  ci_tcp_prev_seq_from_ts(ni, ts, &ts_prev_seq);

  if( __ci_tcp_prev_seq_remember(ni, &ts_prev_seq) )
    ts->tcpflags |= CI_TCPT_FLAG_SEQNO_REMEMBERED;

}


#if !defined(__KERNEL__) || CI_CFG_ENDPOINT_MOVE
/* Linux clears implicit address on connect failure */
ci_inline void ci_tcp_connect_drop_implicit_address(ci_tcp_state *ts)
{
    if( ! (ts->s.cp.sock_cp_flags & OO_SCP_BOUND_ADDR) ) {
#if CI_CFG_IPV6
      if( ts->s.domain == AF_INET6 )
        ts->s.cp.laddr = ts->s.laddr = addr_any;
      else
#endif
        ts->s.cp.laddr = ts->s.laddr = ip4_addr_any;
    }
}


/* Return codes from ci_tcp_connect_ul_start(). */
#define CI_CONNECT_UL_OK                0
#define CI_CONNECT_UL_FAIL              -1
#define CI_CONNECT_UL_START_AGAIN	-2
#define CI_CONNECT_UL_LOCK_DROPPED	-3
#define CI_CONNECT_UL_ALIEN_BOUND	-4

/* The fd parameter is ignored when this is called in the kernel */
static int ci_tcp_connect_ul_start(ci_netif *ni, ci_tcp_state* ts, ci_fd_t fd,
                                   ci_addr_t dst, unsigned dport_be16,
                                   int* fail_rc)
{
  ci_ip_pkt_fmt* pkt;
  int rc = 0;
  oo_sp active_wild = OO_SP_NULL;
  ci_uint32 prev_seq = 0;
  int added_scalable = 0;
  ci_addr_t saddr;

  ci_assert(ts->s.pkt.mtu);

  ts->tcpflags &=~ CI_TCPT_FLAG_FIN_RECEIVED;

  /* Now that we know the outgoing route, set the MTU related values.
   * Note, even these values are speculative since the real MTU
   * could change between now and passing the packet to the lower layers
   */
  ts->amss = ci_tcp_amss(ni, &ts->c, &ts->s.pkt, __func__);

  /* Default smss until discovered by MSS option in SYN - RFC1122 4.2.2.6 */
  ts->smss = CI_CFG_TCP_DEFAULT_MSS;

  /* set pmtu, eff_mss, snd_buf and adjust windows */
  ci_tcp_set_eff_mss(ni, ts);
  ci_tcp_set_initialcwnd(ni, ts);

  /* Send buffer adjusted by ci_tcp_set_eff_mss(), but we want it to stay
   * zero until the connection is established.
   */
  ts->so_sndbuf_pkts = 0;

  /* Reset ka_probes if it is a second connect after failure.
   */
  ts->ka_probes = 0;

  /* 
   * 3. State and address are OK. It's address routed through our NIC.
   *    Do connect().
   */
  ci_assert(!CI_IPX_ADDR_IS_ANY(ipcache_laddr(&ts->s.pkt)));

  /* socket can only could have gotten scalative on prior
   * implicit bind */
  ci_assert_impl(ts->s.s_flags & CI_SOCK_FLAG_SCALACTIVE,
                 ~ts->s.s_flags & CI_SOCK_FLAG_CONNECT_MUST_BIND);

  if( ts->s.s_flags & CI_SOCK_FLAG_CONNECT_MUST_BIND ) {
    ci_uint16 source_be16 = 0;
    ci_sock_cmn* s = &ts->s;

    saddr = sock_ipx_laddr(s);

#if !defined(__KERNEL__) && CI_CFG_TCP_SHARED_LOCAL_PORTS
    active_wild = ci_netif_active_wild_get(ni, sock_ipx_laddr(&ts->s),
                                           sock_ipx_raddr(&ts->s),
                                           dport_be16, &source_be16, &prev_seq);
#endif

    /* Defer active_wild related state update to after potential lock drops
     * (pkt wait) */
    if( active_wild == OO_SP_NULL ) {
#if CI_CFG_TCP_SHARED_LOCAL_PORTS
      if( NI_OPTS(ni).tcp_shared_local_no_fallback )
        /* error matching exhaustion of ephemeral ports */
        CI_SET_ERROR(rc, EADDRNOTAVAIL);
      else
#endif
      if( s->cp.sock_cp_flags & OO_SCP_BOUND_ADDR )
        rc = __ci_tcp_bind(ni, &ts->s, fd, saddr, &source_be16, 0);
      else
        rc = __ci_tcp_bind(ni, &ts->s, fd, addr_any, &source_be16, 0);

      if(CI_UNLIKELY( rc != 0 )) {
        LOG_U(ci_log("__ci_tcp_bind returned %d at %s:%d", rc,
                     __FILE__, __LINE__));
        *fail_rc = rc;
        return CI_CONNECT_UL_FAIL;
      }
      if(CI_UNLIKELY( CI_IPX_ADDR_IS_ANY(saddr) )) {
        /* FIXME is this an impossible branch? */
        CI_SET_ERROR(*fail_rc, EINVAL);
        return CI_CONNECT_UL_FAIL;
      }
    }
    /* Commit source port now.  In case of failure down the lane, an implicit port
     * might be overwritten by following attempt */
    TS_IPX_TCP(ts)->tcp_source_be16 = source_be16;
    ts->s.cp.lport_be16 = source_be16;
    LOG_TC(log(LNT_FMT "connect: our bind returned " IPX_PORT_FMT,
               LNT_PRI_ARGS(ni, ts), IPX_ARG(AF_IP(saddr)),
               (unsigned) CI_BSWAP_BE16(TS_IPX_TCP(ts)->tcp_source_be16)));
  }

  /* In the normal case, we only install filters for IP addresses configured on
   * acceleratable interfaces, and so if the socket is bound to an alien
   * address, we can't accelerate it.  Using a MAC filter overcomes this
   * limitation, however. */
  if( ~ni->state->flags & CI_NETIF_FLAG_USE_ALIEN_LADDRS &&
      (ts->s.s_flags & CI_SOCK_FLAG_BOUND_ALIEN) &&
      ! (ts->s.pkt.flags & CI_IP_CACHE_IS_LOCALROUTE ||
         ts->s.s_flags & (CI_SOCK_FLAG_TPROXY | CI_SOCK_FLAG_SCALACTIVE)) ) {
    ci_assert_equal(active_wild, OO_SP_NULL);
    return CI_CONNECT_UL_ALIEN_BOUND;
  }

  /* Commit peer now - these are OK to be overwritten by following attempt */
  ci_tcp_set_peer(ts, dst, dport_be16);

  /* Make sure we can get a buffer before we change state. */
  pkt = ci_netif_pkt_tx_tcp_alloc(ni, ts);
  if( CI_UNLIKELY(! pkt) ) {
    /* Should we block or return error? */
    if( NI_OPTS(ni).tcp_nonblock_no_pkts_mode &&
        (ts->s.b.sb_aflags & (CI_SB_AFLAG_O_NONBLOCK | CI_SB_AFLAG_O_NDELAY)) ) {
      CI_SET_ERROR(*fail_rc, ENOBUFS);
      rc = CI_CONNECT_UL_FAIL;
      goto fail;
    }
    /* NB. We've already done a poll above. */
    rc = ci_netif_pkt_wait(ni, &ts->s, CI_SLEEP_NETIF_LOCKED|CI_SLEEP_NETIF_RQ);
    if( ci_netif_pkt_wait_was_interrupted(rc) ) {
      CI_SET_ERROR(*fail_rc, -rc);
      rc = CI_CONNECT_UL_LOCK_DROPPED;
      goto fail;
    }
    /* OK, there are (probably) packets available - go try again.  Note we
     * jump back to the top of the function because someone may have
     * connected this socket in the mean-time, so we need to check the
     * state once more.
     */
    rc = CI_CONNECT_UL_START_AGAIN;
    goto fail;
  }

  if( active_wild != OO_SP_NULL &&
      (ts->s.s_flags & CI_SOCK_FLAG_TPROXY) == 0 ) {
      /* Need to set the flag now for consumption by ci_tcp_ep_set_filters */
      ts->s.s_flags |= CI_SOCK_FLAG_SCALACTIVE;
      added_scalable = 1;
  }

  rc = ci_tcp_ep_set_filters(ni, S_SP(ts), ts->s.cp.so_bindtodevice,
                             active_wild);
  if( rc < 0 ) {
    /* Perhaps we've run out of filters?  See if we can push a socket out
     * of timewait and steal its filter.
     */
    ci_assert_nequal(rc, -EFILTERSSOME);
    if( rc != -EBUSY || ! ci_netif_timewait_try_to_free_filter(ni) ||
        (rc = ci_tcp_ep_set_filters(ni, S_SP(ts),
                                    ts->s.cp.so_bindtodevice,
                                    active_wild)) < 0 ) {
      ci_assert_nequal(rc, -EFILTERSSOME);
      /* Either a different error, or our efforts to free a filter did not
       * work.
       */
      if( added_scalable )
        ts->s.s_flags &= ~CI_SOCK_FLAG_SCALACTIVE; /* rollback scalactive flag */
      ci_netif_pkt_release(ni, pkt);
      CI_SET_ERROR(*fail_rc, -rc);
      rc = CI_CONNECT_UL_FAIL;
      goto fail;
    }
  }

  /* Point of no failure */

  /* Commit active_wild related flags */
  if( active_wild != OO_SP_NULL ) {
    ts->tcpflags |= CI_TCPT_FLAG_ACTIVE_WILD;
    ts->s.s_flags &= ~(CI_SOCK_FLAG_DEFERRED_BIND |
                       CI_SOCK_FLAG_CONNECT_MUST_BIND);
  }

  LOG_TC(log(LNT_FMT "CONNECT " IPX_PORT_FMT "->" IPX_PORT_FMT,
            LNT_PRI_ARGS(ni, ts),
            IPX_ARG(AF_IP(ipcache_laddr(&ts->s.pkt))),
            (unsigned) CI_BSWAP_BE16(TS_IPX_TCP(ts)->tcp_source_be16),
            IPX_ARG(AF_IP(ipcache_raddr(&ts->s.pkt))),
            (unsigned) CI_BSWAP_BE16(TS_IPX_TCP(ts)->tcp_dest_be16)));

  /* We are going to send the SYN - set states appropriately */

  /* We test prev_seq in a moment, which is always zero in the kernel, but
   * that's OK, because this function is only called in the kernel for loopback
   * connections. */

  if( NI_OPTS(ni).tcp_isn_mode == 1 ) {
    if( prev_seq == 0 ) {
      prev_seq = ci_tcp_prev_seq_lookup(ni, ts);
    }
    else {
#ifndef NDEBUG
      /* If we got a sequence number from TIME_WAIT-reuse, the table should not
       * have an entry for this four-tuple, as any such entry would now
       * necessarily be stale.  Assert this.  Use an intermediate variable to
       * avoid calling the function more than once. */
      ci_uint32 table_seq = ci_tcp_prev_seq_lookup(ni, ts);
      ci_assert_equal(table_seq, 0);
#endif
    }
  }

  if( prev_seq )
    /* We're reusing a TIME_WAIT.  We do the same as Linux, and choose the new
     * sequence number a little way from the old.
     */
    tcp_snd_nxt(ts) = prev_seq;
  else
    tcp_snd_nxt(ts) = ci_tcp_initial_seqno(ni,
                                           tcp_ipx_laddr(ts),
                                           TS_IPX_TCP(ts)->tcp_source_be16,
                                           tcp_ipx_laddr(ts),
                                           TS_IPX_TCP(ts)->tcp_dest_be16);
  tcp_snd_una(ts) = tcp_enq_nxt(ts) = tcp_snd_up(ts) = tcp_snd_nxt(ts);
  ts->snd_max = tcp_snd_nxt(ts) + 1;

  /* Must be after initialising snd_una. */
  ci_tcp_clear_rtt_timing(ts);
  ci_tcp_set_flags(ts, CI_TCP_FLAG_SYN);
  ts->tcpflags &=~ CI_TCPT_FLAG_OPT_MASK;
  ts->tcpflags |= NI_OPTS(ni).syn_opts;

  if( (ts->tcpflags & CI_TCPT_FLAG_WSCL) ) {
    if( NI_OPTS(ni).tcp_rcvbuf_mode == 1 )
      ts->rcv_wscl =
	ci_tcp_wscl_by_buff(ni, ci_tcp_max_rcvbuf(ni, ts->amss));
    else
      ts->rcv_wscl =
	ci_tcp_wscl_by_buff(ni, ci_tcp_rcvbuf_established(ni, &ts->s));
    CI_IP_SOCK_STATS_VAL_RXWSCL(ts, ts->rcv_wscl);
  }
  else {
    ts->rcv_wscl = 0;
    CI_IP_SOCK_STATS_VAL_RXWSCL(ts, 0);
  }
  ci_tcp_set_rcvbuf(ni, ts);
  TS_IPX_TCP(ts)->tcp_window_be16 = ci_tcp_calc_rcv_wnd_syn(ts->s.so.rcvbuf,
                                                        ts->amss,
                                                        ts->rcv_wscl);
  tcp_rcv_wnd_right_edge_sent(ts) = tcp_rcv_nxt(ts) +
      TS_IPX_TCP(ts)->tcp_window_be16;
  ts->rcv_wnd_advertised = TS_IPX_TCP(ts)->tcp_window_be16;
  TS_IPX_TCP(ts)->tcp_window_be16 =
      CI_BSWAP_BE16(TS_IPX_TCP(ts)->tcp_window_be16);

  /* outgoing_hdrs_len is initialised to include timestamp option. */
  if( ! (ts->tcpflags & CI_TCPT_FLAG_TSO) )
    ts->outgoing_hdrs_len = CI_IPX_HDR_SIZE(ipcache_af(&ts->s.pkt)) +
                            sizeof(ci_tcp_hdr);
  if( ci_tcp_can_stripe(ni, ts->s.pkt.ipx.ip4.ip_saddr_be32,
			ts->s.pkt.ipx.ip4.ip_daddr_be32) )
    ts->tcpflags |= CI_TCPT_FLAG_STRIPE;
  ci_tcp_set_slow_state(ni, ts, CI_TCP_SYN_SENT);

  /* If the app trys to send data on a socket in SYN_SENT state
  ** then the data is queued for send until the SYN gets ACKed.
  ** (rfc793 p56)
  **
  ** Receive calls on the socket should block until data arrives
  ** (rfc793 p58)
  **
  ** Clearing tx_errno and rx_errno acheive this. The transmit window
  ** is set to 1 byte which ensures that only the SYN packet gets
  ** sent until the ACK is received with more window. 
  */
  ci_assert(ts->snd_max == tcp_snd_nxt(ts) + 1);
  ts->s.rx_errno = 0;
  ts->s.tx_errno = 0; 
  /* If ARP resolution fails, we have to drop the connection, so we store
   * the socket id in the SYN packet. */
  pkt->pf.tcp_tx.sock_id = ts->s.b.bufid;
  ci_tcp_enqueue_no_data(ts, ni, pkt);
  ci_tcp_set_flags(ts, CI_TCP_FLAG_ACK);  

  if( ts->s.b.sb_aflags & (CI_SB_AFLAG_O_NONBLOCK | CI_SB_AFLAG_O_NDELAY) ) {
    ts->tcpflags |= CI_TCPT_FLAG_NONBLOCK_CONNECT;
    LOG_TC(log( LNT_FMT "Non-blocking connect - return EINPROGRESS",
		LNT_PRI_ARGS(ni, ts)));
    CI_SET_ERROR(*fail_rc, EINPROGRESS);
    /* We don't jump to the "fail" label here, as this is a failure only from
     * the point of view of the connect() API, and we don't want to tear down
     * the socket. */
    return CI_CONNECT_UL_FAIL;
  }

  return CI_CONNECT_UL_OK;

 fail:
  ci_tcp_connect_drop_implicit_address(ts);
  return rc;
}

ci_inline int ci_tcp_connect_handle_so_error(ci_sock_cmn *s)
{
  ci_int32 rc = ci_get_so_error(s);
  if( rc == 0 )
    return 0;
  s->rx_errno = ENOTCONN;
  return rc;
}

static int ci_tcp_connect_ul_syn_sent(ci_netif *ni, ci_tcp_state *ts)
{
  int rc = 0;

  if( ts->s.b.state == CI_TCP_SYN_SENT ) {
    ci_uint32 timeout = ts->s.so.sndtimeo_msec;

    ci_netif_poll(ni);
    if( OO_SP_NOT_NULL(ts->local_peer) ) {
      /* No reason to sleep.  Obviously, listener have dropped our syn
       * because of some reason.  Go away! */
      ci_tcp_drop(ni, ts, EBUSY);
      RET_WITH_ERRNO(EBUSY);
    }

#ifndef __KERNEL__
    /* This "if" starts and ends with the stack being locked.  It can
     * release the stack lock while spinning. */
    if( oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_TCP_CONNECT) ) {
      ci_uint64 start_frc, now_frc, schedule_frc;
      citp_signal_info* si = citp_signal_get_specific_inited();
      ci_uint64 max_spin = ts->s.b.spin_cycles;
      int stack_locked = 1;

      if( ts->s.so.sndtimeo_msec ) {
        ci_uint64 max_so_spin = (ci_uint64)ts->s.so.sndtimeo_msec *
            IPTIMER_STATE(ni)->khz;
        if( max_so_spin <= max_spin )
          max_spin = max_so_spin;
      }

      ci_frc64(&start_frc);
      schedule_frc = start_frc;
      now_frc = start_frc;

      do {
        if( ci_netif_may_poll(ni) ) {
          if( ci_netif_need_poll_spinning(ni, now_frc) ) {
            if( stack_locked || ci_netif_trylock(ni) ) {
              ci_netif_poll(ni);
              ci_netif_unlock(ni);
              stack_locked = 0;
            }
          }
          else if( ! ni->state->is_spinner )
            ni->state->is_spinner = 1;
        }
        if( ts->s.b.state != CI_TCP_SYN_SENT ) {
          ni->state->is_spinner = 0;
          if( ! stack_locked )
            ci_netif_lock(ni);
          rc = 0;
          goto out;
        }

        /* Unlock the stack to allow kernel to process ICMP */
        if( stack_locked ) {
          ci_netif_unlock(ni);
          stack_locked = 0;
        }

        ci_frc64(&now_frc);
        rc = OO_SPINLOOP_PAUSE_CHECK_SIGNALS(ni, now_frc, &schedule_frc, 
                                             ts->s.so.sndtimeo_msec, NULL, si);
        if( rc != 0 ) {
          ni->state->is_spinner = 0;
          if( ! stack_locked )
            ci_netif_lock(ni);
          goto out;
        }
#if CI_CFG_SPIN_STATS
        ni->state->stats.spin_tcp_connect++;
#endif
      } while( now_frc - start_frc < max_spin );

      ni->state->is_spinner = 0;
      if( ! stack_locked )
        ci_netif_lock(ni);

      if( timeout ) {
        ci_uint32 spin_ms = (now_frc - start_frc) / IPTIMER_STATE(ni)->khz;
        if( spin_ms < timeout )
          timeout -= spin_ms;
        else {
          if( ts->s.b.state == CI_TCP_SYN_SENT )
            rc = -EAGAIN;
          goto out;
        }
      }
    }
#endif

    CI_TCP_SLEEP_WHILE(ni, ts, CI_SB_FLAG_WAKE_RX,
                       timeout,
                       ts->s.b.state == CI_TCP_SYN_SENT, &rc); 
  }

#ifndef __KERNEL__
 out:
#endif
  if( rc == -EAGAIN ) {
    LOG_TC(log( LNT_FMT "timeout on sleep: %d",
		LNT_PRI_ARGS(ni, ts), -rc));
    if( ! (ts->tcpflags & CI_TCPT_FLAG_NONBLOCK_CONNECT) ) {
      ts->tcpflags |= CI_TCPT_FLAG_NONBLOCK_CONNECT;
      CI_SET_ERROR(rc, EINPROGRESS);
    }
    else
      CI_SET_ERROR(rc, EALREADY);
    return rc;
  }
  else if( rc == -EINTR ) {
    LOG_TC(log(LNT_FMT "connect() was interrupted by a signal", 
               LNT_PRI_ARGS(ni, ts)));
    ts->tcpflags |= CI_TCPT_FLAG_NONBLOCK_CONNECT;
    CI_SET_ERROR(rc, EINTR);
    return rc;
  }

  /*! \TODO propagate the correct error code: CONNREFUSED, NOROUTE, etc. */

  if( ts->s.b.state == CI_TCP_CLOSED ) {
    /* Bug 3558: 
     * Set OS socket state to allow/disallow next bind().
     * It is Linux hack. */
    if( ts->s.b.sb_aflags & CI_SB_AFLAG_OS_BACKED ) {
#ifdef __ci_driver__
      CI_TRY(efab_tcp_helper_set_tcp_close_os_sock(
                                                 netif2tcp_helper_resource(ni),
                                                 S_SP(ts)));
#else
      CI_TRY(ci_tcp_helper_set_tcp_close_os_sock(ni, S_SP(ts)));
#endif
    }

    /* We should re-bind socket on the next use if the port was determined by
     * OS.
     */
    if( ! (ts->s.s_flags & CI_SOCK_FLAG_PORT_BOUND) )
      ts->s.s_flags |= CI_SOCK_FLAG_CONNECT_MUST_BIND;

    /* - if SO_ERROR is set, handle it and return this value;
     * - else if rx_errno is set, return it;
     * - else (TCP_RX_ERRNO==0, socket is CI_SHUT_RD) return ECONNABORTED */
    if( (rc = ci_tcp_connect_handle_so_error(&ts->s)) == 0)
        rc = TCP_RX_ERRNO(ts) ? TCP_RX_ERRNO(ts) : ECONNABORTED;
    CI_SET_ERROR(rc, rc);

    ci_tcp_connect_drop_implicit_address(ts);
    return rc;
  }

  return 0;
}


#ifndef __KERNEL__
static int
complete_deferred_bind(ci_netif* netif, ci_sock_cmn* s, ci_fd_t fd)
{
  ci_uint16 source_be16 = 0;
  int rc;

  ci_assert_flags(s->s_flags, CI_SOCK_FLAG_DEFERRED_BIND);

  if( s->cp.sock_cp_flags & OO_SCP_BOUND_ADDR )
    rc = __ci_tcp_bind(netif, s, fd, s->laddr, &source_be16, 0);
  else
    rc = __ci_tcp_bind(netif, s, fd, addr_any, &source_be16, 0);

  if(CI_LIKELY( rc == 0 )) {
    s->s_flags &= ~(CI_SOCK_FLAG_DEFERRED_BIND |
                    CI_SOCK_FLAG_CONNECT_MUST_BIND);
    sock_lport_be16(s) = source_be16;
    s->cp.lport_be16 = source_be16;
    LOG_TC(log(NSS_FMT "Deferred bind returned " IPX_FMT " :%u",
               NSS_PRI_ARGS(netif, s),
               IPX_ARG(AF_IP(addr_any)), ntohs(sock_lport_be16(s))));
  }
  else {
    LOG_U(ci_log("__ci_tcp_bind returned %d at %s:%d", CI_GET_ERROR(rc),
                 __FILE__, __LINE__));
  }
  return rc;
}


static int
ci_tcp_retrieve_addr(ci_netif* netif, const struct sockaddr* serv_addr,
                     ci_addr_t* dst_addr, ci_uint16* dst_port)
{
  /* Address family is validated to be AF_INET or AF_INET6 earlier. */
  const struct sockaddr_in* inaddr = (struct sockaddr_in*) serv_addr;
  *dst_addr = ci_get_addr(serv_addr);
  *dst_port = inaddr->sin_port;
  int rc = 0;

  /* Only perform DNAT off of init_net */
  if( netif->cplane_init_net != NULL ) {
    ci_addr_sh_t dnat_addr = CI_ADDR_SH_FROM_ADDR(*dst_addr);
    rc = cp_svc_check_dnat(netif->cplane_init_net, &dnat_addr, dst_port);
    *dst_addr = CI_ADDR_FROM_ADDR_SH(dnat_addr);
  }
  return rc;
}


/* Returns:
 *          0                  on success
 *          
 *          CI_SOCKET_ERROR (and errno set)
 *                             this is a normal error that is returned to the
 *                             the application
 *
 *          CI_SOCKET_HANDOVER we tell the upper layers to handover, no need
 *                             to set errno since it isn't a real error
 */
int ci_tcp_connect(citp_socket* ep, const struct sockaddr* serv_addr,
		   socklen_t addrlen, ci_fd_t fd, int *p_moved)
{
  ci_sock_cmn* s = ep->s;
  ci_tcp_state* ts = &SOCK_TO_WAITABLE_OBJ(s)->tcp;
  int rc = 0, crc;
  ci_addr_t dst_addr;
  ci_uint16 dst_port;
  int /*bool*/ dnat;

  if( NI_OPTS(ep->netif).tcp_connect_handover )
    return CI_SOCKET_HANDOVER;

  /* Make sure we're up-to-date. */
  ci_netif_lock(ep->netif);
  CHECK_TEP(ep);
  ci_netif_poll(ep->netif);

  /*
   * 1. Check if state of the socket is OK for connect operation.
   */

 start_again:

  if( (rc = ci_tcp_connect_handle_so_error(s)) != 0) {
    CI_SET_ERROR(rc, rc);
    goto unlock_out;
  }

  if( s->b.state != CI_TCP_CLOSED ) {
    /* see if progress can be made on this socket before
    ** determining status  (e.g. non-blocking connect and connect poll)*/
    if( s->b.state & CI_TCP_STATE_SYNCHRONISED ) {
      if( ts->tcpflags & CI_TCPT_FLAG_NONBLOCK_CONNECT ) {
        ts->tcpflags &= ~CI_TCPT_FLAG_NONBLOCK_CONNECT;
	rc = 0;
	goto unlock_out;
      }
      if( serv_addr->sa_family == AF_UNSPEC )
        LOG_E(ci_log("Onload does not support TCP disconnect via "

                     "connect(addr->sa_family==AF_UNSPEC)"));
      CI_SET_ERROR(rc, EISCONN);
    }
    else if( s->b.state == CI_TCP_LISTEN ) {
#if CI_CFG_POSIX_CONNECT_AFTER_LISTEN
      CI_SET_ERROR(rc, EOPNOTSUPP);
#else
      if( ci_tcp_validate_sa(s->domain, serv_addr, addrlen) ) {
        /* Request should be forwarded to OS */
        rc = CI_SOCKET_HANDOVER;
	goto unlock_out;
      }
      if( serv_addr->sa_family == AF_UNSPEC ) {
        /* Linux does listen shutdown on disconnect (AF_UNSPEC) */
        ci_netif_unlock(ep->netif);
        rc = ci_tcp_shutdown(ep, SHUT_RD, fd);
	goto out;
      } else {
        /* Linux has curious error reporting in this case */
        CI_SET_ERROR(rc, EISCONN);
      }
#endif
    }
    else {
      /* Socket is in SYN-SENT state. Let's block for receiving SYN-ACK */
      ci_assert_equal(s->b.state, CI_TCP_SYN_SENT);
      if( s->b.sb_aflags & (CI_SB_AFLAG_O_NONBLOCK | CI_SB_AFLAG_O_NDELAY) )
        CI_SET_ERROR(rc, EALREADY);
      else
        goto syn_sent;
    }
    goto unlock_out;
  }

  /* Check if we've ever been connected. */
  if( ts->tcpflags & CI_TCPT_FLAG_WAS_ESTAB ) {
    CI_SET_ERROR(rc, EISCONN);
    goto unlock_out;
  }

  /* 
   * 2. Check address parameter, if it's inappropriate for handover
   *    decision or handover should be done, try to to call OS and
   *    do handover on success.
   */

  if (
    /* Af first, check that address family and length is OK. */
    ci_tcp_validate_sa(s->domain, serv_addr, addrlen)
    /* Check for NAT. */
    || (dnat = ci_tcp_retrieve_addr(ep->netif, serv_addr, &dst_addr,
                                    &dst_port)) < 0
    /* rfc793 p54 if the foreign socket is unspecified return          */
    /* "error: foreign socket unspecified" (EINVAL), but keep it to OS */
    || CI_IPX_ADDR_IS_ANY(dst_addr)
    /* Zero destination port is tricky as well, keep it to OS */
    || dst_port == 0 )
  {
    rc = CI_SOCKET_HANDOVER;
    goto unlock_out;
  }

#if CI_CFG_IPV6
  if( CI_IPX_IS_LINKLOCAL(dst_addr) &&
      ci_sock_set_ip6_scope_id(ep->netif, s, serv_addr, addrlen, 1) ) {
    rc = CI_SOCKET_HANDOVER;
    goto unlock_out;
  }
#endif

  /* is this a socket that we can handle? */
  rc = ci_tcp_connect_check_dest(ep, dst_addr, dst_port);
  if( rc )  goto unlock_out;

#if CI_CFG_ENDPOINT_MOVE
  if( (ts->s.pkt.flags & CI_IP_CACHE_IS_LOCALROUTE) &&
      OO_SP_IS_NULL(ts->local_peer) ) {
    /* Try to connect to another stack; handover if can't */
    struct oo_op_loopback_connect op;
    op.dst_port = dst_port;
    op.dst_addr = dst_addr;
    /* this operation unlocks netif */
    rc = oo_resource_op(fd, OO_IOC_TCP_LOOPBACK_CONNECT, &op);
    if( rc < 0)
      return CI_SOCKET_HANDOVER;
    if( op.out_moved )
      *p_moved = 1;
    if( op.out_rc == -EINPROGRESS )
      RET_WITH_ERRNO( EINPROGRESS );
    else if( op.out_rc == -EAGAIN )
      RET_WITH_ERRNO(EAGAIN);
    else if( op.out_rc != 0 )
      return CI_SOCKET_HANDOVER;
    return 0;
  }
#endif

  if( dnat ) {
    ts->s.s_flags |= CI_SOCK_FLAG_DNAT;
    ts->pre_nat.daddr_be32 = ci_get_addr(serv_addr);
    ts->pre_nat.dport_be16 = ((struct sockaddr_in*) serv_addr)->sin_port;
  }

  crc = ci_tcp_connect_ul_start(ep->netif, ts, fd, dst_addr, dst_port,
                                &rc);
  if( crc != CI_CONNECT_UL_OK ) {
    switch( crc ) {
    case CI_CONNECT_UL_ALIEN_BOUND:
      rc = CI_SOCKET_HANDOVER;
      /* Fall through. */
    case CI_CONNECT_UL_FAIL:
      /* Check non-blocking */
      if( errno == EINPROGRESS ) {
        CI_TCP_STATS_INC_ACTIVE_OPENS( ep->netif );
      }
      goto unlock_out;
    case CI_CONNECT_UL_LOCK_DROPPED:
      goto out;
    case CI_CONNECT_UL_START_AGAIN:
      goto start_again;
    }
  }
  CI_TCP_STATS_INC_ACTIVE_OPENS( ep->netif );

 syn_sent:
  rc = ci_tcp_connect_ul_syn_sent(ep->netif, ts);

 unlock_out:
  ci_netif_unlock(ep->netif);
 out:
  if( rc == CI_SOCKET_HANDOVER && (s->s_flags & CI_SOCK_FLAG_DEFERRED_BIND) ) {
    int rc1 = complete_deferred_bind(ep->netif, &ts->s, fd);
    if( rc1 < 0 )
      return rc1;
  }
  return rc;
}
#endif

int ci_tcp_listen_init(ci_netif *ni, ci_tcp_socket_listen *tls)
{
  int i;
  oo_p sp;

  /* In theory, we can avoid listenq_tid timer for loopback-only listening
   * socket, but then it becomes complicated to distinguish different kind
   * of sockets and clear the timer when needed only. */
  sp = TS_OFF(ni, tls);
  OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_tcp_socket_listen, listenq_tid));
  ci_ip_timer_init(ni, &tls->listenq_tid, sp, "lstq");
  tls->listenq_tid.fn = CI_IP_TIMER_TCP_LISTEN;

  tls->acceptq_n_in = tls->acceptq_n_out = 0;
  tls->acceptq_put = CI_ILL_END;
  tls->acceptq_get = OO_SP_NULL;
  tls->n_listenq = 0;
  tls->n_listenq_new = 0;

  /* Allocate and initialise the listen bucket */
  tls->bucket = ci_ni_aux_alloc_bucket(ni);
  if( OO_P_IS_NULL(tls->bucket) )
    return -ENOBUFS;
  tls->n_buckets = 1;

  /* Initialise the listenQ. */
  for( i = 0; i <= CI_CFG_TCP_SYNACK_RETRANS_MAX; ++i )
    oo_p_dllink_init(ni, oo_p_dllink_sb(ni, &tls->s.b, &tls->listenq[i]));

  /* Initialize the cache and pending lists for the EP-cache.
   * See comment at definition for details
   */
  LOG_EP (log ("Initialise cache and pending list for id %d",
	       S_FMT(tls)));

#if CI_CFG_FD_CACHING
  sp = TS_OFF(ni, tls);
  OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_tcp_socket_listen, epcache.cache));
  ci_ni_dllist_init(ni, &tls->epcache.cache, sp, "epch");

  sp = TS_OFF(ni, tls);
  OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_tcp_socket_listen, epcache.pending));
  ci_ni_dllist_init(ni, &tls->epcache.pending, sp, "eppd");

  sp = TS_OFF(ni, tls);
  OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_tcp_socket_listen, epcache_connected));
  ci_ni_dllist_init(ni, &tls->epcache_connected, sp, "epco");

  sp = TS_OFF(ni, tls);
  OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_tcp_socket_listen, epcache.fd_states));
  ci_ni_dllist_init(ni, &tls->epcache.fd_states, sp, "ecfd");

  tls->epcache.avail_stack = oo_ptr_to_statep
    (ni, &ni->state->passive_cache_avail_stack);

  tls->cache_avail_sock = ni->state->opts.per_sock_cache_max;
#endif

  return 0;
}


#ifdef __KERNEL__
int ci_tcp_connect_lo_samestack(ci_netif *ni, ci_tcp_state *ts, oo_sp tls_id,
                                int *stack_locked)
{
  int crc, rc = 0;

  ci_assert(ci_netif_is_locked(ni));
  *stack_locked = 1;

  ts->local_peer = tls_id;
  crc = ci_tcp_connect_ul_start(ni, ts, CI_FD_BAD, sock_ipx_raddr(&ts->s),
                                ts->s.pkt.dport_be16, &rc);

  /* The connect is really finished, but we should return EINPROGRESS
   * for non-blocking connect and 0 for normal. */
  if( crc == CI_CONNECT_UL_OK )
    rc = ci_tcp_connect_ul_syn_sent(ni, ts);
  else if( crc == CI_CONNECT_UL_LOCK_DROPPED )
    *stack_locked = 0;
  return rc;
}

/* c_ni is assumed to be locked on enterance and is always unlocked on
 * exit. */
int ci_tcp_connect_lo_toconn(ci_netif *c_ni, oo_sp c_id, ci_addr_t dst,
                             ci_netif *l_ni, oo_sp l_id)
{
  ci_tcp_state *ts;
  ci_tcp_socket_listen *tls, *alien_tls;
  citp_waitable_obj *wo;
  citp_waitable *w;
  int rc;
  int stack_locked;

  ci_assert(ci_netif_is_locked(c_ni));
  ci_assert(OO_SP_NOT_NULL(c_id));
  ci_assert(OO_SP_NOT_NULL(l_id));

  LOG_TC(log("%s: connect %d:%d to %d:%d", __FUNCTION__,
             c_ni->state->stack_id, OO_SP_TO_INT(c_id),
             l_ni->state->stack_id, OO_SP_TO_INT(l_id)));

  alien_tls = SP_TO_TCP_LISTEN(l_ni, l_id);
  if( (int)ci_tcp_acceptq_n(alien_tls) >= alien_tls->acceptq_max ) {
    ci_netif_unlock(c_ni);
    return -EBUSY;
  }

  /* In c_ni, create shadow listening socket tls (copy l_id) */
  ts = ci_tcp_get_state_buf(c_ni);
  if( ts == NULL ) {
    ci_netif_unlock(c_ni);
    LOG_E(ci_log("%s: [%d] out of socket buffers", __FUNCTION__, NI_ID(c_ni)));
    return -ENOMEM;
  }

  /* init common tcp fields */
  ts->s.so = alien_tls->s.so;
  ts->s.cp.ip_ttl = alien_tls->s.cp.ip_ttl;
#if CI_CFG_IPV6
  ts->s.cp.hop_limit = alien_tls->s.cp.hop_limit;
#endif
  S_IPX_TCP_HDR(&ts->s)->tcp_source_be16 =
      S_IPX_TCP_HDR(&alien_tls->s)->tcp_source_be16;
  ts->s.domain = alien_tls->s.domain;
  ts->c = alien_tls->c;
  ts->c.tcp_defer_accept = OO_TCP_DEFER_ACCEPT_OFF;

  /* make sure nobody will ever connect to our "shadow" socket
   * except us */
  ci_bit_set(&ts->s.b.sb_aflags, CI_SB_AFLAG_ORPHAN_BIT);

  ci_tcp_set_slow_state(c_ni, ts, CI_TCP_LISTEN);
  tls = SOCK_TO_TCP_LISTEN(&ts->s);
  /* no timer: */
  tls->s.s_flags = alien_tls->s.s_flags | CI_SOCK_FLAG_BOUND_ALIEN;

  tls->acceptq_max = 1;
  rc = ci_tcp_listen_init(c_ni, tls);
  if( rc != 0 ) {
    citp_waitable_obj_free(c_ni, &tls->s.b);
    ci_netif_unlock(c_ni);
    return rc;
  }

  /* Connect c_id to tls */
  ts = SP_TO_TCP(c_ni, c_id);
  rc = ci_tcp_connect_lo_samestack(c_ni, ts, tls->s.b.bufid, &stack_locked);

  /* We have to destroy the shadow listener in the connecting stack,
   * so we really need to get the stack lock. */
  if( ! stack_locked ) {
    int rc1 = ci_netif_lock(c_ni);
    if( rc1 != 0 ) {
      /* we leak the shadow listener and a synrecv state, but so be it */
      ci_log("%s([%d:%d] to [%d:%d]): leaking the shadow listener "
             "[%d:%d] rc=%d",
             __func__, c_ni->state->stack_id, OO_SP_TO_INT(c_id),
             l_ni->state->stack_id, OO_SP_TO_INT(l_id),
             c_ni->state->stack_id, tls->s.b.bufid, rc);
      /* rc is usually -ERESTARTSYS, and it does not help user */
      return -ENOBUFS;
    }
  }

  /* Accept as from tls */
  if( !ci_tcp_acceptq_not_empty(tls) ) {
    /* it is possible, for example, if ci_tcp_listenq_try_promote() failed
     * because there are no endpoints */
    ci_tcp_listenq_drop_all(c_ni, tls);
    citp_waitable_obj_free(c_ni, &tls->s.b);
    ci_netif_unlock(c_ni);
    return -EBUSY;
  }
  w = ci_tcp_acceptq_get(c_ni, tls);
  ci_assert(w);
  LOG_TV(ci_log("%s: %d:%d to %d:%d shadow %d:%d accepted %d:%d",
                __FUNCTION__,
                c_ni->state->stack_id, OO_SP_TO_INT(c_id),
                l_ni->state->stack_id, OO_SP_TO_INT(l_id),
                c_ni->state->stack_id, tls->s.b.bufid,
                c_ni->state->stack_id, w->bufid));

  ci_assert(w->state & CI_TCP_STATE_TCP);
  ci_assert(w->state != CI_TCP_LISTEN);

  /* Destroy tls.
   * NB: nobody could possibly connect to it, so no need to do proper
   * shutdown.
   */
  ci_assert_equal(ci_tcp_acceptq_n(tls), 0);
  ci_tcp_listenq_drop_all(c_ni, tls);
  citp_waitable_obj_free(c_ni, &tls->s.b);
  ci_netif_unlock(c_ni);

  /* Keep a port reference */
  {
    tcp_helper_endpoint_t *l_ep, *a_ep;
    struct file* os_sock_ref;
    unsigned long lock_flags;

    l_ep = ci_trs_ep_get(netif2tcp_helper_resource(l_ni), l_id);
    a_ep = ci_trs_ep_get(netif2tcp_helper_resource(c_ni), W_SP(w));
    spin_lock_irqsave(&l_ep->lock, lock_flags);
    os_sock_ref = l_ep->os_socket;
    ci_assert_equal(a_ep->os_port_keeper, NULL);
    if( os_sock_ref != NULL ) {
      os_sock_ref = get_file(os_sock_ref);
      os_sock_ref = oo_file_xchg(&a_ep->os_port_keeper, os_sock_ref);
      spin_unlock_irqrestore(&l_ep->lock, lock_flags);
      if( os_sock_ref != NULL )
        fput(os_sock_ref);
    }
    else {
      spin_unlock_irqrestore(&l_ep->lock, lock_flags);
      goto cleanup;
    }
  }

  /* lock l_ni: Check that l_id is the same socket it used to be */
  /* create ref-sock in l_ni, put it into acc q */
  if( ci_netif_lock(l_ni) != 0 )
    goto cleanup;
  if( alien_tls->s.b.state != CI_TCP_LISTEN ||
      (alien_tls->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN) ||
      S_IPX_TCP_HDR(&alien_tls->s)->tcp_source_be16 !=
      TS_IPX_TCP(ts)->tcp_dest_be16 ||
      (!CI_IPX_ADDR_IS_ANY(alien_tls->s.laddr) &&
       !CI_IPX_ADDR_EQ(alien_tls->s.laddr, sock_ipx_raddr(&ts->s))) ) {
    ci_netif_unlock(l_ni);
    goto cleanup;
  }

  ci_bit_mask_set(&w->sb_aflags,
                  CI_SB_AFLAG_TCP_IN_ACCEPTQ | CI_SB_AFLAG_ORPHAN);

  wo = citp_waitable_obj_alloc(l_ni);
  if( wo == NULL ) {
    ci_netif_unlock(l_ni);
    goto cleanup;
  }
  wo->waitable.state = CI_TCP_CLOSED;
  wo->waitable.sb_aflags |= CI_SB_AFLAG_MOVED_AWAY;
  wo->waitable.moved_to_stack_id = c_ni->state->stack_id;
  wo->waitable.moved_to_sock_id = W_SP(w);
  LOG_TC(log("%s: put to acceptq %d:%d referencing %d:%d", __func__,
             l_ni->state->stack_id, OO_SP_TO_INT(W_SP(&wo->waitable)),
             c_ni->state->stack_id, OO_SP_TO_INT(W_SP(w))));

  ci_tcp_acceptq_put(l_ni, alien_tls, &wo->waitable);
  citp_waitable_wake_not_in_poll(l_ni, &alien_tls->s.b, CI_SB_FLAG_WAKE_RX);
  ci_netif_unlock(l_ni);

  return rc;

cleanup:
  ci_assert(w->sb_aflags & CI_SB_AFLAG_ORPHAN);
  ci_bit_mask_clear(&w->sb_aflags,
                    CI_SB_AFLAG_TCP_IN_ACCEPTQ | CI_SB_AFLAG_ORPHAN);
  efab_tcp_helper_close_endpoint(netif2tcp_helper_resource(c_ni), w->bufid, 0);
  /* we can not guarantee c_ni lock, so we can' call
   * ci_tcp_drop(c_ni, ts).  So, we return error; UL will handover
   * and close ts endpoint. */
  return -EBUSY;
}
#endif


 
#ifndef __KERNEL__

#if CI_CFG_ENDPOINT_MOVE
/* Set a reuseport bind on a socket.
 */
int ci_tcp_reuseport_bind(ci_sock_cmn* sock, ci_fd_t fd)
{
  int rc;

  ci_assert_nequal(sock->s_flags & CI_SOCK_FLAG_REUSEPORT, 0);
  if ( (rc = ci_tcp_ep_reuseport_bind(fd, CITP_OPTS.cluster_name,
                                      CITP_OPTS.cluster_size,
                                      CITP_OPTS.cluster_restart_opt,
                                      CITP_OPTS.cluster_hot_restart_opt,
                                      sock_ipx_laddr(sock), 
                                      sock_lport_be16(sock))) != 0 ) {
    errno = -rc;
    return -1;
  }
  return 0;
}
#endif

/* In this bind handler we just check that the address to which
 * are binding is either "any" or one of ours. 
 */
int ci_tcp_bind(citp_socket* ep, const struct sockaddr* my_addr,
                socklen_t addrlen, ci_fd_t fd )
{
  ci_uint16 new_port;
  ci_addr_t addr;
  ci_sock_cmn* s = ep->s;
  ci_tcp_state* c = &SOCK_TO_WAITABLE_OBJ(s)->tcp;
  int rc = 0;

  CHECK_TEP(ep);
  ci_assert(ci_netif_is_locked(ep->netif));

  /* Check if state of the socket is OK for bind operation. */
  /* \todo Earlier (TS_TCP( epi->tcpep.state )->tcp_source_be16) is used.
   *       What is better? */
  if (my_addr == NULL)
    RET_WITH_ERRNO( EINVAL );

  if (s->b.state != CI_TCP_CLOSED)
    RET_WITH_ERRNO( EINVAL );

  if (c->tcpflags & CI_TCPT_FLAG_WAS_ESTAB)
    RET_WITH_ERRNO( EINVAL );

  /* There should be address length check before address family validation to
   * match Linux errno value set in inet6_bind(). */
  if (s->domain == PF_INET6 && addrlen < SIN6_LEN_RFC2133)
    RET_WITH_ERRNO( EINVAL );

  if( my_addr->sa_family != s->domain )
    RET_WITH_ERRNO( EAFNOSUPPORT );

  /* sin_port and sin6_port share tha same place in the sockaddr */
  new_port = ((struct sockaddr_in*)my_addr)->sin_port;

  /* Bug 4884: Windows regularly uses addrlen > sizeof(struct sockaddr_in) 
   * Linux is also relaxed about overlength data areas. */
  if (s->domain == PF_INET && addrlen < sizeof(struct sockaddr_in))
    RET_WITH_ERRNO( EINVAL );

#if CI_CFG_FAKE_IPV6
#if ! CI_CFG_IPV6
  if( s->domain == PF_INET6 && !ci_tcp_ipv6_is_ipv4(my_addr) )
    goto handover;
#else
  if( s->domain == PF_INET6 && (s->s_flags & CI_SOCK_FLAG_V6ONLY) &&
      CI_IP6_IS_V4MAPPED(&CI_SIN6(my_addr)->sin6_addr) )
    goto handover;
#endif
#endif

  if( ((s->s_flags & CI_SOCK_FLAG_TPROXY) != 0) &&
      (new_port == 0) ) {
    NI_LOG(ep->netif, USAGE_WARNINGS, "Sockets with IP_TRANSPARENT set must "
           "be explicitly bound to a port to be accelerated");
    goto handover;
  }

  addr = ci_get_addr(my_addr);

  /* In scalable RSS mode accelerated 127.* sockets cause issues:
   *  * with SO_REUSEPORT they would fail at listen
   *  * without SO_REUSEPORT they would end up in non-rss stack degrading performance
   *    with lock contention, epoll3 and accelerated loopback */
  if( CI_IPX_IS_LOOPBACK(addr) &&
      NI_OPTS(ep->netif).scalable_filter_enable != CITP_SCALABLE_FILTERS_DISABLE &&
      ((NI_OPTS(ep->netif).scalable_filter_mode &
                       (CITP_SCALABLE_MODE_PASSIVE | CITP_SCALABLE_MODE_RSS)) ==
                       (CITP_SCALABLE_MODE_PASSIVE | CITP_SCALABLE_MODE_RSS)) )
    goto handover;

  if( ((s->s_flags & CI_SOCK_FLAG_TPROXY) != 0) &&
      CI_IPX_ADDR_IS_ANY(addr) ) {
    NI_LOG(ep->netif, USAGE_WARNINGS, "Sockets with IP_TRANSPARENT set must "
           "be explicitly bound to an address to be accelerated");
    goto handover;
  }

  /* Using the port number provided, see if we can do this bind */
  if( CITP_OPTS.tcp_reuseports != 0 && new_port != 0 ) {
    struct ci_port_list *force_reuseport;
    CI_DLLIST_FOR_EACH2(struct ci_port_list, force_reuseport, link,
                        (ci_dllist*)(ci_uintptr_t)CITP_OPTS.tcp_reuseports) {
      if( force_reuseport->port == new_port ) {
        int one = 1;
        if( ep->s->b.sb_aflags & CI_SB_AFLAG_OS_BACKED ) {
          ci_fd_t os_sock = ci_get_os_sock_fd(fd);
          ci_assert(CI_IS_VALID_SOCKET(os_sock));
          rc = ci_sys_setsockopt(os_sock, SOL_SOCKET, SO_REUSEPORT, &one,
                                 sizeof(one));
          ci_rel_os_sock_fd(os_sock);
          /* Fixme: shouldn't we handle errors? */
        }
        else if( (s->s_flags & CI_SOCK_FLAG_TPROXY) == 0 ) {
          rc = ci_tcp_helper_os_sock_create_and_set(ep->netif, fd, s,
                                                    SOL_SOCKET, SO_REUSEPORT,
                                                    (char*)&one, sizeof(one));
        }
        if( rc != 0 ) {
          log("%s: failed to set SO_REUSEPORT on OS socket: "
              "rc=%d errno=%d", __func__, rc, errno);
        }
        ep->s->s_flags |= CI_SOCK_FLAG_REUSEPORT;
        LOG_TC(log("%s "SF_FMT", applied legacy SO_REUSEPORT flag for port %u",
                   __FUNCTION__, SF_PRI_ARGS(ep, fd), new_port));
      }
    }
  }

#if CI_CFG_IPV6
  if( CI_IPX_IS_LINKLOCAL(addr) &&
      ci_sock_set_ip6_scope_id(ep->netif, s, my_addr, addrlen, 0) )
    goto handover;
#endif

  CI_LOGLEVEL_TRY_RET(LOG_TV,
		      __ci_tcp_bind(ep->netif, ep->s, fd, addr,
                                    &new_port, 1));
  ep->s->s_flags |= CI_SOCK_FLAG_BOUND;
#if CI_CFG_IPV6
  ci_tcp_ipcache_convert(CI_ADDR_AF(addr), c);
#endif
  ci_sock_cmn_set_laddr(ep->s, addr, new_port);
  ci_sock_set_raddr_port(s, addr_any, 0);

  LOG_TC(log(LPF "bind to "IPX_FMT":%u n_p:%u lp:%u", IPX_ARG(AF_IP(addr)),
	     CI_BSWAP_BE16(((struct sockaddr_in*)my_addr)->sin_port),
	     CI_BSWAP_BE16(new_port), CI_BSWAP_BE16(sock_lport_be16(s)))); 

  return 0;

 handover:
  if( !(ep->s->b.sb_aflags & CI_SB_AFLAG_OS_BACKED) ) {
    rc = ci_tcp_helper_os_sock_create_and_set(ep->netif, fd, s, -1, 0, NULL,
                                              0);
    if( rc < 0 )
      RET_WITH_ERRNO(errno);
  }
  return CI_SOCKET_HANDOVER;
}


/* Set the socket to listen, the reorder buffer and txq become
** the listen state, and it is initialised
** \todo split this overlong function up!
**
** NOTE: [fd] is unused in the kernel version
*/

int ci_tcp_listen(citp_socket* ep, ci_fd_t fd, int backlog)
{
  /* 
  ** ?? error handling on possible fails not handled robustly...
  ** ?? Need to check port number is valid TODO
  */

  /*! \todo If not bound then we have to be listening on all interfaces.
   * It's likely that we won't be coming through here as we have to
   * listen on the OS socket too! */
  ci_tcp_state* ts;
  ci_tcp_socket_listen* tls;
  ci_netif* netif = ep->netif;
  ci_sock_cmn* s = ep->s;
  unsigned ul_backlog = backlog;
  int rc;
  int scalable;
  int will_accelerate = 1;

  LOG_TC(log("%s "SK_FMT" listen backlog=%d", __FUNCTION__, SK_PRI_ARGS(ep), 
             backlog));
  CHECK_TEP(ep);

  scalable = ci_tcp_use_mac_filter_listen(netif, s, s->cp.so_bindtodevice);

  if( s->s_flags & CI_SOCK_FLAG_DEFERRED_BIND )
    complete_deferred_bind(netif, s, fd);

  if( NI_OPTS(netif).tcp_listen_handover )
    return CI_SOCKET_HANDOVER;

  /* We should handover if the socket is bound to alien address. */
  if( s->s_flags & CI_SOCK_FLAG_BOUND_ALIEN ) {
    /* We MUST NOT install filters for a loopback address */
    will_accelerate = (netif->state->flags & CI_NETIF_FLAG_USE_ALIEN_LADDRS ||
        scalable) && !CI_IPX_IS_LOOPBACK(s->laddr);
  }

  if(
#if CI_CFG_ENDPOINT_MOVE
      !NI_OPTS(netif).tcp_server_loopback &&
#endif
      ! will_accelerate )
    return CI_SOCKET_HANDOVER;

  if( ul_backlog < 0 )
    ul_backlog = NI_OPTS(netif).max_ep_bufs;
  else if( ul_backlog < NI_OPTS(netif).acceptq_min_backlog )
    ul_backlog = NI_OPTS(netif).acceptq_min_backlog;

  if( s->b.state == CI_TCP_LISTEN ) {
    tls = SOCK_TO_TCP_LISTEN(s);
    ci_netif_lock(ep->netif);
    tls->acceptq_max = ul_backlog;
    if( (s->s_flags & CI_SOCK_FLAG_SCALPASSIVE) == 0 ||
        NI_OPTS(netif).scalable_listen != CITP_SCALABLE_LISTEN_ACCELERATED_ONLY )
      ci_tcp_helper_listen_os_sock(fd, ul_backlog);
    ci_netif_unlock(ep->netif);
    return 0;
  }

  if( s->b.state != CI_TCP_CLOSED ) {
    CI_SET_ERROR(rc, EINVAL);
    return rc;
  }

  ts = SOCK_TO_TCP(s);

  /* Bug 3376: if socket used for a previous, failed, connect then the error
   * numbers will not be as expected.  Only seen when not using listening
   * netifs (as moving the EP to the new netif resets them). 
   */

  ts->s.tx_errno = EPIPE;
  ts->s.rx_errno = ENOTCONN;

  ci_sock_lock(netif, &ts->s.b);
  ci_netif_lock(ep->netif);
  /* fill in address/ports and all TCP state */
  if( ts->s.s_flags & CI_SOCK_FLAG_CONNECT_MUST_BIND ) {
    ci_uint16 source_be16;

    /* They haven't previously done a bind, so we need to choose 
     * a port.  As we haven't been given a hint we let the OS choose.
     *
     * NB The previously-calculated will_accelerate variable remains valid,
     * because this call __ci_tcp_bind() never results in
     * CI_SOCK_FLAG_BOUND_ALIEN flag being set.
     */

    source_be16 = 0;
    rc = __ci_tcp_bind(ep->netif, ep->s, fd, ts->s.laddr, &source_be16, 0);
    if (CI_LIKELY( rc==0 )) {
      TS_IPX_TCP(ts)->tcp_source_be16 = source_be16;
      ts->s.cp.lport_be16 = source_be16;
      LOG_TC(log(LNT_FMT "listen: our bind returned "IPX_FMT":%u",
                 LNT_PRI_ARGS(ep->netif, ts), IPX_ARG(AF_IP(ts->s.laddr)),
                 (unsigned) CI_BSWAP_BE16(TS_IPX_TCP(ts)->tcp_source_be16)));

    } else {
      LOG_U(ci_log("__ci_tcp_bind returned %d at %s:%d", CI_GET_ERROR(rc),
                   __FILE__, __LINE__));
      ci_netif_unlock(ep->netif);
      ci_sock_unlock(netif, &ts->s.b);
      return rc;
    }
  } 

  ci_tcp_set_slow_state(netif, ts, CI_TCP_LISTEN);
  tls = SOCK_TO_TCP_LISTEN(&ts->s);

  ipx_hdr_set_daddr(ipcache_af(&tls->s.pkt), &tls->s.pkt.ipx, addr_any);
  tcp_rport_be16(tls) = 0u;

  ci_assert_equal(tls->s.tx_errno, EPIPE);
  ci_assert_equal(tls->s.rx_errno, ENOTCONN);

  /* Listen timer should be initialized before the first return statement,
   * because __ci_tcp_listen_to_normal() will be called on error path. */
  rc = ci_tcp_listen_init(netif, tls);

  /* Drop the socket lock */
  ci_netif_unlock(ep->netif);
  ci_sock_unlock(netif, &ts->s.b);
  ci_netif_lock(ep->netif);

  if( rc != 0 ) {
    CI_SET_ERROR(rc, -rc);
    goto listen_fail;
  }
  tls->acceptq_max = ul_backlog;

  CITP_STATS_TCP_LISTEN(CI_ZERO(&tls->stats));

  /* install all the filters needed for this connection 
   *    - tcp_laddr_be32(ts) = 0 for IPADDR_ANY
   *
   *  TODO: handle BINDTODEVICE by setting phys_port paramter to correct 
   *        physical L5 port index
   *  TODO: handle REUSEADDR by setting last paramter to TRUE
   */
  if( will_accelerate ) {
    if( scalable )
      tls->s.s_flags |= CI_SOCK_FLAG_SCALPASSIVE;

    rc = ci_tcp_ep_set_filters(netif, S_SP(tls), tls->s.cp.so_bindtodevice,
                               OO_SP_NULL);
    if( rc == -EFILTERSSOME ) {
      if( CITP_OPTS.no_fail )
        rc = 0;
      else {
        ci_tcp_ep_clear_filters(netif, S_SP(tls), 0);
        rc = -ENOBUFS;
      }
    }
    ci_assert_nequal(rc, -EFILTERSSOME);
    VERB(ci_log("%s: set_filters  returned %d", __FUNCTION__, rc));
    if (rc < 0) {
      if( s->s_flags & CI_SOCK_FLAG_BOUND_ALIEN
#if CI_CFG_ENDPOINT_MOVE
          && NI_OPTS(netif).tcp_server_loopback
#endif
          ) {
        /* That alien address can't be served by filters despite
         * CI_NETIF_FLAG_USE_ALIEN_LADDRS.  We'll accelerate loopback in
         * any case.
         */
        rc = 0;
      }
      else {
        CI_SET_ERROR(rc, -rc);
        goto post_listen_fail;
      }
    }
  }

  ci_assert_equal(rc, 0);

  /* 
   * Call of system listen() is required for listen any, local host
   * communications server and multi-homed server (to accept connections
   * to L5 assigned address(es), but incoming from other interfaces).
   * The exception is scalable passive mode where we avoid listen on
   * OS socket to avoid kernel LHTABLE related performance degradation. */
  if( (s->s_flags & CI_SOCK_FLAG_SCALPASSIVE) == 0 ||
      NI_OPTS(netif).scalable_listen != CITP_SCALABLE_LISTEN_ACCELERATED_ONLY ) {
#ifdef __ci_driver__
    rc = efab_tcp_helper_listen_os_sock( netif2tcp_helper_resource(netif),
					 S_SP(tls), backlog);
#else
    rc = ci_tcp_helper_listen_os_sock(fd, backlog);
#endif
  }
  if ( rc < 0 ) {
    /* clear the filter we've just set */
    ci_tcp_ep_clear_filters(netif, S_SP(tls), 0);
    goto post_listen_fail;
  }
  ci_netif_unlock(ep->netif);
  return 0;

 post_listen_fail:
  ci_tcp_listenq_drop_all(netif, tls);
 listen_fail:
  /* revert TCP state to a non-listening socket format */
  __ci_tcp_listen_to_normal(netif, tls);
  /* Above function sets orphan flag but we are attached to an FD. */
  ci_bit_clear(&tls->s.b.sb_aflags, CI_SB_AFLAG_ORPHAN_BIT);
  ci_netif_unlock(ep->netif);
#ifdef __ci_driver__
  return rc;
#else
  return CI_SOCKET_ERROR;
#endif
}


static int ci_tcp_shutdown_listen(citp_socket* ep, int how, ci_fd_t fd)
{
  ci_tcp_socket_listen* tls = SOCK_TO_TCP_LISTEN(ep->s);

  if( how == SHUT_WR )
    return 0;

  ci_sock_lock(ep->netif, &tls->s.b);
  ci_netif_lock(ep->netif);
  LOG_TC(ci_log(SK_FMT" shutdown(SHUT_RD)", SK_PRI_ARGS(ep)));
  __ci_tcp_listen_shutdown(ep->netif, tls);
  __ci_tcp_listen_to_normal(ep->netif, tls);
  {
    ci_fd_t os_sock = ci_get_os_sock_fd(fd);
    int flags = ci_sys_fcntl(os_sock, F_GETFL);
    flags &= (~O_NONBLOCK);
    CI_TRY(ci_sys_fcntl(os_sock, F_SETFL, flags));
    ci_rel_os_sock_fd(os_sock);
  }
  citp_waitable_wake_not_in_poll(ep->netif, &tls->s.b,
                                 CI_SB_FLAG_WAKE_RX | CI_SB_FLAG_WAKE_TX);
  ci_netif_unlock(ep->netif);
  ci_sock_unlock(ep->netif, &tls->s.b);
  return 0;
}


int ci_tcp_shutdown(citp_socket* ep, int how, ci_fd_t fd)
{
  ci_sock_cmn* s = ep->s;
  int rc;

  if( s->b.state == CI_TCP_LISTEN )
    return ci_tcp_shutdown_listen(ep, how, fd);

  if( SOCK_TO_TCP(s)->snd_delegated ) {
    /* We do not know which seq number to use.  Call
     * onload_delegated_send_cancel(). */
    CI_SET_ERROR(rc, EBUSY);
    return rc;
  }

  if( ! ci_netif_trylock(ep->netif) ) {
    /* Can't get lock, so try to defer shutdown to the lock holder. */
    unsigned flags = 0;
    switch( s->b.state ) {
    case CI_TCP_CLOSED:
    case CI_TCP_TIME_WAIT:
      CI_SET_ERROR(rc, ENOTCONN);
      return rc;
    }
    if( how == SHUT_RD || how == SHUT_RDWR )
      flags |= CI_SOCK_AFLAG_NEED_SHUT_RD;
    if( how == SHUT_WR || how == SHUT_RDWR )
      flags |= CI_SOCK_AFLAG_NEED_SHUT_WR;
    ci_atomic32_or(&s->s_aflags, flags);
    if( ci_netif_lock_or_defer_work(ep->netif, &s->b) )
      ci_netif_unlock(ep->netif);
    return 0;
  }

  rc = __ci_tcp_shutdown(ep->netif, SOCK_TO_TCP(s), how);
  ci_netif_unlock(ep->netif);
  if( rc < 0 )
    CI_SET_ERROR(rc, -rc);
  return rc;
}


void ci_tcp_get_peer_addr(ci_tcp_state* ts, struct sockaddr* name,
                          socklen_t* namelen)
{
  int af = ipcache_af(&ts->s.pkt);
  int /*bool*/ dnat = ts->s.s_flags & CI_SOCK_FLAG_DNAT;
  ci_addr_t raddr = dnat ? ts->pre_nat.daddr_be32 : tcp_ipx_raddr(ts);
  ci_uint16 port = dnat ? ts->pre_nat.dport_be16 :
                          TS_IPX_TCP(ts)->tcp_dest_be16;
  ci_addr_to_user(name, namelen, af, ts->s.domain, port,
                  CI_IPX_ADDR_PTR(af, raddr), ts->s.cp.so_bindtodevice);
}

int ci_tcp_getpeername(citp_socket* ep, struct sockaddr* name,
		       socklen_t* namelen)
{
  ci_sock_cmn* s = ep->s;
  int rc;

  CHECK_TEP_NNL(ep);

  /* If we're not connected... */
  if( ! (s->b.state & CI_TCP_STATE_SYNCHRONISED) ||
      s->b.state == CI_TCP_TIME_WAIT )
    CI_SET_ERROR(rc, ENOTCONN);
  else if( name == NULL || namelen == NULL )
    CI_SET_ERROR(rc, EFAULT);
  else {
    rc = 0;
    if( s->b.state != CI_TCP_LISTEN )
      ci_tcp_get_peer_addr(SOCK_TO_TCP(s), name, namelen);
  }

  return rc;
}


int ci_tcp_getsockname(citp_socket* ep, ci_fd_t fd, struct sockaddr* sa,
                       socklen_t* p_sa_len) {
  ci_sock_cmn* s = ep->s;
  int rc = 0;

  /* Check consistency of multitude of bind flags */
  ci_tcp_bind_flags_assert_valid(s);

  if( s->s_flags & CI_SOCK_FLAG_DEFERRED_BIND )
    complete_deferred_bind(ep->netif, s, fd);

  return rc;
}

#endif

#endif
#endif

