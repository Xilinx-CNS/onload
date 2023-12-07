/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr/stg
**  \brief  UDP sendmsg() etc.
**   \date  2003/12/28
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */
  
#include "ip_internal.h"
#include "udp_internal.h"
#include "ip_tx.h"
#include <ci/tools/pktdump.h>
#include <onload/osfile.h>
#include <onload/pkt_filler.h>
#include <onload/sleep.h>

#ifndef __KERNEL__
#include <ci/internal/efabcfg.h>
#endif


#if OO_DO_STACK_POLL
#define VERB(x)

#define LPF "ci_udp_"
#define LPFIN "-> " LPF
#define LPFOUT "<- " LPF


/* This just avoids some ugly #ifdef.  This val is not used at userlevel. */
#ifndef __KERNEL__
# define ERESTARTSYS 0
#endif


#define TXQ_LEVEL(us)                                           \
  ((us)->tx_count + oo_atomic_read(&(us)->tx_async_q_level))

/* If not locked then trylock, and if successful set locked flag and (in
 * some cases) increment the counter.  Return true if lock held, else
 * false.  si_ variants take a [struct udp_send_info*].
 */
#define trylock(ni, locked)                                     \
  ((locked) || (ci_netif_trylock(ni) && ((locked) = 1)))
#define si_trylock(ni, sinf)                    \
  trylock((ni), (sinf)->stack_locked)
#define trylock_and_inc(ni, locked, cntr)                               \
  ((locked) || (ci_netif_trylock(ni) && (++(cntr), (locked) = 1)))
#define si_trylock_and_inc(ni, sinf, cntr)              \
  trylock_and_inc((ni), (sinf)->stack_locked, (cntr))

#if CI_CFG_IPV6
#define msg_namelen_ok(af, namelen) ((af) == AF_INET6 ? \
  (namelen) >= sizeof(struct sockaddr_in6) : \
  (namelen) >= sizeof(struct sockaddr_in))
#else
#define msg_namelen_ok(af, namelen) \
  ((namelen) >= sizeof(struct sockaddr_in))
#endif

#define oo_tx_udp_hdr(pkt)  ((ci_udp_hdr*) oo_tx_ip_data(pkt))
#define oo_tx_ipx_udp_hdr(af, pkt) ((ci_udp_hdr*) oo_tx_ipx_data(af, pkt))


struct udp_send_info {
  int                   rc;
  ci_ip_cached_hdrs     ipcache;
  int                   used_ipcache;
  int                   stack_locked;
  ci_uint32             timeout;
  int                   old_ipcache_updated;
};

static bool ci_ipx_is_first_frag(int af, ci_ipx_hdr_t* ipx)
{
#if CI_CFG_IPV6
  if( IS_AF_INET6(af) ) {
    ci_ip6_frag_hdr* frag_hdr;
    if( ipx->ip6.next_hdr != CI_NEXTHDR_FRAGMENT )
      return true;
    frag_hdr = ipx_hdr_data(af, ipx);
    if( (frag_hdr->frag_off & CI_BSWAPC_BE16(CI_IP6_OFFSET)) == 0 )
      return true;
  }
  else
#endif
  {
    if( (ipx->ip4.ip_frag_off_be16 & CI_IP4_OFFSET_MASK) == 0 )
      return true;
  }
  return false;
 }

/* Check if More Fragments flag is set for IPv4 or IPv6 header */
static bool ci_ipx_is_mf_set(int af, ci_ipx_hdr_t* ipx)
{
#if CI_CFG_IPV6
  if( IS_AF_INET6(af) ) {
    ci_ip6_frag_hdr* frag_hdr;
    if( ipx->ip6.next_hdr != CI_NEXTHDR_FRAGMENT )
      return false;
    frag_hdr = ipx_hdr_data(af, ipx);
    if( frag_hdr->frag_off & CI_BSWAPC_BE16(CI_IP6_MF) )
      return true;
  }
  else
#endif
  {
    if( ipx->ip4.ip_frag_off_be16 & CI_IP4_FRAG_MORE )
      return true;
  }
  return false;
}

ci_noinline void ci_udp_sendmsg_chksum(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                       int af, ci_ipx_hdr_t* first_hdr)
{
  /* 1400*50 = 70000, i.e. in normal situation there are <50 fragments */
#define MAX_IP_FRAGMENTS 50
  struct iovec iov[MAX_IP_FRAGMENTS];
  int n = -1;
  ci_udp_hdr* udp = TX_PKT_IPX_UDP(af, pkt, true);
  ci_ip_pkt_fmt* p = pkt;
  int first_frag = 1;

  /* iterate all IP fragments */
  while( OO_PP_NOT_NULL(p->next) ) {
    int frag_len;
    char *frag_start;
    int max_sg_len;

    /* When too many fragments, let's send it without checksum */
    if( ++n == MAX_IP_FRAGMENTS )
      return;

    if( first_frag ) {
      frag_start = (char*)(udp + 1);
      frag_len = ( WITH_CI_CFG_IPV6( IS_AF_INET6(af) ?
          CI_BSWAP_BE16(first_hdr->ip6.payload_len) - sizeof(ci_ip6_frag_hdr) : )
          CI_BSWAP_BE16(first_hdr->ip4.ip_tot_len_be16) -
          CI_IP4_IHL(&first_hdr->ip4)) - sizeof(ci_udp_hdr);
      first_frag = 0;
    }
    else {
      ci_ipx_hdr_t* p_ipx;
      p = PKT_CHK(ni, p->next);
      p_ipx = TX_PKT_IPX_HDR(af, p);
      frag_len = WITH_CI_CFG_IPV6( IS_AF_INET6(af) ?
          CI_BSWAP_BE16(p_ipx->ip6.payload_len) - sizeof(ci_ip6_frag_hdr) : )
          CI_BSWAP_BE16(p_ipx->ip4.ip_tot_len_be16) - CI_IP4_IHL(&p_ipx->ip4);
      frag_start = (char*)ipx_hdr_data(af, p_ipx) + CI_IPX_FRAG_HDR_SIZE(af);
    }

    iov[n].iov_base = frag_start;
    iov[n].iov_len = frag_len;
    max_sg_len = CI_PTR_ALIGN_FWD(PKT_START(p), CI_CFG_PKT_BUF_SIZE) -
        frag_start;
    if( frag_len > max_sg_len ) {
      iov[n].iov_len = max_sg_len;
      frag_len -= max_sg_len;
    }

    /* do we have scatte-gather for this IP fragment? */
    if( p->frag_next != p->next ) {
      ci_ip_pkt_fmt* sg_pkt = p;
      while( sg_pkt->frag_next != p->next ) {
        ci_assert(frag_len);
        sg_pkt = PKT_CHK(ni, sg_pkt->frag_next);
        ++n;
        ci_assert_le(n, MAX_IP_FRAGMENTS);

        iov[n].iov_base = PKT_START(sg_pkt);
        iov[n].iov_len = frag_len;
        max_sg_len = CI_PTR_ALIGN_FWD(PKT_START(sg_pkt),
                                      CI_CFG_PKT_BUF_SIZE) -
                     PKT_START(sg_pkt);
        if( frag_len > max_sg_len ) {
          iov[n].iov_len = max_sg_len;
          frag_len -= max_sg_len;
        }
        else
          frag_len = 0;
      }
      ci_assert_equal(frag_len, 0);
    }
  }
  
  udp->udp_check_be16 = WITH_CI_CFG_IPV6( IS_AF_INET6(af) ?
                        ci_ip6_udp_checksum(&first_hdr->ip6, udp, iov, n+1) : )
                        ci_udp_checksum(&first_hdr->ip4, udp, iov, n+1);
}


static void
ci_ip_send_udp_slow(ci_netif* ni, struct oo_sock_cplane* sock_cp,
                    ci_ip_pkt_fmt* pkt, ci_ip_cached_hdrs* ipcache)
{
  int os_rc = 0;

  /* Release the ref we've taken in ci_udp_sendmsg_fill() for
   * ci_netif_send().  We already hold initial reference to the packet,
   * so could not free it here. */
  ci_assert_gt(pkt->refcount, 1);
  --pkt->refcount;

  ci_ip_send_pkt_defer(ni, sock_cp, retrrc_nomac, &os_rc, pkt, ipcache);
}


static int ci_udp_sendmsg_loop(ci_sock_cmn* s, void* opaque_arg)
{
  struct ci_udp_rx_deliver_state* state = opaque_arg;
  ci_ip_pkt_fmt* frag_head;
  ci_ip_pkt_fmt* buf_pkt;
  int seg_i, buf_len;
  ci_udp_hdr* udp;
  void* buf_start;

  if( ! state->delivered ) {
    /* Setup the fields that are expected in an RX packet.  The UDP
     * datagram consists of a sequence of one or more IP fragments.  Each
     * fragment may be split over multiple buffers.  The whole lot are
     * chained together by the [frag_next] field.
     */
    frag_head = state->pkt;
    udp = (ci_udp_hdr*) (oo_ip_hdr(frag_head) + 1);
    frag_head->tstamp_frc  = IPTIMER_STATE(state->ni)->frc;
    frag_head->pf.udp.pay_len = CI_BSWAP_BE16(udp->udp_len_be16) - sizeof(*udp);
    buf_pkt = frag_head;
    seg_i = 0;
    while( 1 ) {
      ++state->ni->state->n_rx_pkts;
      ci_assert(!(buf_pkt->flags & CI_PKT_FLAG_RX));
      buf_pkt->flags |= CI_PKT_FLAG_RX;
      if( buf_pkt == state->pkt )
        /* First IP fragment, move past IP+UDP header */
        buf_start = udp + 1;
      else if( seg_i == 0 )
        /* Subsequent IP fragment, move past IP header */
        buf_start = oo_ip_hdr(buf_pkt) + 1;
      else
        /* Internal (jumbo) fragment, no header to move past */ 
        buf_start = PKT_START(buf_pkt);
      buf_len = buf_pkt->buf_len;
      buf_len -= (char*) buf_start - PKT_START(buf_pkt);
      oo_offbuf_init(&buf_pkt->buf, buf_start, buf_len);
      if( OO_PP_IS_NULL(buf_pkt->frag_next) )
        break;
      buf_pkt = PKT_CHK(state->ni, buf_pkt->frag_next);
      if( ++seg_i == frag_head->n_buffers ) {
        seg_i = 0;
        frag_head = buf_pkt;
      }
    }
  }

  CITP_STATS_NETIF_INC(state->ni, udp_send_mcast_loop);
  ci_udp_rx_deliver(s, opaque_arg);
  citp_waitable_wake_not_in_poll(state->ni, &s->b, CI_SB_FLAG_WAKE_RX);

  return 0;  /* continue delivering to other sockets */
}


static void ci_udp_sendmsg_mcast(ci_netif* ni, ci_udp_state* us,
                                 ci_ip_cached_hdrs* ipcache,
                                 ci_ip_pkt_fmt* pkt)
{
  /* NB. We don't deliver multicast packets directly to local sockets if
   * sending via the control plane (below) as they'll get there via the
   * OS socket.
   *
   * FIXME: Problem is, they'll get there even if IP_MULTICAST_LOOP is
   * disabled.  Fix would be to send via the OS socket instead of the
   * control plane route and find an alternative way to keep neighbour
   * entries alive.
   */
  struct ci_udp_rx_deliver_state state;
  const ci_udp_hdr* udp;

  if( ! (us->udpflags & CI_UDPF_MCAST_LOOP) ||
      ! (NI_OPTS(ni).mcast_send & CITP_MCAST_SEND_FLAG_LOCAL) )
    return;
  if(CI_UNLIKELY( ni->state->n_rx_pkts >= NI_OPTS(ni).max_rx_packets )) {
    ci_netif_try_to_reap(ni, 100);
    if( ni->state->n_rx_pkts >= NI_OPTS(ni).max_rx_packets ) {
      CITP_STATS_NETIF_INC(ni, udp_send_mcast_loop_drop);
      return;
    }
  }

  state.ni = ni;
  state.pkt = pkt;
  state.queued = 0;
  state.delivered = 0;

  udp = TX_PKT_UDP(pkt);

  /* Packets sent via loopback don't involve polling the netif, which
   * is the normal point for updating stack frc, so add an explicit
   * call here to ensure RX timestamps reported for this packets are
   * correct
   */
  ci_ip_time_resync(IPTIMER_STATE(ni));

  ci_netif_filter_for_each_match(ni,
                                 oo_ip_hdr(pkt)->ip_daddr_be32,
                                 udp->udp_dest_be16,
                                 oo_ip_hdr(pkt)->ip_saddr_be32,
                                 udp->udp_source_be16,
                                 IPPROTO_UDP, ipcache->intf_i,
                                 ipcache->encap.vlan_id,
                                 ci_udp_sendmsg_loop, &state, NULL);
  ci_netif_filter_for_each_match(ni,
                                 oo_ip_hdr(pkt)->ip_daddr_be32,
                                 udp->udp_dest_be16,
                                 0, 0, IPPROTO_UDP, ipcache->intf_i,
                                 ipcache->encap.vlan_id,
                                 ci_udp_sendmsg_loop, &state, NULL);
}


/* Pass prepared packet to ip_send(), release our ref & and update stats */
ci_inline void prep_send_pkt(ci_netif* ni, ci_udp_state* us,
                             ci_ip_pkt_fmt* pkt, ci_ip_cached_hdrs* ipcache)
{
  int af = ipcache_af(&us->s.pkt);
  ci_ipx_hdr_t* ipx = oo_tx_ipx_hdr(af, pkt);
  ni->state->n_async_pkts -= pkt->n_buffers;

  TX_PKT_SET_SADDR(af, pkt, ipcache_laddr(ipcache));
  TX_PKT_SET_DADDR(af, pkt, ipcache_raddr(ipcache));
  TX_PKT_TTL(af, pkt) = ipcache_ttl(ipcache);
  ci_ip_set_mac_and_port(ni, ipcache, pkt);
  us->tx_count += pkt->pf.udp.tx_length;
  pkt->flags |= CI_PKT_FLAG_UDP;
  pkt->pf.udp.tx_sock_id = S_SP(us);
  CI_UDP_STATS_INC_OUT_DGRAMS( ni );

#if CI_CFG_IPV6
  if( IS_AF_INET6(af) ) {
    if( us->s.s_flags & CI_SOCK_FLAG_AUTOFLOWLABEL_REQ ) {
      TX_PKT_SET_FLOWLABEL(af, pkt, ci_ip6_flowlabel_be32(&ipcache->ipx.ip6));
    }
    pkt->flags |= CI_PKT_FLAG_IS_IP6;
  }
  else {
    pkt->flags &=~ CI_PKT_FLAG_IS_IP6;
  }
#endif

  if( ci_ipx_is_first_frag(af, ipx) ) {
#if CI_CFG_TIMESTAMPING
    /* Request TX timestamp for the first segment */
    if( onload_timestamping_want_tx_nic(us->s.timestamping_flags) )
      pkt->flags |= CI_PKT_FLAG_TX_TIMESTAMPED;
#endif
    if( ci_ipx_is_mf_set(af, ipx) ) {
      /* First fragmented chunk: calculate UDP checksum. */
      ci_udp_sendmsg_chksum(ni, pkt, af, ipx);
    }
  }
}


#ifdef __KERNEL__

static int do_sys_sendmsg(tcp_helper_endpoint_t *ep, oo_os_file os_sock,
                          const ci_msghdr* msg,
                          int flags, int user_buffers, int atomic)
{
  struct socket* sock;
  int i, bytes;
  struct msghdr kmsg;

  ci_assert(S_ISSOCK(os_sock->f_path.dentry->d_inode->i_mode));
  sock = SOCKET_I(os_sock->f_path.dentry->d_inode);
  ci_assert(! user_buffers || ! atomic);

  LOG_NT(ci_log("%s: user_buffers=%d atomic=%d sk_allocation=%x ATOMIC=%x",
               __FUNCTION__, user_buffers, atomic,
               sock->sk->sk_allocation, GFP_ATOMIC));

  if( atomic && sock->sk->sk_allocation != GFP_ATOMIC ) {
    ci_log("%s: cannot proceed", __FUNCTION__);
    return -EINVAL;
  }

  for( i = 0, bytes = 0; i < msg->msg_iovlen; ++i )
    bytes += msg->msg_iov[i].iov_len;

  memset(&kmsg, 0, sizeof(kmsg));
  if( user_buffers ) {
    oo_msg_iov_init(&kmsg, WRITE, msg->msg_iov, msg->msg_iovlen, bytes);
    bytes = sock_sendmsg(sock, &kmsg);
  }
  else {
    bytes = kernel_sendmsg(sock, &kmsg,
                           (struct kvec*) msg->msg_iov, msg->msg_iovlen,
                           bytes);
  }

  /* Clear OS TX flag if necessary  */
  oo_os_sock_status_bit_clear_handled(ep, os_sock, OO_OS_STATUS_TX);
  return bytes;
}

static int ci_udp_sendmsg_os(ci_netif* ni, ci_udp_state* us,
                             const ci_msghdr* msg, int flags,
                             int user_buffers, int atomic)
{
  int rc;
  tcp_helper_endpoint_t *ep = ci_netif_ep_get(ni, us->s.b.bufid);
  oo_os_file os_sock;

  ++us->stats.n_tx_os;

  rc = oo_os_sock_get_from_ep(ep, &os_sock);
  if( rc == 0 ) {
    rc = do_sys_sendmsg(ep, os_sock, msg, flags, user_buffers, atomic);
    oo_os_sock_put(os_sock);
  }
  return rc;
}


#else

ci_inline int ci_udp_sendmsg_os(ci_netif* ni, ci_udp_state* us,
                             const struct msghdr* msg, int flags,
                             int user_buffers, int atomic)
{
  ++us->stats.n_tx_os;
  return oo_os_sock_sendmsg(ni, S_SP(us), msg, flags);
}

#endif


#ifndef __KERNEL__
/* Bind OS socket to zero port to obtain a port value.
 * Must only be called with the local port set to 0 (default).
 *
 * TODO: wrap it into ioctl: bind+getsockname.
 * */
static int ci_udp_sendmsg_os_get_binding(citp_socket *ep, ci_fd_t fd,
                                         const struct msghdr * msg, int flags)
{
  ci_netif* ni = ep->netif;
  ci_udp_state* us = SOCK_TO_UDP(ep->s);
  int rc;
  union ci_sockaddr_u sa_u = {};
  socklen_t salen = sizeof(sa_u);
  ci_fd_t os_sock = (ci_fd_t)ci_get_os_sock_fd(fd);
  ci_addr_t laddr;
  ci_uint16 lport;

  ci_assert( !udp_lport_be16(us));

  if ( !CI_IS_VALID_SOCKET(os_sock) ) {
    LOG_U( log("%s: "NT_FMT" can't get OS socket (%d)", __FUNCTION__, 
		NT_PRI_ARGS(ni,us), os_sock));
    RET_WITH_ERRNO((int)os_sock); /*! \todo FIXME remvoce cast */
  }

  /* Not bound.  Probably not connected & sending for the first time,
   * therefore we let the OS do it & record the ephemeral port on
   * return from the sys_sendmsg. */

  /* We're not actually sending over the ef stack! :-) */
  UDP_CLR_FLAG(us, CI_UDPF_EF_SEND);

  sa_u.sa.sa_family = us->s.domain;
  rc = ci_sys_bind(os_sock, &sa_u.sa, IPX_SOCKADDR_SIZE(sa_u.sa.sa_family));

  /* see what the kernel did - we'll do just the same */
  if( rc == 0 )
    rc = ci_sys_getsockname( os_sock, &sa_u.sa, &salen);

  /* Must release the os_sock fd before we can take the stack lock, as the
   * citp_dup2_lock is held until we do so, and lock ordering does not allow
   * us to take the stack lock with the dup2 lock held.
   */
  ci_rel_os_sock_fd( os_sock );

  /* get out if getsockname fails or returns a non INET family
    * or a sockaddr struct that's too darned small */
  if( CI_UNLIKELY( rc || (!rc &&
			  ( sa_u.sa.sa_family != us->s.domain ||
			    /* FIXME case when sa_family is AF_INET and us->s.domain is AF_INET6 */
			    salen < IPX_SOCKADDR_SIZE(sa_u.sa.sa_family))))) {
    LOG_UV(log("%s: "NT_FMT" sys_getsockname prob. (rc:%d err:%d, fam:%d, "
		"len:%d - exp %u)",
		__FUNCTION__, NT_PRI_ARGS(ni,us), rc, errno, sa_u.sa.sa_family,
		salen, (unsigned)IPX_SOCKADDR_SIZE(sa_u.sa.sa_family)));
    return rc;
  }

  ci_netif_lock(ni);
  us->udpflags |= CI_UDPF_IMPLICIT_BIND;
  laddr = ci_get_addr(&sa_u.sa);
  lport = ci_get_port(&sa_u.sa);
  ci_sock_cmn_set_laddr(ep->s, laddr, lport);

  /* Add a filter if the local addressing is appropriate. */
  if( ~ni->state->flags & CI_NETIF_FLAG_USE_ALIEN_LADDRS &&
      lport != 0 && (CI_IPX_ADDR_IS_ANY(laddr) ||
      cicp_user_addr_is_local_efab(ni, laddr)) ) {
    ci_assert( ! (us->udpflags & CI_UDPF_FILTERED) );

    rc = ci_tcp_ep_set_filters(ni, S_SP(us), us->s.cp.so_bindtodevice,
                               OO_SP_NULL);
    if( rc ) {
      LOG_U(log("%s: FILTER ADD FAIL %d", __FUNCTION__, -rc));
      if( rc == -EFILTERSSOME )
        UDP_SET_FLAG(us, CI_UDPF_FILTERED);
      if( CITP_OPTS.no_fail )
        rc = 0;
    }
    else {
      UDP_SET_FLAG(us, CI_UDPF_FILTERED);
    }
  }
  ci_netif_unlock(ni);

  laddr = sock_laddr(&us->s);
  LOG_UV(ci_log("%s: "NT_FMT"Unbound: first send via OS got L:[" IPX_PORT_FMT "]",
                __FUNCTION__, NT_PRI_ARGS(ni,us),
                IPX_ARG(AF_IP(laddr)), udp_lport_be16(us)));

  return rc;
}
#endif


static int ci_udp_sendmsg_send_pkt_via_os(ci_netif* ni, ci_udp_state* us,
                                          ci_ip_pkt_fmt* pkt, int flags,
                                          struct udp_send_info* sinf)
{
  int seg_i, buf_len, iov_i;
  ci_ip_pkt_fmt* frag_head;
  ci_ip_pkt_fmt* buf_pkt;
  struct iovec iov[30];
  ci_udp_hdr* udp;
  void* buf_start;
  ci_msghdr m;
#ifndef __KERNEL__
  struct sockaddr_storage ss;
#endif
  int af = ipcache_af(&us->s.pkt);

  m.msg_iov = iov;
  m.msg_iovlen = 0;

#ifndef __KERNEL__
  /* This function is called in kernel mode when Onload socket is passed to
   * libc/syscall write() call.  It happens if and only if the socket is
   * connected, so there is no need to handle msg_name in kernel case. */
  {
    ci_addr_t daddr = TX_PKT_DADDR(af, pkt);
    if( ! CI_IPX_ADDR_IS_ANY(daddr) ) {
      ss = ci_make_sockaddr_storage_from_addr(TX_PKT_UDP(pkt)->udp_dest_be16,
                                              daddr);
      m.msg_name = &ss;
      m.msg_namelen = IPX_SOCKADDR_SIZE(af);
    }
    else {
      m.msg_name = NULL;
      m.msg_namelen = 0;
    }
    m.msg_controllen = 0;
  }
#endif /* __KERNEL__ */

  frag_head = pkt;
  udp = TX_PKT_UDP(frag_head);
  buf_pkt = frag_head;
  seg_i = 0;
  iov_i = 0;
  while( 1 ) {
    if( buf_pkt == pkt )
      /* First IP fragment, move past IP+UDP header */
      buf_start = udp + 1;
    else if( seg_i == 0 )
      /* Subsequent IP fragment, move past IP header */
      buf_start = oo_tx_ipx_data(af, buf_pkt);
    else
      /* Internal (jumbo) fragment, no header to move past */ 
      buf_start = PKT_START(buf_pkt);
    buf_len = buf_pkt->buf_len;
    buf_len -= (char*) buf_start - PKT_START(buf_pkt);
    iov[iov_i].iov_base = buf_start;
    iov[iov_i].iov_len = buf_len;
    if( OO_PP_IS_NULL(buf_pkt->frag_next) )
      break;
    if( ++iov_i == sizeof(iov) / sizeof(iov[0]) ) {
      /* We're out of iovec space; MTU must be very small.  You have to be
       * pretty unlucky to hit this path, so bomb.
       */
      return -EMSGSIZE;
    }
    buf_pkt = PKT_CHK(ni, buf_pkt->frag_next);
    if( ++seg_i == frag_head->n_buffers ) {
      seg_i = 0;
      frag_head = buf_pkt;
    }
  }

#ifdef __KERNEL__
  if( sinf == NULL ) {
    /* We're not in the context of the thread that invoked sendmsg(), so we
     * mustn't block this thread.
     */
    ci_assert(flags == 0 || flags == MSG_CONFIRM);
    flags |= MSG_DONTWAIT;
  }
#endif

  m.msg_iovlen = iov_i + 1;
  return ci_udp_sendmsg_os(ni, us, &m, flags, 0, sinf == NULL);
}


static void fixup_pkt_not_transmitted(ci_netif *ni, ci_ip_pkt_fmt* pkt)
{
  ci_assert(ci_netif_is_locked(ni));
  while( 1 ) {
    /* This is normally done in prep_send_pkt() */
    ci_assert_gt(pkt->n_buffers, 0);
    ni->state->n_async_pkts -= pkt->n_buffers;

    /* Drop additional ref taken in ci_udp_sendmsg_fill() which is normally
     * consumed by ci_netif_send(). */
    ci_assert_gt(pkt->refcount, 1);
    pkt->refcount--;

    if( OO_PP_IS_NULL(pkt->next) )
      break;
    pkt = PKT_CHK(ni, pkt->next);
  }
}


static void ci_udp_sendmsg_send(ci_netif* ni, ci_udp_state* us,
                                ci_ip_pkt_fmt* pkt, int flags,
                                bool may_poll,
                                struct udp_send_info* sinf)
{
  ci_ip_pkt_fmt* first_pkt = pkt;
  ci_ip_cached_hdrs* ipcache;
  int ipcache_onloadable, is_connected_send;
#ifdef __KERNEL__
  int i = 0;
#endif
  int af = ipcache_af(&us->s.pkt);
  ci_addr_t pkt_daddr = TX_PKT_DADDR(af, pkt);
  unsigned tot_len;
  int old_ipcache_updated = (sinf == NULL) ? 0 : sinf->old_ipcache_updated;

  ci_assert(ci_netif_is_locked(ni));

  is_connected_send = CI_IPX_ADDR_IS_ANY(pkt_daddr) ? 1 : 0;

  if( ! is_connected_send ) {
    /**********************************************************************
     * Unconnected send -- dest IP and port provided.  First packet
     * contains correct remote IP and port.
     */
    ++us->stats.n_tx_onload_uc;
    ipcache = &us->ephemeral_pkt;

    if( CI_IPX_ADDR_EQ(pkt_daddr, ipcache_raddr(ipcache)) &&
        TX_PKT_IPX_DPORT(af, pkt) == ipcache->dport_be16 ) {
      if( oo_cp_ipcache_is_valid(ni, ipcache) )
        goto done_hdr_update;
      old_ipcache_updated = 1;
    }
    else {
      us->udpflags &=~ CI_UDPF_LAST_SEND_NOMAC;
      ci_ipcache_set_daddr(ipcache, pkt_daddr);
      ipcache->dport_be16 = TX_PKT_IPX_DPORT(af, pkt);
      if( sinf != NULL && sinf->used_ipcache &&
          oo_cp_ipcache_is_valid(ni, &sinf->ipcache) ) {
        /* Caller did control plane lookup earlier, and it is still
         * valid.
         */
        ci_ipcache_set_saddr(ipcache, ipcache_laddr(&sinf->ipcache));
        cicp_ip_cache_update_from(ni, ipcache, &sinf->ipcache);
        goto done_hdr_update;
      }
    }

    ++us->stats.n_tx_cp_uc_lookup;
    /* Although we know that [ipcache] has the wrong destination, it might
     * still be valid for the old destination.  Invalidate it to avoid wrong-
     * footing cicp_user_retrieve(). */
    ci_ip_cache_invalidate(ipcache);
    cicp_user_retrieve(ni, ipcache, &us->s.cp);
  }
  else {
    /**********************************************************************
     * Connected send.
     */
    ci_addr_t udp_raddr = udp_ipx_raddr(us);
    int is_frag = ci_ipx_is_frag(af, TX_PKT_IPX_HDR(af, pkt));

    ++us->stats.n_tx_onload_c;
    if( CI_IPX_ADDR_IS_ANY(udp_raddr) )
      goto no_longer_connected;
    ipcache = &us->s.pkt;
    if(CI_UNLIKELY( ! oo_cp_ipcache_is_valid(ni, ipcache) )) {
      ++us->stats.n_tx_cp_c_lookup;
      cicp_user_retrieve(ni, ipcache, &us->s.cp);
      old_ipcache_updated = 1;
    }

    /* Set IP and port now we know we're not going to send_pkt_via_os. */
    TX_PKT_SET_DADDR(af, pkt, udp_raddr);
    TX_PKT_IPX_UDP(af, pkt, is_frag)->udp_dest_be16 = udp_rport_be16(us);
  }

 done_hdr_update:
  switch( ipcache->status ) {
  case retrrc_success:
    ipcache_onloadable = 1;

    /* Try to avoid reordering of the packets: send all nomac packets */
    if( old_ipcache_updated && (us->udpflags & CI_UDPF_LAST_SEND_NOMAC) ) {
      oo_deferred_send(ni);
      us->udpflags &=~ CI_UDPF_LAST_SEND_NOMAC;
    }
    break;
  case retrrc_nomac:
    ipcache_onloadable = 0;
    break;
  default:
    goto send_pkt_via_os;
  }

#if CI_CFG_IPV6
  if( ! is_connected_send && IS_AF_INET6(af) &&
      us->s.s_flags & CI_SOCK_FLAG_AUTOFLOWLABEL_REQ ) {
    ci_uint32 flowlabel = ci_make_flowlabel(ni, ipcache_laddr(ipcache),
        TX_PKT_IPX_SPORT(af, pkt), ipcache_raddr(ipcache),
        TX_PKT_IPX_DPORT(af, pkt), IPPROTO_UDP);
    ci_ip6_set_flowlabel_be32(&ipcache->ipx.ip6, flowlabel);
  }
#endif

  tot_len = ipx_hdr_tot_len(af, oo_tx_ipx_hdr(af, pkt));

  if(CI_UNLIKELY( tot_len > ipcache->mtu ))
    /* Oh dear -- we've fragmented the packet with too large an MTU.
     * Either the MTU has recently changed, or we are unconnected and
     * sampled the MTU from the cached value at a bad time.
     *
     * ?? TODO: We either need to fragment again, or send via the OS
     * socket.
     *
     * For now just carry on regardless...
     */
    ci_log("%s: pkt mtu=%d exceeds path mtu=%d", __FUNCTION__,
           tot_len, ipcache->mtu);

  /* Linux allows sending IPv6 packets with zero Hop Limit field */
  if( ipcache_ttl(ipcache) || ipcache_is_ipv6(ipcache) ) {
    if(CI_LIKELY( ipcache_onloadable )) {
      /* TODO: Hit the doorbell just once. */
      while( 1 ) {
        oo_pkt_p next = pkt->next;
        prep_send_pkt(ni, us, pkt, ipcache);
        /* We've called ci_netif_pkt_hold() in ci_udp_sendmsg_fill(). */
        ci_netif_send(ni, pkt);
        if( OO_PP_IS_NULL(next) )
          break;
        pkt = PKT_CHK(ni, next);
#ifdef __KERNEL__
        if(CI_UNLIKELY( i++ > ni->pkt_sets_n << CI_CFG_PKTS_PER_SET_S )) {
          ci_netif_error_detected(ni, CI_NETIF_ERROR_UDP_SEND_PKTS_LIST,
                                  __FUNCTION__);
        }
#endif
      }
      if( flags & MSG_CONFIRM )
        oo_cp_arp_confirm(ni->cplane, &ipcache->fwd_ver,
                          ci_ni_fwd_table_id(ni));

      if( CI_IPX_IS_MULTICAST(ipcache_raddr(ipcache)) )
        ci_udp_sendmsg_mcast(ni, us, ipcache, first_pkt);
      us->udpflags &=~ CI_UDPF_LAST_SEND_NOMAC;
    }
     else {
      /* Packet should go via an onload interface, but ipcache is not valid.
       * Could be that we don't have a mac, or could be that we need to drop
       * into the kernel to keep the mac entry alive.
       *
       * ?? FIXME: Currently this will end up sending the packet via the
       * kernel stack.  This is very bad because it can result in
       * out-of-orderness (which, although technically allowed for unreliable
       * datagram sockets, is undesirable as it provokes some apps to perform
       * poorly or even misbehave).  If mac exists, we need to ensure we send
       * via onload.  (And make sure we get the multicast case right).
       */
      ++us->stats.n_tx_cp_no_mac;
      us->udpflags |= CI_UDPF_LAST_SEND_NOMAC;
      while( 1 ) {
        oo_pkt_p next = pkt->next;
        prep_send_pkt(ni, us, pkt, ipcache);
        ci_ip_send_udp_slow(ni, &us->s.cp, pkt, ipcache);
        if( OO_PP_IS_NULL(next) )
          break;
        pkt = PKT_CHK(ni, next);
#ifdef __KERNEL__
        if(CI_UNLIKELY( i++ > ni->pkt_sets_n << CI_CFG_PKTS_PER_SET_S )) {
          ci_netif_error_detected(ni, CI_NETIF_ERROR_UDP_SEND_PKTS_LIST,
                                  __FUNCTION__);
        }
#endif
      }
    }
  }
  else if( CI_IPX_IS_MULTICAST(ipcache_raddr(ipcache)) ) {
    fixup_pkt_not_transmitted(ni, first_pkt);
    ci_udp_sendmsg_mcast(ni, us, ipcache, first_pkt);
  }
  else {
    fixup_pkt_not_transmitted(ni, first_pkt);
    LOG_U(ci_log("%s: do not send UDP packet because IP TTL = 0",
                 __FUNCTION__));
  }

  /* For an application which does almost nothing but sending UDP
   * it would help to handle TX complete events in time.
   * We should do it from direct user calls only, and avoid any internal
   * recursion.
   */
  if( may_poll && ipcache->status == retrrc_success ) {
    ci_netif_state_nic_t* nsn = &ni->state->nic[ipcache->intf_i];
    if( nsn->tx_dmaq_insert_seq - nsn->tx_dmaq_insert_seq_last_poll >
        NI_OPTS(ni).send_poll_thresh ) {
      nsn->tx_dmaq_insert_seq_last_poll = nsn->tx_dmaq_insert_seq;
      ci_netif_poll(ni);
    }
  }

  return;

 send_pkt_via_os:
  ++us->stats.n_tx_os_late;
  fixup_pkt_not_transmitted(ni, pkt);

  {
    int rc = ci_udp_sendmsg_send_pkt_via_os(ni, us, pkt, flags, sinf);
    if( rc < 0 ) {
      if( sinf != NULL )
        sinf->rc = rc;
      else
        ci_log("ci_udp_sendmsg_send_pkt_via_os failed rc=%d", rc);
    }
  }
  return;

 no_longer_connected:
  /* We were connected when we entered ci_udp_sendmsg(), but we're not now.
   * If not draining tx_async_q, return error to caller.  Otherwise just
   * drop this datagram.
   */
  if( sinf != NULL )
    sinf->rc = -EDESTADDRREQ;
  else
    /* We're draining [tx_async_q], so too late to return an error to the
     * thread that invoked sendmsg().  Silent drop is only option available
     * to us.  This is not so bad -- can only happen if one thread is doing
     * sendmsg() and another is doing connect() concurrently (which is an
     * odd thing to do).
     */
    ++us->stats.n_tx_unconnect_late;
  fixup_pkt_not_transmitted(ni, pkt);
  return;
}


static int ci_udp_tx_datagram_level(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                    ci_boolean_t ni_locked)
{
  /* Sum the contributions from each IP fragment. */
  int level = 0;
  for( ; ; pkt = PKT_CHK_NML(ni, pkt->next, ni_locked) ) {
    level += pkt->pf.udp.tx_length;
    if( OO_PP_IS_NULL(pkt->next) )
      return level;
  }
}


void ci_udp_sendmsg_send_async_q(ci_netif* ni, ci_udp_state* us)
{
  oo_pkt_p pp, send_list;
  ci_ip_pkt_fmt* pkt;
  int flags, level = 0;

  /* Grab the contents of [tx_async_q]. */
  do {
    OO_PP_INIT(ni, pp, us->tx_async_q);
    if( OO_PP_IS_NULL(pp) )  return;
  } while( ci_cas32_fail(&us->tx_async_q, OO_PP_ID(pp), OO_PP_ID_NULL) );

  /* Reverse the list. */
  send_list = OO_PP_NULL;
  do {
    pkt = PKT_CHK(ni, pp);
    level += ci_udp_tx_datagram_level(ni, pkt, CI_TRUE);
    pp = pkt->netif.tx.dmaq_next;
    pkt->netif.tx.dmaq_next = send_list;
    send_list = OO_PKT_P(pkt);
  }
  while( OO_PP_NOT_NULL(pp) );

  oo_atomic_add(&us->tx_async_q_level, -level);

  /* Send each datagram. */
  while( 1 ) {
    pp = pkt->netif.tx.dmaq_next;
    if( pkt->flags & CI_PKT_FLAG_MSG_CONFIRM )
      flags = MSG_CONFIRM;
    else
      flags = 0;
    ++us->stats.n_tx_lock_defer;
    ci_udp_sendmsg_send(ni, us, pkt, flags, false/*don't poll*/, NULL);
    ci_netif_pkt_release(ni, pkt);
    if( OO_PP_IS_NULL(pp) )  break;
    pkt = PKT_CHK(ni, pp);
  }
}

static void ci_udp_sendmsg_async_q_enqueue(ci_netif* ni, ci_udp_state* us,
                                           ci_ip_pkt_fmt* pkt, int flags)
{
  if( flags & MSG_CONFIRM )
    /* Only setting this for first IP fragment -- that should be fine. */
    pkt->flags |= CI_PKT_FLAG_MSG_CONFIRM;

  oo_atomic_add(&us->tx_async_q_level, 
                ci_udp_tx_datagram_level(ni, pkt, CI_FALSE));
  do
    OO_PP_INIT(ni, pkt->netif.tx.dmaq_next, us->tx_async_q);
  while( ci_cas32_fail(&us->tx_async_q,
                       OO_PP_ID(pkt->netif.tx.dmaq_next), OO_PKT_ID(pkt)) );

  if( ci_netif_lock_or_defer_work(ni, &us->s.b) )
    ci_netif_unlock(ni);
}


#ifndef __KERNEL__
/* Check if provided address struct/content is OK for us. */
static int ci_udp_name_is_ok(int af, ci_udp_state* us, const struct msghdr* msg)
{
  ci_assert(us);
  ci_assert(msg != NULL);
  ci_assert(msg->msg_namelen > 0);

  /* name ptr must be valid if len != 0 */
  if( msg->msg_name == NULL )
    return 0;

#if CI_CFG_FAKE_IPV6 && !CI_CFG_IPV6
  if( us->s.domain == AF_INET6 ) {
    return msg->msg_namelen >= SIN6_LEN_RFC2133 && af == AF_INET6 &&
      ci_tcp_ipv6_is_ipv4((struct sockaddr*) msg->msg_name);
  }
#endif

  if( af != AF_INET && !IS_AF_INET6(us->s.domain) )
    return 0;

  return msg_namelen_ok(af, msg->msg_namelen);
}
#endif


#define OO_TIMEVAL_UNINITIALISED  ((struct oo_timeval*) 1)


static int ci_udp_sendmsg_may_send(ci_udp_state* us, int bytes_to_send)
{
  int sndbuf = us->s.so.sndbuf;

  if( bytes_to_send > sndbuf / 2 )
    /* Datagrams are large: Send at least two before blocking.  Otherwise
     * we risk allowing the link to go idle because we'll not get any
     * pipelining.
     */
    if( TXQ_LEVEL(us) < sndbuf )
      return 1;

  if( ci_udp_tx_advertise_space(us) )
    /* App may have been told by select/poll that there is space in the
     * sendq, and so may have called us expecting to not block (or get
     * EAGAIN).  So don't disappoint them...
     */
    return 1;

  return sndbuf >= (int) (TXQ_LEVEL(us) + bytes_to_send);
}


static int ci_udp_sendmsg_wait(ci_netif* ni, ci_udp_state* us,
                               unsigned bytes_to_send, int flags,
                               struct udp_send_info* sinf)
{
  ci_uint64 start_frc = 0, now_frc = 0;
  ci_uint64 schedule_frc = 0;
#ifndef __KERNEL__
  citp_signal_info* si = citp_signal_get_specific_inited();
#endif
  ci_uint64 max_spin = 0;
  int spin_limit_by_so = 0;
  ci_uint64 sleep_seq;
  int rc, first_time = 1;
  unsigned udp_send_spin;

  if( ci_udp_sendmsg_may_send(us, bytes_to_send) )
    return 0;

#ifndef __KERNEL__
  udp_send_spin = oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_UDP_SEND);
#else
  udp_send_spin = 0;
#endif

  /* Processing events may free space. */
  if( ci_netif_may_poll(ni) && ci_netif_has_event(ni) )
    if( si_trylock_and_inc(ni, sinf, us->stats.n_tx_lock_poll) )
      ci_netif_poll(ni);

 no_error:
  while( 1 ) {
    sleep_seq = us->s.b.sleep_seq.all;
    ci_rmb();
    if(CI_UNLIKELY( (rc = ci_get_so_error(&us->s)) != 0 || us->s.tx_errno ))
      goto so_error;
    if( ci_udp_sendmsg_may_send(us, bytes_to_send) ) {
      us->stats.n_tx_poll_avoids_full += first_time;
      if( udp_send_spin )
        ni->state->is_spinner = 0;
      return 0;
    }
    if( (flags & MSG_DONTWAIT) ||
        (us->s.b.sb_aflags & (CI_SB_AFLAG_O_NONBLOCK|CI_SB_AFLAG_O_NDELAY)) ) {
      ++us->stats.n_tx_eagain;
      return -EAGAIN;
    }
    if( first_time ) {
      first_time = 0;
      if( udp_send_spin ) {
        max_spin = us->s.b.spin_cycles;
        if( us->s.so.sndtimeo_msec ) {
          ci_uint64 max_so_spin = sinf->timeout * IPTIMER_STATE(ni)->khz;
          if( max_so_spin <= max_spin ) {
            max_spin = max_so_spin;
            spin_limit_by_so = 1;
          }
        }
        ++us->stats.n_tx_spin;
        ci_frc64(&start_frc);
        now_frc = start_frc;
        schedule_frc = start_frc;
      }
    }
    if( udp_send_spin ) {
      if( now_frc - start_frc < max_spin ) {
#if CI_CFG_SPIN_STATS
        ni->state->stats.spin_udp_send++;
#endif
        if( ci_netif_may_poll(ni) ) {
          if( ci_netif_need_poll_spinning(ni, now_frc) ) {
            if( si_trylock(ni, sinf) )
              ci_netif_poll(ni);
          }
          else if( ! ni->state->is_spinner )
            ni->state->is_spinner = 1;
        }
        if( sinf->stack_locked ) {
          ci_netif_unlock(ni);
          sinf->stack_locked = 0;
        }
        rc = OO_SPINLOOP_PAUSE_CHECK_SIGNALS(ni, now_frc, &schedule_frc,
                                             us->s.so.sndtimeo_msec,
                                             NULL, si);
        if( rc != 0 ) {
          ni->state->is_spinner = 0;
          return rc;
        }
      }
      else if( spin_limit_by_so ) {
        ++us->stats.n_tx_eagain;
        return -EAGAIN;
      }
    }
    else {
      if( sinf->timeout && udp_send_spin ) {
        ci_uint32 spin_ms = NI_OPTS(ni).spin_usec >> 10;
        if( spin_ms < sinf->timeout )
          sinf->timeout -= spin_ms;
        else {
          ++us->stats.n_tx_eagain;
          return -EAGAIN;
        }
      }
      ++us->stats.n_tx_block;
      rc = ci_sock_sleep(ni, &us->s.b, CI_SB_FLAG_WAKE_TX,
                         sinf->stack_locked ? CI_SLEEP_NETIF_LOCKED : 0,
                         sleep_seq, &sinf->timeout);
      sinf->stack_locked = 0;
      if( rc < 0 )
        return rc;
    }
  }

 so_error:
  if( udp_send_spin )
    ni->state->is_spinner = 0;
  if( rc == 0 )
    rc = -us->s.tx_errno;
  if( rc == 0 )
    goto no_error;
  return rc;
}
  

ci_inline ci_udp_hdr* udp_init(ci_udp_state* us, ci_ip_pkt_fmt* pkt,
                               unsigned payload_bytes, bool is_frag)
{
  int af = ipcache_af(&us->s.pkt);
  ci_udp_hdr* udp = TX_PKT_IPX_UDP(af, pkt, is_frag);
  udp->udp_len_be16 = (ci_uint16) (payload_bytes + sizeof(ci_udp_hdr));
  udp->udp_len_be16 = CI_BSWAP_BE16(udp->udp_len_be16);
  udp->udp_check_be16 = 0;
  udp->udp_source_be16 = udp_lport_be16(us);
  return udp;
}


/* put in the def. eth hdr, IP hdr then update the address
 * and IP ID fields. */
ci_inline ci_ip4_hdr* eth_ip_init(ci_netif* ni, ci_udp_state* us, 
				  ci_ip_pkt_fmt* pkt)
{
  ci_ip4_hdr* ip;

  ip = oo_tx_ip_hdr(pkt);

  ip->ip_ihl_version = CI_IP4_IHL_VERSION(sizeof(*ip));
  ip->ip_tos = UDP_IP_HDR(us)->ip_tos;
  /* ip_tot_len_be16 */
  /* ip_id_be16 */
  ip->ip_frag_off_be16 = CI_IP4_FRAG_DONT;
  ip->ip_protocol = IPPROTO_UDP;
  ip->ip_check_be16 = 0;
  return ip;
}

#if CI_CFG_IPV6
ci_inline ci_ip6_hdr* eth_ip6_init(ci_netif* ni, ci_udp_state* us,
                                   ci_ip_pkt_fmt* pkt, bool is_frag)
{
  ci_ip6_hdr* ip6 = oo_tx_ip6_hdr(pkt);
  ci_uint8 tclass = ci_ip6_tclass(&us->s.pkt.ipx.ip6);

  ip6->prio_version = 6 << 4u;
  ci_ip6_set_flowinfo(ip6, tclass, 0);
  ip6->next_hdr = (is_frag) ? CI_NEXTHDR_FRAGMENT : IPPROTO_UDP;
  return ip6;
}
#endif


/* Allocate packet buffers and fill them with the payload.
 *
 * Returns [bytes_to_send] on success, -errno on failure.
 */
static
int ci_udp_sendmsg_fill(ci_netif* ni, ci_udp_state* us,
                        ci_iovec_ptr* piov, int bytes_to_send,
                        int flags,
                        struct oo_pkt_filler* pf,
                        struct udp_send_info* sinf,
                        bool need_frag)
{
  ci_ip_pkt_fmt* first_pkt;
  ci_ip_pkt_fmt* new_pkt;
  int rc, frag_bytes, payload_bytes;
  int bytes_left, frag_off;
  ci_ipx_id_t ipx_id;
  int pmtu = sinf->ipcache.mtu;
  int can_block = ! ((NI_OPTS(ni).udp_nonblock_no_pkts_mode) &&
                     ((flags & MSG_DONTWAIT) ||
                       (us->s.b.sb_aflags & (CI_SB_AFLAG_O_NONBLOCK|CI_SB_AFLAG_O_NDELAY))));
  int af = ipcache_af(&us->s.pkt);
  ci_udp_hdr* udp;

  ci_assert(pmtu > 0);
  ci_assert_equiv( need_frag,
      bytes_to_send > pmtu - CI_IPX_HDR_SIZE(af) - sizeof(ci_udp_hdr) );

  frag_off = 0;
  bytes_left = bytes_to_send;

  /* Grab lock early, if options allow.  This reduces overhead and latency
   * because we avoid the cost of atomic ops to allocate packet buffers.
   */
  if( bytes_to_send < NI_OPTS(ni).udp_send_unlock_thresh &&
      ! sinf->stack_locked )
    sinf->stack_locked = ci_netif_trylock(ni);

  rc = ci_netif_pkt_alloc_block(ni, &us->s, &sinf->stack_locked, can_block,
                                &first_pkt);
  if( rc != 0 )
    return rc;
  oo_tx_pkt_layout_init(first_pkt);

  /* ID for IPv6 case should only be generated when fragmentation is really
   * required. */
  if( !IS_AF_INET6(af) || need_frag )
    ipx_id = ci_next_ipx_id_be(af, ni);

  udp = udp_init(us, first_pkt, bytes_to_send, need_frag);

  oo_pkt_filler_init(pf, first_pkt, (uint8_t*) udp + sizeof(ci_udp_hdr));
  first_pkt->pay_len = ((char*) udp + sizeof(ci_udp_hdr) - PKT_START(first_pkt));

  oo_pkt_af_set(first_pkt, af);

  payload_bytes = pmtu - CI_IPX_HDR_SIZE(af) - sizeof(ci_udp_hdr);
  if( payload_bytes >= bytes_left ) {
    payload_bytes = bytes_left;
    bytes_left = 0;
  }
  else {
    payload_bytes = UDP_PAYLOAD1_SPACE_PMTU(af, pmtu);
    bytes_left -= payload_bytes;
  }
  frag_bytes = payload_bytes + sizeof(ci_udp_hdr);

  while( 1 ) {
    pf->pkt->pf.udp.tx_length = payload_bytes + sizeof(ci_udp_hdr) +
        CI_IPX_HDR_SIZE(af) + sizeof(ci_ether_hdr);
    if( need_frag )
      pf->pkt->pf.udp.tx_length += CI_IPX_FRAG_HDR_SIZE(af);

#if CI_CFG_IPV6
    if( IS_AF_INET6(af) ) {
      ci_ip6_hdr *ip6 = eth_ip6_init(ni, us, pf->pkt, need_frag);
      ip6->payload_len = frag_bytes;
      if( need_frag ) {
        ci_ip6_frag_hdr_init(ci_ip6_data(ip6), IPPROTO_UDP, frag_off,
                             (bytes_left > 0) ? 1 : 0, ipx_id.ip6);

        ip6->payload_len += CI_IPX_FRAG_HDR_SIZE(af);
      }
      ip6->payload_len = CI_BSWAP_BE16(ip6->payload_len);
    }
    else
#endif
    {
      ci_ip4_hdr *ip = eth_ip_init(ni, us, pf->pkt);
      ip->ip_tot_len_be16 = frag_bytes + sizeof(ci_ip4_hdr);
      ip->ip_tot_len_be16 = CI_BSWAP_BE16(ip->ip_tot_len_be16);
      ip->ip_frag_off_be16 = frag_off >> 3u;
      ip->ip_frag_off_be16 = CI_BSWAP_BE16(ip->ip_frag_off_be16);
      if( bytes_left > 0 )
        ip->ip_frag_off_be16 |= CI_IP4_FRAG_MORE;
      else if( us->s.s_flags & CI_SOCK_FLAG_ALWAYS_DF ||
               ( us->s.s_flags & CI_SOCK_FLAG_PMTU_DO &&
                 pf->pkt == first_pkt ) ) {
        ip->ip_frag_off_be16 = CI_IP4_FRAG_DONT;
      }
      ip->ip_id_be16 = ipx_id.ip4;
    }
    frag_off += frag_bytes;

    /* This refcount is used later by ci_netif_send() */
    ci_netif_pkt_hold(ni, pf->pkt);

    rc = oo_pkt_fill(ni, &us->s, &sinf->stack_locked, can_block, pf, piov,
                     payload_bytes CI_KERNEL_ARG(CI_ADDR_SPC_CURRENT));
    if( CI_UNLIKELY( rc != 0 ) )
      goto fill_failed;

    if( bytes_left == 0 )
      break;

    /* This counts the number of fragments not including the first. */
    ++us->stats.n_tx_fragments;

    rc = ci_netif_pkt_alloc_block(ni, &us->s, &sinf->stack_locked, 
                                  can_block, &new_pkt);
    if( CI_UNLIKELY( rc != 0 ))
      goto fill_failed;
    oo_tx_pkt_layout_init(new_pkt);

    pf->pkt->next = OO_PKT_P(new_pkt);
    pf->last_pkt->frag_next = OO_PKT_P(new_pkt);

    udp = TX_PKT_IPX_UDP(af, new_pkt, need_frag);
    oo_pkt_filler_init(pf, new_pkt, udp);
    new_pkt->pay_len = (char*) udp - PKT_START(new_pkt);

    oo_pkt_af_set(new_pkt, af);

    payload_bytes = UDP_PAYLOAD2_SPACE_PMTU(af, pmtu);
    payload_bytes = CI_MIN(payload_bytes, bytes_left);
    bytes_left -= payload_bytes;
    frag_bytes = payload_bytes;
  }

  pf->pkt->next = OO_PP_NULL;
  pf->last_pkt = pf->pkt;
  pf->pkt = first_pkt;

  return bytes_to_send;

 fill_failed:
  if( ! sinf->stack_locked && ci_netif_lock(ni) == 0 )
    sinf->stack_locked = 1;

  /* Release the refs we've taken for ci_netif_send().
   * Unlike fixup_pkt_not_transmitted(), we can't rely that ->next links to
   * the next IP fragment, because oo_pkt_fill() can leave it in other way.
   * So, we should go through all fragments and decrement refcounts for IP
   * fragments only. */
  {
    ci_ip_pkt_fmt* pkt = first_pkt;
    int n_buffers;

    while( 1 ) {
      n_buffers = pkt->n_buffers;
      ci_assert_gt(pkt->refcount, 1);
      pkt->refcount--;
      /* Skip scatter-gather fragments, we need to release
       * IP fragments only. */
      while( n_buffers-- > 0 ) {
        CI_NETIF_STATE_MOD(ni, sinf->stack_locked, n_async_pkts, -);
        if( OO_PP_IS_NULL(pkt->frag_next) )
          goto pkt_chain_released;
        pkt = PKT_CHK(ni, pkt->frag_next);
      }
    }
  }
 pkt_chain_released:

  /* Free the packet chain by freeing the first fragment. */
 #ifdef __KERNEL__
   if( ! sinf->stack_locked )
     ci_netif_set_merge_atomic_flag(ni);
   ci_netif_pkt_release_mnl(ni, first_pkt, &sinf->stack_locked);
 #else
   /* ci_netif_lock() can't fail in UL */
   ci_assert(sinf->stack_locked);
   ci_netif_pkt_release(ni, first_pkt);
 #endif

  return rc;
}


static
void ci_udp_sendmsg_onload(ci_netif* ni, ci_udp_state* us,
                           const ci_msghdr* msg, int flags,
                           struct udp_send_info* sinf)
{
  int rc, i;
  unsigned long bytes_to_send;
  struct oo_pkt_filler pf;
  ci_iovec_ptr piov;
  int was_locked;
  int af = ipcache_af(&us->s.pkt);
  bool need_frag = false;

  /* Caller should guarantee the following: */
  ci_assert(ni);
  ci_assert(us);
  ci_assert(msg != NULL);

  /* Find total amount of payload, and validate pointers. */
  bytes_to_send = 0;
  if( msg->msg_iovlen > 0 ) {
    i = msg->msg_iovlen - 1;
    do {
      if( CI_IOVEC_BASE(&msg->msg_iov[i]) != NULL )
        bytes_to_send += CI_IOVEC_LEN(&msg->msg_iov[i]);
      else if( CI_IOVEC_LEN(&msg->msg_iov[i]) > 0 )
        goto efault;
    } while( --i >= 0 );
    ci_iovec_ptr_init_nz(&piov, msg->msg_iov, msg->msg_iovlen);
  }
  else {
    ci_iovec_ptr_init(&piov, NULL, 0);
  }

  if( bytes_to_send > sinf->ipcache.mtu - CI_IPX_HDR_SIZE(af) -
      sizeof(ci_udp_hdr) )
    need_frag = true;

  /* For now we don't allocate packets in advance, so init to NULL */
  pf.alloc_pkt = NULL;

  if( ! UDP_HAS_SENDQ_SPACE(us, bytes_to_send)         |
      (bytes_to_send > (unsigned long) CI_UDP_MAX_PAYLOAD_BYTES(af)) )
    goto no_space_or_too_big;

 back_to_fast_path:
  was_locked = sinf->stack_locked;
  if( need_frag && is_sock_flag_always_df_set(&us->s, af) ) {
    /* We are trying to send too large a datagram with DontFragment bit */
    if( is_sockopt_flag_ip_recverr_set(&us->s, af ) ) {
      /* We have to add an error message to the error queue.
       * Let OS do it! */
      goto send_via_os;
    }
    if( is_sock_flag_pmtu_do_set(&us->s, af) ) {
      /* IP_PMTUDISC_DO */
      sinf->rc = -EMSGSIZE;
      return;
    }
    else
#ifndef __KERNEL__
        if( msg->msg_namelen == 0 )
#endif
    {
      /* IP_PMTUDISC_PROBE connected case.
       * Linux does following:
       * - try to send the large packet with DF bit;
       * - IP subsytem finds out that it does not fit into current PMTU;
       * - IP subsystem sends a sort of ICMP Too Big message;
       * - socket gets the error.
       *
       * So we return bytes_to_send to user, pretending that "we tried to
       * send it", but set SO_ERROR so that the next socket call will tell
       * the caller about this error.
       */
      sinf->rc = bytes_to_send;
      us->s.so_error = EMSGSIZE;
      return;
    }
    /* IP_PMTUDISC_PROBE does not do anything in non-connected case */
  }
  rc = ci_udp_sendmsg_fill(ni, us, &piov, bytes_to_send, flags, &pf, sinf,
                           need_frag);
#if CI_CFG_TIMESTAMPING
  if( us->s.timestamping_flags & ONLOAD_SOF_TIMESTAMPING_OPT_ID ) {
    pf.pkt->ts_key = us->s.ts_key;
    ci_atomic32_inc(&us->s.ts_key);
  }
#endif
  if( sinf->stack_locked && ! was_locked )
    ++us->stats.n_tx_lock_pkt;
  if(CI_LIKELY( rc >= 0 )) {
    sinf->rc = bytes_to_send;
    TX_PKT_SET_DADDR(af, pf.pkt, ipcache_raddr(&sinf->ipcache));
    TX_PKT_IPX_UDP(af, pf.pkt, need_frag)->udp_dest_be16 =
        sinf->ipcache.dport_be16;

    if( si_trylock_and_inc(ni, sinf, us->stats.n_tx_lock_snd) ) {
      ci_udp_sendmsg_send(ni, us, pf.pkt, flags,
                          ci_netif_may_poll(ni), sinf);
      ci_netif_pkt_release(ni, pf.pkt);
      ci_netif_unlock(ni);
      sinf->stack_locked = 0;
    }
    else {
      ci_udp_sendmsg_async_q_enqueue(ni, us, pf.pkt, flags);
    }
  }
  else {
    sinf->rc = rc;
  }
  return;


  /* *********************** */
 efault:
  sinf->rc = -EFAULT;
  return;

 send_via_os:
  if( sinf->stack_locked ) {
    ci_netif_unlock(ni);
    sinf->stack_locked = 0;
  }
  sinf->rc = ci_udp_sendmsg_os(ni, us, msg, flags, 1, 0);
  return;

 no_space_or_too_big:
  /* TODO: If we implement IP options we'll have to calculate
   * CI_UDP_MAX_PAYLOAD_BYTES depending on them.
   */
  if( bytes_to_send > CI_UDP_MAX_PAYLOAD_BYTES(af) ) {
    sinf->rc = -EMSGSIZE;
    return;
  }

  /* There may be insufficient room in the sendq. */
  rc = ci_udp_sendmsg_wait(ni, us, bytes_to_send, flags, sinf);
  if(CI_UNLIKELY( rc != 0 )) {
    sinf->rc = rc;
    return;
  }

  LOG_UV(ci_log("%s: "NT_FMT"back to fast path", __FUNCTION__,
		NT_PRI_ARGS(ni,us)));
  goto back_to_fast_path;
}

#if !defined(__KERNEL__) && defined(__i386__)
static int ci_udp_sendmsg_control_os(ci_fd_t fd, ci_udp_state *us,
                                     const struct msghdr* msg, int flags)
{
  ci_fd_t os_sock;
  int rc;

  ++us->stats.n_tx_os;

  os_sock = ci_get_os_sock_fd(fd);
  rc = ci_sys_sendmsg(os_sock, msg, flags);
  ci_rel_os_sock_fd(os_sock);
  return rc;
}
#endif

int ci_udp_sendmsg(ci_udp_iomsg_args *a,
                   const ci_msghdr* msg, int flags)
{
  ci_netif *ni = a->ni;
  ci_udp_state *us = a->us;
  struct udp_send_info sinf;
  int rc;

  /* Caller should have checked this. */
  ci_assert(msg != NULL);

  /* Init sinf to properly unlock netif on exit */
  sinf.rc = 0;
  sinf.stack_locked = 0;
  sinf.used_ipcache = 0;
  sinf.old_ipcache_updated = 0;
  sinf.timeout = us->s.so.sndtimeo_msec;

#ifndef __KERNEL__
#ifdef __i386__
  /* We do not want to re-pack msg_control field or to find out sys_sendmsg32()
   * syscall when sending from a 32-bit application. So, let the kernel to take
   * care of it. */
  if(CI_UNLIKELY( msg->msg_controllen != 0 ))
    return ci_udp_sendmsg_control_os(a->fd, us, msg, flags);
#else
  if(CI_UNLIKELY( CMSG_FIRSTHDR(msg) != NULL )) {
    void* info = NULL;
    if( ci_ip_cmsg_send(msg, &info) != 0 || info != NULL )
      goto send_via_os;
  }
#endif
#endif

  if(CI_UNLIKELY( flags & MSG_MORE )) {
    LOG_E(ci_log("%s: MSG_MORE not yet supported", __FUNCTION__));
    CI_SET_ERROR(rc, EOPNOTSUPP);
    return rc;
  }

  if(CI_UNLIKELY( flags & MSG_OOB ))
    /* This returns an error, so very unlikely! */
    goto send_via_os;

  if(CI_UNLIKELY( us->s.so_error | us->s.tx_errno ))
    goto so_error;
 no_error:

  if( ! NI_OPTS(ni).udp_send_unlocked ) {
# ifndef __KERNEL__
    ci_netif_lock(ni);
# else
    if( (rc = ci_netif_lock(ni)) < 0 ) {
      rc = -ERESTARTSYS;
      goto error;
    }
# endif
    sinf.stack_locked = 1;
  }

#if CI_CFG_IPV6
  /* Set ether_type according to ci_udp_state ipcache. Although, should be
   * modified on ci_udp_ipcache_convert() call for unconnected send. */
  sinf.ipcache.ether_type = us->s.pkt.ether_type;
#endif

#ifndef __KERNEL__
  if( msg->msg_namelen == 0 )
#endif
  {
    /**********************************************************************
     * Connected send.
     */

    /* Don't allow UDP connected send when in not connected socket state */
    if( ! (us->s.s_flags & CI_SOCK_FLAG_CONNECTED) ) {
      rc = -EDESTADDRREQ;
      goto error;
    }

    ci_ipcache_set_daddr(&sinf.ipcache, addr_any);

    if( us->s.pkt.status == retrrc_success ) {
      /* All good -- was accelerated last time we looked, so we'll work on
       * the assumption we still are.  We'll check again before sending.
       */
      /* ?? TODO: put some code here to avoid conditional branch forward on
       * fast path.
       */
    }
    else {
      /* In the case of a control plane change and stack lock contention we
       * may use old info here.  Worst case is that we'll send via OS when
       * we could have accelerated (and that can only happen if the control
       * plane change affected this connection).
       */
      if(CI_UNLIKELY( ! oo_cp_ipcache_is_valid(ni, &us->s.pkt) )) {
        if( si_trylock_and_inc(ni, &sinf, us->stats.n_tx_lock_cp) ) {
          ++us->stats.n_tx_cp_c_lookup;
          cicp_user_retrieve(ni, &us->s.pkt, &us->s.cp);
          sinf.old_ipcache_updated = 1;
        }
      }
      if( us->s.pkt.status != retrrc_success &&
          us->s.pkt.status != retrrc_nomac )
        goto send_via_os;
    }
    sinf.ipcache.mtu = us->s.pkt.mtu;
  }
#ifndef __KERNEL__
  else if(CI_UNLIKELY( msg->msg_name == NULL )) {
    rc = -EFAULT;
    goto error;
  }
  else {
    /**********************************************************************
     * Unconnected send -- dest IP and port provided.
     */
    ci_addr_t pkt_daddr;
    int af = CI_SIN(msg->msg_name)->sin_family;
    int reuse_ipcache;

    if( msg->msg_name != NULL && msg_namelen_ok(af, msg->msg_namelen) &&
        (! CI_CFG_FAKE_IPV6 || us->s.domain == AF_INET) && af == AF_INET ) {
      /* Fast check -- we're okay. */
    }
    else if( ! ci_udp_name_is_ok(af, us, msg) )
      /* Fast check and more detailed check failed. */
      goto send_via_os;

    pkt_daddr = ci_get_addr(CI_SA(msg->msg_name));

#if CI_CFG_IPV6
    if( CI_IPX_IS_LINKLOCAL(pkt_daddr) &&
        ci_sock_set_ip6_scope_id(ni, &us->s, CI_SA(msg->msg_name),
                                 msg->msg_namelen, 1) )
      goto send_via_os;
    ci_udp_ipcache_convert(CI_ADDR_AF(pkt_daddr), us);
    sinf.ipcache.ether_type = us->s.pkt.ether_type;
#endif

    ci_ipcache_set_daddr(&sinf.ipcache, pkt_daddr);
    sinf.ipcache.dport_be16 = ci_get_port(CI_SA(msg->msg_name));

    if( CI_IPX_ADDR_IS_ANY(ipcache_raddr(&sinf.ipcache)) )
      goto send_via_os;

#ifndef __KERNEL__
    if(CI_UNLIKELY( udp_lport_be16(us) == 0 )) {
      /* We haven't yet allocated a local port.  Do it now. */
      if( sinf.stack_locked )
        ci_netif_unlock(ni);
      rc = ci_udp_sendmsg_os_get_binding(a->ep, a->fd, msg, flags);
      if( rc < 0 )
        return rc;
    }
#endif

    reuse_ipcache = (sinf.ipcache.dport_be16 ==
                     us->ephemeral_pkt.dport_be16) &&
                    CI_IPX_ADDR_EQ(pkt_daddr,
                                   ipcache_raddr(&us->ephemeral_pkt));
    if( ! reuse_ipcache )
      us->udpflags &=~ CI_UDPF_LAST_SEND_NOMAC;
    if( reuse_ipcache &&
        oo_cp_ipcache_is_valid(ni, &us->ephemeral_pkt) ) {
      /* Looks like [us->ephemeral_pkt] has up-to-date info for this
       * destination, so go with it.  This is racey if another thread is
       * sending on the same socket concurrently (and happens to be
       * modifying [us->ephemeral_pkt]), but we'll check again before
       * finally sending.  Worst case is we use the wrong MTU and send via
       * OS when we could have accelerated.
       *
       * ?? TODO: cache is not valid when status is retrrc_nomac -- do we
       * care?  prob not -- expect that to be relatively uncommon
       */
      if( us->ephemeral_pkt.status != retrrc_success &&
          us->ephemeral_pkt.status != retrrc_nomac )
        goto send_via_os;
      sinf.ipcache.mtu = us->ephemeral_pkt.mtu;
      ++us->stats.n_tx_cp_match;
    }
    else if( si_trylock_and_inc(ni, &sinf, us->stats.n_tx_lock_cp) ) {
      if( !reuse_ipcache ) {
        ci_ipcache_set_daddr(&us->ephemeral_pkt, ipcache_raddr(&sinf.ipcache));
        us->ephemeral_pkt.dport_be16 = sinf.ipcache.dport_be16;
        ci_ip_cache_invalidate(&us->ephemeral_pkt);
      }
      if(CI_UNLIKELY( ! oo_cp_ipcache_is_valid(ni, &us->ephemeral_pkt) )) {
        ++us->stats.n_tx_cp_uc_lookup;
        cicp_user_retrieve(ni, &us->ephemeral_pkt, &us->s.cp);
        if( reuse_ipcache )
          sinf.old_ipcache_updated = 1;
      }
      if( us->ephemeral_pkt.status != retrrc_success &&
          us->ephemeral_pkt.status != retrrc_nomac )
        goto send_via_os;
      sinf.ipcache.mtu = us->ephemeral_pkt.mtu;
    }
    else {
      /* Need control plane lookup and could not grab stack lock; so do
       * lookup with temporary ipcache [sinf.ipcache].
       */
      sinf.used_ipcache = 1;
      ++us->stats.n_tx_cp_a_lookup;
      ci_ip_cache_invalidate(&sinf.ipcache);
      cicp_user_retrieve(ni, &sinf.ipcache, &us->s.cp);
      if( sinf.ipcache.status != retrrc_success &&
          sinf.ipcache.status != retrrc_nomac )
        goto send_via_os;
      sinf.old_ipcache_updated = 1;
    }
  }
#endif

  ci_assert_gt(sinf.ipcache.mtu, 0);
  ci_udp_sendmsg_onload(ni, us, msg, flags, &sinf);
  if( sinf.stack_locked )
    ci_netif_unlock(ni);
  if( sinf.rc < 0 )
      CI_SET_ERROR(sinf.rc, -sinf.rc);
  return sinf.rc;

 so_error:
  if( (rc = -ci_get_so_error(&us->s)) == 0 && (rc = -us->s.tx_errno) == 0 )
    goto no_error;
  goto error;

 error:
  if( sinf.stack_locked )
    ci_netif_unlock(ni);
  CI_SET_ERROR(rc, -rc);
  return rc;

 send_via_os:
  if( sinf.stack_locked )
    ci_netif_unlock(ni);
  rc = ci_udp_sendmsg_os(ni, us, msg, flags, 1, 0);
  if( rc >= 0 )
    return rc;
  else
    RET_WITH_ERRNO(-rc);
}

#endif
/*! \cidoxg_end */
