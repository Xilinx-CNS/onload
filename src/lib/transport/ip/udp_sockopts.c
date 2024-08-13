/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  ctk, stg
**  \brief  UDP socket option control; getsockopt, setsockopt
**   \date  2005/05/19
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"

#ifndef __KERNEL__
#include <limits.h>
#include <ci/internal/efabcfg.h>
#endif

#include <netinet/udp.h>


#define LPF "UDP SOCKOPTS "


static void ci_mcast_opts_updated(ci_netif* ni, ci_udp_state* us)
{
  if( CI_IP_IS_MULTICAST(us->ephemeral_pkt.ipx.ip4.ip_daddr_be32) )
    ci_ip_cache_invalidate(&us->ephemeral_pkt);
  if( CI_IP_IS_MULTICAST(us->s.pkt.ipx.ip4.ip_daddr_be32) )
    ci_ip_cache_invalidate(&us->s.pkt);
}


static int/*bool*/
ip_to_ifindex_check(struct oo_cplane_handle* cp,
                    ci_ifid_t ifindex, uint8_t scope, void* data)
{
  (void) scope;
  *(ci_ifid_t*)data = ifindex;
  /* as in Linux, we accept any interface */
  return 1;
}
static void ci_mcast_set_outgoing_if(ci_netif* ni, ci_udp_state* us,
                                     int ifindex, ci_uint32 laddr)
{
  int rc;

  us->s.cp.ip_multicast_if_laddr_be32 = laddr;
  if( ifindex == 0 ) {
    if( laddr == INADDR_ANY ) {
      us->s.cp.ip_multicast_if = CI_IFID_BAD;
      return;
    }
    rc = oo_cp_find_ipif_by_ip(ni->cplane, laddr,
                               ip_to_ifindex_check, &us->s.cp.ip_multicast_if);
    if(CI_UNLIKELY( rc == 0 ))
      /* Unlikely because when we invoked this on the kernel socket, it
       * thought that given ifindex does exist.
       *
       * ?? FIXME: We should return error to the caller in this case.
       */
      LOG_E(ci_log("%s: cicp_user_find_home %s failed (%d)",
                   __FUNCTION__, ip_addr_str(laddr), rc));
  }
  else {
    us->s.cp.ip_multicast_if = ifindex;
  }
}


struct llap_param_data {
  cicp_hwport_mask_t* hwports;
  ci_ifid_t* ifindex;
};
static int/*bool*/
llap_param_from_ip(struct oo_cplane_handle* cp,
                   cicp_llap_row_t* llap, void* data)
{
  struct llap_param_data* d = data;
  *d->hwports = llap->rx_hwports;
  *d->ifindex = llap->ifindex;
  return 1;
}

static int ci_mcast_join_leave(ci_netif* ni, ci_udp_state* us,
                               ci_ifid_t ifindex, ci_uint32 laddr,
                               ci_uint32 maddr, int /*bool*/ add)
{
  cicp_hwport_mask_t hwports = 0;
  int rc;

  if( add )
    us->udpflags |= CI_UDPF_MCAST_JOIN;

  if( NI_OPTS(ni).mcast_join_handover == 2 )
    return CI_SOCKET_HANDOVER;
  if( ! NI_OPTS(ni).mcast_recv || UDP_GET_FLAG(us, CI_UDPF_NO_MCAST_FILTER) )
    return 0;

  /* Find the RX hwports on which to join the group. */
  if( ifindex != 0 ) {
    /* The application specified the ifindex on which to join the group. */
    rc = oo_cp_find_llap(ni->cplane, ifindex, NULL, NULL, &hwports, NULL,
                         NULL);
  }
  else if( laddr != 0 ) {
    /* The application specified an IP address of the interface on which to
     * join the group. */
    struct llap_param_data data;
    data.hwports = &hwports;
    data.ifindex = &ifindex;
    rc = ! oo_cp_find_llap_by_ip(ni->cplane, laddr, cicp_ipif_check_ok, NULL,
                                 llap_param_from_ip, &data);
  }
  else {
    /* The application did not specify the interface on which to join the
     * group.  This means that we must infer the interface from the routing
     * table. */
    ci_ip_cached_hdrs ipcache;
    struct oo_sock_cplane sock_cp = us->s.cp;
    struct cp_fwd_key key;
    struct cp_fwd_data data;

    ci_ip_cache_init(&ipcache, AF_INET);
    ipcache.ipx.ip4.ip_daddr_be32 = maddr;
    ipcache.dport_be16 = 0;

    /* OO_SCP_NO_MULTICAST may forbid multicast send through this socket.
     * Here we are not going to send anything; we want to receive, and we
     * need a route resolution even if sending is forbidden.
     * We use a copy of sock_cp to resolve this multicast route;
     * original flag is not changed. */
    sock_cp.sock_cp_flags &=~ OO_SCP_NO_MULTICAST;

    /* Look up the routing table.  Note that, in the cross-veth case, we
     * resolve the first hop only. */
    rc = cicp_user_build_fwd_key(ni, &ipcache, &sock_cp,
                                 CI_ADDR_FROM_IP4(maddr), AF_INET, &key);
    if( rc == 0 )
      rc = cicp_user_resolve(ni, ni->cplane, &ipcache.fwd_ver,
                             sock_cp.sock_cp_flags, &key, &data);
    if( rc == 0 && data.base.ifindex != CI_IFID_BAD ) {
      ifindex = data.base.ifindex;
      rc = cicp_user_get_fwd_rx_hwports(ni, &data, &hwports);
    }
    else {
      rc = 1;
    }
  }

  if( rc != 0 || hwports == 0 )
    /* Not acceleratable.  NB. The mcast_join_handover takes effect even if
     * this socket has joined a group that is accelerated.  This is
     * deliberate.
     */
    return NI_OPTS(ni).mcast_join_handover ? CI_SOCKET_HANDOVER : 0;

  rc = ci_tcp_ep_mcast_add_del(ni, S_SP(us), ifindex, maddr, add);
  if( rc != 0 ) {
    LOG_E(log(FNS_FMT "%s ifindex=%d maddr="CI_IP_PRINTF_FORMAT" failed "
              "%d", FNS_PRI_ARGS(ni, &us->s), add ? "ADD" : "DROP",
              (int) ifindex, CI_IP_PRINTF_ARGS(&maddr), rc));
    if( CITP_OPTS.no_fail )
      return 0;
    else {
      /* If the user tries to join a multicast group on a bond we might end up
       * in the situation where the filter is installed on at least one nic, but
       * not all. In this case remove the existing filter and return a
       * predictable error code. */
      if( rc == -EFILTERSSOME ) {
        ci_tcp_ep_mcast_add_del(ni, S_SP(us), ifindex, maddr, /*false*/0);
        rc = -ENOBUFS;
      }
      /* The caller is responsible for rolling back the OS socket state */
      RET_WITH_ERRNO(-rc);
    }
  }

  LOG_UC(log(FNS_FMT "ci_tcp_ep_mcast_add_del(%s, %d, "CI_IP_PRINTF_FORMAT")",
             FNS_PRI_ARGS(ni, &us->s), add ? "ADD" : "DROP", 
             (int) ifindex, CI_IP_PRINTF_ARGS(&maddr)));

  if( add )
    us->udpflags |= CI_UDPF_MCAST_FILTER;

  if( add && NI_OPTS(ni).mcast_join_bindtodevice &&
      ! (us->udpflags & CI_UDPF_NO_MCAST_B2D) &&
      us->s.cp.so_bindtodevice == CI_IFID_BAD ) {
    /* When app does IP_ADD_MEMBERSHIP, automatically bind the socket to
     * the device that the multicast join was on.
     */
    if( us->s.rx_bind2dev_ifindex == CI_IFID_BAD ) {
      if( (rc = ci_sock_rx_bind2dev(ni, &us->s, ifindex)) == 0 ) {
        LOG_UC(log(FNS_FMT "bound rx to ifindex=%d",
                   FNS_PRI_ARGS(ni, &us->s), ifindex));
        us->udpflags |= CI_UDPF_MCAST_B2D;
      }
      else {
        LOG_E(log(FNS_FMT "ERROR: joined on ifindex=%d but bind failed (%d)",
                  FNS_PRI_ARGS(ni, &us->s), ifindex, rc));
      }
    }
    else if( us->s.rx_bind2dev_ifindex != ifindex ) {
      LOG_UC(log(FNS_FMT "unbinding socket from ifindex=%d",
                 FNS_PRI_ARGS(ni, &us->s), us->s.rx_bind2dev_ifindex));
      us->udpflags |= CI_UDPF_NO_MCAST_B2D;
      us->s.rx_bind2dev_ifindex = CI_IFID_BAD;
      us->s.rx_bind2dev_hwports = 0;
      us->s.rx_bind2dev_vlan = 0;
    }
  }

  return 0;
}


ci_inline int __get_socket_opt(citp_socket* ep, ci_fd_t sock, int level, 
                               int name, void* v, socklen_t* len )
{
  return CI_IS_VALID_SOCKET(sock) ? 
    ci_sys_getsockopt(sock, level, name, v, len) : -1;
}



/* BUG1439: pass in [fd] so we can go ask the OS for it's SO_ERROR */
int ci_udp_getsockopt(citp_socket* ep, ci_fd_t fd, int level,
		      int optname, void *optval, socklen_t *optlen )
{
  ci_netif* netif;
  ci_udp_state* us;
  unsigned u = 0;

  ci_assert(ep);
  netif = ep->netif;
  us = SOCK_TO_UDP(ep->s);

  /* ?? what to do about optval and optlen checking
  ** Kernel can raise EFAULT, here we are a little in the dark.
  */

  if(level == SOL_SOCKET) {
    if(optname == SO_ERROR) {
      /* Allow OS errors to be passed-up to app.  Our own error
       * takes priority. Usually, our own errors are just copied from OS. */
      u = 0;
      if(  us->s.so_error ) {
      	u = ci_get_so_error(&us->s);
      } else {
	ci_fd_t os_sock = ci_get_os_sock_fd(fd);
        if( !__get_socket_opt(ep, os_sock, level, optname, optval, optlen) )
	  u = *(int*)optval;
        ci_rel_os_sock_fd( os_sock );
      }
      goto u_out;
    }
    else {
      /* Common SOL_SOCKET option handler */
      return ci_get_sol_socket(netif, &us->s, optname, optval, optlen);
    }
  } else if (level ==  IPPROTO_IP) {
    /* IP level options valid for UDP */
    switch (optname) {
    case IP_RECVERR:
      {
	ci_fd_t os_sock = ci_get_os_sock_fd(fd);
        if( !__get_socket_opt(ep, os_sock, level, optname, optval, optlen) )
	  u = *(int*)optval;
        ci_rel_os_sock_fd( os_sock );
      }
      goto u_out;

    case IP_MULTICAST_IF:
      u = us->s.cp.ip_multicast_if_laddr_be32;
      /* Hack: multicast options are not handled in the same way as other
       * opts in SOL_IP level in Linux. */
      return ci_getsockopt_final(optval, optlen, SOL_UDP, &u, sizeof(u));

    case IP_MULTICAST_LOOP:
      u = (us->udpflags & CI_UDPF_MCAST_LOOP) != 0;
      goto u_out_char;

    case IP_MULTICAST_TTL:
      u = us->s.cp.ip_mcast_ttl;
      goto u_out_char;

#ifdef IP_MULTICAST_ALL
    case IP_MULTICAST_ALL:
      u = 0;
      goto u_out_char;
#endif

    default:
      return ci_get_sol_ip(netif, &us->s, fd, optname, optval, optlen);
    }

#if CI_CFG_FAKE_IPV6
  } else if (level ==  IPPROTO_IPV6 && us->s.domain == AF_INET6) {
    /* IP6 level options valid for TCP */
    return ci_get_sol_ip6(netif, &us->s, fd, optname, optval, optlen);
#endif

  } else if (level == IPPROTO_UDP) {
    /* We definitely don't support this */
    RET_WITH_ERRNO(ENOPROTOOPT);
  } else {
    SOCKOPT_RET_INVALID_LEVEL(&us->s);
  }

 u_out_char:
 u_out:
  return ci_getsockopt_final(optval, optlen, SOL_IP, &u, sizeof(u));
}


static int ci_udp_setsockopt_lk(citp_socket* ep, ci_fd_t fd, ci_fd_t os_sock,
				int level, int optname, const void* optval,
				socklen_t optlen)
{
  ci_netif* netif;
  ci_udp_state* us;
  int rc, v;

  ci_assert(ep);
  netif = ep->netif;
  us = SOCK_TO_UDP(ep->s);

  /* Note that the OS backing socket [os_sock] is expected to be available
   * in the following code. */
  ci_assert( CI_IS_VALID_SOCKET( os_sock ) );

#define CHECK_MCAST_JOIN_LEAVE_RC(_rc, os_sock, optname, optval, optlen) \
  do {                                                                   \
    int _tmp_errno = errno;                                              \
                                                                         \
    if( ((_rc) != 0) && ((_rc) != CI_SOCKET_HANDOVER) ) {                \
      ci_sys_setsockopt((os_sock), SOL_IP, (optname),                    \
                        (optval), (optlen));                             \
      errno = _tmp_errno;                                                \
    }                                                                    \
  } while (0)

  if(level == SOL_SOCKET) {
    /* socket level options valid for UDP */
    switch(optname) {
    case SO_SNDBUF:
    case SO_SNDBUFFORCE:
      /* sets the maximum socket send buffer in bytes */
      if( (rc = opt_not_ok(optval,optlen,int)) )
        goto fail_inval;

      /* Since we keep both a user-level and an OS socket around and can send
      ** via either it is extremely important we keep both in sync.  Where
      ** possible we read back the effective send buffer size set above.
      */
      if( __get_socket_opt(ep, os_sock, SOL_SOCKET, SO_SNDBUF, &v, &optlen)) {
        /* We don't have an OS socket or we can't read the buffer size back.
        ** Emulate the OS behaviour. */
        v = *(int*) optval;
        /* To match kernel behaviour, limit input value to INT_MAX/2
         * so it can't wrap to a negative value when doubled */
        v = CI_MIN(v, INT_MAX/2);
        v = CI_MAX(v, (int)NI_OPTS(netif).udp_sndbuf_min);
        if( optname == SO_SNDBUF ) {
          v = CI_MIN(v, (int)NI_OPTS(netif).udp_sndbuf_max);
        }
        else {
          int lim = CI_MAX((int)NI_OPTS(netif).udp_sndbuf_max,
                           ci_netif_max_tx_packets_size_per_socket(netif) / 2);
          if( v > lim ) {
            NI_LOG_ONCE(netif, RESOURCE_WARNINGS,
                        "SO_SNDBUFFORCE: limiting user-provided value %d "
                        "to %d.  "
                        "Consider increasing of EF_MAX_PACKETS.", v, lim);
            v = lim;
          }
        }
        v = oo_adjust_SO_XBUF(v);
      }
      else if( NI_OPTS(netif).udp_sndbuf_user ) {
        v = oo_adjust_SO_XBUF(NI_OPTS(netif).udp_sndbuf_user);
      }

      us->s.so.sndbuf = v;
      break;

    case SO_RCVBUF:
    case SO_RCVBUFFORCE:
      /* sets the maximum socket receive buffer in bytes */
      if( (rc = opt_not_ok(optval,optlen,int)) )
        goto fail_inval;

      /* Since we keep both a user-level and an OS socket around and can
      ** receive via either it is extremely important we keep both in sync.
      ** Where possible we read back the effective receive buffer size set
      ** above.
      */
      if( __get_socket_opt(ep, os_sock, SOL_SOCKET, SO_RCVBUF, &v, &optlen)) {
        /* We don't have an OS socket or we can't read the buffer size back.
        ** Emulate the OS behaviour. */
        v = *(int*) optval;
        /* To match kernel behaviour, limit input value to INT_MAX/2
         * so it can't wrap to a negative value when doubled */
        v = CI_MIN(v, INT_MAX/2);
        v = CI_MAX(v, (int)NI_OPTS(netif).udp_rcvbuf_min);
        if( optname == SO_RCVBUF ) {
          v = CI_MIN(v, (int)NI_OPTS(netif).udp_rcvbuf_max);
        }
        else {
          int lim = CI_MAX((int)NI_OPTS(netif).udp_rcvbuf_max,
                           ci_netif_max_rx_packets_size_per_socket(netif) / 2);
          if( v > lim ) {
            NI_LOG_ONCE(netif, RESOURCE_WARNINGS,
                        "SO_RCVBUFFORCE: limiting user-provided value %d "
                        "to %d.  "
                        "Consider increasing of EF_MAX_PACKETS.", v, lim);
            v = lim;
          }
        }
        v = oo_adjust_SO_XBUF(v);
      }
      else if( NI_OPTS(netif).udp_rcvbuf_user ) {
        v = oo_adjust_SO_XBUF(NI_OPTS(netif).udp_rcvbuf_user);
      }

      us->s.so.rcvbuf = v;
      /* It is essential that [max_recvq_pkts] be <= SO_RCVBUF, else
       * SO_RCVBUF has no effect (see ci_udp_rx_deliver()).  Simplest thing
       * is to reset it to zero.
       */
      us->stats.max_recvq_pkts = 0;
      break;

    case SO_TIMESTAMP:
    case SO_TIMESTAMPNS:
      /* Make sure the siocgstamp returns correct value until
       * SO_TIMESTAMP[NS] is turned off again
       */
      if( (rc = opt_not_ok(optval, optlen, char)) )
        goto fail_inval;
      if( (us->s.cmsg_flags & CI_IP_CMSG_TIMESTAMP_ANY) == 0 ) {
          /* Make sure the siocgstamp returns correct value until
           * SO_TIMESTAMP[NS] is turned off again
           */
          if( ci_get_optval(optval, optlen) )
            us->stamp_pre_sots = us->stamp;
          else
            us->stamp = us->stamp_pre_sots;
      }
      /* Then use the common path */
      return ci_set_sol_socket(netif, &us->s, optname, optval, optlen);
      break;

    default:
      /* Common socket level options */
      return ci_set_sol_socket(netif, &us->s, optname, optval, optlen);
    }
  } else if (level == IPPROTO_IP) {
    /* IP level options valid for UDP */
    switch(optname) {
    case IP_ADD_MEMBERSHIP:
    case IP_DROP_MEMBERSHIP:
    {
      const struct ip_mreqn *mreqn = (void *)optval;
      const struct ip_mreq *mreq = (void *)optval;

      if( optlen >= sizeof(struct ip_mreqn) ) {
        rc = ci_mcast_join_leave(netif, us, (ci_ifid_t)mreqn->imr_ifindex,
                                 mreqn->imr_address.s_addr,
                                 mreqn->imr_multiaddr.s_addr,
                                 optname == IP_ADD_MEMBERSHIP);
      }
      else 
      if( optlen >= sizeof(struct ip_mreq) ) {
        rc = ci_mcast_join_leave(netif, us, 0, mreq->imr_interface.s_addr,
                                 mreq->imr_multiaddr.s_addr,
                                 optname == IP_ADD_MEMBERSHIP);
      }
      else
        RET_WITH_ERRNO(EFAULT);

      if (optname == IP_ADD_MEMBERSHIP)
        CHECK_MCAST_JOIN_LEAVE_RC(rc, os_sock, IP_DROP_MEMBERSHIP, optval,
                                  optlen);
      return rc;
    }

#ifdef IP_ADD_SOURCE_MEMBERSHIP
    case IP_ADD_SOURCE_MEMBERSHIP:
    case IP_DROP_SOURCE_MEMBERSHIP:
    {
      /* NB. We are treating this just like IP_ADD_MEMBERSHIP.  ie. The
       * hardware filters we insert are not source specific.  The kernel
       * will still take account of the source for igmp purposes.
       *
       * I think this should be okay, because joining a group controls the
       * delivery of packets to the host.  It does not in any way limit the
       * packets that can arrive at a particular socket.
       */
      const struct ip_mreq_source *mreqs = (void *)optval;

      if( optlen >= sizeof(struct ip_mreq_source) ) {
        rc = ci_mcast_join_leave(netif, us, 0, mreqs->imr_interface.s_addr,
                                 mreqs->imr_multiaddr.s_addr,
                                 optname == IP_ADD_SOURCE_MEMBERSHIP);
      }
      else
        RET_WITH_ERRNO(EFAULT);

      if (optname == IP_ADD_SOURCE_MEMBERSHIP)
        CHECK_MCAST_JOIN_LEAVE_RC(rc, os_sock, IP_DROP_SOURCE_MEMBERSHIP,
                                  optval, optlen);
      return rc;
    }
#endif

#ifdef IP_MULTICAST_ALL
    case IP_MULTICAST_ALL:
    {
      if( (rc = opt_not_ok(optval,optlen,int)) )
        goto fail_inval;
      if( *(int *)optval )
        RET_WITH_ERRNO(EINVAL);
      else
        return rc;
    }
#endif

#ifdef MCAST_JOIN_GROUP
    case MCAST_JOIN_GROUP:
    case MCAST_LEAVE_GROUP:
    {
      struct group_req *greq = (void *)optval;

      if( optlen < sizeof(struct group_req) )
        RET_WITH_ERRNO(EFAULT);
      if( greq->gr_group.ss_family != AF_INET )
        return CI_SOCKET_HANDOVER;
      rc = ci_mcast_join_leave(netif, us, greq->gr_interface, 0,
                CI_SIN(&greq->gr_group)->sin_addr.s_addr,
                optname == MCAST_JOIN_GROUP);

      if (optname == MCAST_JOIN_GROUP)
        CHECK_MCAST_JOIN_LEAVE_RC(rc, os_sock, MCAST_LEAVE_GROUP, optval,
                                  optlen);
      return rc;
    }
#endif

#ifdef MCAST_JOIN_SOURCE_GROUP
    case MCAST_JOIN_SOURCE_GROUP:
    case MCAST_LEAVE_SOURCE_GROUP:
    {
      /* NB. We are treating this just like IP_ADD_MEMBERSHIP.  ie. The
       * hardware filters we insert are not source specific.  The kernel
       * will still take account of the source for igmp purposes.
       *
       * I think this should be okay, because joining a group controls the
       * delivery of packets to the host.  It does not in any way limit the
       * packets that can arrive at a particular socket.
       */
      struct group_source_req *gsreq = (void *)optval;

      if( optlen < sizeof(struct group_source_req) )
        RET_WITH_ERRNO(EFAULT);
      if( gsreq->gsr_group.ss_family != AF_INET )
        return CI_SOCKET_HANDOVER;
      rc = ci_mcast_join_leave(netif, us, gsreq->gsr_interface, 0,
                CI_SIN(&gsreq->gsr_group)->sin_addr.s_addr,
                optname == MCAST_JOIN_SOURCE_GROUP);

      if (optname == MCAST_JOIN_SOURCE_GROUP)
        CHECK_MCAST_JOIN_LEAVE_RC(rc, os_sock, MCAST_LEAVE_SOURCE_GROUP,
                                  optval, optlen);

      return rc;
    }
#endif

    case IP_MULTICAST_IF:
    {
      const struct ip_mreqn *mreqn = (void *)optval;
      const struct ip_mreq *mreq = (void *)optval;

      if( optlen >= sizeof(struct ip_mreqn) )
        ci_mcast_set_outgoing_if(netif, us, mreqn->imr_ifindex,
                                 mreqn->imr_address.s_addr);
      else if( optlen >= sizeof(struct ip_mreq) )
        ci_mcast_set_outgoing_if(netif, us, 0,
                                 mreq->imr_interface.s_addr);
      else if( optlen >= sizeof(struct in_addr) )
        ci_mcast_set_outgoing_if(netif, us, 0, *(ci_uint32 *)optval);
      else
        us->s.cp.ip_multicast_if = CI_IFID_BAD;
      ci_mcast_opts_updated(netif, us);
      break;
    }

    case IP_MULTICAST_LOOP:
      if( (rc = opt_not_ok(optval, optlen, char)) )
        goto fail_inval;
      if( ci_get_optval(optval, optlen) ) {
        us->udpflags |= CI_UDPF_MCAST_LOOP;
        if( NI_OPTS(netif).force_send_multicast )
          /* Options say accelerate mcast sends anyway. */
          us->s.cp.sock_cp_flags &= ~OO_SCP_NO_MULTICAST;
        else
          us->s.cp.sock_cp_flags |= OO_SCP_NO_MULTICAST;
      }
      else {
        /* Can accelerate when no loopback. */
        us->udpflags &= ~CI_UDPF_MCAST_LOOP;
        us->s.cp.sock_cp_flags &= ~OO_SCP_NO_MULTICAST;
      }
      ci_mcast_opts_updated(netif, us);
      break;

    case IP_MULTICAST_TTL:
    {
      int ttl;
      if( (rc = opt_not_ok(optval, optlen, char)) )
        goto fail_inval;
      ttl = (int) ci_get_optval(optval, optlen);
      /* On linux, -1 for IP_MULTICAST_TTL means reset to default. */
      us->s.cp.ip_mcast_ttl = ttl == -1 ? 1 : ttl;
      ci_mcast_opts_updated(netif, us);
      break;
    }
    default:
      /* Common SOL_IP option handler */
      return ci_set_sol_ip( netif, &us->s, optname, optval, optlen );
    }

#if CI_CFG_FAKE_IPV6
  } else if (level ==  IPPROTO_IPV6) {
    /* IP6 level options valid for TCP */
    return ci_set_sol_ip6( netif, &us->s, optname, optval, optlen);
#endif

  } else if (level == IPPROTO_UDP) {
    RET_WITH_ERRNO(ENOPROTOOPT);
  }
  else {
    LOG_U(log(FNS_FMT "unknown level=%d optname=%d accepted by O/S",
              FNS_PRI_ARGS(netif, ep->s), level, optname));
  }

#undef CHECK_MCAST_JOIN_LEAVE_RC

  return 0;

 fail_inval:
  LOG_UC(log("%s: "SF_FMT" option %i ptr/len error (EINVAL or EFAULT)",
             __FUNCTION__, SF_PRI_ARGS(ep,fd), optname));
  RET_WITH_ERRNO(-rc);

}

ci_inline int __set_socket_opt(citp_socket* ep, ci_fd_t sock, int level, 
                               int name, const void* v, socklen_t len )
{
  return CI_IS_VALID_SOCKET(sock) ? 
    ci_sys_setsockopt(sock, level, name, v, len) : -1;
}

ci_inline int ci_udp_set_filtered_socket_opt(citp_socket* ep, ci_fd_t sock, int level,
                                             int name, const void* v, socklen_t len )
{
  union {
    struct {
      int flags;
      int bind_phc;
    } so_timestamping;
  } filtered_val;

  if( len <= sizeof filtered_val ) {
    if( name == SO_TIMESTAMPING_OOEXT &&
        len >= sizeof filtered_val.so_timestamping.flags ) {

      /* Remove v2 extension options for kernel */
      memcpy(&filtered_val, v, len);
      filtered_val.so_timestamping.flags &= ~(
        ONLOAD_SOF_TIMESTAMPING_ONLOAD_MASK |
        SOF_TIMESTAMPING_OOEXT_MASK);
      v = &filtered_val;
      name = SO_TIMESTAMPING;
    }
  }

  return __set_socket_opt(ep, sock, level, name, v, len);
}

int ci_udp_setsockopt(citp_socket* ep, ci_fd_t fd, int level,
		      int optname, const void *optval, socklen_t optlen )
{
  ci_fd_t os_sock;
  int rc;

  /* We need to grab the stack lock before getting the os_sock fd, which
   * holds the dup2 lock until released.
   */
  ci_netif_lock_id(ep->netif, SC_SP(ep->s));

  /* Keep the OS socket in sync so we can move freely between efab & OS fds
  ** on a per-call basis if necessary. */
  os_sock = ci_get_os_sock_fd(fd);
  ci_assert(CI_IS_VALID_SOCKET(os_sock));
  rc = ci_udp_set_filtered_socket_opt(ep, os_sock, level, optname, optval, optlen);
  if( rc == CI_SOCKET_ERROR &&
      ! ci_setsockopt_os_fail_ignore(ep->netif, ep->s, errno, level,
                                     optname, optval, optlen) ) {
    goto out;
  }
  rc = 0;

  if( level == SOL_SOCKET ) {
    rc = ci_set_sol_socket_nolock(ep->netif, ep->s, optname, optval, optlen);
    if( rc <= 0 )  goto out;
  }

  rc = ci_udp_setsockopt_lk(ep, fd, os_sock, level, optname, optval, optlen);
 out:
  ci_rel_os_sock_fd(os_sock);
  ci_netif_unlock(ep->netif);
  return rc;
}

/*! \cidoxg_end */
