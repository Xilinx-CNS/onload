/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  ctk
**  \brief  TCP socket option control; getsockopt, setsockopt
**   \date  2004/01/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include <ci/internal/ip_stats.h>
#include <ci/net/sockopts.h>

#if !defined(__KERNEL__)
#  include <netinet/tcp.h>

#define LPF "TCP SOCKOPTS "

/* Mapping for congestion states */
static const unsigned char sock_congstate_linux_map[] = {
  TCP_CA_Open,           /* CI_TCP_CONG_OPEN */
  TCP_CA_Loss,           /* CI_TCP_CONG_RTO */
  TCP_CA_Recovery,       /* CI_TCP_CONG_RTO_RECOVER */
  TCP_CA_Open,
  TCP_CA_Disorder,       /* CI_TCP_CONG_FAST_RECOV */
  TCP_CA_Open,
  TCP_CA_Open,
  TCP_CA_Open,
  TCP_CA_Recovery,       /* CI_TCP_CONG_COOLING */
  TCP_CA_Loss,           /* CI_TCP_CONG_RTO | CI_TCP_CONG_COOLING */
  TCP_CA_Open,
  TCP_CA_Open,
  TCP_CA_CWR,            /* CI_TCP_CONG_NOTIFIED */
};

/*
 * TCP constants to mimic linux kernel validation for TCP options.
 * Constants originate from <net/tcp.h>
 */
#define CI_MAX_TCP_KEEPIDLE 32767
#define CI_MAX_TCP_KEEPINTVL 32767
#define CI_MAX_TCP_KEEPCNT 127

static int
ci_tcp_info_get(ci_netif* netif, ci_sock_cmn* s, struct ci_tcp_info* uinfo,
                socklen_t* optlen)
{
  ci_iptime_t now = ci_ip_time_now(netif);
  struct ci_tcp_info info;

  memset(&info, 0, sizeof(info));

  info.tcpi_state = ci_sock_states_linux_map[CI_TCP_STATE_NUM(s->b.state)];
  /* info.tcpi_backoff = 0; */

  info.tcpi_ato = 
    ci_ip_time_ticks2ms(netif, netif->state->conf.tconst_delack) * 1000;
  info.tcpi_rcv_mss    = CI_CFG_TCP_DEFAULT_MSS;
  /* no way to get the actual mss */
  /* info.tcpi_sacked     = 0; */ /* there is no way to get any of these */
  /* info.tcpi_lost       = 0; */
  /* info.tcpi_fackets    = 0; */
  /* info.tcpi_reordering = 0; */
  /* info.tcpi_last_ack_sent = 0; */
  /* info.tcpi_last_ack_recv = 0; */

  if( s->b.state != CI_TCP_LISTEN ) {
    ci_tcp_state* ts = SOCK_TO_TCP(s);

    info.tcpi_pmtu       = ci_tcp_get_pmtu(netif, ts);
    info.tcpi_ca_state = sock_congstate_linux_map[ts->congstate];
    info.tcpi_retransmits = ts->retransmits;
    info.tcpi_probes = ts->ka_probes;

    /* info.tcpi_options = 0; */
    if( ts->tcpflags & CI_TCPT_FLAG_TSO )
      info.tcpi_options |= CI_TCPI_OPT_TIMESTAMPS;
    if( ts->tcpflags & CI_TCPT_FLAG_ECN )
      info.tcpi_options |= CI_TCPI_OPT_ECN;
    if( ts->tcpflags & CI_TCPT_FLAG_SACK )
      info.tcpi_options |= CI_TCPI_OPT_SACK;

    if( ts->tcpflags & CI_TCPT_FLAG_WSCL ) {
      info.tcpi_options |= CI_TCPI_OPT_WSCALE;
      info.tcpi_snd_wscale = ts->snd_wscl;
      info.tcpi_rcv_wscale = ts->rcv_wscl;
    }

    info.tcpi_rto = ci_ip_time_ticks2ms(netif, ts->rto) * 1000;
    info.tcpi_snd_mss    = ts->eff_mss;
    info.tcpi_unacked    = ts->acks_pending & CI_TCP_ACKS_PENDING_MASK;
#if CI_CFG_TCP_SOCK_STATS
    info.tcpi_retrans    = ts->stats_cumulative.count.tx_retrans_pkt;
#endif
#if CI_CFG_CONGESTION_WINDOW_VALIDATION
    info.tcpi_last_data_sent = ci_ip_time_ticks2ms(netif,
						    now - ts->t_last_sent);
#else
    info.tcpi_last_data_sent = 0;
#endif
    info.tcpi_last_data_recv = ci_ip_time_ticks2ms(netif,
						    now - ts->tspaws);
    
    info.tcpi_rtt = ci_ip_time_ticks2ms(netif, ts->sa) * 1000 / 8;
    info.tcpi_rttvar = ci_ip_time_ticks2ms(netif, ts->sv) * 1000 / 4;
    info.tcpi_rcv_ssthresh = ts->ssthresh;
    if( tcp_eff_mss(ts) != 0 ) {
      info.tcpi_snd_ssthresh = ts->ssthresh / tcp_eff_mss(ts);
      info.tcpi_snd_cwnd     = ts->cwnd / tcp_eff_mss(ts);
    }
    else { /* non-initialised connection */
      info.tcpi_snd_ssthresh = 0;
      info.tcpi_snd_cwnd     = 0;
    }
    info.tcpi_advmss     = ts->amss;

    if ( NI_OPTS(netif).tcp_rcvbuf_mode == 1 ) {
      info.tcpi_rcv_rtt = info.tcpi_rtt; /* we currently use same measure */
      info.tcpi_rcv_space = ts->rcvbuf_drs.bytes;
    }
    else {
      info.tcpi_rcv_rtt = 0; /* we do not support adaptive SO_RCVBUF */
      info.tcpi_rcv_space = tcp_rcv_wnd_right_edge_sent(ts) - ts->rcv_added;
    }
    info.tcpi_total_retrans = ts->stats.total_retrans;

    /* Starting from linux-3.15, there are tcpi_pacing_rate and
     * tcpi_max_pacing_rate fields.  However, as Onload does not support
     * pacing, we might as well pretend that we simulate older kernel
     * with smaller tcp_info size. */
  }

  if( *optlen > sizeof(info) )
    *optlen = sizeof(info);
  memcpy(uinfo, &info, *optlen);

  return 0;
}

#endif /* !defined(__KERNEL__) */

int ci_get_sol_tcp(ci_netif* netif, ci_sock_cmn* s, int optname, void *optval,
                   socklen_t *optlen )
{
  ci_tcp_socket_cmn *c = &(SOCK_TO_WAITABLE_OBJ(s)->tcp.c);
  unsigned u = 0;

  switch(optname){
  case TCP_NODELAY:
    /* gets status of TCP Nagle algorithm  */
    u = ((s->s_aflags & CI_SOCK_AFLAG_NODELAY) != 0);
    goto u_out;
  case TCP_MAXSEG:
    /* gets the MSS size for this connection */
    if ((s->b.state & CI_TCP_STATE_TCP_CONN)) {
      u = tcp_eff_mss(SOCK_TO_TCP(s));
    } else {
      u = 536;
    }
    goto u_out;
#ifdef TCP_CORK
  case TCP_CORK:
    /* don't send partial framses, all partial frames sent
    ** when the option is cleared */
    u = ((s->s_aflags & CI_SOCK_AFLAG_CORK) != 0);
    goto u_out;
#endif

  case TCP_KEEPIDLE:
    {
      /* idle time for keepalives  */
      u = (unsigned) c->t_ka_time_in_secs;
    }
    goto u_out;
  case TCP_KEEPINTVL:
    {
      /* time between keepalives */
      u = (unsigned) c->t_ka_intvl_in_secs;
    }
    goto u_out;
  case TCP_KEEPCNT:
    {
      /* number of keepalives before giving up */
      u = c->ka_probe_th;
    }
    goto u_out;
  case TCP_INFO:
#ifndef __KERNEL__
    /* struct tcp_info to be filled */
    return ci_tcp_info_get(netif, s, (struct ci_tcp_info*) optval, optlen);
#else
      /* We only do getopt in the kernel to synchronise options that have
       * been set.
       */
      ci_assert(0);
      break;
#endif
  case TCP_DEFER_ACCEPT:
    {
      u = 0;
      if( c->tcp_defer_accept != OO_TCP_DEFER_ACCEPT_OFF ) {
        u = ci_ip_time_ticks2ms(netif, NI_CONF(netif).tconst_rto_initial);
        u = ((u + 500) / 1000) * ( (1 << c->tcp_defer_accept) - 1);
      }
      goto u_out;
    }
  case TCP_QUICKACK:
    {
      u = 0;
      if( s->b.state & CI_TCP_STATE_TCP_CONN )
        u = ci_tcp_is_in_faststart(SOCK_TO_TCP(s));
      goto u_out;
    }
  default:
#ifndef __KERNEL__
    LOG_TC( log(LPF "getsockopt: unimplemented or bad option: %i", 
                optname));
    RET_WITH_ERRNO(ENOPROTOOPT);
#else
      /* In the kernel we explicitly sync options, so shouldn't be making up
       * crazy new things.
       */
      ci_assert(0);
#endif
  }

  return 0;

 u_out:
  return ci_getsockopt_final(optval, optlen, IPPROTO_TCP, &u, sizeof(u));
}


#if !defined(__KERNEL__)
int ci_tcp_getsockopt(citp_socket* ep, ci_fd_t fd, int level,
		      int optname, void *optval, socklen_t *optlen )
{
  ci_sock_cmn* s = ep->s;
  ci_netif* netif = ep->netif;

  /* NOTE: The setsockopt() call is reflected into the os socket to
   * keep the two in sync - it's assumed that we know everything
   * to allow us to give good answers here - and therefore we don't
   * bother the os with the get call */

  /* ?? what to do about optval and optlen checking
   * Kernel can raise EFAULT, here we are a little in the dark.
   *  - sockcall_intercept.c checks that optlen is non-NULL and if *optlen
   *    is non-zero that optval is non-NULL, returning EFAULT if false
   */

  if(level == SOL_SOCKET) {
    if( optname == SO_SNDBUF &&
	NI_OPTS(netif).tcp_sndbuf_mode == 2 &&
	s->b.state & CI_TCP_STATE_TCP_CONN ) {
      /* need to update sndbuf (bytes) from current sndbuf_pkts */
      ci_tcp_state* ts = SOCK_TO_TCP(s);
      ci_tcp_set_sndbuf_from_sndbuf_pkts(netif, ts);
    }

    /* Common SOL_SOCKET handler */
    return ci_get_sol_socket(netif, s, optname, optval, optlen);

  }
  else if (level ==  IPPROTO_IP) {
    /* IP level options valid for TCP */
    return ci_get_sol_ip(netif, s, fd, optname, optval, optlen);

#if CI_CFG_FAKE_IPV6
  }
  else if (level ==  IPPROTO_IPV6 && s->domain == AF_INET6) {
    /* IP6 level options valid for TCP */
    return ci_get_sol_ip6(netif, s, fd, optname, optval, optlen);
#endif

  }
  else if (level == IPPROTO_TCP) {
    /* TCP specific options */
    return ci_get_sol_tcp(netif, s, optname, optval, optlen);
  }
  else {
    SOCKOPT_RET_INVALID_LEVEL(s);
  }
}


static int ci_tcp_setsockopt_lk(citp_socket* ep, ci_fd_t fd, int level,
				int optname, const void* optval,
				socklen_t optlen )
{
  ci_sock_cmn* s = ep->s;
  ci_tcp_socket_cmn* c = &(SOCK_TO_WAITABLE_OBJ(s)->tcp.c);
  ci_netif* netif = ep->netif;
  int rc;

  if( optlen < 0 ) {
    rc = -EINVAL;
    goto fail_inval;
  }

  /* If you're adding to this please remember to look in common_sockopts.c
   * and decide if the option is common to all protocols. */

  if(level == SOL_SOCKET) {
    switch(optname) {
    case SO_KEEPALIVE:
      /* Over-ride the default common handler.
       * Enable sending of keep-alive messages */
      if( (rc = opt_not_ok(optval, optlen, unsigned)) )
      	goto fail_inval;

      if( *(unsigned*) optval ) {
	unsigned prev_flags = s->s_flags;
	s->s_flags |= CI_SOCK_FLAG_KALIVE;
	/* Set KEEPALIVE timer only if we are not in
	** CLOSE or LISTENING state. */
	if( s->b.state != CI_TCP_CLOSED && s->b.state != CI_TCP_LISTEN &&
	    !(prev_flags & CI_SOCK_FLAG_KALIVE) ) {
	  ci_tcp_state* ts = SOCK_TO_TCP(s);
	  LOG_TV(log("%s: "NSS_FMT" run KEEPALIVE timer from setsockopt()",
		     __FUNCTION__, NSS_PRI_ARGS(netif, s)));
	  ci_assert(ts->ka_probes == 0);
	  ci_tcp_kalive_restart(netif, ts, ci_tcp_kalive_idle_get(ts));
	}
      }
      else {
      	s->s_flags &=~ CI_SOCK_FLAG_KALIVE;
	if( s->b.state != CI_TCP_LISTEN ) {
	  ci_tcp_state* ts = SOCK_TO_TCP(s);
	  ci_tcp_kalive_check_and_clear(netif, ts);
	  ts->ka_probes = 0;
	}
      }
      break;

    default:
      {
        /* Common socket level options */
        return ci_set_sol_socket(netif, s, optname, optval, optlen);
      }
    }
  }
  else if( level == IPPROTO_IP ) {
    /* IP level options valid for TCP */
    return ci_set_sol_ip(netif, s, optname, optval, optlen);
  }
  else if( level == IPPROTO_IPV6 ) {
    /* IPv6 level options valid for TCP */
    return ci_set_sol_ip6(netif, s, optname, optval, optlen);
  }
  else if( level == IPPROTO_TCP ) {
    /* These are ints values */
    if( (rc = opt_not_ok(optval, optlen, int)) )
      goto fail_inval;
    switch(optname) {
#ifdef TCP_CORK
    case TCP_CORK:
      if( *(unsigned*) optval ) {
	ci_bit_set(&s->s_aflags, CI_SOCK_AFLAG_CORK_BIT);
      } else {
	ci_bit_clear(&s->s_aflags, CI_SOCK_AFLAG_CORK_BIT);
        /* We need to push out a segment that was corked. */
	if( s->b.state != CI_TCP_LISTEN )
          ci_tcp_send_corked_packets(netif, SOCK_TO_TCP(s));
      }
      break;
#endif
    case TCP_NODELAY:
      if( NI_OPTS(netif).tcp_force_nodelay )
        break;
      if( *(unsigned*) optval ) {
	ci_bit_set(&s->s_aflags, CI_SOCK_AFLAG_NODELAY_BIT);

	if( s->b.state != CI_TCP_LISTEN ) {
          ci_uint32 cork; 

          /* When TCP_NODELAY is set, push out pending segments (even if
          ** CORK is set).
          */
          if( (cork = (s->s_aflags & CI_SOCK_AFLAG_CORK)) )
            ci_bit_clear(&s->s_aflags, CI_SOCK_AFLAG_CORK_BIT);
          ci_tcp_send_corked_packets(netif, SOCK_TO_TCP(s));
          if ( cork )
            ci_bit_set(&s->s_aflags, CI_SOCK_AFLAG_CORK_BIT);
        }
      }
      else
        ci_bit_clear(&s->s_aflags, CI_SOCK_AFLAG_NODELAY_BIT);
      break;
     
    case TCP_MAXSEG:
      /* sets the MSS size for this connection */
      if( (rc = opt_not_ok(optval, optlen, unsigned)) )
        goto fail_inval;
      if( (*(unsigned*)optval < 8) || 
          (*(unsigned*)optval > CI_CFG_TCP_MAX_WINDOW)) {
        rc = -EINVAL;
        goto fail_inval;
      }
      c->user_mss = (ci_uint16) *(unsigned*) optval;
      break;

    case TCP_KEEPIDLE:
      if( *(int*)optval < 1 || *(int*)optval > CI_MAX_TCP_KEEPIDLE ) {
        rc = -EINVAL;
        goto fail_inval;
      }
      /* idle time for keepalives  */
      c->t_ka_time = ci_ip_time_ms2ticks(netif, *(unsigned*)optval*1000);
      c->t_ka_time_in_secs = *(unsigned*)optval;
      break;

    case TCP_KEEPINTVL:
      if( *(int*)optval < 1 || *(int*)optval > CI_MAX_TCP_KEEPINTVL ) {
        rc = -EINVAL;
        goto fail_inval;
      }
      /* time between keepalives */
      c->t_ka_intvl = ci_ip_time_ms2ticks(netif, *(unsigned*)optval*1000);
      c->t_ka_intvl_in_secs = *(unsigned*)optval;
      break;

    case TCP_KEEPCNT:
      if( *(int*)optval < 1 || *(int*)optval > CI_MAX_TCP_KEEPINTVL ) {
        rc = -EINVAL;
        goto fail_inval;
      }
      /* number of keepalives before giving up */
      c->ka_probe_th = *(unsigned*)optval;
      break;
    case TCP_DEFER_ACCEPT:
      if( *(int*) optval > 0 ) {
        /* Value is timeout in seconds.  Convert to a number of retries. */
        int timeo = CI_MIN(*(int*) optval, 100000) * 1000;
        timeo = ci_ip_time_ms2ticks(netif, timeo);
        timeo = CI_MIN(timeo, NI_CONF(netif).tconst_rto_max);
        c->tcp_defer_accept = 1;
        while( timeo > ((int) NI_CONF(netif).tconst_rto_initial *
                        ((1 << c->tcp_defer_accept) - 1)) &&
               c->tcp_defer_accept <= CI_CFG_TCP_SYNACK_RETRANS_MAX )
          ++c->tcp_defer_accept;
      }
      else
        c->tcp_defer_accept = OO_TCP_DEFER_ACCEPT_OFF;
      break;
    case TCP_QUICKACK:
      {
        if( s->b.state & CI_TCP_STATE_TCP_CONN ) {
          ci_tcp_state* ts = SOCK_TO_TCP(s);
          if( *(int*) optval != 0 ) {
            CITP_TCP_FASTSTART(ts->faststart_acks = 
                               NI_OPTS(netif).tcp_faststart_idle);
            if( ts->acks_pending ) {
              ci_ip_pkt_fmt* pkt = ci_netif_pkt_alloc(netif, 0);
              if( CI_LIKELY(pkt != NULL) )
                ci_tcp_send_ack(netif, ts, pkt, CI_FALSE);
            }
          }
          else {
            ts->tcpflags |= CI_TCPT_FLAG_NO_QUICKACK;
            CITP_TCP_FASTSTART(ts->faststart_acks = 0);
          }
        }
      }
      break;
    default:
      LOG_TC(log("%s: "NSS_FMT" option %i unimplemented (ENOPROTOOPT)", 
             __FUNCTION__, NSS_PRI_ARGS(netif,s), optname));
      goto fail_unsup;
    }
  }
  else {
    if( s->b.sb_aflags & CI_SB_AFLAG_OS_BACKED ) {
      LOG_U(log(FNS_FMT "unknown level=%d optname=%d accepted by O/S",
                FNS_PRI_ARGS(netif, s), level, optname));
    }
    else {
      goto fail_unsup;
    }
  }

  return 0;

 fail_unsup:
  RET_WITH_ERRNO(ENOPROTOOPT);

 fail_inval:
  LOG_TC(log("%s: "NSS_FMT" option %i  bad param (EINVAL or EFAULT)",
	     __FUNCTION__, NSS_PRI_ARGS(netif,s), optname));
  RET_WITH_ERRNO(-rc);
}


/* Setsockopt() handler called by appropriate Unix/Windows intercepts.
 * \param ep       Context
 * \param fd       Linux: Our FD, Windows: ignored (CI_INVALID_SOCKET)
 * \param level    From intercept
 * \param optname  From intercept
 * \param optval   From intercept
 * \param optlen   From intercept
 * \return         As for setsockopt()
 */
int ci_tcp_setsockopt(citp_socket* ep, ci_fd_t fd, int level,
		      int optname, const void* optval,
		      socklen_t optlen )
{
  ci_sock_cmn* s = ep->s;
  ci_netif* ni = ep->netif;
  int rc = 0;

  ci_netif_lock_count(ni, setsockopt_ni_lock_contends);

  /* If not yet connected, apply to the O/S socket.  This keeps the O/S
  ** socket in sync in case we need to hand-over.
  */
  /*! \todo This is very much a "make it work" change.  Ideally we should
   * do the updates lazily so that we don't waste time with a socket that
   * may never be used for an OS connection.  At the moment lazy sockopts
   * are only done when scalable filters are enabled.
   */
  if( ! (s->b.state & CI_TCP_STATE_SYNCHRONISED) ) {
    ci_fd_t os_sock = CI_FD_BAD;
    if( s->b.sb_aflags & CI_SB_AFLAG_OS_BACKED )
      os_sock = ci_get_os_sock_fd(fd);
    if( CI_IS_VALID_SOCKET(os_sock) ) {
      rc = ci_sys_setsockopt(os_sock, level, optname, optval, optlen);
      ci_rel_os_sock_fd(os_sock);
      if( rc != 0 &&
          ! ci_setsockopt_os_fail_ignore(ni, s, errno, level, optname,
                                         optval, optlen) ) {
        goto unlock_out;
      }
      rc = 0;
    }
  }

  if( level == SOL_SOCKET ) {
    rc = ci_set_sol_socket_nolock(ni, s, optname, optval, optlen);
    if( rc <= 0 )  goto unlock_out;
  }

  rc = ci_tcp_setsockopt_lk(ep, fd, level, optname, optval, optlen);

 unlock_out:
  ci_netif_unlock(ni);
  return rc;
}
#endif /* !defined(__KERNEL__) */

/*! \cidoxg_end */
