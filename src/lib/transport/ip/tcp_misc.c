/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  TCP misc stuff.
**   \date  2003/08/19
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include <onload/sleep.h>
#include <onload/tmpl.h>

#define LPF "TCP MISC "

#if OO_DO_STACK_POLL
#define VERB(x)

enum {
  CI_LINUX_TCP_ESTABLISHED = 1,
  CI_LINUX_TCP_SYN_SENT,
  CI_LINUX_TCP_SYN_RECV,
  CI_LINUX_TCP_FIN_WAIT1,
  CI_LINUX_TCP_FIN_WAIT2,
  CI_LINUX_TCP_TIME_WAIT,
  CI_LINUX_TCP_CLOSE,
  CI_LINUX_TCP_CLOSE_WAIT,
  CI_LINUX_TCP_LAST_ACK,
  CI_LINUX_TCP_LISTEN,
  CI_LINUX_TCP_CLOSING,  /* now a valid state */
};


/* Mapping between socket states in L5 stack and Linux */
const unsigned char ci_sock_states_linux_map [] = {
  CI_LINUX_TCP_CLOSE,        /* CI_TCP_CLOSED */
  CI_LINUX_TCP_LISTEN,       /* CI_TCP_LISTEN */
  CI_LINUX_TCP_SYN_SENT,     /* CI_TCP_SYN_SENT */
  CI_LINUX_TCP_ESTABLISHED,  /* CI_TCP_ESTABLISHED */
  CI_LINUX_TCP_CLOSE_WAIT,   /* CI_TCP_CLOSE_WAIT */
  CI_LINUX_TCP_LAST_ACK,     /* CI_TCP_LAST_ACK */
  CI_LINUX_TCP_FIN_WAIT1,    /* CI_TCP_FIN_WAIT1 */
  CI_LINUX_TCP_FIN_WAIT2,    /* CI_TCP_FIN_WAIT2 */
  CI_LINUX_TCP_CLOSING,      /* CI_TCP_CLOSING */
  /* Linux does not have sockets in TIME-WAIT state; socket is CLOSED,
   * and timewait object is in TIME-WAIT. */
  CI_LINUX_TCP_CLOSE         /* CI_TCP_TIME_WAIT */
};


const char* type_str(int type)
{
  static const char* type_strs[] = {
    "<unknown>",              /* 0 */
    "SOCK_STREAM",            /* 1 */
    "SOCK_DGRAM",             /* 2 */
    "SOCK_RAW",               /* 3 */
    "SOCK_RDM",               /* 4 */
    "SOCK_SEQPACKET",         /* 5 */
    "<unknown>",              /* 6 */
    "<unknown>",              /* 7 */
    "<unknown>",              /* 8 */
    "<unknown>",              /* 9 */
    "SOCK_PACKET"             /* 10 */
  };

  type &= SOCK_TYPE_MASK;

  if (type < 0 || type >= (sizeof (type_strs) / sizeof (type_strs[0])))
    return "<out of range>";

  return type_strs[type];
}

const char* domain_str(int domain)
{
  static const char* domain_strs[] = {
    "AF_UNSPEC",              /* 0 */
    "AF_UNIX/LOCAL",          /* 1 */
    "AF_INET",                /* 2 */
    "AF_AX25",                /* 3 */
    "AF_IPX",                 /* 4 */
    "AF_APPLETALK",           /* 5 */
    "AF_NETROM",              /* 6 */
    "AF_BRIDGE",              /* 7 */
    "AF_ATMPVC",              /* 8 */
    "AF_X25",                 /* 9 */
    "AF_INET6",               /* 10 */
    "AF_ROSE",                /* 11 */
    "AF_DECnet",              /* 12 */
    "AF_NETBEUI",             /* 13 */
    "AF_SECURITY",            /* 14 */
    "AF_KEY",                 /* 15 */
    "AF_NETLINK/ROUTE",       /* 16 */
    "AF_PACKET",              /* 17 */
    "AF_ASH",                   /* 18 */
    "AF_ECONET",              /* 19 */
    "AF_ATMSVC",              /* 20 */
    "<unknown>",              /* 21 */
    "AF_SNA",                   /* 22 */
    "AF_IRDA",                /* 23 */
    "AF_PPPOX",               /* 24 */
    "AF_WANPIPE",             /* 25 */
    "<unknown>",              /* 26 */
    "<unknown>",              /* 27 */
    "<unknown>",              /* 28 */
    "<unknown>",              /* 29 */
    "<unknown>",              /* 30 */
    "AF_BLUETOOTH",           /* 31 */
    "AF_MAX"                    /* 32 */
  };

  if (domain < 0 || domain >= (sizeof (domain_strs) / sizeof (domain_strs[0])))
    return "<out of range>";

  return domain_strs[domain];
}

const char* ip_addr_str(ci_uint32 addr_be32)
{
  static char buf[4][16];
  static int buf_i;
  int i = ++buf_i & 3;

  ci_format_ip4_addr(buf[i], sizeof(buf[i]), addr_be32);
  return buf[i];
}
#endif /* OO_DO_STACK_POLL */


const char* ci_tcp_state_num_str(int state_i)
{
  static const char* state_strs[] = {
    "CLOSED",
    "LISTEN",
    "SYN-SENT",
    "ESTABLISHED",
    "CLOSE-WAIT",
    "LAST-ACK",
    "FIN-WAIT1",
    "FIN-WAIT2",
    "CLOSING",
    "TIME-WAIT",
    "FREE",
    "UDP",
    "PIPE",
    "AUXBUF",
    "ACTIVE_WILD",
  };

  if( state_i < 0 || state_i >= (sizeof(state_strs) / sizeof(state_strs[0])) )
    return "<invalid-TCP-state>";

  return state_strs[state_i];
}


#if OO_DO_STACK_POLL
const char* ci_tcp_congstate_str(unsigned s)
{
  switch( s ) {
  case CI_TCP_CONG_OPEN:        return "Open";
  case CI_TCP_CONG_RTO:         return "RTO";
  case CI_TCP_CONG_RTO_RECOV:   return "RTORecovery";
  case CI_TCP_CONG_FAST_RECOV:  return "FastRecovery";
  case CI_TCP_CONG_COOLING:     return "Cooling";
  case CI_TCP_CONG_COOLING | CI_TCP_CONG_RTO:     return "RTOCooling";
  case CI_TCP_CONG_NOTIFIED:    return "Notified";
  default:
    ci_log("BAD CONGESTION STATE %x", s);
    return "<invalid-congstate>";
  }
}


#ifndef NDEBUG
void ci_tcp_state_verify_no_timers(ci_netif *ni, ci_tcp_state *ts)
{
# define chk(x) ci_assert(!ci_ip_timer_pending(ni, &ts->x))
  chk(rto_tid);
  chk(delack_tid);
  chk(zwin_tid);
  chk(kalive_tid);
  chk(cork_tid);
#if CI_CFG_TCP_SOCK_STATS
  chk(stats_tid);
#endif
#undef chk
  ci_assert(OO_PP_IS_NULL(ts->pmtus));
}
#endif


static void __ci_tcp_state_free(ci_netif *ni, ci_tcp_state *ts)
{
  VERB(ci_log("%s("NTS_FMT")", __FUNCTION__, NTS_PRI_ARGS(ni,ts)));
  ci_assert(ni);
  ci_assert(ts);

  /* Disconnect local peer if any */
  if( OO_SP_NOT_NULL(ts->local_peer) ) {
    ci_tcp_state* peer = ID_TO_TCP(ni, ts->local_peer);
    if( peer->local_peer == S_SP(ts) )
      peer->local_peer = OO_SP_NULL;
  }

#if CI_CFG_PIO
  /* Free up any associated templated sends */
  ci_tcp_tmpl_free_all(ni, ts);
#endif

  /* Remove from any lists we're in. */
  oo_p_dllink_del_init(ni, oo_p_dllink_sb(ni, &ts->s.b,
                                          &ts->s.b.post_poll_link));
  ci_ni_dllist_remove_safe(ni, &ts->s.reap_link);

  citp_waitable_remove_from_epoll(ni, &ts->s.b, 1);

  /* By the time we get here the send queues must be empty (otherwise it
  ** means we have a leak!).  Receive queues may have data due to
  ** asynchronous receive.
  */
  ci_assert(ci_tcp_sendq_is_empty(ts));
  ci_assert(ci_ip_queue_is_empty(&ts->rob));
  ci_assert(ci_ip_queue_is_empty(&ts->retrans));

  ci_tcp_rx_queue_drop(ni, ts, &ts->recv1);
  ci_tcp_rx_queue_drop(ni, ts, &ts->recv2);

#if CI_CFG_TIMESTAMPING
  ci_udp_recv_q_drop(ni, &ts->timestamp_q);
  ts->timestamp_q_pending = OO_PP_NULL;
#endif
  ci_assert_equal(__ci_tcp_rx_buf_count(ni, ts), 0);

#if CI_CFG_FD_CACHING
  /* Clear any cache link - it's possible that this socket is on the
   * the connected list.  Now that we're closed there's no need, as we
   * don't need our filters updated.
   *
   * We should have already removed our filters by this point, but it's safe
   * to stay on this list even after the filters have been cleared, as the
   * state changes don't require the filters to be in place.  By doing it
   * here we have a single point responsible for the removal.
   */
  ci_ni_dllist_remove_safe(ni, &ts->epcache_link);
#endif

  ci_tcp_state_verify_no_timers(ni, ts);
}


static void ci_tcp_set_state(ci_netif* ni, ci_tcp_state* ts, int new_state)
{
  ci_tcp_rx_buf_account_begin(ni, ts);
  ts->s.b.state = new_state;
  ci_tcp_rx_buf_account_end(ni, ts);
}


/* This frees up the resources used by the tcp state, but if there are
   outstanding async ops on the netif it will delay clearing the
   address space and freeing the tcp state until they are complete.
   If no aops outstanding, it does that immediately */
void ci_tcp_state_free(ci_netif* ni, ci_tcp_state* ts)
{
  VERB(ci_log("%s("NTS_FMT")", __FUNCTION__, NTS_PRI_ARGS(ni,ts)));
  ci_assert(ci_netif_is_locked(ni));
  ci_assert(ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN);

  __ci_tcp_state_free(ni, ts);
  citp_waitable_obj_free(ni, &ts->s.b);
}


/* care about established connections counters */
ci_inline void ci_tcp_estabs_handle(ci_netif *ni, ci_tcp_state *ts, int state)
{
#if CI_CFG_SUPPORT_STATS_COLLECTION
  /* On linux this counter only reflects the number of TCP connections for
  ** which the current state is ESTABLISHED.
  **
  ** ?? So on what platform(s) does it represent something else?
  */
  if( (ts->s.b.state == CI_TCP_ESTABLISHED ) )
    CI_TCP_STATS_DEC_CURR_ESTAB(ni);

  if ((state == CI_TCP_CLOSED) &&
      ((ts->s.b.state == CI_TCP_ESTABLISHED) ||
       (ts->s.b.state == CI_TCP_CLOSE_WAIT)))
    CI_TCP_STATS_INC_ESTAB_RESETS( ni );
#endif
}

ci_int32 ci_tcp_rcvbuf_established(ci_netif* ni, ci_sock_cmn* s)
{
  ci_assert(s->b.state & CI_TCP_STATE_TCP);
  if( NI_OPTS(ni).tcp_rcvbuf_user != 0 )
    return oo_adjust_SO_XBUF(NI_OPTS(ni).tcp_rcvbuf_user);
  if( ~s->s_flags & CI_SOCK_FLAG_SET_RCVBUF ) {
    if( NI_OPTS(ni).tcp_rcvbuf_est_def > s->so.rcvbuf )
      return NI_OPTS(ni).tcp_rcvbuf_est_def;
    else if( s->so.rcvbuf > NI_OPTS(ni).tcp_rcvbuf_est_def * 4 ) {
      /* Do not allow one RCVBUF to eat all packets from this stack */
      return NI_OPTS(ni).tcp_rcvbuf_est_def * 4;
    }
  }
  return s->so.rcvbuf;
}

void ci_tcp_set_established_state(ci_netif* ni, ci_tcp_state* ts)
{
  ci_assert(ts);
  ci_assert(ci_netif_is_locked(ni));

  ci_tcp_set_state(ni, ts, CI_TCP_ESTABLISHED);
  CI_TCP_STATS_INC_CURR_ESTAB( ni );

  ts->s.tx_errno = 0;
  ts->s.rx_errno = 0;
  ts->tcpflags |= CI_TCPT_FLAG_WAS_ESTAB;

  /* ?? HACK: Reset window sizes to a suitable value (if app hasn't already
  ** modified them).  The defaults are too small, but we need to stick with
  ** them at socket creation time because some apps (e.g. netperf) modify
  ** their behaviour depending on what they see in SO_SNDBUF and SO_RCVBUF.
  **
  ** It would be more elegant to grow them dynamically as needed:
  ** EF_TCP_SNDBUF_MODE=2 and EF_TCP_RCVBUF_MODE=1 now do this.
  */
  if( NI_OPTS(ni).tcp_sndbuf_user != 0 )
    ts->s.so.sndbuf = oo_adjust_SO_XBUF(NI_OPTS(ni).tcp_sndbuf_user);
  else if( ~ts->s.s_flags & CI_SOCK_FLAG_SET_SNDBUF ) {
    if( NI_OPTS(ni).tcp_sndbuf_est_def > ts->s.so.sndbuf )
      ts->s.so.sndbuf = NI_OPTS(ni).tcp_sndbuf_est_def;
    else if( ts->s.so.sndbuf > NI_OPTS(ni).tcp_sndbuf_est_def * 4 )
      ts->s.so.sndbuf = NI_OPTS(ni).tcp_sndbuf_est_def * 4;
  }

  if( NI_OPTS(ni).tcp_sndbuf_mode == 2 && (~ts->s.s_flags & CI_SOCK_FLAG_SET_SNDBUF) )
    ci_tcp_expand_sndbuf(ni, ts);
  else
    ci_tcp_set_sndbuf(ni, ts);

  ts->s.so.rcvbuf = ci_tcp_rcvbuf_established(ni, &ts->s);
  ci_tcp_set_rcvbuf(ni, ts);

  /* setup stats for Dynamic Right Sizing */
  ts->rcvbuf_drs.bytes = ts->rcv_wnd_advertised;
  ts->rcvbuf_drs.seq   = ts->rcv_delivered;
  ts->rcvbuf_drs.time  = ci_tcp_time_now(ni);

#if CI_CFG_PORT_STRIPING
  if( ts->tcpflags & CI_TCPT_FLAG_STRIPE )
    LOG_TC(ci_log(NT_FMT "striping on (l=%x r=%x m=%x)", NT_PRI_ARGS(ni, ts),
                  tcp_laddr_be32(ts), tcp_raddr_be32(ts),
                  NI_OPTS(ni).stripe_netmask_be32));
#endif

  CITP_TCP_FASTSTART(ts->faststart_acks = NI_OPTS(ni).tcp_faststart_init);
  /* dirty hack to abuse this, init for faststart */
  CITP_TCP_FASTSTART(ts->tslastack = tcp_rcv_nxt(ts));

  if( ci_tcp_can_use_fast_path(ts) )
    ci_tcp_fast_path_enable(ts);
}


void ci_tcp_set_slow_state(ci_netif *ni, ci_tcp_state* ts, int state)
{
  ci_assert(ts);
  ci_assert(state & CI_TCP_STATE_SLOW_PATH);

#ifndef NDEBUG
  /* temporary checks to try and track down a set of possibly related
     bugs: 557, 908, 936 & 940 */
  if(ts->s.b.state != CI_TCP_LISTEN){
    if(!(state & CI_TCP_STATE_TXQ_ACTIVE)){
      ci_assert(ci_tcp_sendq_is_empty(ts));
      ci_assert(ci_ip_queue_is_empty(&ts->retrans));
    }
    if( state & CI_TCP_STATE_NO_TIMERS )
      ci_tcp_state_verify_no_timers(ni, ts);
  }

  /* to try and track down Bug 1427 and similar we check that errno
     has been set when moving the state to closed */
  if (CI_TCP_CLOSED == state) {
    ci_assert(ts->s.rx_errno != 0);
    ci_assert(ts->s.tx_errno != 0);
  }

  if(ts->s.b.state == CI_TCP_TIME_WAIT){
    /* basic sanity */
    ci_assert(state != CI_TCP_TIME_WAIT);
    /* make sure it's not still in the list */
    ci_assert(ci_ni_dllist_is_free(&ts->timeout_q_link));
  }
#endif
  ci_tcp_estabs_handle(ni, ts, state);
  ci_tcp_set_state(ni, ts, state);
  ci_tcp_fast_path_disable(ts);
}


int ci_tcp_parse_options(ci_netif* ni, ciip_tcp_rx_pkt* rxp,
                         ci_tcp_options* topts)
{
  /* Parse TCP header options.
  **
  ** We can come through here 0, 1 or 2 times per packet.  0 if we see a
  ** case that we handle inline in tcp_rx.c.  Otherwise once, unless its a
  ** SYN segment, in which case we call this a second time to get the SYN
  ** options.  In this case [topts] will be non-null.
  */
  ci_tcp_hdr* tcp;
  ci_uint8* opt;
  int i, bytes, len;

  ci_assert(rxp);
  ci_assert(rxp->pkt);
  ci_assert(rxp->tcp);
  ci_assert(rxp->tcp == PKT_IPX_TCP_HDR(oo_pkt_af(rxp->pkt), rxp->pkt));

  tcp = rxp->tcp;
  opt = CI_TCP_HDR_OPTS(tcp);
  bytes = CI_TCP_HDR_OPT_LEN(tcp);
  rxp->flags = 0;

  LOG_TV(log(LPF "parsing options packet %d, optlen %d",
             OO_PKT_FMT(rxp->pkt), bytes));

  /* parse valid TCP options */
  for( ; bytes > 0;  bytes -= len, opt += len ) {
    /* In the most cases, length of a TCP option is opt[1],
     * but such options as NOP reset it. */
    if( opt[0] == CI_TCP_OPT_NOP ) {
      len = 1;
      continue;
    }
    else if( opt[0] == CI_TCP_OPT_END ) {
      break;
    }
    else if ( bytes < 2 ) {
      LOG_U(log(LPF "TCP option %d truncated", opt[0]));
      goto fail_out;
    }
    else {
      len = opt[1];
    }

    /*
    ** RFC 1122 "(all TCP options defined in the future will have
    **      length fields)"
    */
    if( bytes < len || len < 2 ) {
      LOG_U(log(LPF "TCP option %d truncated", opt[0]));
      goto fail_out;
    }

    switch(opt[0]) {
    case CI_TCP_OPT_TIMESTAMP:
      if( len != 0xa ) {
        LOG_U(log(LPF "TSopt(bad length %d)", len));
        goto fail_out;
      }
      rxp->flags |= CI_TCPT_FLAG_TSO;
      if( topts == NULL ) {  /* must only byte-swap first time through */
	rxp->timestamp = CI_BSWAP_BE32(*(ci_uint32*) &opt[2]);
	rxp->timestamp_echo = CI_BSWAP_BE32(*(ci_uint32*) &opt[6]);
      }
      break;
    case CI_TCP_OPT_SACK:
      if( len < 2 + 8 || (len & 7) != 2 ) {
        LOG_U(log(LPF "SACK(bad length %d)", len));
        goto fail_out;
      }
      if( topts == NULL ) {
        rxp->flags |= CI_TCPT_FLAG_SACK;
        rxp->sack_blocks = (int)(len >> 3u);
        for( i = 0; i < 2 * rxp->sack_blocks; i++ )
          rxp->sack[i] = CI_BSWAP_BE32(*(ci_uint32*) &opt[2 + i * 4]);
      }
      break;
    case CI_TCP_OPT_MSS:
      if( len != 0x4 ) {
        LOG_U(log(LPF "MSS(bad length %d)", len));
        goto fail_out;
      }
      if( topts ) {
        topts->smss = CI_BSWAP_BE16(*(ci_uint16*)(opt + 2));
        /* RFC 1191 specifies 68 as a minimum, but Linux and
         * ANVL tests use 64.*/
        if( topts->smss < 64 ) {
          LOG_U(log("%s: Clamping smss to 64, value give is %d",
                    __FUNCTION__, topts->smss));
          topts->smss = 64;
        }
      }
      ci_assert_equal(len, 4);
      break;
    case CI_TCP_OPT_WINSCALE:
      if( len != 0x3 ) {
        LOG_U(log(LPF "WSopt(bad length %d)", len));
        goto fail_out;
      }
      if ( opt[2] > CI_TCP_WSCL_MAX ) {
        /* RFC1323 check and silently truncate the WSCL option */
        LOG_U(log( LPF "WSCL_SHFT of %u larger than %d, truncating",
                   CI_TCP_WSCL_MAX, opt[2]));
        opt[2] = CI_TCP_WSCL_MAX;
      }
      if( topts ) {
        topts->flags |= CI_TCPT_FLAG_WSCL;
        topts->wscl_shft = opt[2];
      }
      break;
    case CI_TCP_OPT_SACK_PERM:
      if( len != 0x2 ) {
        LOG_U(log(LPF "SACKperm(bad length %d)", len));
        goto fail_out;
      }
      if( topts )  topts->flags |= CI_TCPT_FLAG_SACK;
      break;
    default:
#if CI_CFG_PORT_STRIPING
      if( opt[0] == NI_OPTS(ni).stripe_tcp_opt ) {
        if( len != 0x2 ) {
          LOG_U(log(LPF "STRIPE(bad length %d)", len));
          goto fail_out;
        }
        if( topts )  topts->flags |= CI_TCPT_FLAG_STRIPE;
        break;
      }
#endif

      LOG_U(log(LPF "unknown/invalid TCP option %x length %d",
                (unsigned) opt[0], (int) len));
      break;
    }
  }

  return 0;
 fail_out:
  LOG_U(log(LPF "failed to process (some) TCP option(s)"));
  return -1;
}


/* ci_ip_timer_clear() actually expands to a surprisingly large amount of code
 * and uses quite a lot of stack, and gcc stupidly allocates that amount of
 * stack for *each* call in ci_tcp_stop_timers(), which adds up to far too much
 * when running in a kernel with 4K stacks.  So here's an out-of-lined version
 * of it for ci_tcp_stop_timers() to use -- saves nearly 1/2 K of stack!
 */
static void ci_ip_timer_clear_ool(ci_netif* netif, ci_ip_timer* tmr)
{
  ci_ip_timer_clear(netif, tmr);
}

void ci_tcp_stop_timers(ci_netif* netif, ci_tcp_state* ts)
{
  ci_ip_timer_clear_ool(netif, &ts->rto_tid);
  ci_ip_timer_clear_ool(netif, &ts->delack_tid);
  ci_ip_timer_clear_ool(netif, &ts->zwin_tid);
  ci_ip_timer_clear_ool(netif, &ts->kalive_tid);
  ci_ip_timer_clear_ool(netif, &ts->cork_tid);
  if( OO_PP_NOT_NULL(ts->pmtus) ) {
    ci_pmtu_state_t* pmtus = ci_ni_aux_p2pmtus(netif, ts->pmtus);
    ci_ip_timer_clear_ool(netif, &pmtus->tid);
    ci_pmtu_state_free(netif, pmtus);
    ts->pmtus = OO_PP_NULL;
  }
#if CI_CFG_TCP_SOCK_STATS
  ci_ip_timer_clear_ool(netif, &ts->stats_tid);
#endif
}


/*
** Drop anything on an IP queue
*/
#if defined(__KERNEL__) || ! defined(NDEBUG)
  /* In both kernel case and debug case we want to detect corrupted shared
   * state and exit from the loop below. */
  #define CI_DEBUG_OR_KERNEL(x) x
#else
  #define CI_DEBUG_OR_KERNEL(x)
#endif
void ci_ip_queue_drop(ci_netif* netif, ci_ip_pkt_queue *qu)
{
  ci_ip_pkt_fmt* p;
  CI_DEBUG_OR_KERNEL(int i = qu->num);

  ci_assert(netif);
  ci_assert(qu);
  ci_assert(ci_ip_queue_is_valid(netif, qu));

  while( OO_PP_NOT_NULL(qu->head)   CI_DEBUG_OR_KERNEL( && i-- > 0) ) {
    p = PKT_CHK(netif, qu->head);
    qu->head = p->next;
    ci_netif_pkt_release_check_keep(netif, p);
  }
  ci_assert_equal(i, 0);
  ci_assert(OO_PP_IS_NULL(qu->head));
  qu->num = 0;
}

static void ci_tcp_tx_drop_queues(ci_netif* ni, ci_tcp_state* ts)
{
  ci_tcp_retrans_drop(ni, ts);
  ci_tcp_sendmsg_enqueue_prequeue(ni, ts, CI_TRUE);
  ci_tcp_sendq_drop(ni, ts);

  /* Maintain invariants. */
  tcp_snd_nxt(ts) = tcp_enq_nxt(ts) = tcp_snd_una(ts);
  ts->congstate = CI_TCP_CONG_OPEN;
  ts->cwnd_extra = 0;
  ts->dup_acks = 0;
  ts->tcpflags &=~ CI_TCPT_FLAG_FIN_PENDING;
}


#if CI_CFG_FD_CACHING
/* This frees up the resources used by the tcp state, as ci_tcp_state_free, but
 * does not free the underlying waitable object.
 *
 * The tcp state is pushed to the appropriate epcache_cache list.
 */
void ci_tcp_state_free_to_cache(ci_netif* netif, ci_tcp_state* ts)
{
  oo_sp sock;
  ci_tcp_socket_listen* tls;
  ci_socket_cache_t* cache;

  ci_assert(ci_tcp_is_cached(ts));

  if( ts->s.s_flags & CI_SOCK_FLAG_SCALPASSIVE ) {
    cache = &netif->state->passive_scalable_cache;
  }
  else if( ts->s.b.sb_aflags & CI_SB_AFLAG_IN_PASSIVE_CACHE ) {
    /* We can only cache passively accepted sockets if they have filters,
     * so they must have been bound.
     */
    ci_assert_nequal(tcp_laddr_be32(ts), 0);
    ci_assert_nequal(tcp_lport_be16(ts), 0);
    sock = ci_netif_listener_lookup(netif, sock_af_space(&ts->s),
                                    sock_ipx_laddr(&ts->s),
                                    tcp_lport_be16(ts));
    if( OO_SP_NOT_NULL(sock) ) {
      tls = ID_TO_TCP_LISTEN(netif, sock);

      ci_assert_equal(tls->s.b.state, CI_TCP_LISTEN);
      ci_assert_nflags(tls->s.s_flags, CI_SOCK_FLAG_SCALPASSIVE);
      cache = &tls->epcache;
    }
    else {
      /* The listening socket clears its cache (including the epcache_pending
       * queue) on shutdown, so the fact that we have a cached socket means
       * that the listening socket must still exist.  However,
       * ci_netif_listener_lookup() uses the software filter table to do its
       * lookup, so this can still fail if the software filter has been
       * removed, which happens if the IP address has been removed from the
       * interface.  In this case we have a bit of a problem, because we can't
       * move the socket through the caching state machine without getting at
       * the listener.  On the other hand, if the IP address has been removed,
       * then the cached socket is useless anyway.  We pop it from
       * epcache_pending but leave it in limbo for the rest of the lifetime of
       * the listening socket, meaning that it consumes one of the available
       * caching slots.  The TCP state will eventually be freed when the
       * listening socket is closed, because then we iterate over the fd_states
       * list, of which this socket will still be a member, and close the
       * associated file descriptors.  Bug79267 discusses a possible way to
       * overcome this limitation.
       */
      LOG_EP(ci_log("Couldn't find listener for cached socket "NSS_FMT" fd %d",
                    NSS_PRI_ARGS(netif,&ts->s), ts->cached_on_fd));
      cache = NULL;
    }
  }
  else {
    cache = &netif->state->active_cache;
  }

  /* Pop off the pending list, push on the cached list. Means that next
   * time a SYNACK is received, try_promote will reuse this cached item,
   * rather than allocating a new TCP state
   */
#if CI_CFG_DETAILED_CHECKS
  if( cache != NULL ) {
    /* Check that this TS is really on the pending list */
    ci_ni_dllist_link *link =
      ci_ni_dllist_start(netif, &cache->pending);
    while( link != ci_ni_dllist_end(netif, &cache->pending) ) {
      if( ts == CI_CONTAINER (ci_tcp_state, epcache_link, link) )
        break;
      ci_ni_dllist_iter(netif, link);
    }
    ci_assert_nequal(link, ci_ni_dllist_end(netif, &cache->pending));
  }
#endif
  /* Switch lists */
  LOG_EP(ci_log("Cached socket "NSS_FMT" fd %d from pending to cached",
                NSS_PRI_ARGS(netif,&ts->s), ts->cached_on_fd));
  ci_ni_dllist_link_assert_is_in_list(netif, &ts->epcache_link);
  ci_ni_dllist_remove_safe(netif, &ts->epcache_link);

  /* When we push this onto the epcache_cache link it needs to be treatable
   * as similarly as possible to a shiny fresh tcp state.  Tidy that up now,
   * so the only differences should be:
   * - cached_on_...
   * - on epcache_cache list
   * As well as the differences in the tcp state we also:
   * - retain hw filter ref
   * - retain fd
   */
  __ci_tcp_state_free(netif, ts);
  citp_waitable_obj_free_to_cache(netif, &ts->s.b);

  if( cache != NULL )
    ci_ni_dllist_push(netif, &cache->cache, &ts->epcache_link);
}
#endif


/*
** Drop a connection to CLOSED, flush buffers and set error code as given.
** After calling this [ts] may have been freed, so you must not touch it
** again.  The only exception is if you know that it is not orphaned.
*/
void ci_tcp_drop(ci_netif* netif, ci_tcp_state* ts, int so_error)
{
  int rc = 0;

  ci_assert(ci_netif_is_locked(netif));
  ci_assert(ts->s.b.state != CI_TCP_LISTEN);

  LOG_TC(log(LPF "%d TCP_DROP %s->CLOSED so_error=%d%s%s",
             S_FMT(ts), ci_tcp_state_str(ts->s.b.state), so_error,
             (ts->s.b.sb_aflags&CI_SB_AFLAG_ORPHAN) ? " orphan":"",
             (ts->s.b.sb_aflags&CI_SB_AFLAG_TCP_IN_ACCEPTQ) ? " acceptq":""));

  if( so_error != 0 )
    ts->s.so_error = so_error;

  if( ts->s.b.state == CI_TCP_CLOSED ) {
    /* This happens to connections on the accept queue that are RST. */
    if( (ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN) && 
        ! (ts->s.b.sb_aflags & CI_SB_AFLAG_TCP_IN_ACCEPTQ) )
      ci_tcp_state_free(netif, ts);
    return;
  }

  ts->s.tx_errno = EPIPE;
  ts->s.rx_errno = CI_SHUT_RD;
  if( ts->s.b.state == CI_TCP_TIME_WAIT || ci_tcp_is_timeout_orphan(ts) )
    ci_netif_timeout_remove(netif, ts);
  ci_tcp_tx_drop_queues(netif, ts);

  ci_tcp_rx_queue_drop(netif, ts, &ts->rob);

  ci_tcp_stop_timers(netif, ts);
  ci_tcp_state_tcb_reinit_minimal(netif, ts);
  ts->acks_pending = 0;
  if( ts->s.b.state == CI_TCP_SYN_SENT ) {
    ts->tcpflags &= ~CI_TCPT_FLAG_NO_ARP;
    switch( so_error ) {
      case ETIMEDOUT:
        CITP_STATS_NETIF(++netif->state->stats.tcp_connect_etimedout);
        break;
      case ECONNREFUSED:
        CITP_STATS_NETIF(++netif->state->stats.tcp_connect_econnrefused);
        break;
      case EHOSTUNREACH:
        CITP_STATS_NETIF(++netif->state->stats.tcp_connect_ehostunreach);
        break;
      case ENETUNREACH:
        CITP_STATS_NETIF(++netif->state->stats.tcp_connect_enetunreach);
        break;
      case ENETDOWN:
        CITP_STATS_NETIF(++netif->state->stats.tcp_connect_enetdown);
        break;
      default:
        CITP_STATS_NETIF(++netif->state->stats.tcp_connect_eother);
        netif->state->stats.tcp_connect_eother_val = so_error;
        break;
    }
  }
  ci_tcp_set_slow_state(netif, ts, CI_TCP_CLOSED);

#if CI_CFG_FD_CACHING
  if( ts->s.s_flags & CI_SOCK_FLAGS_SCALABLE ) {
    rc = ci_tcp_ep_clear_filters(netif, S_SP(ts), 0);
    /* no clearing of SCALPASSIVE flag as it
     * is needed by ci_tcp_state_free_to_cache() below */
    ts->s.s_flags &= ~CI_SOCK_FLAG_SCALACTIVE;
  }
  else if( !ci_tcp_is_cached(ts) ) {
    if( !ci_ni_dllist_is_self_linked(netif, &ts->epcache_link) ) {
      ci_ni_dllist_remove_safe(netif, &ts->epcache_link);
      rc = ci_tcp_ep_clear_filters(netif, S_SP(ts), 1);
    }
    else {
      rc = ci_tcp_ep_clear_filters(netif, S_SP(ts), 0);
    }
  }
  else {
    /* Remove sw filters only for cached endpoint. */
    ci_netif_filter_remove(netif, S_ID(ts), sock_af_space(&ts->s),
                           tcp_ipx_laddr(ts), tcp_lport_be16(ts),
                           tcp_ipx_raddr(ts), tcp_rport_be16(ts),
                           tcp_protocol(ts));
    ts->s.s_flags &= ~(CI_SOCK_FLAG_FILTER | CI_SOCK_FLAG_STACK_FILTER);
  }
#else
  rc = ci_tcp_ep_clear_filters(netif, S_SP(ts), 0);
#endif

  if( ts->s.b.sb_aflags & CI_SB_AFLAG_TCP_IN_ACCEPTQ ) {
    /* We don't free unaccepted states -- they stay on the acceptq */
  }
  else if( ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN ) {
    ci_assert(!ci_tcp_is_cached(ts));
#ifdef __KERNEL__
    /* If the filters have not gone yet, we should not free the endpoint. */
    __ci_tcp_state_free(netif, ts);
#if OO_HAS_ATOMIC_CONTEXT
    if( rc == -EAGAIN ) {
      tcp_helper_endpoint_t* ep = ci_netif_get_valid_ep(netif,  S_SP(ts));
      tcp_helper_endpoint_queue_non_atomic(ep, OO_THR_EP_AFLAG_NEED_FREE);
    }
    else
#endif
    {
      ci_assert_equal(rc, 0);
      citp_waitable_obj_free(netif, &ts->s.b);
    }
#else
    ci_assert_equal(rc, 0);
    ci_tcp_state_free(netif, ts);
    (void)rc; /* unused in UL NDEBUG build */
#endif
  }
#if CI_CFG_FD_CACHING
  else if( ci_tcp_is_cached(ts) ) {
    ci_tcp_state_free_to_cache(netif, ts);
  }
#endif
  else {
    ci_tcp_wake_possibly_not_in_poll(netif, ts,
                                     CI_SB_FLAG_WAKE_RX|CI_SB_FLAG_WAKE_TX);
  }
}

/*!
 * Calculate Window Scale to be advertised in accordance with Rx buffer size.
 *
 * \todo May be it's better to keep better precision and use less window
 *       scale.
 */
unsigned int ci_tcp_wscl_by_buff(ci_netif *netif, ci_int32 rcv_buff)
{
  unsigned int wscl;

  ci_assert(rcv_buff > 0);
  for( wscl = 0;
       (wscl < NI_OPTS(netif).tcp_adv_win_scale_max) &&
         ((unsigned)(CI_CFG_TCP_MAX_WINDOW << wscl) < (unsigned int)rcv_buff);
       ++wscl );

  return wscl;
}


void ci_tcp_clear_sacks(ci_netif* ni, ci_tcp_state* ts)
{
  /* Clear all SACK marks (and associated pointers) in retransmit queue. */

  ci_ip_pkt_queue* rtq = &ts->retrans;
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p id = rtq->head;

  while( OO_PP_NOT_NULL(id) ) {
    pkt = PKT_CHK(ni, id);
    pkt->pf.tcp_tx.block_end = OO_PP_NULL;
    pkt->flags &=~ CI_PKT_FLAG_RTQ_SACKED;
    id = pkt->next;
  }

  ts->retrans_seq = tcp_snd_una(ts);
  ts->retrans_ptr = rtq->head;
}


void ci_tcp_retrans_init_ptrs(ci_netif* ni, ci_tcp_state* ts,
                              unsigned* recover_seq_out)
{
  ci_ip_pkt_queue* rtq = &ts->retrans;
  ci_ip_pkt_fmt* pkt;

  ci_assert(!ci_ip_queue_is_empty(rtq));
  pkt = PKT_CHK(ni, rtq->head);
  ts->retrans_ptr = rtq->head;
  ts->retrans_seq = pkt->pf.tcp_tx.start_seq;

  while( 1 ) {
    if( pkt->flags & CI_PKT_FLAG_RTQ_SACKED ) {
      /* Skip the SACK block. */
      *recover_seq_out = pkt->pf.tcp_tx.start_seq;
      pkt = PKT_CHK(ni, pkt->pf.tcp_tx.block_end);
    }

    if( OO_PP_IS_NULL(pkt->next) )  break;
    pkt = PKT_CHK(ni, pkt->next);
  }
}


void ci_tcp_get_fack(ci_netif* ni, ci_tcp_state* ts,
                     unsigned* fack_out, int* retrans_data_out)
{
  /* Determines the forward ACK and calculates the number of bytes of
  ** retransmission we've done since starting.
  **
  ** The forward ACK is the highest sequence number our peer has
  ** acknowledged using SACK info.
  */
  ci_ip_pkt_queue* rtq = &ts->retrans;
  ci_ip_pkt_fmt* block;
  ci_ip_pkt_fmt* end;
  int retrans_data = 0;
  unsigned fack;

#ifndef NDEBUG
  /* We have very occasionally seen the assert following this being hit.
   * However, we haven't tracked down the reason.  This hope is that by
   * adding a bit of logging here we'll have a bit more to go on if we hit
   * it again.
   */
  if( ci_ip_queue_is_empty(rtq) ) {
    ci_log("%s: "NTS_FMT, __FUNCTION__, NTS_PRI_ARGS(ni, ts));
    ci_tcp_state_dump_id(ni, ts->s.b.bufid);
    ci_tcp_state_dump_qs(ni, ts->s.b.bufid, 1);
  }
#endif

  ci_assert(! ci_ip_queue_is_empty(rtq));

  block = PKT_CHK(ni, rtq->head);
  fack = tcp_snd_una(ts);

  while( 1 ) {
    if( OO_PP_IS_NULL(block->pf.tcp_tx.block_end) ) {
      /* We're in the last (unsacked) block. */
      ci_assert(~block->flags & CI_PKT_FLAG_RTQ_SACKED);
      ci_assert(SEQ_LE(block->pf.tcp_tx.start_seq, fack));
      if( SEQ_LT(fack, ts->retrans_seq) )
        retrans_data += SEQ_SUB(ts->retrans_seq, fack);
      break;
    }
    end = PKT_CHK(ni, block->pf.tcp_tx.block_end);

    if( block->flags & CI_PKT_FLAG_RTQ_SACKED )
      fack = end->pf.tcp_tx.end_seq;
    else if( SEQ_LT(block->pf.tcp_tx.start_seq, ts->retrans_seq) ) {
      /* At least some of this block has been retransmitted. */
      if( SEQ_LE(end->pf.tcp_tx.end_seq, ts->retrans_seq) )
        /* This whole block has been retransmitted. */
        retrans_data += SEQ_SUB(end->pf.tcp_tx.end_seq,
                                block->pf.tcp_tx.start_seq);
      else
        retrans_data += SEQ_SUB(ts->retrans_seq, block->pf.tcp_tx.start_seq);
    }

    if( OO_PP_IS_NULL(end->next) )  break;
    block = PKT_CHK(ni, end->next);
  }

  *fack_out = fack;
  *retrans_data_out = retrans_data;
}


void ci_tcp_recovered(ci_netif* ni, ci_tcp_state* ts)
{
  ci_assert(ts->congstate != CI_TCP_CONG_OPEN &&
            ts->congstate != CI_TCP_CONG_NOTIFIED);

  if( ts->congstate == CI_TCP_CONG_FAST_RECOV ) {
    if( !(ts->tcpflags & CI_TCPT_FLAG_SACK) ) {
      /* RFC2581 says set cwnd to ssthresh on exit from fast recovery.
      ** NewReno (RFC2582) says min(ssthresh, FlightSize+MSS) or ssthresh.
      ** So I guess we could use either.
      ** chosen as the more aggresive and to allow ANVL tcp-advanced/4.17 to pass
      */
      ts->cwnd = CI_MAX(ts->ssthresh, NI_OPTS(ni).loss_min_cwnd);
      ts->cwnd = CI_MAX(ts->cwnd, NI_OPTS(ni).min_cwnd);
    }
  }
  /* Transition from RTO recovery to fast recovery if that's the right thing to
   * do. */
  else if( ts->congstate == CI_TCP_CONG_RTO_RECOV &&
           ci_tcp_maybe_enter_fast_recovery(ni, ts) ) {
    return;
  }

  /* If we get here, we've recovered. */

  ts->congstate = CI_TCP_CONG_OPEN;
  ts->cwnd_extra = 0;
  ts->dup_acks = 0;

  LOG_TL(log(LNT_FMT "RECOVERED "TCP_SND_FMT" cwnd=%d ssthresh=%d rto=%d",
             LNT_PRI_ARGS(ni, ts), TCP_SND_PRI_ARG(ts),
             ts->cwnd, ts->ssthresh, ts->rto));

  ci_assert(ts->cwnd >= tcp_eff_mss(ts));
}


static int ci_tcp_rx_pkt_coalesce(ci_netif* ni, ci_ip_pkt_queue* q,
                                  ci_ip_pkt_fmt* pkt, int* p_freed,
                                  ci_tcp_state* ts)
{
  /* Coalesces [pkt] with the one that follows it.  Requires that there is
  ** a packet that follows it.  Also requires that the sock-lock be held,
  ** and that ts->recv1_extract cannot point at the packet following the
  ** one given.
  **
  ** Returns true if there is further space available in [pkt].
  */
  ci_tcp_hdr* pkt_tcp = PKT_IPX_TCP_HDR(ipcache_af(&ts->s.pkt), pkt);
  char* pkt_payload = CI_TCP_PAYLOAD(pkt_tcp);
  oo_offbuf* pkt_buf = &pkt->buf;
  char* pkt_buf_end = (char*) pkt + CI_CFG_PKT_BUF_SIZE;

  ci_assert(oo_offbuf_ptr(pkt_buf) >= pkt_payload);
  PKT_TCP_RX_BUF_ASSERT_VALID(ni, pkt);

  /* Move contents of packet to the beginning of the buffer. */
  if( oo_offbuf_ptr(pkt_buf) != pkt_payload ) {
    int n = (int)(oo_offbuf_ptr(pkt_buf) - pkt_payload);
    memmove(pkt_payload, oo_offbuf_ptr(pkt_buf), oo_offbuf_left(pkt_buf));
    pkt_buf->off -= n;
    pkt_buf->end -= n;
    pkt_tcp->tcp_seq_be32 = CI_BSWAP_BE32(
                                CI_BSWAP_BE32(pkt_tcp->tcp_seq_be32) + n);
  }

  { /* Move data from next buffer into remaining space in this buffer. */
    ci_ip_pkt_fmt* next = PKT_CHK(ni, pkt->next);
    oo_offbuf* next_buf = &next->buf;
    int n, space = (int)(pkt_buf_end - oo_offbuf_end(pkt_buf));

    if( next->refcount != 1 || space == 0 )
      return 0;

    n = oo_offbuf_left(next_buf);
    n = CI_MIN(space, n);
    memcpy(oo_offbuf_end(pkt_buf), oo_offbuf_ptr(next_buf), n);

    pkt_buf->end += n;
    pkt->pf.tcp_rx.end_seq += n;
    oo_offbuf_advance(next_buf, n);

    if( oo_offbuf_is_empty(next_buf) ) {
      pkt->next = next->next;
      if( OO_PP_IS_NULL(pkt->next) ) {
        ci_assert(OO_PP_EQ(q->tail, OO_PKT_P(next)));
        q->tail = OO_PKT_P(pkt);
      }
      ci_assert( ! OO_PP_EQ(ts->recv1_extract, OO_PKT_P(next)) );
      ci_netif_pkt_release_rx_1ref(ni, next);
      (*p_freed)++;
      ci_tcp_rx_buf_adjust(ni, ts, q, -1);
      --q->num;
    }

    PKT_TCP_RX_BUF_ASSERT_VALID(ni, pkt);
    PKT_TCP_RX_BUF_ASSERT_VALID(ni, next);

    /* Return the amount of space left in [pkt]. */
    return (int)(pkt_buf_end - oo_offbuf_end(pkt_buf));
  }
}


static int ci_tcp_rx_coalesce_recv(ci_netif* ni, ci_tcp_state* ts,
                                    ci_ip_pkt_queue* q)
{
  ci_ip_pkt_fmt* pkt;
  int freed = 0;

  ci_assert(ci_netif_is_locked(ni));
  ci_assert(ci_sock_is_locked(ni, &ts->s.b));

  if( OO_PP_IS_NULL(q->head) )
    return 0;

  pkt = PKT_CHK(ni, q->head);
  if( pkt->refcount != 1 )
    return freed;

  do {
    while( OO_PP_NOT_NULL(pkt->next) )
      if( ! ci_tcp_rx_pkt_coalesce(ni, q, pkt, &freed, ts) )
        break;
    if( OO_PP_IS_NULL(pkt->next) )
      break;
    pkt = PKT_CHK(ni, pkt->next);
  } while(1);
  return freed;
}


void ci_tcp_drop_rob(ci_netif* ni, ci_tcp_state* ts)
{
  int i;
  ci_tcp_rx_queue_drop(ni, ts, &ts->rob);
  for( i = 0; i <= CI_TCP_SACK_MAX_BLOCKS; ++i )
    ts->last_sack[i] = OO_PP_NULL;
  ts->dsack_block = OO_PP_INVALID;
}


static inline void
ci_tcp_rcvbuf_unabuse_socklocked(ci_netif* ni, ci_tcp_state* ts)
{
  ci_tcp_rx_reap_rxq_bufs_socklocked(ni, ts);
  ci_tcp_rx_coalesce_recv(ni, ts, &ts->recv1);
  ci_tcp_rx_coalesce_recv(ni, ts, &ts->recv2);
}

int ci_tcp_try_to_free_pkts(ci_netif* ni, ci_tcp_state* ts,
                             int desperation)
{
  int freed;
  ci_assert(ts->s.b.state & CI_TCP_STATE_TCP_CONN);

  switch( desperation ) {
  case 0:
    if( ! ci_sock_trylock(ni, &ts->s.b) )  break;
    {
      freed = __ci_tcp_rx_buf_count(ni, ts);
      ci_tcp_rcvbuf_unabuse_socklocked(ni, ts);
      freed -= __ci_tcp_rx_buf_count(ni, ts);
      ci_assert_ge(freed, 0);
      ci_sock_unlock(ni, &ts->s.b);
      return freed;
    }
  case 1:
    {
      freed = ts->rob.num;
      ci_tcp_drop_rob(ni, ts);
      return freed;
    }
  default:
    break;
  }

  /* ?? TODO: could also coalesce the retrans queue. */
  return 0;
}

void
ci_tcp_rcvbuf_unabuse(ci_netif* ni, ci_tcp_state* ts, int sock_already_locked)
{
  int rob_dropped = 0;
#ifndef NDEBUG
  int pkts = __ci_tcp_rx_buf_count(ni, ts);
#endif

  CITP_STATS_NETIF_INC(ni, tcp_rcvbuf_abused);
  ci_assert(ci_tcp_rcvbuf_abused(ni, ts));
  ci_assert(ci_netif_is_locked(ni));

  /* Easy: reap receive queue. */
  ci_tcp_rx_reap_rxq_bufs(ni, ts);
  if( ! ci_tcp_rcvbuf_abused(ni, ts) )
    goto out;

  /* If reorder buffer is too large, just drop it.
   * Probably, we are under attack. */
  if( ts->rob.num > ts->rcv_window_max / ts->amss ) {
    CITP_STATS_NETIF_INC(ni, tcp_rcvbuf_abused_rob_guilty);
    ci_tcp_drop_rob(ni, ts);
    rob_dropped = 1;
    if( ! ci_tcp_rcvbuf_abused(ni, ts) )
      goto out;
  }

  /* Try to get socket lock so that we can coalesce the receive queue.
   * We mustn't block on the socket lock because it violates lock ordering.
   * And we mustn't drop the stack lock and then block on the socket lock
   * because this function may be called from ci_netif_poll().  It is
   * definitely a bad idea to drop the stack lock in the middle of the
   * poll.
   *
   * If we can't get the socket lock, then no luck - we'll unabuse the RXQ
   * later.
   *
   * If we already have the socket lock, then the caller is probably doing
   * something with the RXQ, and we should not touch it under the caller's
   * feet; see the call chain ci_tcp_recvmsg_get_nopeek() ->
   * ci_tcp_recvmsg_send_wnd_update() -> ci_tcp_send_ack() -> here.
   */
  if( ! sock_already_locked && ci_sock_trylock(ni, &ts->s.b)) {
    CITP_STATS_NETIF_INC(ni, tcp_rcvbuf_abused_recv_coalesced);
    ci_tcp_rcvbuf_unabuse_socklocked(ni, ts);
    ci_sock_unlock(ni, &ts->s.b);
    if( ! ci_tcp_rcvbuf_abused(ni, ts) )
      goto out;
  }

  /* Nothing helps.  Probably, we are under attack with a lot of small
   * non-continuous segments.  Drop reorder buffer. */
  if( !rob_dropped ) {
    CITP_STATS_NETIF_INC(ni, tcp_rcvbuf_abused_rob_desperate);
    ci_tcp_drop_rob(ni, ts);
  }

out:
#ifndef NDEBUG
  /* If the user have reduced SO_RCVBUF, but have not read all the previously
   * received data, we are still abused.  There is no reason for application
   * to do this, so we do not care that his function will be called
   * too frequently in that case but asserting would be too harsh. */
  {
    /* Print a message: LOG_U if still abused and LOG_TV overwise. */
    int print = 0;

    if( ci_tcp_rcvbuf_abused(ni, ts) ) {
      LOG_U(print = 1);
    }
    LOG_TV(print = 1);
    if( print )
      ci_log(LNT_FMT" %s: already_locked=%d from %d to %d limited by %d %s",
             LNT_PRI_ARGS(ni, ts), __func__,
             sock_already_locked, pkts,
             ts->recv1.num + ts->recv2.num + ts->rob.num,
             (ts->s.so.rcvbuf + ts->rcv_window_max) / ts->amss,
             ci_tcp_rcvbuf_abused(ni, ts) ? " ABUSED" : "");
  }
#endif

  if( ci_tcp_rcvbuf_abused(ni, ts) )
    CITP_STATS_NETIF_INC(ni, tcp_rcvbuf_abused_badly);
  return;
}


#if CI_CFG_LIMIT_AMSS || CI_CFG_LIMIT_SMSS
#include <ci/driver/efab/hardware.h>
ci_uint16 ci_tcp_limit_mss(ci_uint16 mss, ci_netif* ni, const char* caller)
{
  if( mss > ni->state->max_mss ) {
#if CI_CFG_STATS_NETIF
    if (1 == ++ni->state->stats.mss_limitations) {
      LOG_U(ci_log("%s: (%s) limiting mss %d => %d", __FUNCTION__, caller,
                   mss, ni->state->max_mss));
    }
#else
    ci_log("%s: (%s) limiting mss %d => %d", __FUNCTION__, caller,
           mss, ni->state->max_mss);
#endif
    mss = ni->state->max_mss;
  }
  return mss;
}
#endif


unsigned ci_tcp_amss(ci_netif* ni, const ci_tcp_socket_cmn* c,
                     ci_ip_cached_hdrs* ipcache, const char* caller)
{
  unsigned amss = ipcache->mtu - sizeof(ci_tcp_hdr) -
                  CI_IPX_HDR_SIZE(ipcache_af(ipcache));
  if( c->user_mss && c->user_mss < amss )
    amss = c->user_mss;
#if CI_CFG_LIMIT_AMSS
  amss = ci_tcp_limit_mss(amss, ni, caller);
#endif
  return amss;
}


void ci_tcp_perform_deferred_socket_work(ci_netif* ni, ci_tcp_state* ts)
{
  unsigned aflags, interesting;

  /* There are configurations where connection can be closed here. */
  ci_assert((ts->s.b.state & CI_TCP_STATE_TCP)
            && (ts->s.b.state != CI_TCP_LISTEN));

  interesting = CI_SOCK_AFLAG_NEED_ACK | CI_SOCK_AFLAG_NEED_SHUT_RD |
    CI_SOCK_AFLAG_NEED_SHUT_WR;

  /* Note: The order here is critical (see bug38511).  [s_aflags] must be
   * read before prequeue so that we only do SHUT_WR after we've handled
   * all prequeued data.
   */
  aflags = ts->s.s_aflags & interesting;
  ci_rmb();
  ci_tcp_sendmsg_enqueue_prequeue_deferred(ni, ts);

  if( aflags ) {
    ci_atomic32_and(&ts->s.s_aflags, ~aflags);
    if( aflags & CI_SOCK_AFLAG_NEED_ACK )
      ci_tcp_send_wnd_update(ni, ts, CI_FALSE);
    switch( aflags & (CI_SOCK_AFLAG_NEED_SHUT_RD|CI_SOCK_AFLAG_NEED_SHUT_WR) ) {
    case CI_SOCK_AFLAG_NEED_SHUT_RD | CI_SOCK_AFLAG_NEED_SHUT_WR:
      __ci_tcp_shutdown(ni, ts, SHUT_RDWR);
      break;
    case CI_SOCK_AFLAG_NEED_SHUT_RD:
      __ci_tcp_shutdown(ni, ts, SHUT_RD);
      break;
    case CI_SOCK_AFLAG_NEED_SHUT_WR:
      __ci_tcp_shutdown(ni, ts, SHUT_WR);
      break;
    default:
      break;
    }
  }
}


void ci_tcp_set_sndbuf(ci_netif* ni, ci_tcp_state* ts)
{
  int size = tcp_eff_mss(ts);
  ci_int32 old_so_sndbuf_pkts = ts->so_sndbuf_pkts;

  ci_assert(tcp_eff_mss(ts) != 0);

  /* Do not assume CI_CFG_PKT_BUF_SIZE size of packets - it breaks apps,
   * for example netperf -t TCP_STREAM -- -m 1024 -M 1024 .
   * So, just use tcp_eff_mss() but check it is not too small. */
  if( NI_OPTS(ni).tcp_sndbuf_mode )
    size = CI_MAX(size, CI_CFG_TCP_DEFAULT_MSS);

  ts->so_sndbuf_pkts = (ts->s.so.sndbuf + size - 1) / size;

  if( NI_OPTS(ni).tcp_sndbuf_mode ) {
    /* some packets for retransmit queue: */
    ts->so_sndbuf_pkts = ts->so_sndbuf_pkts * 3 / 2;
#if CI_CFG_TIMESTAMPING
    /* and some packets for tx timestamps: */
    if( ts->s.timestamping_flags & ONLOAD_SOF_TIMESTAMPING_STREAM )
      ts->so_sndbuf_pkts = ts->so_sndbuf_pkts * 3 / 2;
#endif
  }

  /* If we've tx space available and ( there were no space when we started
   * or we are racing with prequeue refill ), send a wake up. */
  if( ci_tcp_tx_advertise_space(ni, ts ) &&
      old_so_sndbuf_pkts < ts->so_sndbuf_pkts )
    ci_tcp_wake_possibly_not_in_poll(ni, ts, CI_SB_FLAG_WAKE_TX);
}



void ci_tcp_set_sndbuf_from_sndbuf_pkts(ci_netif* ni, ci_tcp_state* ts)
{
  /* Use sndbuf_pkts to set sndbuf (in bytes)
   * The calculations below should be the inverse of those used in
   * ci_tcp_set_sndbuf (which turns sndbuf in bytes into sndbuf_pkts) */

  int size = tcp_eff_mss(ts);

  ci_assert_nequal(tcp_eff_mss(ts), 0);

  size = CI_MAX(size, CI_CFG_TCP_DEFAULT_MSS);
  ts->s.so.sndbuf = ts->so_sndbuf_pkts * size;

  /* some packets for retransmit queue: */
  ts->s.so.sndbuf = (ts->s.so.sndbuf / 3) * 2;
#if CI_CFG_TIMESTAMPING
  /* and possible some packets for tx timestamps: */
  if( ts->s.timestamping_flags & ONLOAD_SOF_TIMESTAMPING_STREAM )
    ts->s.so.sndbuf = (ts->s.so.sndbuf / 3) * 2;
#endif
}


void ci_tcp_expand_sndbuf(ci_netif* ni, ci_tcp_state* ts)
{
  /* Autotune code
   * Overwrite existing value of ts->so_sndbuf_pkts with the autotuned version
   * Caller should check whether user/app has explictly set SO_SNDBUF */

  unsigned nr_segs;
  unsigned sndpkts;
  unsigned max_sndbuf_pkts =
    NI_OPTS(ni).max_tx_packets >> NI_OPTS(ni).tcp_sockbuf_max_fraction;

  /* Ensure at least 10 segments for initial connection window */
  nr_segs = CI_MAX(10, ts->cwnd / tcp_eff_mss(ts));
  /* Allow for Fast Recovery (RFC 5681 3.2)
   * Cubic needs 1.7 factor, rounded to 2 for extra cushion */
  sndpkts = 2 * nr_segs;

  if( ts->so_sndbuf_pkts < sndpkts )
    ts->so_sndbuf_pkts = CI_MIN(sndpkts, max_sndbuf_pkts);
}


bool ci_tcp_should_expand_sndbuf(ci_netif* ni, ci_tcp_state* ts)
{
  /* User specified sndbuf so we should not adjust it */
  if( ts->s.s_flags & CI_SOCK_FLAG_SET_SNDBUF )
    return false;

  /* Memory pressure - don't expand */
  if( ni->state->mem_pressure &
      (OO_MEM_PRESSURE_CRITICAL | OO_MEM_PRESSURE_LOW) )
    return false;

  /* Filled congestion window, so no point in expanding */
  if( ci_tcp_inflight(ts) >= ts->cwnd )
    return false;

  return true;
}


void ci_tcp_moderate_sndbuf(ci_netif* ni, ci_tcp_state* ts)
{
  const ci_int32 min_sndbuf_pkts = 2; /* ensure we always have some room */
  if( ! (ts->s.s_flags & CI_SOCK_FLAG_SET_SNDBUF) ) {
    ts->so_sndbuf_pkts = CI_MIN(ts->so_sndbuf_pkts,
				ci_tcp_sendq_n_pkts(ts) >> 1);
    ts->so_sndbuf_pkts = CI_MAX(ts->so_sndbuf_pkts, min_sndbuf_pkts);
  }
}


ci_int32 ci_tcp_max_rcvbuf(ci_netif* ni, ci_uint16 amss)
{
  /* estimate the largest rcvbuf we could allocate in
   * ci_tcp_rcvbuf_drs() */
  ci_uint64 res = ( (ci_uint64)NI_OPTS(ni).max_rx_packets >>
                    NI_OPTS(ni).tcp_sockbuf_max_fraction ) * amss;
  return CI_MIN(res, 0x7fffffff);
}


#if CI_CFG_FD_CACHING
int /*bool*/ ci_tcp_is_cacheable_active_wild_sharer(ci_sock_cmn* s)
{
  ci_tcp_state* ts;

  if( ! (s->b.state & CI_TCP_STATE_TCP) || s->b.state == CI_TCP_LISTEN )
    return 0;

  ts = SOCK_TO_TCP(s);
  if( ! (ts->tcpflags & CI_TCPT_FLAG_ACTIVE_WILD) )
    return 0;

  return 1;
}
#endif


#if CI_CFG_TCP_OFFLOAD_RECYCLER
/* This function is called at stream setup time (i.e. accept()/connect()) to
 * grab the plugin stream ID for the rest of the connection. Since the stream
 * ID represents state stored on the NIC, interface changes after that point
 * (e.g. bond failover, routing changes) can't work since we have no means to
 * to migrate that state. The intf_i should be the interface on which packets
 * are being received (often, but not always, the same as the sending
 * interface) since the plugin is operating on rx packets.
 *
 * The special-case when we move a TCP connection from one port on a NIC to a
 * different port on the same NIC can work, but doesn't need special handling
 * since both interfaces will work equally well for talking to the plugin. */
int ci_tcp_offload_get_stream_id(ci_netif* ni, ci_tcp_state* ts, int intf_i)
{
  ci_tcp_offload_get_stream_id_t get = {
    .ep_id = S_SP(ts),
    .intf_i = intf_i,
  };
  int rc;

  ci_assert(ci_tcp_is_pluginized(ts));
#ifdef __KERNEL__
  rc = efab_tcp_helper_tcp_offload_get_stream_id(netif2tcp_helper_resource(ni),
                                                 get.ep_id, get.intf_i,
                                                 &get.stream_id);
#else
  rc = oo_resource_op(ci_netif_get_driver_handle(ni),
                      OO_IOC_TCP_OFFLOAD_GET_STREAM_ID, &get);
#endif
  if( rc < 0 )
    return rc;
  ci_assert_le(get.stream_id, (__typeof__(ts->plugin_stream_id))~0);
  ts->plugin_stream_id = get.stream_id;
  return 0;
}
#endif

#endif
/*! \cidoxg_end */
