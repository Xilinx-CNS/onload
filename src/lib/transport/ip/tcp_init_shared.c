/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/************************************************************************** \
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Initialisation for TCP state.
**   \date  2003/06/03
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"


#if OO_DO_STACK_POLL

#define TCP_STATE_POISON 0xff


#define LPF "TCP "


static void ci_tcp_state_setup_timers(ci_netif* ni, ci_tcp_state* ts)
{
#define ci_tcp_setup_timer(name, callback, label)                      \
  do {                                                          \
    ci_ip_timer* t = &ts->name##_tid;                           \
    oo_p sp;                                                    \
    t->fn = callback;                                           \
    sp = TS_OFF(ni, ts);                                        \
    OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_tcp_state, name##_tid));   \
    ci_ip_timer_init(ni, &ts->name##_tid, sp, label);           \
  } while(0)

  ci_tcp_setup_timer(rto,      CI_IP_TIMER_TCP_RTO,    "rtot");
  ci_tcp_setup_timer(delack,   CI_IP_TIMER_TCP_DELACK, "dela");
  ci_tcp_setup_timer(zwin,     CI_IP_TIMER_TCP_ZWIN,   "zwin");
  ci_tcp_setup_timer(kalive,   CI_IP_TIMER_TCP_KALIVE, "kalv");
#if CI_CFG_TCP_SOCK_STATS
  ci_tcp_setup_timer(stats,    CI_IP_TIMER_TCP_STATS,  "stat");
#endif
  ci_tcp_setup_timer(cork,     CI_IP_TIMER_TCP_CORK,   "cork");

#undef ci_tcp_setup_timer
}


static void ci_tcp_state_connected_opts_init(ci_netif* netif, ci_tcp_state* ts)
{
  int i;

  ts->send_prequeue = CI_ILL_END;
  oo_atomic_set(&ts->send_prequeue_in, 0);
  ts->send_in = 0;
  ts->send_out = 0;

  /* Queues. */
  ci_ip_queue_init(&ts->recv1);
  ci_ip_queue_init(&ts->recv2);
  TS_QUEUE_RX_SET(ts, recv1);
  ts->recv1_extract = OO_PP_NULL;

  /* Re-order buffer length is limited by our window. */
  ci_ip_queue_init(&ts->rob);
  /* Send queue max length will be set in ci_tcp_set_eff_mss() using
   * so.sndbuf value. */
  ts->so_sndbuf_pkts = 0;
  ci_ip_queue_init(&ts->send);
  /* Retransmit queue is limited by peer window. */
  ci_ip_queue_init(&ts->retrans);
  for(i = 0; i <= CI_TCP_SACK_MAX_BLOCKS; i++ )
      ts->last_sack[i] = OO_PP_NULL;
  ts->dsack_block = OO_PP_INVALID;

  oo_p_dllink_init(netif,
                   oo_p_dllink_sb(netif, &ts->s.b, &ts->timeout_q_link));
}


static void ci_tcp_state_tcb_init_fixed(ci_netif* netif, ci_tcp_state* ts,
                                        int from_cache)
{
  /* SO_RCVLOWAT */
  ts->s.so.rcvlowat = 1;

  /* keep alive probes options */
  ts->c.ka_probe_th = NI_OPTS(netif).keepalive_probes;
  ts->c.t_ka_time = NI_CONF(netif).tconst_keepalive_time;
  ts->c.t_ka_time_in_secs = NI_OPTS(netif).keepalive_time / 1000;
  ts->c.t_ka_intvl = NI_CONF(netif).tconst_keepalive_intvl;
  ts->c.t_ka_intvl_in_secs = NI_OPTS(netif).keepalive_intvl / 1000;

  /* Initialise packet header and flow control state. */
  ci_ipx_hdr_init_fixed(&ts->s.pkt.ipx, AF_INET, IPPROTO_TCP,
                       CI_IP_DFLT_TTL, CI_IP_DFLT_TOS);

  ts->pmtus = OO_PP_NULL;

  ts->s.laddr = ip4_addr_any;
  TS_IPX_TCP(ts)->tcp_source_be16 = 0;
#if CI_CFG_FD_CACHING
  /* If this is being initialised from the cache we need to preserve the cache
   * details.
   */
  if( !from_cache ) {
    ts->cached_on_fd = -1;
    ts->cached_on_pid = -1;
  }
#endif

  /*
   * It's required to set protocol before ci_tcp_helper_sock_attach()
   * since it's used to determine TCP or UDP file operations should be
   * attached to the file descriptor in kernel.
   */
  ts->s.pkt.ipx.ip4.ip_ihl_version = CI_IP4_IHL_VERSION(sizeof(ci_ip4_hdr));
  ts->s.pkt.ipx.ip4.ip_protocol = IPPROTO_TCP;
  ts->s.pkt.ipx.ip4.ip_check_be16 = 0;
  ts->s.pkt.ipx.ip4.ip_id_be16 = 0;
  TS_IPX_TCP(ts)->tcp_check_be16 = 0;
}

void ci_tcp_state_tcb_reinit_minimal(ci_netif* netif, ci_tcp_state* ts)
{
  ts->congstate = CI_TCP_CONG_OPEN;
  ts->cwnd_extra = 0;
  ts->dup_acks = 0;
  ts->bytes_acked = 0;

  /* ts->eff_mss is not cleared as might be used without lock on send path */
  ts->ssthresh = 0;

  /* PAWs RFC1323, connections always start idle */
  ts->tspaws = ci_tcp_time_now(netif) - (NI_CONF(netif).tconst_paws_idle+1);
  ts->tsrecent = 0;

  /* delayed acknowledgements */
  ts->acks_pending = 0;

  /* Faststart */
  CITP_TCP_FASTSTART(ts->faststart_acks = 0);

  /* number of retransmissions */
  ts->retransmits = 0;

  /* TCP timers, RTO, SRTT, RTTVAR */
  ts->rto = NI_CONF(netif).tconst_rto_initial;
  ts->sa = 0; /* set to zero to provoke initialisation in ci_tcp_update_rtt */
  ts->sv = NI_CONF(netif).tconst_rto_initial; /* cwndrecover b4 rtt measured */

  ts->local_peer = OO_SP_NULL;
}

/* Reset state for a connection, used for shutdown following listen. */
static void ci_tcp_state_tcb_reinit(ci_netif* netif, ci_tcp_state* ts,
                                    int from_cache)
{
  ci_tcp_state_setup_timers(netif, ts);

#if CI_CFG_FD_CACHING
  if( !from_cache ) {
    oo_p sp;
    ts->cached_on_fd = -1;
    ts->cached_on_pid = -1;
    sp = TS_OFF(netif, ts);
    OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_tcp_state, epcache_link));
    ci_ni_dllist_link_init(netif, &ts->epcache_link, sp, "epch");
    ci_ni_dllist_self_link(netif, &ts->epcache_link);
    sp = TS_OFF(netif, ts);
    OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_tcp_state, epcache_fd_link));
    ci_ni_dllist_link_init(netif, &ts->epcache_fd_link, sp, "ecfd");
    ci_ni_dllist_self_link(netif, &ts->epcache_fd_link);
  }
#endif

  ci_tcp_fast_path_disable(ts);

  ts->tcpflags = NI_OPTS(netif).syn_opts;

  ts->outgoing_hdrs_len = sizeof(ci_ip4_hdr) + sizeof(ci_tcp_hdr);
  if( ts->tcpflags & CI_TCPT_FLAG_TSO )  ts->outgoing_hdrs_len += 12;
  ts->incoming_tcp_hdr_len = (ci_uint8)sizeof(ci_tcp_hdr);
  ts->c.tcp_defer_accept = OO_TCP_DEFER_ACCEPT_OFF;

  ci_tcp_state_connected_opts_init(netif, ts);

  /* Initialise packet header and flow control state. */
  TS_IPX_TCP(ts)->tcp_urg_ptr_be16 = 0;
  tcp_enq_nxt(ts) = tcp_snd_una(ts) = tcp_snd_nxt(ts) = tcp_snd_up(ts) = 0;
  ts->snd_delegated = 0;
  ts->snd_max = tcp_snd_nxt(ts) + 1;
  /* ?? snd_nxt, snd_max, should be set as SYN is sent */

  /* WSCL option variables RFC1323 */
  ts->snd_wscl = 0;
  CI_IP_SOCK_STATS_VAL_TXWSCL( ts, ts->snd_wscl);
  ts->rcv_wscl = 0;
  CI_IP_SOCK_STATS_VAL_RXWSCL( ts, ts->rcv_wscl);

  /* receive window */
  tcp_rcv_wnd_right_edge_sent(ts) = tcp_rcv_wnd_advertised(ts) = 0;
  ts->rcv_added = ts->rcv_delivered = tcp_rcv_nxt(ts) = 0;
  tcp_rcv_up(ts) = SEQ_SUB(tcp_rcv_nxt(ts), 1);

  /* setup header length */
  CI_TCP_HDR_SET_LEN(TS_IPX_TCP(ts),
                     (ts->outgoing_hdrs_len - sizeof(ci_ip4_hdr)));
  TS_IPX_TCP(ts)->tcp_flags = 0u;

#if CI_CFG_TCP_OFFLOAD_RECYCLER
  {
    oo_p sp = TS_OFF(netif, ts);
    OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_tcp_state, recycle_link));
    ci_ni_dllist_link_init(netif, &ts->recycle_link, sp, "eprc");
    ci_ni_dllist_self_link(netif, &ts->recycle_link);
  }
#endif

#if CI_CFG_BURST_CONTROL
  /* Burst control */
  ts->burst_window = 0;
#endif

  /* congestion window validation RFC2861 */
#if CI_CFG_CONGESTION_WINDOW_VALIDATION
  ts->t_last_sent = ci_tcp_time_now(netif);
  ts->t_last_full = ci_tcp_time_now(netif);
  ts->cwnd_used = 0;
#endif
  ts->t_last_recv_ack = ts->t_last_recv_payload = ts->t_prev_recv_payload = 
    ci_tcp_time_now(netif);
  ts->t_last_invalid_ack = ci_tcp_time_now(netif) -
                           NI_CONF(netif).tconst_invalid_ack_ratelimit;

  /* TCP_MAXSEG */
  ts->c.user_mss = 0;
  ts->amss = 0;
  ts->eff_mss = 0;

  ts->zwin_probes = 0;
  ts->zwin_acks = 0;
  ts->ka_probes = 0;

  ci_tcp_state_tcb_reinit_minimal(netif, ts);

#if CI_CFG_TCP_SOCK_STATS
  ci_tcp_stats_init(netif, ts);
#endif
  tcp_urg_data(ts) = 0;

  if (NI_OPTS(netif).tcp_force_nodelay == 1)
    ci_bit_set(&ts->s.s_aflags, CI_SOCK_AFLAG_NODELAY_BIT);

  ts->tmpl_head = OO_PP_NULL;


  memset(&ts->stats, 0, sizeof(ts->stats));

  ci_assert(OO_PP_IS_NULL(ts->pmtus));

  /* ts is in valid state now */
  ci_wmb();
  ts->s.b.state = CI_TCP_CLOSED;
}


void ci_tcp_state_init(ci_netif* netif, ci_tcp_state* ts, int from_cache)
{
  ci_assert(CI_PTR_OFFSET(&ts->s.pkt.ipx.ip4, 4) == 0);
  LOG_TV(ci_log(LPF "%s(): %d", __FUNCTION__, S_FMT(ts)));

#if defined(TCP_STATE_POISON) && !defined(NDEBUG)
  /* Can't poison a cached socket - there's some bits of state to preserve. */
  if( !from_cache ) {
    void *poison_start = &ts->s.b + 1;
    memset(poison_start, TCP_STATE_POISON,
           ((char*)(ts+1)) - (char*)poison_start);
  }
#endif

  /* Initialise the lower level. */
  ci_sock_cmn_init(netif, &ts->s, !from_cache);
#if CI_CFG_TIMESTAMPING
  ci_udp_recv_q_init(&ts->timestamp_q);
  ts->timestamp_q_pending = OO_PP_NULL;
#endif

  /* Initialise this level. */
  ci_tcp_state_tcb_init_fixed(netif, ts, from_cache);
  ci_tcp_state_tcb_reinit(netif, ts, from_cache);
}

void ci_tcp_state_reinit(ci_netif* netif, ci_tcp_state* ts)
{
  ci_assert(CI_PTR_OFFSET(&ts->s.pkt.ipx.ip4, 4) == 0);
  LOG_TV(ci_log(LPF "%s(): %d", __FUNCTION__, S_FMT(ts)));

  /* When we have not finished it, the state in not valid and should not be
   * used. */
  ts->s.b.state = CI_TCP_INVALID;
  ci_wmb();

  /* This functions leaves ts->s.addr_spc_id alone so that 
     the state can still be freed correctly. */

  /* Reinitialise the lower level. */
  ci_sock_cmn_reinit(netif, &ts->s);
#if CI_CFG_TIMESTAMPING
  ci_udp_recv_q_init(&ts->timestamp_q);
  ts->timestamp_q_pending = OO_PP_NULL;
#endif
  /* Reinitialise this level. */
  ci_tcp_state_tcb_reinit(netif, ts, 0);
}


#if ! defined(__KERNEL__) && CI_CFG_FD_CACHING
ci_tcp_state* ci_tcp_get_state_buf_from_cache(ci_netif *netif, int pid)
{
  ci_tcp_state *ts = NULL;

  if( ci_ni_dllist_not_empty(netif, &netif->state->active_cache.cache) ) {
    /* Take the first entry from the cache.  However, do not take it
     * if the ep's pid does not match current pid which may happen if
     * we are doing stack sharing. */
    ci_ni_dllist_link *link =
      ci_ni_dllist_head(netif, &netif->state->active_cache.cache);
    ts = CI_CONTAINER(ci_tcp_state, epcache_link, link);
    ci_assert(ts);

    if( S_TO_EPS(netif, ts)->fd != CI_FD_BAD &&
        ! (ts->s.b.sb_aflags & CI_SB_AFLAG_IN_CACHE_NO_FD) ) {
      /* We have an FD cached if the cached endpoint has been reused by
       * other process let's restore state */
      if( ts->cached_on_pid != pid ) {
        /* This context has its own FD
         * no race with kernel file close() expected.
         * sys_close() in other process will merely decrease sys file refcount
         * and in this process no other thread could use the fd.
         * note: concurrent accept and dup2 are not supported */
        CITP_STATS_NETIF(++netif->state->stats.active_attach_fd_reuse);
        ts->cached_on_fd = S_TO_EPS(netif,ts)->fd;
        ts->cached_on_pid = pid;
      }
      else {
        ci_assert_equal(ts->cached_on_fd, S_TO_EPS(netif, ts)->fd);
      }
    }
    /* The use-case we are targeting is that there is only one active
     * process using the stack with active cache.  Reuse an endpoint from
     * other process if it is marked with NO_FD flags (NO_FD is set when fd
     * is closed, for example when the process exits).
     *
     * The concurrent access to this list from different processes is
     * guarged by the stack lock, i.e. we guarantee a sort of correctness
     * for this unsupported use-case.
     *
     * Another use-case is: this process closed this fd via direct syscall,
     * which we were unable to intercept.  We restore the fd.
     */
    else if( ci_tcp_is_cached(ts) &&
             ( (ts->cached_on_pid == pid) ==
             (ts->s.b.sb_aflags & CI_SB_AFLAG_IN_CACHE_NO_FD) ) ) {
      ci_fd_t stack_fd = ci_netif_get_driver_handle(netif);
      /* Other process put the endpoint to cache, we need to create an FD
       * for this process to use */
      int rc = ci_tcp_helper_sock_attach_to_existing_file(stack_fd, S_SP(ts));
      if( rc < 0 ) {
        CITP_STATS_NETIF(++netif->state->stats.active_attach_fd_fail);
        return NULL;
      }
      CITP_STATS_NETIF(++netif->state->stats.active_attach_fd);
      /* Set state to indicate FD cache, note comments in previous clause */
      S_TO_EPS(netif, ts)->fd = rc;
      ci_atomic32_and(&ts->s.b.sb_aflags, ~CI_SB_AFLAG_IN_CACHE_NO_FD);
      ts->cached_on_fd = rc;
      ts->cached_on_pid = pid;
    }
    /* Sian says that cached_on_pid is not used by the following code, so
     * we can leave it as-is even if we steal a NO_FD endpoint from another
     * process. */

    ci_ni_dllist_pop(netif, &netif->state->active_cache.cache);
    ci_ni_dllist_self_link(netif, &ts->epcache_link);
    ci_ni_dllist_remove_safe(netif, &ts->epcache_fd_link);
    CITP_STATS_NETIF(++netif->state->stats.activecache_hit);
    ci_atomic32_inc((volatile ci_uint32*)CI_NETIF_PTR(netif,
                    netif->state->active_cache.avail_stack));
/* FIXME SCJ assert on number in cache (task54537) */

    LOG_EP(ci_log("Taking cached socket "NSS_FMT" fd %d off cached list",
                  NSS_PRI_ARGS(netif, &ts->s), ts->cached_on_fd));

    ci_tcp_state_init(netif, ts, 1);

    /* Shouldn't have touched these bits of state */
    ci_assert(!(ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN));
    ci_assert(ci_tcp_is_cached(ts));

    CITP_STATS_NETIF(++netif->state->stats.sockcache_hit);
  }
  return ts;
}
#endif


ci_tcp_state* ci_tcp_get_state_buf(ci_netif* netif)
{
  citp_waitable_obj* wo;

  ci_assert(netif);

  wo = citp_waitable_obj_alloc(netif);
  if( ! wo )  {
    LOG_TV(ci_log("%s: [%d] out of socket buffers",__FUNCTION__,NI_ID(netif)));
    return NULL;
  }

  ci_tcp_state_init(netif, &wo->tcp, 0);
  return &wo->tcp;
}
#endif

void ci_ni_aux_more_bufs(ci_netif* ni)
{
  citp_waitable_obj* wo = citp_waitable_obj_alloc(ni);
  ci_ni_aux_mem* aux;
  oo_p sp;
  int i;
  struct oo_p_dllink_state free_aux_mem =
                           oo_p_dllink_ptr(ni, &ni->state->free_aux_mem);

  if( wo == NULL )
    return;

  wo->header.state = CI_TCP_STATE_AUXBUF;
  sp = oo_sockp_to_statep(ni, W_SP(&wo->waitable));
  ci_assert_equal(CI_MEMBER_OFFSET(ci_ni_aux_mem, link), 0);
  OO_P_ADD(sp, CI_AUX_HEADER_SIZE);

  for( aux = (void *)((ci_uintptr_t)wo + CI_AUX_HEADER_SIZE), i = 1;
       (ci_uintptr_t)(wo+1) >= (ci_uintptr_t)(aux+1);
       aux++, i++ ) {
    oo_p_dllink_add(ni, free_aux_mem, oo_p_dllink_statep(ni, sp));
    /* We could call ci_ni_aux_free() here, but we already have correct sp
     * to use. */
    ni->state->n_free_aux_bufs++;
    OO_P_ADD(sp, CI_AUX_MEM_SIZE);
  }
}

/*! \cidoxg_end */
