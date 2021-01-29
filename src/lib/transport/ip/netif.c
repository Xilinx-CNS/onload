/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: djr
**     Started: 2003/08/18
** Description: General network interface routines.
** </L5_PRIVATE>
\**************************************************************************/


#include "ip_internal.h"
#include <ci/tools/utils.h>
#include <onload/cplane_ops.h>

#define LPF "NETIF "

#if CI_CFG_DETAILED_CHECKS
char* CI_NETIF_PTR(ci_netif* ni, oo_p off)
{
  ASSERT_VALID_NETIF_ADDR(ni, off, 1);
  return __CI_NETIF_PTR(ni, off);
}
#endif


#if OO_DO_STACK_POLL
/*--------------------------------------------------------------------
 *
 * Common routines for timeout lists
 *
 *--------------------------------------------------------------------*/

/*! set or clear global netif "timeout state" timer */
ci_inline void ci_netif_timeout_set_timer(ci_netif* ni, ci_iptime_t prev_time)
{
  ci_iptime_t time = 0; /* shut up gcc */
  int i, found = 0;

  for( i = 0; i < OO_TIMEOUT_Q_MAX; i++ ) {
    ci_tcp_state* ts;
    if( ci_ni_dllist_is_empty(ni, &ni->state->timeout_q[i]) )
      continue;
    ts = TCP_STATE_FROM_LINK(ci_ni_dllist_head(ni, &ni->state->timeout_q[i]));
    if( TIME_LE(ts->t_last_sent, prev_time) )
      return;
    if( !found || TIME_LT(ts->t_last_sent, time) ) {
      found = 1;
      time = ts->t_last_sent;
    }
  }
  /* We can be called both from timer handler (when the timer is not
   * running) and from RX handler (the timer is running).
   * Take care about all cases. */
  if( ! found )
    ci_ip_timer_clear(ni, &ni->state->timeout_tid);
  else if( ci_ip_timer_pending(ni, &ni->state->timeout_tid) )
    ci_ip_timer_modify(ni, &ni->state->timeout_tid, time);
  else
    ci_ip_timer_set(ni, &ni->state->timeout_tid, time);
}


/*! add a state to the timeout list */
ci_inline void ci_netif_timeout_add(ci_netif* ni, ci_tcp_state* ts, int idx)
{
  int is_first;
  ci_ni_dllist_t* my_list = &ni->state->timeout_q[idx];
  ci_ni_dllist_t* other_list;
  ci_tcp_state* other_ts;

  ci_assert( ci_ni_dllist_is_free(&ts->timeout_q_link) );

  is_first = ci_ni_dllist_is_empty(ni, my_list);
  ci_ni_dllist_push_tail(ni, my_list, &ts->timeout_q_link);

  /* Set up the timer */
  if( ! is_first )
    return;

  other_list = &ni->state->timeout_q[1-idx];
  if( ci_ni_dllist_is_empty(ni, other_list) ) {
    ci_ip_timer_set(ni, &ni->state->timeout_tid, ts->t_last_sent);
    return;
  }

  other_ts = TCP_STATE_FROM_LINK(ci_ni_dllist_head(ni, other_list));
  if( TIME_LT(ts->t_last_sent, other_ts->t_last_sent) )
    ci_ip_timer_modify(ni, &ni->state->timeout_tid, ts->t_last_sent);
  else
    ci_ip_timer_modify(ni, &ni->state->timeout_tid, other_ts->t_last_sent);
}

/*! remove a state from the timeout list */
void ci_netif_timeout_remove(ci_netif* ni, ci_tcp_state* ts)
{
  int is_first, idx;

  ci_assert( (ts->s.b.state == CI_TCP_TIME_WAIT) ||
              ci_tcp_is_timeout_orphan(ts));
  ci_assert( !ci_ni_dllist_is_free(&ts->timeout_q_link) );

  if( ts->s.b.state == CI_TCP_TIME_WAIT )
    idx = OO_TIMEOUT_Q_TIMEWAIT;
  else
    idx = OO_TIMEOUT_Q_FINWAIT;
  is_first = OO_P_EQ( ci_ni_dllist_link_addr(ni, &ts->timeout_q_link),
               ci_ni_dllist_link_addr(ni, ci_ni_dllist_head(ni,
                                                &ni->state->timeout_q[idx])) );

  /* remove from the list */
  ci_ni_dllist_remove(ni, &ts->timeout_q_link);
  ci_ni_dllist_mark_free(&ts->timeout_q_link);

  /* if needed re-set or clear timer */
  if( ! is_first )
    return;

  ci_netif_timeout_set_timer(ni, ts->t_last_sent);
}

/*! timeout a state from the list */
void ci_netif_timeout_leave(ci_netif* netif, ci_tcp_state* ts)
{
  ci_assert(netif);
  ci_assert(ts);
  ci_assert( (ts->s.b.state == CI_TCP_TIME_WAIT) ||
              ci_tcp_is_timeout_orphan(ts) );

#ifndef NDEBUG
  if (ts->s.b.state == CI_TCP_TIME_WAIT)
      LOG_TC(log(LPF "%d TIME_WAIT->CLOSED (2MSL expired)", S_FMT(ts)));
  else
      LOG_TC(log(LPF "%d Droping ORPHANed %s", S_FMT(ts), state_str(ts)));
#endif

  /* drop will call ci_netif_timeout_remove;
   * See bug 10638 for details about CI_SHUT_RD */
  ci_tcp_drop(netif, ts, 0);
}

/*! called to try and free up a connection from
    this list when we are low on tcp states */
/* todo: pass listening socket as a parameter
 * if we are satisfyed by a cached ep */
void ci_netif_timeout_reap(ci_netif* ni)
{
  int i;
  int reaped = 0;

  ci_assert(ni);
  ci_assert(ci_netif_is_locked(ni));
  ci_assert(OO_SP_IS_NULL(ni->state->free_eps_head));

  for( i = 0; i < OO_TIMEOUT_Q_MAX; i++ ) {
    ci_ni_dllist_t* list = &ni->state->timeout_q[i];
    ci_ni_dllist_link* l;
    oo_p next;

    for( l = ci_ni_dllist_start(ni, list); l != ci_ni_dllist_end(ni, list);
         l = (void*) CI_NETIF_PTR(ni, next) ) {
      ci_tcp_state* ts = TCP_STATE_FROM_LINK(l);
      next = l->next;

#if CI_CFG_FD_CACHING
      if( ts->s.b.sb_aflags & (CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_IN_CACHE) ) {
#else
      if( ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN ) {
#endif
        LOG_NV(log(LPF "Reaping %d from %s", S_FMT(ts), state_str(ts)));
        ci_netif_timeout_leave(ni, ts);
        CITP_STATS_NETIF(++ni->state->stats.timewait_reap);
        if( OO_SP_NOT_NULL(ni->state->free_eps_head) )
          return;

        /* We've probably reaped a cached connection,
         * but in some cases it can be used by the caller. */
        reaped = 1;
      }
    }
  }

  if( ! reaped )
    LOG_U(log(LPF "No more connections to reap from TIME_WAIT/FIN_WAIT2"));
}

/*! this is the timeout timer callback function */
void
ci_netif_timeout_state(ci_netif* ni)
{
  int i;

  LOG_NV(log(LPF "timeout state timer, now=0x%x", ci_ip_time_now(ni)));

  /* check last active state of each connection in TIME_WAIT */

  for( i = 0; i < OO_TIMEOUT_Q_MAX; i++ ) {
    ci_ni_dllist_link* lnk;
    ci_tcp_state* ts;
    ci_ni_dllist_t* list = &ni->state->timeout_q[i];

    while( ci_ni_dllist_not_empty(ni, list) ) {
      lnk = ci_ni_dllist_head(ni, list);
      ts = TCP_STATE_FROM_LINK(lnk);
      ci_assert( (ts->s.b.state == CI_TCP_TIME_WAIT) ||
                  ci_tcp_is_timeout_orphan(ts) );

      if( TIME_GT(ts->t_last_sent, ci_ip_time_now(ni)) )
        break; /* break from the inner loop */

      /* ci_netif_timeout_leave() calls ci_tcp_drop() calls
       * ci_netif_timeout_remove() which re-enables timer */
      ci_netif_timeout_leave(ni, ts);
    }
  }
}

/*--------------------------------------------------------------------
 *
 * TIME_WAIT handling
 *
 *--------------------------------------------------------------------*/

/* restart a timewait state
 * - remove from timeout list
 * - store time to leave TIMEOUT state
 * - add back onto timeout list
 */

void ci_netif_timeout_restart(ci_netif *ni, ci_tcp_state *ts)
{
  int is_tw = (ts->s.b.state == CI_TCP_TIME_WAIT);
  ci_assert(ts);
  ci_assert( is_tw || ci_tcp_is_timeout_orphan(ts));

  /* take it off the list */
  ci_netif_timeout_remove(ni, ts);
  /* store time to leave TIMEWAIT state */
  ts->t_last_sent = ci_ip_time_now(ni) +
      ( is_tw ?
        NI_CONF(ni).tconst_2msl_time : NI_CONF(ni).tconst_fin_timeout );
  /* add to list */
  ci_netif_timeout_add(
                ni, ts,
                is_tw ?  OO_TIMEOUT_Q_TIMEWAIT : OO_TIMEOUT_Q_FINWAIT);
}


/*
** - add a connection to the timewait queue,
** - stop its timers
*/
void ci_netif_timewait_enter(ci_netif* ni, ci_tcp_state* ts)
{
  ci_assert(ts);

  /* If we're entering time-wait, then our FIN has been acked, so send-q
   * and retrans-q should be empty.  We've received and processed an
   * incoming FIN, so reorder buffer has already been purged by
   * ci_tcp_rx_process_fin().
   */
  ci_assert(ci_tcp_sendq_is_empty(ts));
  ci_assert(ci_ip_queue_is_empty(&ts->retrans));
  ci_assert(ci_ip_queue_is_empty(&ts->rob));

  /* called before the state is changed to TIME_WAIT */
  ci_assert(ts->s.b.state != CI_TCP_TIME_WAIT);
  /* if already in the timeout list */
  if ( ci_tcp_is_timeout_orphan(ts) ) {
    ci_netif_timeout_remove(ni, ts);
  }
  ci_assert( ci_ni_dllist_is_free(&ts->timeout_q_link) );

  ci_tcp_stop_timers(ni, ts);

  /* store time to leave TIMEWAIT state */
  ts->t_last_sent = ci_ip_time_now(ni) + NI_CONF(ni).tconst_2msl_time;
  /* add to list */
  ci_netif_timeout_add(ni, ts, OO_TIMEOUT_Q_TIMEWAIT);
}


int ci_netif_timewait_try_to_free_filter(ci_netif* ni)
{
  int i;
  int found = 0;

  ci_assert(ci_netif_is_locked(ni));

  for( i = 0; i < OO_TIMEOUT_Q_MAX; i++ ) {
    ci_ni_dllist_t* list = &ni->state->timeout_q[i];
    ci_ni_dllist_link* l;
    oo_p next;

    for( l = ci_ni_dllist_start(ni, list); l != ci_ni_dllist_end(ni, list);
         l = (void*) CI_NETIF_PTR(ni, next) ) {
      ci_tcp_state* ts = TCP_STATE_FROM_LINK(l);
      next = l->next;

      if( ts->s.s_flags & CI_SOCK_FLAG_FILTER ) {
        /* No cached sockets here: orphaned or timewait only.
         * They really free the hw filter when we drop them. */
        ci_assert( (ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN) ||
                   ts->s.b.state == CI_TCP_TIME_WAIT );

        ci_netif_timeout_leave(ni, ts);
        CITP_STATS_NETIF(++ni->state->stats.timewait_reap_filter);

        /* With EF10, there is no guarantee that the filter we've freed can
         * be reused for the filter parameters needed now.  Moreover, in most
         * cases it can't.
         * We reap ALL time-wait sockets in hope they'll help us.
         * Reaping finwait&friends is a more sensitive action - so we reap
         * one and go away. */
        if( i == OO_TIMEOUT_Q_FINWAIT )
          return 1;
        found = 1;
      }
    }
    if( found )
      return 1;
  }
  return 0;
}


/*--------------------------------------------------------------------
 *
 * FIN_WAIT2 handling
 *
 *--------------------------------------------------------------------*/

/*! add a state to the fin timeout list */
void ci_netif_fin_timeout_enter(ci_netif* ni, ci_tcp_state* ts)
{
  /* check endpoint is an orphan */
#if CI_CFG_FD_CACHING
  ci_assert(ts->s.b.sb_aflags & (CI_SB_AFLAG_ORPHAN|CI_SB_AFLAG_IN_CACHE));
#else
  ci_assert(ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN);
#endif
  /* check state is correct */
  ci_assert(ts->s.b.state & CI_TCP_STATE_TIMEOUT_ORPHAN);

  /* It's possible to come down this path twice in the caching case.  We can
   * queue a fin-timeout when the user socket is closed and the socket enters
   * the cache.  However, it if becomes a true orphan while still cached we
   * will come this way again, so need to avoid re-queueing.  At the point it
   * may have been removed from the cache (for example if clearing the cache
   * queue on listener shutdown), so we've lost it's history, so can't check
   * unfortunately.
   */
#if CI_CFG_FD_CACHING
  if( ci_ni_dllist_is_free(&ts->timeout_q_link) ) {
#else
  ci_assert(ci_ni_dllist_is_free(&ts->timeout_q_link));
#endif
    LOG_TC(log(LPF "%s: %d %s", __FUNCTION__, S_FMT(ts), state_str(ts)));
    /* store time to leave FIN_WAIT2 state */
    ts->t_last_sent = ci_ip_time_now(ni) + NI_CONF(ni).tconst_fin_timeout;
    ci_netif_timeout_add(ni, ts, OO_TIMEOUT_Q_FINWAIT);
#if CI_CFG_FD_CACHING
  }
#endif
}


static int ci_netif_try_to_reap_udp_recv_q(ci_netif* ni,
                                           ci_udp_recv_q* recv_q, 
                                           int* add_to_reap_list)
{
  int freed_n;
  ci_uint32 reaped_b4 = recv_q->pkts_reaped;
  ci_udp_recv_q_reap(ni, recv_q);
  freed_n = recv_q->pkts_reaped - reaped_b4;
  if( recv_q->pkts_reaped != recv_q->pkts_added )
    ++(*add_to_reap_list);
  return freed_n;
}


void ci_netif_try_to_reap(ci_netif* ni, int stop_once_freed_n)
{
  /* Look for packet buffers that can be reaped. */

  ci_ni_dllist_link* lnk;
  ci_ni_dllist_link* last;
  citp_waitable_obj* wo;
  int freed_n = 0;
  int add_to_reap_list;
  int reap_harder = ni->packets->sets_n == ni->packets->sets_max
      || ni->state->mem_pressure;

  if( ci_ni_dllist_is_empty(ni, &ni->state->reap_list) )
    return;

  /* Caller has told us how many packet buffers it needs.  But really we
   * should reap more -- otherwise we can get into a steady state of not
   * having enough free buffers around.
   */
  stop_once_freed_n <<= 1u;

  lnk = ci_ni_dllist_start(ni, &ni->state->reap_list);
  last = ci_ni_dllist_start_last(ni, &ni->state->reap_list);

  do {
    add_to_reap_list = 0;

    wo = CI_CONTAINER(citp_waitable_obj, sock.reap_link, lnk);
    lnk = (ci_ni_dllist_link*) CI_NETIF_PTR(ni, lnk->next);
    ci_ni_dllist_remove_safe(ni, &wo->sock.reap_link);

    if( wo->waitable.state & CI_TCP_STATE_TCP_CONN ) {
      ci_tcp_state* ts = &wo->tcp;
      ci_int32 q_num_b4 = ts->recv1.num;
      ci_tcp_rx_reap_rxq_bufs(ni, ts);

      freed_n += q_num_b4 - ts->recv1.num;
#if CI_CFG_TIMESTAMPING
      freed_n += ci_netif_try_to_reap_udp_recv_q(ni, &ts->timestamp_q,
                                                 &add_to_reap_list);
#endif

      /* Try to reap the last packet */
      if( reap_harder && ts->recv1.num == 1 &&
          ci_sock_trylock(ni, &ts->s.b) ) {
        q_num_b4 = ts->recv1.num;
        ci_tcp_rx_reap_rxq_bufs_socklocked(ni, ts);
        freed_n += q_num_b4 - ts->recv1.num;
        ci_sock_unlock(ni, &ts->s.b);
      }
      if( ts->recv1.num > 1 || add_to_reap_list)
        ci_ni_dllist_put(ni, &ni->state->reap_list, &ts->s.reap_link);
    }
    else if( wo->waitable.state == CI_TCP_STATE_UDP ) {
      ci_udp_state* us = &wo->udp;
      freed_n += ci_netif_try_to_reap_udp_recv_q(ni, &us->recv_q,
                                                 &add_to_reap_list);
#if CI_CFG_TIMESTAMPING
      freed_n += ci_netif_try_to_reap_udp_recv_q(ni, &us->timestamp_q,
                                                 &add_to_reap_list);
#endif

      if( add_to_reap_list )
        ci_ni_dllist_put(ni, &ni->state->reap_list, &us->s.reap_link);
    }
  } while( freed_n < stop_once_freed_n && &wo->sock.reap_link != last );

  if( freed_n < (stop_once_freed_n >> 1) ) {
    /* We do not get here from ci_netif_pkt_alloc_slow,
     * because it uses stop_once_freed_n=1. */
    freed_n += ci_netif_pkt_try_to_free(ni, 0, stop_once_freed_n - freed_n);
    if( freed_n < (stop_once_freed_n >> 1) && reap_harder ) {
      freed_n += ci_netif_pkt_try_to_free(ni, 1,
                                          stop_once_freed_n - freed_n);
    }
  }

  CITP_STATS_NETIF_ADD(ni, pkts_reaped, freed_n);
}


void ci_netif_rxq_low_on_recv(ci_netif* ni, ci_sock_cmn* s,
                              int bytes_freed)
{
  /* Called by the recv() paths when [ni->state->rxq_low] is non-zero.  It
   * is moderately hard to track exactly how many packet buffers were freed
   * by the recv() call, so we approximate by assuming approx standard-mtu
   * sized packets.
   *
   * [bytes_freed] may be negative or zero.  This is just to save the
   * caller a little work.
   */
  int intf_i;
  if( bytes_freed <= 0 ||
      (ni->state->rxq_low -= (bytes_freed / 1500 + 1)) > 0 )
    return;
  if( ! ci_netif_trylock(ni) ) {
    /* TODO: Probably better to defer the work of refilling to lock holder. */
    ni->state->rxq_low = 1;
    return;
  }
  /* Multiple threads can do the above decrement concurrently, so [rxq_low]
   * can go negative.  If it does, we want to reset to zero to avoid
   * hitting this path constantly.
   */
  ni->state->rxq_low = 0;

  /* We've just received from [s], so very likely to have buffers 'freed'
   * and ripe for reaping.  ci_netif_rx_post() will also try to reap more
   * buffers from other sockets if necessary.
   */
  if( s->b.state == CI_TCP_STATE_UDP ) {
    ci_udp_recv_q_reap(ni, &SOCK_TO_UDP(s)->recv_q);
#if CI_CFG_TIMESTAMPING
    ci_udp_recv_q_reap(ni, &SOCK_TO_UDP(s)->timestamp_q);
#endif
  }
  else if( s->b.state & CI_TCP_STATE_TCP_CONN ) {
    ci_tcp_rx_reap_rxq_bufs(ni, SOCK_TO_TCP(s));
#if CI_CFG_TIMESTAMPING
    ci_udp_recv_q_reap(ni, &SOCK_TO_TCP(s)->timestamp_q);
#endif
  }

  if( ni->state->mem_pressure & OO_MEM_PRESSURE_CRITICAL )
    /* See if we've freed enough to exit memory pressure.  Done here so
     * we'll fill the rings properly below if we succeed in exiting.
     */
    if( ci_netif_mem_pressure_try_exit(ni) )
      CITP_STATS_NETIF_INC(ni, memory_pressure_exit_recv);

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    ci_netif_rx_post_all_batch(ni, intf_i);
  CITP_STATS_NETIF_INC(ni, rx_refill_recv);
  ci_netif_unlock(ni);
}
#endif /* OO_DO_STACK_POLL */


void ci_netif_mem_pressure_pkt_pool_fill(ci_netif* ni)
{
  ci_ip_pkt_fmt* pkt;
  int intf_i, n = 0;
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    n += (2*CI_CFG_RX_DESC_BATCH);
  while( ni->state->mem_pressure_pkt_pool_n < n &&
         (pkt = ci_netif_pkt_alloc(ni, 0)) != NULL ) {
    pkt->flags |= CI_PKT_FLAG_RX;
    ++ni->state->n_rx_pkts;
    ++ni->state->mem_pressure_pkt_pool_n;
    pkt->refcount = 0;
    pkt->next = ni->state->mem_pressure_pkt_pool;
    ni->state->mem_pressure_pkt_pool = OO_PKT_P(pkt);
  }
}


#if OO_DO_STACK_POLL
static void ci_netif_mem_pressure_pkt_pool_use(ci_netif* ni)
{
  /* Empty the special [mem_pressure_pkt_pool] into the free pool. */
  ci_ip_pkt_fmt* pkt;
#ifdef __KERNEL__
  int is_locked = 1;
#endif
  while( ! OO_PP_IS_NULL(ni->state->mem_pressure_pkt_pool) ) {
    pkt = PKT(ni, ni->state->mem_pressure_pkt_pool);
    ni->state->mem_pressure_pkt_pool = pkt->next;
    --ni->state->mem_pressure_pkt_pool_n;
    ci_assert_equal(pkt->refcount, 0);
    ci_assert(pkt->flags & CI_PKT_FLAG_RX);
    ci_netif_pkt_free(ni, pkt CI_KERNEL_ARG(&is_locked));
  }
}


static void ci_netif_mem_pressure_enter_critical(ci_netif* ni, int intf_i)
{
  if( ni->state->mem_pressure & OO_MEM_PRESSURE_CRITICAL )
    return;

  CITP_STATS_NETIF_INC(ni, memory_pressure_enter);
  ni->state->mem_pressure |= OO_MEM_PRESSURE_CRITICAL;
  ni->state->rxq_limit = 2*CI_CFG_RX_DESC_BATCH;
  ci_netif_mem_pressure_pkt_pool_use(ni);
  ci_netif_rx_post_all_batch(ni, intf_i);
}


static void ci_netif_mem_pressure_exit_critical(ci_netif* ni)
{
  ci_assert(OO_PP_IS_NULL(ni->state->mem_pressure_pkt_pool));
  ci_netif_mem_pressure_pkt_pool_fill(ni);
  ni->state->rxq_limit = NI_OPTS(ni).rxq_limit;
  ni->state->mem_pressure &= ~OO_MEM_PRESSURE_CRITICAL;
}


int ci_netif_mem_pressure_try_exit(ci_netif* ni)
{
  /* Exit memory pressure only when there are enough packet buffers free
   * (and available to RX path) to be able to fill all of the RX rings.
   *
   * Returns true if we do exit critical memory pressure.
   */
  int intf_i, pkts_needed = 0;
  ci_ip_pkt_fmt* pkt;

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    ef_vi* vi = ci_netif_vi(ni, intf_i);
    pkts_needed += NI_OPTS(ni).rxq_limit - ef_vi_receive_fill_level(vi);
  }

  if( NI_OPTS(ni).max_rx_packets - ni->state->n_rx_pkts < pkts_needed ||
      ni->packets->n_free < pkts_needed ) {
    /* TODO: May not be necessary in future, as rxq_low should be set, and
     * should provoke the recv() path to free packet bufs.  For now this is
     * needed though.
     */
    ci_netif_try_to_reap(ni, pkts_needed);

    if( NI_OPTS(ni).max_rx_packets - ni->state->n_rx_pkts < pkts_needed )
      return 0;

    /* The RX packet limit is okay, but do we have enough free buffers?
     * Take from async pool if not.
     *
     * TODO: Be more efficient here by grabbing the whole pool, taking what
     * we need, and put back.
     */
    while( ni->packets->n_free < pkts_needed ) {
      if( (pkt = ci_netif_pkt_alloc_nonb(ni)) == NULL )
        return 0;
      --ni->state->n_async_pkts;
      CITP_STATS_NETIF_INC(ni, pkt_nonb_steal);
      pkt->flags &= ~CI_PKT_FLAG_NONB_POOL;
      ci_netif_pkt_release_1ref(ni, pkt);
    }
  }

  ci_netif_mem_pressure_exit_critical(ni);
  return 1;
}
#endif

/*--------------------------------------------------------------------
 *
 *
 *--------------------------------------------------------------------*/

static int __ci_netif_rx_post(ci_netif* ni, ef_vi* vi, int intf_i,
                               int bufset_id, int max)
{
  ci_ip_pkt_fmt* pkt;
  int i;
  int posted = 0;
  oo_pktbuf_set* bufset = &ni->packets->set[bufset_id];

  ci_assert_ge(max, CI_CFG_RX_DESC_BATCH);
  ci_assert_ge(bufset->n_free, max);

  do {
    for( i = 0; i < CI_CFG_RX_DESC_BATCH; ++i ) {
      /* We know we have free pkts, so this is faster than calling
      ** ci_netif_pkt_alloc().  Nasty, but this is really performance
      ** critical.
      */
      ci_assert(OO_PP_NOT_NULL(bufset->free));
      pkt = PKT(ni, bufset->free);
      ci_assert(OO_PP_EQ(bufset->free, OO_PKT_P(pkt)));
      bufset->free = pkt->next;
      pkt->refcount = 1;
      pkt->flags |= CI_PKT_FLAG_RX;
      pkt->intf_i = intf_i;
      pkt->pkt_start_off = ef_vi_receive_prefix_len(vi);
      ci_netif_poison_rx_pkt(pkt);
      ef_vi_receive_init(vi, pkt_dma_addr_bufset(ni, pkt, intf_i, bufset),
                         OO_PKT_ID(pkt));
#ifdef __powerpc__
      {
        /* Flush RX buffer from cache.  This saves significant latency when
         * data is DMAed into the buffer (on ppc at least).
         *
         * TODO: I think the reason we're seeing dirty buffers is because
         * TX buffers are being recycled into the RX ring.  Might be better
         * to segregate buffers so that doesn't happen so much.
         *
         * TODO: See if any benefit/downside to enabling on x86.  (Likely
         * to be less important on systems with DDIO).
         */
        int off;
        for( off = 0; off < pkt->buf_len; off += EF_VI_DMA_ALIGN )
          ci_clflush(pkt->dma_start + off);
        /* This seems like a good idea (only flush buffer if it was last
         * used for TX) but it seems to make latency worse by around 30ns:
         *
         *   pkt->buf_len = 0;
         */
      }
#endif
    }
    ni->packets->set[bufset_id].n_free -= CI_CFG_RX_DESC_BATCH;
    ni->packets->n_free -= CI_CFG_RX_DESC_BATCH;
    ni->state->n_rx_pkts  += CI_CFG_RX_DESC_BATCH;
    ef_vi_receive_push(vi);
    posted += CI_CFG_RX_DESC_BATCH;
  } while( max - posted >= CI_CFG_RX_DESC_BATCH );

  return posted;
}


#define low_thresh(ni)       ((ni)->state->rxq_limit / 2)


int ci_netif_rx_post(ci_netif* netif, int intf_i, ef_vi* vi)
{
  /* TODO: When under packet buffer pressure, post fewer on the receive
  ** queue.  As an easy first stab could have a threshold for the number of
  ** free buffers, and not post any on receive queue when below that level.
  **
  ** It would also be sensible to not post (many) more buffers than can
  ** possibly be consumed by existing sockets receive windows.  This would
  ** reduce resource consumption for apps that have few sockets.
  */
  ci_ip_pkt_fmt* pkt;
  int max_n_to_post, rx_allowed, n_to_post, n_posted = 0;
  int bufset_id = NI_PKT_SET(netif);
  int ask_for_more_packets = 0;

  ci_assert(ci_netif_is_locked(netif));
  ci_assert(ci_netif_rx_vi_space(netif, vi) >= CI_CFG_RX_DESC_BATCH);

  max_n_to_post = ci_netif_rx_vi_space(netif, vi);
  rx_allowed = NI_OPTS(netif).max_rx_packets - netif->state->n_rx_pkts;
  if( max_n_to_post > rx_allowed )
    goto rx_limited;
 not_rx_limited:

  ci_assert_ge(max_n_to_post, CI_CFG_RX_DESC_BATCH);
  /* We could have enough packets in all sets together, but we need them
   * in one set. */
  if( netif->packets->set[bufset_id].n_free < CI_CFG_RX_DESC_BATCH )
    goto find_new_bufset;

 good_bufset:
  do {
    int n;
    n_to_post = CI_MIN(max_n_to_post, netif->packets->set[bufset_id].n_free);
    n = __ci_netif_rx_post(netif, vi, intf_i, bufset_id, n_to_post);
    max_n_to_post -= n;
    n_posted += n;
    ci_assert_ge(max_n_to_post, 0);

    if( max_n_to_post < CI_CFG_RX_DESC_BATCH ) {
      if( bufset_id != netif->packets->id ) {
        ci_netif_pkt_set_change(netif, bufset_id,
                                ask_for_more_packets);
      }
      CHECK_FREEPKTS(netif);
      return n_posted;
    }

 find_new_bufset:
    bufset_id = ci_netif_pktset_best(netif);
    if( bufset_id == -1 ||
        netif->packets->set[bufset_id].n_free < CI_CFG_RX_DESC_BATCH )
      goto not_enough_pkts;
    ask_for_more_packets = ci_netif_pkt_set_is_underfilled(netif,
                                                           bufset_id);
  } while( 1 );
  /* unreachable */


 rx_limited:
  /* [rx_allowed] can go negative. */
  if( rx_allowed < 0 )
    rx_allowed = 0;
#if OO_DO_STACK_POLL
  /* Only reap if ring is getting pretty empty. */
  if( ef_vi_receive_fill_level(vi) + rx_allowed < low_thresh(netif) ) {
    CITP_STATS_NETIF_INC(netif, reap_rx_limited);
    ci_netif_try_to_reap(netif, max_n_to_post - rx_allowed);
    rx_allowed = NI_OPTS(netif).max_rx_packets - netif->state->n_rx_pkts;
    if( rx_allowed < 0 )
      rx_allowed = 0;
    max_n_to_post = CI_MIN(max_n_to_post, rx_allowed);
    if( ef_vi_receive_fill_level(vi) + max_n_to_post < low_thresh(netif) )
      /* Ask recv() path to refill when some buffers are freed. */
      netif->state->rxq_low = ci_netif_rx_vi_space(netif, vi) - max_n_to_post;
    if( max_n_to_post >= CI_CFG_RX_DESC_BATCH )
      goto not_rx_limited;
  }
  if( netif->state->mem_pressure & OO_MEM_PRESSURE_CRITICAL ) {
    /* We want to always be able to post a small number of buffers to
     * the rxq when in critical memory pressure as otherwise we may
     * drop packets that would release queued buffers.
     *
     * When we enter critical memory pressure we release a few packet
     * buffers for exactly this purpose, so make sure we can use them
     * here.
     */
    rx_allowed = CI_CFG_RX_DESC_BATCH;
    max_n_to_post = ci_netif_rx_vi_space(netif, vi);
  }
#endif
  max_n_to_post = CI_MIN(max_n_to_post, rx_allowed);
  if(CI_LIKELY( max_n_to_post >= CI_CFG_RX_DESC_BATCH ))
    goto not_rx_limited;
  CITP_STATS_NETIF_INC(netif, refill_rx_limited);
#if OO_DO_STACK_POLL
  if( ef_vi_receive_fill_level(vi) < CI_CFG_RX_DESC_BATCH )
    ci_netif_mem_pressure_enter_critical(netif, intf_i);
#endif
  return n_posted;

 not_enough_pkts:
  /* The best packet set has less than CI_CFG_RX_DESC_BATCH packets.
   * We should free some packets or allocate a new set. */

  /* Even if we free packets and find a good bufset, we'd better to
   * allocate more packets when time allows: */
  ask_for_more_packets = 1;

  /* Grab buffers from the non-blocking pool. */
  while( (pkt = ci_netif_pkt_alloc_nonb(netif)) != NULL ) {
    --netif->state->n_async_pkts;
    CITP_STATS_NETIF_INC(netif, pkt_nonb_steal);
    pkt->flags &= ~CI_PKT_FLAG_NONB_POOL;
    bufset_id = PKT_SET_ID(pkt);
    ci_netif_pkt_release_1ref(netif, pkt);
    if( netif->packets->set[bufset_id].n_free >= CI_CFG_RX_DESC_BATCH )
      goto good_bufset;
  }

  /* Still not enough -- allocate more memory if possible. */
  if( netif->packets->sets_n < netif->packets->sets_max &&
      ci_tcp_helper_more_bufs(netif) == 0 ) {
    bufset_id = netif->packets->sets_n - 1;
    ci_assert_equal(netif->packets->set[bufset_id].n_free,
                    1 << CI_CFG_PKTS_PER_SET_S);
    ask_for_more_packets = 0;
    goto good_bufset;
  }

#if OO_DO_STACK_POLL
  if( ef_vi_receive_fill_level(vi) < low_thresh(netif) ) {
    CITP_STATS_NETIF_INC(netif, reap_buf_limited);
    ci_netif_try_to_reap(netif, max_n_to_post);
    max_n_to_post = CI_MIN(max_n_to_post, netif->packets->n_free);
    bufset_id = ci_netif_pktset_best(netif);
    if( bufset_id != -1 &&
        netif->packets->set[bufset_id].n_free >= CI_CFG_RX_DESC_BATCH )
      goto good_bufset;
    /* Ask recv() path to refill when some buffers are freed. */
    netif->state->rxq_low = ci_netif_rx_vi_space(netif, vi);
  }

  CITP_STATS_NETIF_INC(netif, refill_buf_limited);
  if( ef_vi_receive_fill_level(vi) < CI_CFG_RX_DESC_BATCH )
    ci_netif_mem_pressure_enter_critical(netif, intf_i);
#endif
  return n_posted;
}


#if OO_DO_STACK_POLL
static void citp_waitable_deferred_work(ci_netif* ni, citp_waitable* w)
{
  citp_waitable_obj* wo = CI_CONTAINER(citp_waitable_obj, waitable, w);

  if( wo->waitable.state & CI_TCP_STATE_TCP )
    ci_tcp_perform_deferred_socket_work(ni, &wo->tcp);
  else if( wo->waitable.state == CI_TCP_STATE_UDP )
    ci_udp_perform_deferred_socket_work(ni, &wo->udp);
  else {
    /* This happens when we move socket and continue to use it from another
     * thread or signal handler */
    ci_log("%s: unexpected status %s for socket [%d:%d]", __func__,
           ci_tcp_state_str(wo->waitable.state), NI_ID(ni), w->bufid);
  }
}


int ci_netif_lock_or_defer_work(ci_netif* ni, citp_waitable* w)
{
#if CI_CFG_FD_CACHING && !defined(NDEBUG)
  /* Cached sockets should not be deferring work - there are no user references
   */
  if( (w->state & CI_TCP_STATE_TCP) && !(w->state == CI_TCP_LISTEN) )
    ci_assert(!ci_tcp_is_cached(&CI_CONTAINER(citp_waitable_obj,
                                              waitable, w)->tcp));
#endif
  /* Orphaned sockets should not be deferring work - no-one has a reference to
   * them, and the queue link can be used for other things.
   */
  ci_assert(!(w->sb_aflags & CI_SB_AFLAG_ORPHAN));

  if( ni->state->defer_work_count >= NI_OPTS(ni).defer_work_limit ) {
    int rc = ci_netif_lock(ni);
    if( rc == 0 ) {
      CITP_STATS_NETIF_INC(ni, defer_work_limited);
      citp_waitable_deferred_work(ni, w);
      return 1;
    }
    /* We got a signal while waiting for the stack lock.  Best thing to do
     * here is to just go ahead and defer the work despite exceeding the
     * limit.  (Returning the error to the caller is much more complex).
     */
  }

  if( ci_bit_test_and_set(&w->sb_aflags, CI_SB_AFLAG_DEFERRED_BIT) ) {
    /* Already set.  Another thread is trying to defer some work for this
     * socket.  However, we must do **our** work in time, so let's push it
     * forward.
     *
     * We can't trust this other thread to do the job, because that thread
     * can be descheduled for some time, and we'll return to user with
     * non-empty prequeue.  Then user asks us to perform another send(),
     * and the new data go our before already-prequeued data.
     *
     * We can implement something more clever here, but this contention is
     * really rare, and it is simpler just to push on.
     */
    int rc = ci_netif_lock(ni);
    if( rc == 0 ) {
      /* We should not remove CI_SB_AFLAG_DEFERRED_BIT, because it was set
       * by someone else, and that someone else is responsible for
       * removing. */
      citp_waitable_deferred_work(ni, w);
      return 1;
    }
    /* We are interrupted by a signal.  We are in kernel.  Let's return and
     * trust the other contending thread to do the work or to defer this
     * work.
     *
     * FIXME
     * It is possible that this work will be done too late, see bug 78628
     * comment 9 for details.  Let's live with it for now.
     */
    CITP_STATS_NETIF_INC(ni, defer_work_contended_unsafe);
    ++ni->state->defer_work_count;
    return 0;
  }

  while( 1 ) {
    ci_uint64 new_v, v = ni->state->lock.lock;
    if( ! (v & CI_EPLOCK_LOCKED) ) {
      if( ci_netif_trylock(ni) ) {
        ci_bit_clear(&w->sb_aflags, CI_SB_AFLAG_DEFERRED_BIT);
        citp_waitable_deferred_work(ni, w);
        return 1;
      }
    }
    else {
      w->next_id = v & CI_EPLOCK_NETIF_SOCKET_LIST;
      new_v = (v & ~CI_EPLOCK_NETIF_SOCKET_LIST) | (W_ID(w) + 1);
      if( ci_cas64u_succeed(&ni->state->lock.lock, v, new_v) ) {
        ++ni->state->defer_work_count;
        return 0;
      }
    }
  }
}


static void ci_netif_perform_deferred_socket_work(ci_netif* ni,
                                                  unsigned sock_id)
{
  citp_waitable* w;
  oo_sp sockp;

  ci_assert(ci_netif_is_locked(ni));

  do {
    ci_assert(sock_id > 0);
    --sock_id;
    sockp = OO_SP_FROM_INT(ni, sock_id);
    w = SP_TO_WAITABLE(ni, sockp);
    sock_id = w->next_id;
    ci_bit_clear(&w->sb_aflags, CI_SB_AFLAG_DEFERRED_BIT);
    CITP_STATS_NETIF(++ni->state->stats.deferred_work);

    citp_waitable_deferred_work(ni, w);
  }
  while( sock_id > 0 );
}


ci_uint64 ci_netif_purge_deferred_socket_list(ci_netif* ni)
{
  ci_uint64 l;

  ci_assert(ci_netif_is_locked(ni));

  while( (l = ni->state->lock.lock) & CI_EPLOCK_NETIF_SOCKET_LIST ) {
    if( ci_cas64u_succeed(&ni->state->lock.lock, l,
                        l &~ CI_EPLOCK_NETIF_SOCKET_LIST) )
      ci_netif_perform_deferred_socket_work(ni,
                                            l & CI_EPLOCK_NETIF_SOCKET_LIST);

    /* It is not possible to clear defer_work_count atomically together
     * with NETIF_SOCKET_LIST.  We can do it before or after.
     * In both cases the real length of the deferred list is limited by
     * 2 * defer_work_limit.
     */
    ni->state->defer_work_count = 0;
  }

  return l;
}

void ci_netif_merge_atomic_counters(ci_netif* ni)
{
  ci_int32 val;
#define merge(ni, field) \
  do {                                                          \
    val = ni->state->atomic_##field;                            \
  } while( ci_cas32_fail(&ni->state->atomic_##field, val, 0) );\
  ni->state->field += val;

  merge(ni, n_rx_pkts);
  merge(ni, n_async_pkts);
#undef merge
}


#if CI_CFG_UL_INTERRUPT_HELPER
static
#endif
int oo_want_proactive_packet_allocation(ci_netif* ni)
{
  ci_uint32 current_free;

  /* This is used from stack unlock callback, which can occur during failed
   * stack allocation when we don't have any packet sets, and aren't going to
   * get any.
   */
  if( ni->packets->sets_n == 0 )
    return 0;

  current_free = ni->packets->set[NI_PKT_SET(ni)].n_free;

  /* All the packets allocated */
  if( pkt_sets_n(ni) == pkt_sets_max(ni) )
    return 0;

  /* We need to have a decent number of free packets. */
  if( ni->packets->n_free > NI_OPTS(ni).free_packets_low ) {
    /* But these free packets may be distributed between sets in
     * unfortunate way, so we do additional checks. */

    /* Good if the packets are underused */
    if( ni->packets->n_free > ni->packets->n_pkts_allocated / 3 )
      return 0;

    /* Good: a lot of packets in the current set and also some packets in
     * non-current sets, so it'll be possible to switch to another set when
     * this one is empty. */
    if( current_free > PKTS_PER_SET / 2 &&
        ni->packets->n_free > PKTS_PER_SET * 3 / 4 )
      return 0;

    /* Good: a lot of packets in non-current sets, and
     * some of them have at least CI_CFG_RX_DESC_BATCH packets. */
    if( ni->packets->n_free - current_free >
        CI_MAX(PKTS_PER_SET / 2, CI_CFG_RX_DESC_BATCH * (pkt_sets_n(ni) - 1)) )
      return 0;
  }

  CITP_STATS_NETIF_INC(ni, proactive_packet_allocation);
  LOG_NC(ci_log("%s: [%d] proactive packet allocation: "
                "%d sets n_freepkts=%d free_packets_low=%d "
                "current_set.n_free=%d", __func__, NI_ID(ni),
                pkt_sets_n(ni), ni->packets->n_free,
                NI_OPTS(ni).free_packets_low, current_free));
  return 1;
}


/* Handling for lock flags that is common to UL and kernel paths.
 * flags_to_handle allows restricting work in DL context.
 * flags_to_handle will be cleared from lock and return value
 * unless work failed/need redoing.
 */
ci_uint64 ci_netif_unlock_slow_common(ci_netif* ni, ci_uint64 lock_val,
                                      ci_uint64 flags_to_handle)
{
  ci_uint64 set_flags = 0;
  ci_uint64 test_val;

  /* Do this first, because ci_netif_purge_deferred_socket_list() acts on the
   * lock directly. */
  if( lock_val & CI_EPLOCK_NETIF_SOCKET_LIST ) {
    /* assume caller always asks to handle these flags */
    ci_assert_flags(flags_to_handle, CI_EPLOCK_NETIF_SOCKET_LIST);
    CITP_STATS_NETIF_INC(ni, unlock_slow_socket_list);
    lock_val = ci_netif_purge_deferred_socket_list(ni);
  }
  ci_assert(! (lock_val & CI_EPLOCK_NETIF_SOCKET_LIST));

  /* Clear all flags before we handle them, to avoid racing against other
   * threads that set those flags. (note: SOCKET_LIST got handled above) */
  lock_val = ef_eplock_clear_flags(&ni->state->lock,
                          flags_to_handle & ~CI_EPLOCK_NETIF_SOCKET_LIST);

  /* Restrict work below to what has been requested */
  test_val = lock_val & flags_to_handle;

  if( test_val & CI_EPLOCK_NETIF_IS_PKT_WAITER ) {
    if( ci_netif_pkt_tx_can_alloc_now(ni) ) {
      set_flags |= CI_EPLOCK_NETIF_PKT_WAKE;
      CITP_STATS_NETIF_INC(ni, unlock_slow_pkt_waiter);
    }
    else {
      set_flags |= CI_EPLOCK_NETIF_IS_PKT_WAITER;
    }
  }

  if( test_val & CI_EPLOCK_NETIF_NEED_POLL ) {
    CITP_STATS_NETIF(++ni->state->stats.deferred_polls);
    ci_netif_poll(ni);
  }

#if CI_CFG_UL_INTERRUPT_HELPER && ! defined (__KERNEL__)
  if( test_val & CI_EPLOCK_NETIF_CLOSE_ENDPOINT ) {
    ci_netif_close_pending(ni);
  }

  if( test_val & CI_EPLOCK_NETIF_NEED_WAKE ) {
    /* Tell kernel to wake up endpoints */
    ci_ni_dllist_link* lnk;
    citp_waitable* w;
    struct oo_wakeup_eps op;
    oo_sp eps[64];

    op.eps_num = 0;
    CI_USER_PTR_SET(op.eps, eps);

    while( ci_ni_dllist_not_empty(ni, &ni->state->post_poll_list) ) {
      lnk = ci_ni_dllist_head(ni, &ni->state->post_poll_list);
      w = CI_CONTAINER(citp_waitable, post_poll_link, lnk);
      ci_ni_dllist_remove_safe(ni, &w->post_poll_link);
      eps[op.eps_num++] = w->bufid;

      /* Todo: we'd better allocate larger eps and wake up all
       * simultaneously, so that user's poll() returns all ready sockets in
       * one go.
       */
      if( op.eps_num == sizeof(eps) / sizeof(eps[0]) ) {
        oo_resource_op(ci_netif_get_driver_handle(ni),
                       OO_IOC_WAKEUP_WAITERS, &op);
        op.eps_num = 0;

      }
    }

    if( op.eps_num != 0 )
      oo_resource_op(ci_netif_get_driver_handle(ni),
                     OO_IOC_WAKEUP_WAITERS, &op);

  }

  if( test_val & CI_EPLOCK_NETIF_NEED_PKT_SET ||
      oo_want_proactive_packet_allocation(ni) ) {
    /* assume caller always asks to handle this flag */
    ci_assert_flags(flags_to_handle, CI_EPLOCK_NETIF_NEED_PKT_SET);
    ci_tcp_helper_more_bufs(ni);
  }

  if( test_val & CI_EPLOCK_NETIF_NEED_SOCK_BUFS ||
      oo_want_proactive_socket_allocation(ni) ) {
    /* assume caller always asks to handle this flag */
    ci_assert_flags(flags_to_handle, CI_EPLOCK_NETIF_NEED_SOCK_BUFS);
    ci_tcp_helper_more_socks(ni);
  }
#endif

  if( test_val & CI_EPLOCK_NETIF_HAS_DEFERRED_PKTS ) {
    if( ! oo_deferred_send(ni) )
      set_flags |= CI_EPLOCK_NETIF_HAS_DEFERRED_PKTS;
  }

  if( test_val & CI_EPLOCK_NETIF_MERGE_ATOMIC_COUNTERS )
    ci_netif_merge_atomic_counters(ni);

  ef_eplock_holder_set_flags(&ni->state->lock, set_flags);

  /* Returns good reflection on current lock value. */
  return lock_val | set_flags;
}


#ifdef __KERNEL__
static void ci_netif_unlock_slow(ci_netif* ni)
{
  efab_eplock_unlock_and_wake(ni, 0 /* in_dl_context */);
}
#else
static void ci_netif_unlock_slow(ci_netif* ni)
{
  /* All we are doing here is seeing if we can avoid a syscall.  Everything
  ** we do here has to be checked again if we do take the
  ** efab_eplock_unlock_and_wake() path, so no need to do this stuff if
  ** already in kernel.
  */
  ci_uint64 l, k_flags = 0;
  int intf_i;
  int rc = 0;
  ci_uint64 all_handled_flags =
        CI_EPLOCK_NETIF_UL_MASK | CI_EPLOCK_NETIF_SOCKET_LIST;

  if( ~ni->state->flags & CI_NETIF_FLAG_EVQ_KERNEL_PRIME_ONLY )
    all_handled_flags |= CI_EPLOCK_NETIF_NEED_PRIME;

  ci_assert(ci_netif_is_locked(ni));  /* double unlock? */

  CITP_STATS_NETIF_INC(ni, unlock_slow);

  do {
    l = ni->state->lock.lock;
    l = ci_netif_unlock_slow_common(ni, l, all_handled_flags);

    /* If the NEED_PRIME flag was set, handle it here */
    if( l & all_handled_flags & CI_EPLOCK_NETIF_NEED_PRIME ) {
      CITP_STATS_NETIF_INC(ni, unlock_slow_need_prime);
      CITP_STATS_NETIF_INC(ni, unlock_slow_prime_ul);
      ci_assert(NI_OPTS(ni).int_driven);
      /* TODO: When interrupt driven, evq_primed is never cleared, so we
      * don't know here which subset of interfaces needs to be primed.
      * Would be more efficient if we did.
      */
      OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
        ef_eventq_prime(ci_netif_vi(ni, intf_i));
    }

    /* If some flags should be handled in kernel, then there is no point in
     * looping here.  Dive! */
    k_flags |= l & ((CI_EPLOCK_NETIF_UNLOCK_FLAGS & ~all_handled_flags) | CI_EPLOCK_FL_NEED_WAKE);
#if ! CI_CFG_UL_INTERRUPT_HELPER
    if( k_flags != 0 )
      break;
#else
    /* In kernel we can handle following flags only: */
    ci_assert_nflags(k_flags,
                     ~(CI_EPLOCK_NETIF_PKT_WAKE |
                       CI_EPLOCK_NETIF_NEED_PRIME |
                       CI_EPLOCK_FL_NEED_WAKE));
    l = ef_eplock_clear_flags(&ni->state->lock, k_flags);
#endif
  } while ( !ef_eplock_try_unlock(&ni->state->lock, &l,
                                  CI_EPLOCK_NETIF_UNLOCK_FLAGS |
                                  CI_EPLOCK_NETIF_SOCKET_LIST |
                                  CI_EPLOCK_FL_NEED_WAKE) );

  /* We've handled everything we needed to, so can return without
   * dropping to the kernel.
   */
  if( k_flags == 0 )
    return;

  CITP_STATS_NETIF_INC(ni, unlock_slow_syscall);
#if ! CI_CFG_UL_INTERRUPT_HELPER
  rc = oo_resource_op(ci_netif_get_driver_handle(ni),
                      OO_IOC_EPLOCK_WAKE, NULL);
#else
  rc = oo_resource_op(ci_netif_get_driver_handle(ni),
                      OO_IOC_EPLOCK_WAKE_AND_DO, &k_flags);
#endif

  if( rc < 0 )  LOG_NV(ci_log("%s: rc=%d", __FUNCTION__, rc));
}
#endif /* __KERNEL__ */


void ci_netif_unlock(ci_netif* ni)
{
#ifdef __KERNEL__
  ci_assert_nflags(ni->flags, CI_NETIF_FLAG_IN_DL_CONTEXT);
#elif ! defined(NDEBUG)
  int saved_errno = errno;
#endif
  ci_assert_nflags(ni->state->flags, CI_NETIF_FLAG_PKT_ACCOUNT_PENDING);

  ci_assert_equal(ni->state->in_poll, 0);
  if(CI_LIKELY( ni->state->lock.lock == CI_EPLOCK_LOCKED &&
                ci_cas64u_succeed(&ni->state->lock.lock,
                                  CI_EPLOCK_LOCKED, 0) ))
    return;
  ci_netif_unlock_slow(ni);

#ifndef __KERNEL__
  /*  Unlock hooks must not change errno! */
  ci_assert_equal(saved_errno, errno);
#endif
}
#else /* OO_DO_STACK_POLL */
/* FIXME Sort it out somehow.
 * This call is used from:
 * (1) efab_tcp_helper_sock_sleep() when CI_SLEEP_NETIF_LOCKED is set;
 * (2) efab_terminate_unlock_all_stacks().
 * For now we just mark the stack unlocked and hope that someone (e.g.
 * onload_helper process) will take care about all the lock flags
 * eventually.
 */
void ci_netif_unlock(ci_netif* ni)
{
  ci_uint64 l;
  do {
    l = ni->state->lock.lock;
  } while( ci_cas64u_fail(&ni->state->lock.lock, l, l & ~CI_EPLOCK_LOCKED) );
}
#endif /* OO_DO_STACK_POLL */


void ci_netif_error_detected(ci_netif* ni, unsigned error_flag,
                             const char* caller)
{
  if( ni->error_flags & error_flag )
    return;
  ci_log("%s: ERROR: [%d] runtime error %x detected in %s()",
         __FUNCTION__, NI_ID(ni), error_flag, caller);
  ci_log("%s: ERROR: [%d] errors detected: %x %x "CI_NETIF_ERRORS_FMT,
         __FUNCTION__, NI_ID(ni), ni->error_flags, ni->state->error_flags,
         CI_NETIF_ERRORS_PRI_ARG(ni->error_flags | ni->state->error_flags));
  ni->error_flags |= error_flag;
  ni->state->error_flags |= ni->error_flags;
}


#if OO_DO_STACK_POLL
#if CI_CFG_EPOLL3
#ifndef __KERNEL__
int ci_netif_get_ready_list(ci_netif* ni)
{
  int i = 0;

  ci_netif_lock(ni);
  do {
    if( !((ni->state->ready_lists_in_use >> i) & 1) ) {
      ni->state->ready_list_pid[i] = getpid();
      ni->state->ready_lists_in_use |= 1 << i;
      break;
    }
  } while( ++i < CI_CFG_N_READY_LISTS );
  ci_netif_unlock(ni);

  return i < CI_CFG_N_READY_LISTS ? i : -1;
}
#endif

static inline void
ci_netif_put_ready_list_one(ci_netif* ni, ci_ni_dllist_t* list, int id)
{
  while( ci_ni_dllist_not_empty(ni, list) ) {
    ci_ni_dllist_link* lnk = ci_ni_dllist_pop(ni, list);
    ci_sb_epoll_state* epoll = CI_CONTAINER(ci_sb_epoll_state,
                                            e[id].ready_link, lnk);

    ci_ni_dllist_self_link(ni, lnk);
    SP_TO_WAITABLE(ni, epoll->sock_id)->ready_lists_in_use &=~ (1 << id);
  }
}

static void ci_netif_put_ready_list_locked(ci_netif* ni, int id)
{
  ci_netif_put_ready_list_one(ni, &ni->state->ready_lists[id], id);
  ci_netif_put_ready_list_one(ni, &ni->state->unready_lists[id], id);
  ni->state->ready_lists_in_use &= ~(1 << id);
  ni->state->ready_list_pid[id] = 0;
}

void ci_netif_free_ready_lists(ci_netif* ni)
{
  int i;
  for( i = 0; i < CI_CFG_N_READY_LISTS; i++ ) {
    if( (ni->state->ready_list_flags[i] & CI_NI_READY_LIST_FLAG_PENDING_FREE) ) {
      ci_atomic32_and(&ni->state->ready_list_flags[i],
                      ~CI_NI_READY_LIST_FLAG_PENDING_FREE);
      ci_netif_put_ready_list_locked(ni, i);
    }
  }
}

void ci_netif_put_ready_list(ci_netif* ni, int id)
{

  ci_assert(ni->state->ready_lists_in_use & (1 << id));

#ifdef __KERNEL__
  ci_assert(current);
  if( current->flags & PF_EXITING ? ! ci_netif_trylock(ni) :
                                    ci_netif_lock(ni) ) {
    ci_atomic32_or(&ni->state->ready_list_flags[id],
                   CI_NI_READY_LIST_FLAG_PENDING_FREE);
    if(! ef_eplock_lock_or_set_flag(&ni->state->lock,
                                    CI_EPLOCK_NETIF_FREE_READY_LIST) ) {
      /* lock holder will release the ready list */
      return;
    }
    ci_atomic32_and(&ni->state->ready_list_flags[id],
                    ~CI_NI_READY_LIST_FLAG_PENDING_FREE);
  }
#else
  ci_netif_lock(ni);
#endif
  ci_netif_put_ready_list_locked(ni, id);
  ci_netif_unlock(ni);
}
#endif


#ifndef __KERNEL__
int ci_netif_raw_send(ci_netif* ni, int intf_i,
                      const ci_iovec *iov, int iovlen)
{
  ci_ip_pkt_fmt* pkt;
  ci_uint8* p;
  int i;

  ci_netif_lock(ni);
  pkt = ci_netif_pkt_alloc(ni, 0);
  if( pkt == NULL )
    return -ENOBUFS;

  pkt->intf_i = intf_i;
  if( intf_i < 0 || intf_i >= CI_CFG_MAX_INTERFACES )
    return -ENETDOWN;

  pkt->pkt_start_off = 0;
  pkt->buf_len = 0;
  p = pkt->dma_start;
  for( i = 0; i < iovlen; i++ ) {
    if( p + CI_IOVEC_LEN(iov) - (ci_uint8*) pkt > CI_CFG_PKT_BUF_SIZE ) {
      ci_netif_pkt_release(ni, pkt);
      ci_netif_unlock(ni);
      return -EMSGSIZE;
    }

    memcpy(p, CI_IOVEC_BASE(iov), CI_IOVEC_LEN(iov));
    p += CI_IOVEC_LEN(iov);
    pkt->buf_len += CI_IOVEC_LEN(iov);
    iov++;
  }

  if( oo_ether_hdr(pkt)->ether_type != CI_ETHERTYPE_8021Q )
    pkt->pkt_eth_payload_off = pkt->pkt_start_off + ETH_HLEN;
  else
    pkt->pkt_eth_payload_off = pkt->pkt_start_off + ETH_HLEN + ETH_VLAN_HLEN;
#if CI_CFG_IPV6
  if( oo_pkt_ether_type(pkt) == CI_ETHERTYPE_IP )
    pkt->flags &=~ CI_PKT_FLAG_IS_IP6;
  else
    pkt->flags |= CI_PKT_FLAG_IS_IP6;
#endif

  pkt->pay_len = pkt->buf_len;
  ci_netif_pkt_hold(ni, pkt);
  ci_netif_send(ni, pkt);
  ci_netif_pkt_release(ni, pkt);

  ci_netif_unlock(ni);
  return 0;
}
#endif
#endif


#if CI_CFG_TCP_SHARED_LOCAL_PORTS
static ci_uint32 __ci_netif_active_wild_hash(ci_netif *ni,
                                             ci_addr_t laddr, ci_uint16 lport,
                                             ci_addr_t raddr, ci_uint16 rport)
{
  /* FIXME lots of insights into efrm */
  /* FIXME this is copy of hash in efrm_vi_set.c */
  static const uint8_t rx_hash_key[40] = {
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
  };

#ifndef __KERNEL__
  /* We use a transformed key for our optimised Toeplitz hash. */
  __attribute__((aligned(sizeof(ci_uint32))))
  static const uint8_t rx_hash_key_sse[40] = {
    0xb5, 0x6c, 0xb5, 0x6c, 0xb5, 0x6c, 0xb5, 0x6c,
    0xb5, 0x6c, 0xb5, 0x6c, 0xb5, 0x6c, 0xb5, 0x6c,
    0xb5, 0x6c, 0xb5, 0x6c, 0xb5, 0x6c, 0xb5, 0x6c,
    0xb5, 0x6c, 0xb5, 0x6c, 0xb5, 0x6c, 0xb5, 0x6c,
    0xb5, 0x6c, 0xb5, 0x6c, 0xb5, 0x6c, 0xb5, 0x6c,
  };
#endif

#if CI_CFG_IPV6
  if( CI_IS_ADDR_IP6(laddr) ) {
    struct {
      ci_ip6_addr_t raddr;
      ci_ip6_addr_t laddr;
      ci_uint16 rport_be16;
      ci_uint16 lport_be16;
    } __attribute__((packed)) data;
    int data_size = sizeof(data);
    memcpy(data.raddr, raddr.ip6, sizeof(ci_ip6_addr_t));
    memcpy(data.laddr, laddr.ip6, sizeof(ci_ip6_addr_t));
    data.rport_be16 = rport;
    data.lport_be16 = lport;

#ifndef __KERNEL__
    return ci_toeplitz_hash_ul(rx_hash_key, rx_hash_key_sse, (ci_uint8*) &data,
                               data_size);
#endif
    return ci_toeplitz_hash(rx_hash_key, (ci_uint8*) &data, data_size);
  }
#endif
  {
    struct {
      ci_uint32 raddr_be32;
      ci_uint32 laddr_be32;
      ci_uint16 rport_be16;
      ci_uint16 lport_be16;
    } __attribute__((packed)) data = {
      raddr.ip4, laddr.ip4, rport, lport };
    int data_size = sizeof(data);

#ifndef __KERNEL__
    /* N.B.: Only the lower byte is guaranteed to be accurate here, but this is
     * good enough for our purposes. */
    return ci_toeplitz_hash_ul(rx_hash_key, rx_hash_key_sse, (ci_uint8*) &data,
                               data_size);
#endif
    return ci_toeplitz_hash(rx_hash_key, (ci_uint8*) &data, data_size);
  }
}


/* Returns the index in the NIC's RSS indirection table to which the supplied
 * four-tuple would be hashed. */
int ci_netif_active_wild_nic_hash(ci_netif *ni,
                                  ci_addr_t laddr, ci_uint16 lport,
                                  ci_addr_t raddr, ci_uint16 rport)
{
  return __ci_netif_active_wild_hash(ni, laddr, lport, raddr, rport) &
         RSS_HASH_MASK;
}


/* Returns the hash table of active wilds for the specified pool. */
ci_inline ci_ni_dllist_t*
ci_netif_active_wild_pool_table(ci_netif* ni, int aw_pool)
{
  ci_assert(ci_netif_is_locked(ni));
  ci_assert_lt(aw_pool, ni->state->active_wild_pools_n);

  return ni->active_wild_table +
         aw_pool * ni->state->active_wild_table_entries_n;
}


/* Returns the list of active wilds in a specified pool for the specified local
 * address.  If such a list does not exist, an empty list is returned, into
 * which new active wilds for that IP address may be inserted.  The list does
 * not become 'owned' by that address until it becomes non-empty.  This means
 * that the stack lock must not be dropped between retrieving the address of a
 * list using this function and ceasing to use the returned pointer to that
 * list. */
int ci_netif_get_active_wild_list(ci_netif* ni, int aw_pool, ci_addr_t laddr,
                                  ci_ni_dllist_t** list_out)
{
  ci_ni_dllist_t* table = ci_netif_active_wild_pool_table(ni, aw_pool);
  ci_uint32 bucket, hash1, hash2;

  ci_assert(ci_netif_is_locked(ni));

  ci_addr_simple_hash(laddr, ni->state->active_wild_table_entries_n,
                      &hash1, &hash2);
  bucket = hash1;

  do {
    ci_active_wild* aw;
    ci_ni_dllist_link* link;

    *list_out = &table[bucket];

    /* If we've found an empty list, it means there's no entry in the table for
     * the specified IP address.  This empty list is also at the correct
     * location for the insertion of a new list for that IP address, and so we
     * return it. */
    if( ci_ni_dllist_is_empty(ni, *list_out) )
      return 0;

    /* The list is non-empty, so look at one of the active wilds contained in
     * it in order to determine and check the local address. */
    link = ci_ni_dllist_head(ni, *list_out);
    aw = CI_CONTAINER(ci_active_wild, pool_link, link);
    if( CI_IPX_ADDR_EQ(sock_ipx_laddr(&aw->s), laddr) )
      return 0;

    /* This list is for the wrong IP address, so advance to the next bucket. */
    bucket = (bucket + hash2) & (ni->state->active_wild_table_entries_n - 1);
  } while( bucket != hash1 );

  NI_LOG_ONCE(ni, RESOURCE_WARNINGS,
              "No space in active wild table %d for local address "
              IPX_FMT, aw_pool, IPX_ARG(AF_IP_L3(laddr)));

  return -ENOSPC;
}


#ifndef __KERNEL__
#ifndef NDEBUG
static int __ci_netif_active_wild_rss_ok(ci_netif* ni,
                                         ci_addr_t laddr, ci_uint16 lport,
                                         ci_addr_t raddr, ci_uint16 rport)
{
  /* This function checks the compatability of a 4-tuple with this stack.
   * To do so implies we have a destination address and port, have selected
   * a local address, and have an active wild, which must have a non-zero
   * port for protocol reasons.
   */
  ci_assert_nequal(lport, 0);
  ci_assert_nequal(rport, 0);
  ci_assert(!CI_IPX_ADDR_IS_ANY(laddr));
  ci_assert(!CI_IPX_ADDR_IS_ANY(raddr));

  /* It's always ok if we don't have a multi-instance cluster */
  if( ni->state->cluster_size < 2 )
    return 1;

  if( ci_netif_active_wild_nic_hash(ni, laddr, lport, raddr, rport)
      % ni->state->cluster_size == ni->state->rss_instance )
    return 1;
  else
    return 0;

}
#endif


static int __ci_netif_active_wild_pool_select(ci_netif* ni, ci_addr_t laddr,
                                              ci_addr_t raddr, ci_uint16 rport,
                                              int offset)
{
  ci_uint32 pool_index = 0;
  ci_uint32 select_hash;

  if( ni->state->active_wild_pools_n > 1 ) {
    select_hash = ci_netif_active_wild_nic_hash(ni, laddr, 0, raddr, rport);

    ci_assert_equal(0, (offset & ~RSS_HASH_MASK));

    pool_index = select_hash ^ offset;
    pool_index &= (ni->state->active_wild_pools_n - 1);
  }

  return pool_index;
}


/* By using ports from the active wild pool we can potentially be re-using
 * ports very quickly, including to the same remote addr/port.  In that case
 * we may overlap with an earlier incarnation that's still in TIME-WAIT, so
 * we need to ensure that we don't cause the peer to think we're reopening
 * that connection.
 *
 * To do that we record the details of the last closed connection on this port
 * in a way that would leave the peer in TIME-WAIT (if we're in TIME-WAIT we
 * won't re-use the port, as we still have a sw filter for the 4-tuple, if
 * the connection is reset then we're ok).
 *
 * When we assign a new port we check if we expect the peer to be out of
 * TIME-WAIT by now (assuming they're using the same length of timer as us).
 * If so we can give them a new active wild port as usual.  If not, we'll
 * keep looking (potentially increasing the pool).
 */
static int __ci_netif_active_wild_allow_reuse(ci_netif* ni, ci_active_wild* aw,
                                              ci_addr_t laddr, ci_addr_t raddr,
                                              unsigned rport)
{
  if( ci_ip_time_now(ni) > aw->expiry ||
      NI_OPTS(ni).tcp_shared_local_ports_reuse_fast )
    return 1;
  else
    return !CI_IPX_ADDR_EQ(aw->last_laddr, laddr) ||
           !CI_IPX_ADDR_EQ(aw->last_raddr, raddr) ||
           (aw->last_rport != rport);
}


static oo_sp __ci_netif_active_wild_pool_get(ci_netif* ni, int aw_pool,
                                             ci_addr_t laddr, ci_addr_t raddr,
                                             unsigned rport,
                                             ci_uint16* port_out,
                                             ci_uint32* prev_seq_out)
{
  ci_active_wild* aw;
  ci_uint16 lport;
  ci_addr_t laddr_aw =
            NI_OPTS(ni).tcp_shared_local_ports_per_ip ? laddr : addr_any;
  int rc;
  int af_space = AF_SPACE_FLAG_IP4;
  oo_sp sp;
  ci_ni_dllist_t* list;
  ci_ni_dllist_link* link = NULL;
  ci_ni_dllist_link* tail;

  ci_assert(ci_netif_is_locked(ni));

#if CI_CFG_IPV6
  if( CI_IPX_ADDR_IS_ANY(laddr) )
    af_space = AF_SPACE_FLAG_IP6 | AF_SPACE_FLAG_IP4;
  else if( CI_IS_ADDR_IP6(laddr) )
    af_space = AF_SPACE_FLAG_IP6;
#endif

  *prev_seq_out = 0;

  rc = ci_netif_get_active_wild_list(ni, aw_pool, laddr_aw, &list);
  if( rc < 0 )
    return OO_SP_NULL;

  /* This can happen if active wilds are configured, but we failed to allocate
   * any at stack creation time, for example because there were no filters
   * available, or if none of them give a valid hash for this 4-tuple.
   */
  if( ci_ni_dllist_is_empty(ni, list) )
    return OO_SP_NULL;

  tail = ci_ni_dllist_tail(ni, list);
  while( link != tail ) {
    link = ci_ni_dllist_pop(ni, list);
    ci_ni_dllist_push_tail(ni, list, link);

    aw = CI_CONTAINER(ci_active_wild, pool_link, link);

    lport = sock_lport_be16(&aw->s);

    /* We should have been provided with a list of active wilds where the
     * local port will direct to this stack when used with the provided
     * 3-tuple.
     */
    ci_assert(__ci_netif_active_wild_rss_ok(ni, laddr, lport, raddr, rport));

    sp = ci_netif_filter_lookup(ni, af_space, laddr, lport, raddr, rport,
                                sock_protocol(&aw->s));

    if( OO_SP_NOT_NULL(sp) ) {
      ci_sock_cmn* s = ID_TO_SOCK(ni, sp);
      if( s->b.state == CI_TCP_TIME_WAIT ) {
        ci_uint32 seq;
        /* This 4-tuple is in use as TIME_WAIT, but it is safe to re-use
         * TIME_WAIT for active open.  We ensure we use an initial sequence
         * number that is a long way from the one used by the old socket.
         */
        ci_tcp_state* ts = SOCK_TO_TCP(s);
        CITP_STATS_NETIF_INC(ni, tcp_shared_local_ports_reused_tw);
        /* Setting *prev_seq_out to zero indicates to the caller that it should
         * fall back to the clock-driven ISN.  However, sometimes we really do
         * want to report a previous sequence number of zero.  To work around
         * this, report a value of 1 in such cases.  This is valid in practice,
         * as the purpose of this is to allow the selection of an ISN for the
         * next connection that is greater in sequence space than the old one.
         */
        seq = ts->snd_nxt + NI_OPTS(ni).tcp_isn_offset;
        if( seq == 0 )
          seq = 1;

        /* If this socket's final sequence number has already been stored in
         * the table (which only happens when we reached TIME_WAIT via
         * CLOSING), we need to do a lookup to ensure that the entry gets
         * removed. */
        if( ts->tcpflags & CI_TCPT_FLAG_SEQNO_REMEMBERED ) {
          ci_uint32 table_seq = ci_tcp_prev_seq_lookup(ni, ts);
          /* The entry might already have been purged, in which case
           * [table_seq] will be zero.  But otherwise, the table entry should
           * agree with the socket. */
          if( table_seq != 0 )
            ci_assert_equal(seq, table_seq);
        }

        *prev_seq_out = seq;
        ci_netif_timeout_leave(ni, ts);
        *port_out = lport;
        return SC_SP(&aw->s);
      }

      CITP_STATS_NETIF_INC(ni, tcp_shared_local_ports_skipped_in_use);
    }
    else if( __ci_netif_active_wild_allow_reuse(ni, aw, laddr,
                                                raddr, rport) ) {
      /* If no-one's using this 4-tuple we can let the caller share this
       * active wild.
       */
      *port_out = lport;
      return SC_SP(&aw->s);
    }
    CITP_STATS_NETIF_INC(ni, tcp_shared_local_ports_skipped);
  }

  return OO_SP_NULL;
}


static oo_sp __ci_netif_active_wild_get(ci_netif* ni, ci_addr_t laddr,
                                        ci_addr_t raddr, unsigned rport,
                                        ci_uint16* port_out,
                                        ci_uint32* prev_seq_out)
{
  int aw_pool;
  int offset;
  oo_sp aw = OO_SP_NULL;

  ci_assert(ci_netif_is_locked(ni));

  for( offset = ni->state->rss_instance;
       offset < ni->state->active_wild_pools_n;
       offset += ni->state->cluster_size ) {
    aw_pool = __ci_netif_active_wild_pool_select(ni, laddr, raddr, rport,
                                                 offset);
    aw = __ci_netif_active_wild_pool_get(ni, aw_pool, laddr, raddr, rport,
                                         port_out, prev_seq_out);
    if( aw != OO_SP_NULL )
      break;
  }

  return aw;
}


oo_sp ci_netif_active_wild_get(ci_netif* ni, ci_addr_t laddr,
                               ci_addr_t raddr, unsigned rport,
                               ci_uint16* port_out, ci_uint32* prev_seq_out)
{
  oo_sp active_wild;

  ci_assert(ci_netif_is_locked(ni));

  if( ! ci_netif_should_allocate_tcp_shared_local_ports(ni) )
    return OO_SP_NULL;

  active_wild = __ci_netif_active_wild_get(ni, laddr, raddr, rport,
                                           port_out, prev_seq_out);

  /* If we failed to get an active wild try and grow the pool */
  while( active_wild == OO_SP_NULL &&
         ni->state->active_wild_n < NI_OPTS(ni).tcp_shared_local_ports_max ) {
    int rc;
    ci_addr_t laddr_aw =
              NI_OPTS(ni).tcp_shared_local_ports_per_ip ? laddr : addr_any;
    LOG_TC(ci_log(FN_FMT "Didn't get active wild, getting more",
                  FN_PRI_ARGS(ni)));
    rc = ci_tcp_helper_alloc_active_wild(ni, laddr_aw);
    if( rc >= 0 ) {
      CITP_STATS_NETIF_INC(ni, tcp_shared_local_ports_grow);
      active_wild = __ci_netif_active_wild_get(ni, laddr, raddr, rport,
                                               port_out, prev_seq_out);
    }
    else if( rc == -ENOBUFS ) {
      break;
    }
    else {
      LOG_TC(ci_log(FN_FMT "Alloc active wild for "IPX_FMT":0 "
                    IPX_FMT":%u FAILED - rc %d",
                    FN_PRI_ARGS(ni), IPX_ARG(AF_IP(laddr)),
                    IPX_ARG(AF_IP(raddr)), htons(rport), rc));
      CITP_STATS_NETIF_INC(ni, tcp_shared_local_ports_grow_failed);
      break;
    }
  }

  if( active_wild != OO_SP_NULL ) {
    CITP_STATS_NETIF_INC(ni, tcp_shared_local_ports_used);
    LOG_TC(ci_log(FN_FMT "Lookup active wild for "IPX_FMT":0 "
                  IPX_FMT":%u FOUND - lport %u",
                  FN_PRI_ARGS(ni), IPX_ARG(AF_IP(laddr)),
                  IPX_ARG(AF_IP(raddr)),
                  htons(rport), htons(*port_out)));
  }
  else {
    CITP_STATS_NETIF_INC(ni, tcp_shared_local_ports_exhausted);
    LOG_TC(ci_log(FN_FMT "Lookup active wild for "IPX_FMT":0 "
                  IPX_FMT":%u NOT AVAILABLE",
                FN_PRI_ARGS(ni), IPX_ARG(AF_IP(laddr)),
                IPX_ARG(AF_IP(raddr)), htons(rport)));
  }
  return active_wild;
}
#endif

/* See comment on __ci_netif_active_wild_allow_reuse() to explain the reason
 * we need this.
 */
void ci_netif_active_wild_sharer_closed(ci_netif* ni, ci_sock_cmn* s)
{
  oo_sp id;
  ci_active_wild* aw;

  id = ci_netif_filter_lookup(ni, sock_af_space(s),
                                sock_ipx_laddr(s), sock_lport_be16(s),
                                addr_any, 0, sock_protocol(s));

  if( OO_SP_NOT_NULL(id) ) {
    aw = SP_TO_ACTIVE_WILD(ni, id);
    ci_assert(aw->s.b.state == CI_TCP_STATE_ACTIVE_WILD);
    aw->expiry = ci_ip_time_now(ni) + NI_CONF(ni).tconst_2msl_time;
    aw->last_laddr = sock_ipx_laddr(s);
    aw->last_raddr = sock_ipx_raddr(s);
    aw->last_rport = sock_rport_be16(s);
  }
}
#endif /* CI_CFG_TCP_SHARED_LOCAL_PORTS */


#if OO_DO_STACK_POLL
void oo_tcpdump_free_pkts(ci_netif* ni, ci_uint16 i)
{
  ci_uint16 read_i = ni->state->dump_read_i;

  ci_assert(ci_netif_is_locked(ni));

  /* Ensure reader has finished reading before we free packets. */
  ci_mb();

  do {
    oo_pkt_p id = ni->state->dump_queue[i % CI_CFG_DUMPQUEUE_LEN];
    if( id != OO_PP_NULL ) {
      ci_ip_pkt_fmt* pkt = PKT_CHK(ni, id);
      ni->state->dump_queue[i % CI_CFG_DUMPQUEUE_LEN] = OO_PP_NULL;
      ci_wmb();
      ci_netif_pkt_release(ni, pkt);
    }
  } while( (++i - read_i) % CI_CFG_DUMPQUEUE_LEN );
}
#endif


#if CI_CFG_UL_INTERRUPT_HELPER && ! defined(__KERNEL__)

static void sw_update_cb(void* arg, void* data)
{
  ci_netif* ni = arg;
  struct oo_sw_filter_op* op = data;

  ci_assert(ci_netif_is_locked(ni));

  oo_sw_filter_apply(ni, op);
}

/* Do actions asked by kernel.
 * Some actions should be performed immediatedly (sw filter update
 * must happen before the stack poll), others may go to stack lock
 * and deferred to unlock function.
 */
void ci_netif_handle_actions(ci_netif* ni)
{
  ci_int32 val = ci_atomic_xchg(&ni->state->action_flags, 0);

  ci_assert(ci_netif_is_locked(ni));

  /* Poll to process incoming FIN, and close endpoint from unlock hook. */
  if( val & OO_ACTION_CLOSE_EP )
    ef_eplock_holder_set_flags(&ni->state->lock,
                               CI_EPLOCK_NETIF_CLOSE_ENDPOINT |
                               CI_EPLOCK_NETIF_NEED_POLL);

  if( val & OO_ACTION_SWF_UPDATE )
    oo_ringbuffer_iterate(&ni->sw_filter_ops, sw_update_cb, ni);
}

static void close_cb(void* arg, void* data)
{
  ci_netif* ni = arg;
  oo_sp* id_p = data;

  ci_assert(ci_netif_is_locked(ni));
  ci_assert(IS_VALID_SOCK_P(ni, *id_p));

  citp_waitable_all_fds_gone(ni, *id_p);
}

/* Ask kernel for any sockets to be closed and really close them */
void ci_netif_close_pending(ci_netif* ni)
{
  oo_ringbuffer_iterate(&ni->closed_eps, close_cb, ni);
}
#endif
/*! \cidoxg_end */
