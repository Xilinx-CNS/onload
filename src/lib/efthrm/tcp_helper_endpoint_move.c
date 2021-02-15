/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2013-2020 Xilinx, Inc. */
/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: djr
**     Started: 2008/02/20
** Description: Implementation of "ops" invoked by user-level.
** </L5_PRIVATE>
\**************************************************************************/

#include <ci/internal/transport_config_opt.h>
#include <onload/linux_onload_internal.h>
#include <onload/tcp_helper_endpoint.h>
#include <onload/tcp_helper_fns.h>
#include <onload/version.h>
#include <onload/oof_interface.h>

#if CI_CFG_ENDPOINT_MOVE

static int efab_file_move_supported_tcp(ci_netif *ni, ci_tcp_state *ts,
                                        int drop_filter, int do_assert)
{
#if CI_CFG_FD_CACHING
  /* Don't support moving cached sockets for now */
  if( ci_tcp_is_cached(ts) ||
      !oo_p_dllink_is_empty(ni, oo_p_dllink_sb(ni, &ts->s.b,
                                               &ts->epcache_link)) ) {
    if( do_assert ) {
      ci_assert( ! ci_tcp_is_cached(ts) );
      OO_P_DLLINK_ASSERT_EMPTY_SB(ni, &ts->s.b, &ts->epcache_link);
    }
    return false;
  }
#endif
  /* Offload plugin has no API for updating the VI info  */
  if( ci_tcp_is_pluginized(ts) )
    return false;

  /* TCP closed: supported */
  if( ts->s.b.state == CI_TCP_CLOSED ) {
    /* Closed sockets should have no filter, exception being dummy filters,
     * which is the case with bound wild clustered sockets. We cannot move
     * this filter but we can drop it if been told to do so. */
    ci_assert(! oof_socket_is_armed(&(ci_netif_ep_get(ni, ts->s.b.bufid)->
                                      oofilter)));
    if( do_assert && drop_filter ) {
      ci_assert_equal(ci_netif_ep_get(ni, ts->s.b.bufid)->
                      oofilter.sf_local_port,
                      NULL);
    }
    return ci_netif_ep_get(ni, ts->s.b.bufid)->oofilter.sf_local_port == NULL ||
           drop_filter;
  }

  /* everything except TCP connected is not supported */
  if( !(ts->s.b.state & CI_TCP_STATE_TCP_CONN) ||
      ts->local_peer != OO_SP_NULL ||
      !(ts->tcpflags & CI_TCPT_FLAG_PASSIVE_OPENED) ) {
    if( do_assert ) {
      ci_assert_flags(ts->s.b.state, CI_TCP_STATE_TCP_CONN);
      ci_assert_equal(ts->local_peer, OO_SP_NULL);
      ci_assert_flags(ts->tcpflags, CI_TCPT_FLAG_PASSIVE_OPENED);
    }
    return false;
  }

  /* send queue is not supported
   * NB: retrans_ptr is uninitialised when retrans was not used yet,
   * so do not check for !OO_PP_IS_NULL(ts->retrans_ptr) */
  if( !ci_ip_queue_is_empty(&ts->send) ||
      ts->send_prequeue != OO_PP_ID_NULL ||
      oo_atomic_read(&ts->send_prequeue_in) != 0 ||
      !ci_ip_queue_is_empty(&ts->retrans) ||
      ci_ip_timer_pending(ni, &ts->rto_tid) ||
      ci_ip_timer_pending(ni, &ts->zwin_tid) ||
      ci_ip_timer_pending(ni, &ts->cork_tid) ||
      OO_PP_NOT_NULL(ts->pmtus) ) {
    if( do_assert ) {
      ci_assert(ci_ip_queue_is_empty(&ts->send));
      ci_assert_equal(ts->send_prequeue, OO_PP_ID_NULL);
      ci_assert_equal(oo_atomic_read(&ts->send_prequeue_in), 0);
      ci_assert(ci_ip_queue_is_empty(&ts->retrans));
      ci_assert(! ci_ip_timer_pending(ni, &ts->rto_tid));
      ci_assert(! ci_ip_timer_pending(ni, &ts->zwin_tid));
      ci_assert(! ci_ip_timer_pending(ni, &ts->cork_tid));
      ci_assert(OO_PP_IS_NULL(ts->pmtus));
    }
    return false;
  }

  /* non-trivial recv queue is not supported */
  if( ts->recv1_extract != ts->recv1.head ) {
    if( do_assert )
      ci_assert_equal(ts->recv1_extract, ts->recv1.head);
    return false;
  }

  /* Sockets with allocated templates are not supported */
  if( OO_PP_NOT_NULL(ts->tmpl_head) ) {
    if( do_assert )
      ci_assert(OO_PP_IS_NULL(ts->tmpl_head));
    return false;
  }

  /* Sockets in time-wait linked lists are not supported.
   * It is easy to unlink the old and link up the new socket, but this have
   * not been done. */
  if( ! oo_p_dllink_is_empty(ni, oo_p_dllink_sb(ni, &ts->s.b,
                                                &ts->timeout_q_link)) ) {
    if( do_assert )
      OO_P_DLLINK_ASSERT_EMPTY_SB(ni, &ts->s.b, &ts->timeout_q_link);
    return false;
  }

  return true;
}
static int efab_file_move_supported_udp(ci_netif *ni, ci_udp_state *us,
                                        int do_assert)
{
  /* Unbound (without filters) sockets only */
  if( ci_netif_ep_get(ni, us->s.b.bufid)->oofilter.sf_local_port != NULL ) {
    if( do_assert ) {
      ci_assert_equal(ci_netif_ep_get(ni, us->s.b.bufid)->
                      oofilter.sf_local_port,
                      NULL);
    }
    return false;
  }

  /* Do not copy any packets */
  if( ci_udp_recv_q_not_empty(&us->recv_q) ||
      us->zc_kernel_datagram != OO_PP_ID_NULL ||
      us->zc_kernel_datagram_count != 0 ||
      us->tx_count != 0 || us->tx_async_q != CI_ILL_END ) {
    if( do_assert ) {
      ci_assert(! ci_udp_recv_q_not_empty(&us->recv_q));
      ci_assert_equal(us->zc_kernel_datagram, OO_PP_ID_NULL);
      ci_assert_equal(us->zc_kernel_datagram_count, 0);
      ci_assert_equal(us->tx_count, 0);
      ci_assert_equal(us->tx_async_q, CI_ILL_END);
    }
    return false;
  }

  return true;
}

/* Returns true if move of this endpoint is supported */
static int __efab_file_move_supported(ci_netif *ni, ci_sock_cmn *s,
                                      int drop_filter, int do_assert)
{

#if CI_CFG_TIMESTAMPING
  /* We do not copy TX timestamping queue yet. */
  if( s->timestamping_flags != 0 ) {
    if( do_assert )
      ci_assert_equal(s->timestamping_flags, 0);
    return false;
  }
#endif

  /* UDP:  */
  if( s->b.state == CI_TCP_STATE_UDP )
    return efab_file_move_supported_udp(ni, SOCK_TO_UDP(s), do_assert);

  /* TCP or UDP only */
  if( ! (s->b.state & CI_TCP_STATE_TCP ) ) {
    if( do_assert )
      ci_assert_flags(s->b.state, CI_TCP_STATE_TCP);
    return false;
  }

  /* No listening sockets */
  if( s->b.state == CI_TCP_LISTEN ) {
    if( do_assert )
      ci_assert_nequal(s->b.state, CI_TCP_LISTEN);
    return false;
  }

  return efab_file_move_supported_tcp(ni, SOCK_TO_TCP(s), drop_filter, do_assert);
}
static int efab_file_move_supported(ci_netif *ni, ci_sock_cmn *s,
                                    int drop_filter)
{
  return __efab_file_move_supported(ni, s, drop_filter, 0);
}
static void efab_assert_file_move_supported(ci_netif *ni, ci_sock_cmn *s,
                                            int drop_filter)
{
  ci_assert(__efab_file_move_supported(ni, s, drop_filter, 1));
}


static int efab_ip_queue_copy(ci_netif *ni_to, ci_ip_pkt_queue *q_to,
                               ci_netif *ni_from, ci_ip_pkt_queue *q_from)
{
  ci_ip_pkt_fmt *pkt_to, *pkt_from;
  oo_pkt_p pp;

  ci_ip_queue_init(q_to);
  if( q_from->num == 0 )
    return 0;

  ci_assert( OO_PP_NOT_NULL(q_from->head) );
  pp = q_from->head;
  do {
    pkt_from = PKT_CHK(ni_from, pp);
    pkt_to = ci_netif_pkt_alloc(ni_to, 0);
    if( pkt_to == NULL )
      return -ENOBUFS;
    pkt_to->flags |= CI_PKT_FLAG_RX;
    ni_to->state->n_rx_pkts++;
    memcpy(&pkt_to->pay_len, &pkt_from->pay_len,
           CI_CFG_PKT_BUF_SIZE - CI_MEMBER_OFFSET(ci_ip_pkt_fmt, pay_len));
    ci_ip_queue_enqueue(ni_to, q_to, pkt_to);
    pp = pkt_from->next;
  } while( OO_PP_NOT_NULL(pp) );

  return 0;
}

/* Move priv file to the alien_ni stack.
 * Should be called with the locked priv stack and socket;
 * the function returns with this stack being unlocked.
 * If rc=0, it returns with alien_ni stack locked;
 * otherwise, both stacks are unlocked.
 * Original socket is always unlocked on return,
 * while on success the new_socket is kept locked.
 * Filters might be requested to be dropped in the process */
int efab_file_move_to_alien_stack(ci_private_t *priv, ci_netif *alien_ni,
                                  int drop_filter, oo_sp* new_sock_id)
{
  tcp_helper_resource_t *old_thr = priv->thr;
  tcp_helper_resource_t *new_thr = netif2tcp_helper_resource(alien_ni);
  ci_sock_cmn *old_s = SP_TO_SOCK(&old_thr->netif, priv->sock_id);
  ci_sock_cmn *new_s;
  ci_sock_cmn *mid_s;
  tcp_helper_endpoint_t *old_ep, *new_ep;
  int rc, i;
  struct file *old_os_file, *new_os_file;
  unsigned long lock_flags;
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  oo_p sp;
#endif
  struct oo_p_dllink_state link;

  OO_DEBUG_TCPH(ci_log("%s: move %d:%d to %d", __func__,
                       old_thr->id, priv->sock_id, new_thr->id));

  ci_assert(new_sock_id != NULL);
  /* Lock the second stack */
  i = 0;
  while( ! ci_netif_trylock(alien_ni) ) {
    ci_netif_unlock(&old_thr->netif);
    if( i++ >= 1000 ) {
      rc = -EBUSY;
      goto fail1_ni_unlocked;
    }
    /* We are trying to win a race for locking of the new stack.
     * The lock might be held either by one of the stack workqueues or
     * an app.  Workqueue tasks might take long time (pkt set alloc or
     * reset) but they eventually complete - so let us wait untill
     * they have finished.
     * More of an issue is that an app might be spinning on the lock -
     * we should be able to get it if we spin ourselves for a while; or
     * might be performing a long op such as hw filter insertion or a
     * stack poll - empirically we spin long enough to outlive couple of
     * filter insertions. In all of these cases when we contend with app
     * there is a fair chance we might give up prematurely and fail to move
     * the socket.
     * Finally, an app might have reverse dependency or the stack
     * lock is stuck - that is why we need to give up eventually.
     */
    flush_workqueue(new_thr->wq);
    flush_workqueue(new_thr->reset_wq);
    rc = ci_netif_lock(&old_thr->netif);
    if( rc != 0 )
      goto fail1_ni_unlocked;
  }

  /* Poll the old stack - deliver all data to our socket */
  ci_netif_poll(&old_thr->netif);

  /* Endpoints in epoll list should not be moved, because waitq is already
   * in the epoll internal structures (bug 41152). */
  if( !list_empty(&priv->_filp->f_ep_links) ) {
    rc = -EBUSY;
    goto fail1;
  }

  if( !efab_file_move_supported(&old_thr->netif, old_s, drop_filter) ) {
    rc = -EINVAL;
    goto fail1;
  }

  /* Allocate a new socket in the alien_ni stack */
  rc = -ENOMEM;
  if( old_s->b.state == CI_TCP_STATE_UDP ) {
    ci_udp_state *new_us = ci_udp_get_state_buf(alien_ni);
    if( new_us == NULL )
      goto fail2;
    new_s = &new_us->s;
  }
  else {
    ci_tcp_state *new_ts = ci_tcp_get_state_buf(alien_ni);
    if( new_ts == NULL )
      goto fail2;
    new_s = &new_ts->s;
  }

  /* Allocate an intermediate "socket" outside of everything */
  mid_s = ci_alloc(CI_MAX(sizeof(ci_tcp_state), sizeof(ci_udp_state)));
  if( mid_s == NULL )
    goto fail3;

  OO_DEBUG_TCPH(ci_log("%s: move %d:%d to %d:%d", __func__,
                       old_thr->id, priv->sock_id,
                       new_thr->id, new_s->b.bufid));

  /* Copy TCP/UDP state */
  memcpy(mid_s, old_s, CI_MAX(sizeof(ci_tcp_state), sizeof(ci_udp_state)));

  /* do not copy old_s->b.bufid
   * and other fields in stack adress space */
  mid_s->b.sb_aflags |= CI_SB_AFLAG_ORPHAN;
  mid_s->b.bufid = new_s->b.bufid;
  mid_s->b.post_poll_link = new_s->b.post_poll_link;
  mid_s->b.epoll = new_s->b.epoll;
  mid_s->b.ready_lists_in_use = 0;
  mid_s->reap_link = new_s->reap_link;

  if( tcp_helper_get_user_ns(old_thr) != tcp_helper_get_user_ns(new_thr) ) {
    /* Need to update the UID associated with this socket to be correct
     * for the new stack's user namespace.
     */
    uid_t kuid = ci_make_kuid(tcp_helper_get_user_ns(old_thr), old_s->uuid);
    mid_s->uuid = ci_from_kuid_munged(tcp_helper_get_user_ns(new_thr), kuid);
  }

  if( old_s->b.state & CI_TCP_STATE_TCP ) {
    ci_tcp_state *new_ts = SOCK_TO_TCP(new_s);
    ci_tcp_state *mid_ts = SOCK_TO_TCP(mid_s);

    mid_ts->timeout_q_link = new_ts->timeout_q_link;
    mid_ts->rto_tid = new_ts->rto_tid;
    mid_ts->delack_tid = new_ts->delack_tid;
    mid_ts->zwin_tid = new_ts->zwin_tid;
    mid_ts->kalive_tid = new_ts->kalive_tid;
    mid_ts->cork_tid = new_ts->cork_tid;
#if CI_CFG_TCP_SOCK_STATS
    mid_ts->stats_tid = new_ts->stats_tid;
#endif
    ci_ip_queue_init(&mid_ts->recv1);
    ci_ip_queue_init(&mid_ts->recv2);
    ci_ip_queue_init(&mid_ts->send);
    ci_ip_queue_init(&mid_ts->retrans);
    mid_ts->send_prequeue = OO_PP_ID_NULL;
    new_ts->retrans_ptr = OO_PP_NULL;
    mid_ts->tmpl_head = OO_PP_NULL;
    oo_atomic_set(&mid_ts->send_prequeue_in, 0);

    *new_ts = *mid_ts;
#if CI_CFG_FD_CACHING
    link = oo_p_dllink_sb(alien_ni, &new_ts->s.b, &new_ts->epcache_link);
    oo_p_dllink_init(alien_ni, link);
    link = oo_p_dllink_sb(alien_ni, &new_ts->s.b, &new_ts->epcache_fd_link);
    oo_p_dllink_init(alien_ni, link);
#endif
#if CI_CFG_TCP_OFFLOAD_RECYCLER
    /* We banned pluginized sockets in efab_file_move_supported_tcp(), so only
     * need to reinitialise here. */
    sp = TS_OFF(alien_ni, new_ts);
    OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_tcp_state, recycle_link));
    ci_ni_dllist_link_init(alien_ni, &new_ts->recycle_link, sp, "eprc");
    ci_ni_dllist_self_link(alien_ni, &new_ts->recycle_link);
#endif

    /* free temporary mid_ts storage */
    CI_FREE_OBJ(mid_ts);
  }
  else {
    ci_udp_state *mid_us = SOCK_TO_UDP(mid_s);

    *SOCK_TO_UDP(new_s) = *mid_us;
    CI_FREE_OBJ(mid_us);
  }

  /* Move the filter */
  old_ep = ci_trs_ep_get(old_thr, priv->sock_id);
  new_ep = ci_trs_ep_get(new_thr, new_s->b.bufid);
  rc = tcp_helper_endpoint_move_filters_pre(old_ep, new_ep, drop_filter);
  if( rc != 0 ) {
    rc = -EINVAL;
    goto fail3;
  }

  /* Read all already-arrived packets after the filters move but before
   * copying of the receive queue. */
  ci_netif_poll(&old_thr->netif);
  if( old_s->b.state & CI_TCP_STATE_TCP ) {
    ci_tcp_state *new_ts = SOCK_TO_TCP(new_s);
    ci_tcp_state *old_ts = SOCK_TO_TCP(old_s);

    /* Adjust netif reserved_pktbufs value because the socket is moved into
       the new Onload stack. */
    new_thr->netif.state->reserved_pktbufs +=
        ci_tcp_rx_reserved_bufs(&new_thr->netif, new_ts);

    ci_tcp_rx_buf_account_begin(&new_thr->netif, new_ts);
    rc = efab_ip_queue_copy(alien_ni, &new_ts->recv1,
                            &old_thr->netif, &old_ts->recv1);
    ci_tcp_rx_buf_account_end(&new_thr->netif, new_ts);
    if( rc != 0 )
      goto fail4;
    ci_tcp_rx_buf_account_begin(&new_thr->netif, new_ts);
    rc = efab_ip_queue_copy(alien_ni, &new_ts->recv2,
                            &old_thr->netif, &old_ts->recv2);
    ci_tcp_rx_buf_account_end(&new_thr->netif, new_ts);
    if( rc != 0 )
      goto fail4;
  }

  /* Allocate a new file for the new endpoint */
  rc = onload_alloc_file(new_thr, new_s->b.bufid, priv->_filp->f_flags,
                         priv->fd_flags, &old_ep->alien_ref);
  if( rc != 0 )
    goto fail4;
  ci_assert(old_ep->alien_ref);

  new_ep->file_ptr = priv->_filp;

  /* Copy F_SETOWN_EX, F_SETSIG to the new file */
#ifdef F_SETOWN_EX
  rcu_read_lock();
  __f_setown(old_ep->alien_ref->_filp, priv->_filp->f_owner.pid,
             priv->_filp->f_owner.pid_type, 1);
  rcu_read_unlock();
#endif
  old_ep->alien_ref->_filp->f_owner.signum = priv->_filp->f_owner.signum;
  old_ep->alien_ref->_filp->f_flags |= priv->_filp->f_flags & O_NONBLOCK;

  /********* Point of no return  **********/
  ci_wmb();
  priv->fd_flags = OO_FDFLAG_EP_ALIEN;
  priv->_filp->f_op = &linux_tcp_helper_fops_alien;
  ci_wmb();

  tcp_helper_endpoint_move_filters_post(old_ep, new_ep);
  efab_assert_file_move_supported(&old_thr->netif, old_s, drop_filter);

  /* There's a gap between un-registering the old ep, and registering the
   * the new.  However, the notifications shouldn't be in use for sockets
   * that are in a state that can be moved, so this shouldn't be a problem.
   */
  oo_os_sock_poll_register(&old_ep->os_sock_poll, NULL);
  spin_lock_irqsave(&old_ep->lock, lock_flags);
  old_os_file = oo_file_xchg(&old_ep->os_socket, NULL);
  spin_unlock_irqrestore(&old_ep->lock, lock_flags);

  spin_lock_irqsave(&new_ep->lock, lock_flags);
  new_os_file = oo_file_xchg(&new_ep->os_socket, old_os_file);
  spin_unlock_irqrestore(&new_ep->lock, lock_flags);

  if( old_os_file != NULL && OO_ACCESS_ONCE(new_s->b.state) == CI_TCP_STATE_UDP )
    oo_os_sock_poll_register(&new_ep->os_sock_poll, old_os_file);
  if( new_os_file != NULL )
    fput(new_os_file);

  ci_bit_clear(&new_s->b.sb_aflags, CI_SB_AFLAG_ORPHAN_BIT);
  if( new_s->b.state == CI_TCP_ESTABLISHED )
    CI_TCP_STATS_INC_CURR_ESTAB(alien_ni);


  /* Copy/reset protocol-specific values */
  if( new_s->b.state & CI_TCP_STATE_TCP ) {
    ci_tcp_state *new_ts = SOCK_TO_TCP(new_s);
    ci_tcp_state *old_ts = SOCK_TO_TCP(old_s);
    int i;

    /* Stop timers */
    ci_ip_timer_clear(&old_thr->netif, &old_ts->kalive_tid);
    ci_ip_timer_clear(&old_thr->netif, &old_ts->delack_tid);

    /* Recv queue have already been copied */
    ci_tcp_rx_queue_drop(&old_thr->netif, old_ts, &old_ts->recv1);
    ci_tcp_rx_queue_drop(&old_thr->netif, old_ts, &old_ts->recv2);
    new_ts->recv1_extract = new_ts->recv1.head;
    
    /* Ensure we update rcv_added with the data received in the last
     * ci_netif_poll(). */
    new_ts->rcv_added = old_ts->rcv_added;
    tcp_rcv_nxt(new_ts) = tcp_rcv_nxt(old_ts);
    new_ts->ack_trigger = old_ts->ack_trigger;

    /* Drop reorder buffer */
    ci_ip_queue_init(&new_ts->rob);
    new_ts->dsack_block = OO_PP_INVALID;
    new_ts->dsack_start = new_ts->dsack_end = 0;
    for( i = 0; i <= CI_TCP_SACK_MAX_BLOCKS; i++ )
      new_ts->last_sack[i] = OO_PP_NULL;
    ci_tcp_rx_queue_drop(&old_thr->netif, old_ts, &old_ts->rob);

    /* Adjust netif reserved_pktbufs value because the socket is removed from
       the old Onload stack. */
    old_thr->netif.state->reserved_pktbufs -=
        ci_tcp_rx_reserved_bufs(&old_thr->netif, old_ts);
  }
  else {
    /* There should not be any recv q, but drop it to be sure */
    ci_udp_recv_q_init(&SOCK_TO_UDP(new_s)->recv_q);
    ci_udp_recv_q_drop(&old_thr->netif, &SOCK_TO_UDP(old_s)->recv_q);
  }

  /* Remove SO_LINGER flag from the old ep: we want to close it silently */
  old_s->s_flags &=~ CI_SOCK_FLAG_LINGER;

  /* Old ep: get out from any lists; the ep will be dropped as soon as
   * we update all file descriptors which reference it. */
  old_s->b.sb_flags |= CI_SB_FLAG_MOVED;

  link = oo_p_dllink_sb(&old_thr->netif, &old_s->b, &old_s->reap_link);
  oo_p_dllink_del(&old_thr->netif, link);

  link = oo_p_dllink_sb(&old_thr->netif, &old_s->b, &old_s->b.post_poll_link);
  oo_p_dllink_del_init(&old_thr->netif, link);

  /* Old stack can be unlocked */
  ci_netif_unlock(&old_thr->netif);

  efab_assert_file_move_supported(alien_ni, new_s, drop_filter);

  /* Move done: poll for any new data. */
  ci_netif_poll(alien_ni);

  if( new_s->b.state & CI_TCP_STATE_TCP ) {
    ci_tcp_state *new_ts = SOCK_TO_TCP(new_s);
    /* Timers setup: delack, keepalive */
    if( (new_ts->acks_pending & CI_TCP_ACKS_PENDING_MASK) > 0)
      ci_tcp_timeout_delack(alien_ni, new_ts);
    ci_tcp_kalive_reset(alien_ni, new_ts);
  }


  /* Old ep: we are done. */
  ci_bit_set(&old_s->b.sb_aflags, CI_SB_AFLAG_MOVED_AWAY_BIT);
  old_s->b.moved_to_stack_id = alien_ni->state->stack_id;
  old_s->b.moved_to_sock_id = new_s->b.bufid;
  *new_sock_id = new_s->b.bufid;
  if( ! list_empty(&priv->_filp->f_ep_links) )
    ci_bit_set(&old_s->b.sb_aflags, CI_SB_AFLAG_MOVED_AWAY_IN_EPOLL_BIT);

  ci_sock_unlock(&old_thr->netif, &old_s->b);
  ci_assert(ci_netif_is_locked(alien_ni));
  ci_assert(ci_sock_is_locked(alien_ni, &new_s->b));
  OO_DEBUG_TCPH(ci_log("%s: -> [%d:%d] %s", __func__,
                       new_thr->id, new_s->b.bufid,
                       ci_tcp_state_str(new_s->b.state)));
  return 0;

fail4:
  /* We clear the filters from the new ep.
   * For now, we do not need to re-insert old filters because hw filters
   * are alredy here (in case of accepted socket) or not needed.
   * We have not removed old sw filters yet. */
  tcp_helper_endpoint_move_filters_undo(old_ep, new_ep);
fail3:
  if( new_s->b.state & CI_TCP_STATE_TCP ) {
    ci_tcp_state *new_ts = SOCK_TO_TCP(new_s);
    ci_tcp_rx_queue_drop(alien_ni, new_ts, &new_ts->recv1);
    ci_tcp_rx_queue_drop(alien_ni, new_ts, &new_ts->recv2);
    ci_tcp_state_free(alien_ni, new_ts);
  }
  else {
    ci_udp_state_free(alien_ni, SOCK_TO_UDP(new_s));
  }
fail2:
fail1:
  ci_netif_unlock(alien_ni);
  ci_netif_unlock(&old_thr->netif);
fail1_ni_unlocked:
  ci_sock_unlock(&old_thr->netif, &old_s->b);
  OO_DEBUG_TCPH(ci_log("%s: rc=%d", __func__, rc));
  return rc;
}

int efab_file_move_to_alien_stack_rsop(ci_private_t *stack_priv, void *arg)
{
  ci_fixed_descriptor_t sock_fd = *(ci_fixed_descriptor_t *)arg;
  struct file *sock_file = fget(sock_fd);
  ci_private_t *sock_priv;
  tcp_helper_resource_t *old_thr;
  tcp_helper_resource_t *new_thr;
  citp_waitable *w;
  oo_sp new_sock_id;
  int rc;

  if( sock_file == NULL )
    return -EINVAL;
  if( !FILE_IS_ENDPOINT_SOCK(sock_file) ||
      ! (stack_priv->fd_flags & OO_FDFLAG_STACK) ) {
    fput(sock_file);
    return -EINVAL;
  }
  sock_priv = sock_file->private_data;
  ci_assert_nflags(sock_priv->fd_flags,
                   OO_FDFLAG_EP_MASK & ~(OO_FDFLAG_EP_TCP | OO_FDFLAG_EP_UDP));

  old_thr = sock_priv->thr;
  new_thr = stack_priv->thr;
  ci_assert(old_thr);
  ci_assert(new_thr);

  if( old_thr == new_thr ) {
    fput(sock_file);
    return 0;
  }

  if( tcp_helper_cluster_from_cluster(old_thr) != 0 ) {
    LOG_S(ci_log("%s: move_fd() not permitted on clustered stacks", __func__));
    fput(sock_file);
    return -EINVAL;
  }

  w = SP_TO_WAITABLE(&old_thr->netif, sock_priv->sock_id);
  rc = ci_sock_lock(&old_thr->netif, w);
  if( rc != 0 )
    goto sock_lock_fail;

  rc = ci_netif_lock(&old_thr->netif);
  if( rc != 0 )
    goto netif_lock_fail;

  rc = oo_thr_ref_get(new_thr->ref, OO_THR_REF_APP);
  if( rc != 0 )
    goto ref_get_fail;

  rc = efab_file_move_to_alien_stack(sock_priv, &stack_priv->thr->netif, 0,
                                     &new_sock_id);

  if( rc == 0 ) {
    ci_netif_unlock(&new_thr->netif);
    ci_sock_unlock(&new_thr->netif,
                   SP_TO_WAITABLE(&new_thr->netif, new_sock_id));
    fput(sock_file);
    return 0;
  }
  else {
    /* Stack and socket are unlocked by move_to_alien() in case of error. */
    oo_thr_ref_drop(new_thr->ref, OO_THR_REF_APP);
    fput(sock_file);
    return rc;
  }

 ref_get_fail:
  ci_netif_unlock(&old_thr->netif);
 netif_lock_fail:
  ci_sock_unlock(&old_thr->netif, w);
 sock_lock_fail:
  fput(sock_file);
  return rc;
}

/* Locking policy:
 * Enterance: priv->thr->netif is assumed to be locked.
 * Exit: all stacks (the client stack and the listener's stack) are
 * unlocked.
 */
int efab_tcp_loopback_connect(ci_private_t *priv, void *arg)
{
  struct oo_op_loopback_connect *carg = arg;
  ci_netif *alien_ni = NULL;
  oo_sp tls_id;
  int stack_locked;

  ci_assert(ci_netif_is_locked(&priv->thr->netif));
  carg->out_moved = 0;

  if( ! (priv->fd_flags & OO_FDFLAG_EP_TCP) )
    return -EINVAL;
  if( NI_OPTS(&priv->thr->netif).tcp_client_loopback !=
      CITP_TCP_LOOPBACK_TO_CONNSTACK &&
      NI_OPTS(&priv->thr->netif).tcp_client_loopback !=
      CITP_TCP_LOOPBACK_TO_LISTSTACK &&
      NI_OPTS(&priv->thr->netif).tcp_client_loopback !=
      CITP_TCP_LOOPBACK_TO_NEWSTACK) {
    ci_netif_unlock(&priv->thr->netif);
    return -EINVAL;
  }

  if( ~SP_TO_SOCK(&priv->thr->netif, priv->sock_id)->s_flags &
      CI_SOCK_FLAG_TPROXY ) {
    /* Create OS socket if it is not already here. */
    ci_os_file socketp;
    if( oo_os_sock_get_from_ep(efab_priv_to_ep(priv), &socketp) == 0 )
      oo_os_sock_put(socketp);
    else
      efab_tcp_helper_create_os_sock(priv);
  }

  while( iterate_netifs_unlocked(&alien_ni, OO_THR_REF_APP,
                                 OO_THR_REF_INFTY) == 0 ) {

    if( alien_ni->cplane->cp_netns != priv->thr->netif.cplane->cp_netns )
      continue; /* can't accelerate inter-namespace connections */
    if( !efab_thr_can_access_stack(netif2tcp_helper_resource(alien_ni),
                                   EFAB_THR_TABLE_LOOKUP_CHECK_USER) )
      continue; /* no permission to look in here */

    if( NI_OPTS(alien_ni).tcp_server_loopback == CITP_TCP_LOOPBACK_OFF )
      continue; /* server does not accept loopback connections */

    if( NI_OPTS(&priv->thr->netif).tcp_client_loopback !=
        CITP_TCP_LOOPBACK_TO_LISTSTACK &&
        NI_OPTS(alien_ni).tcp_server_loopback !=
        CITP_TCP_LOOPBACK_ALLOW_ALIEN_IN_ACCEPTQ )
      continue; /* options of the stacks to not match */

    if( NI_OPTS(&priv->thr->netif).tcp_client_loopback !=
        CITP_TCP_LOOPBACK_TO_LISTSTACK &&
        !efab_thr_user_can_access_stack(alien_ni->kuid, alien_ni->keuid,
                                        priv->thr) )
      continue; /* server can't accept our socket */

    tls_id = ci_tcp_connect_find_local_peer(alien_ni, 0 /* unlocked */,
                                            carg->dst_addr, carg->dst_port);

    if( OO_SP_NOT_NULL(tls_id) ) {
      int rc;
      tcp_helper_resource_t* alien_thr = netif2tcp_helper_resource(alien_ni);

      switch( NI_OPTS(&priv->thr->netif).tcp_client_loopback ) {
      case CITP_TCP_LOOPBACK_TO_CONNSTACK:
        /* connect_lo_toconn unlocks priv->thr->netif */
        carg->out_rc =
            ci_tcp_connect_lo_toconn(&priv->thr->netif, priv->sock_id,
                                     carg->dst_addr, alien_ni, tls_id);
        oo_thr_ref_drop(alien_thr->ref, OO_THR_REF_APP);
        return 0;

      case CITP_TCP_LOOPBACK_TO_LISTSTACK:
      {
        oo_sp new_sock_id;
        /* Nobody should be using this socket, so trylock should succeed.
         * Overwise we hand over the socket and do not accelerate this
         * loopback connection. */
        rc = ci_sock_trylock(&priv->thr->netif,
                             SP_TO_WAITABLE(&priv->thr->netif,
                                            priv->sock_id));
        if( rc == 0 ) {
          ci_netif_unlock(&priv->thr->netif);
          oo_thr_ref_drop(alien_thr->ref, OO_THR_REF_APP);
          return -ECONNREFUSED;
        }

        /* move_to_alien changes locks - see comments near it */
        rc = efab_file_move_to_alien_stack(priv, alien_ni, 1, &new_sock_id);
        if( rc != 0 ) {
          /* error - everything is already unlocked */
          oo_thr_ref_drop(alien_thr->ref, OO_THR_REF_APP);
          /* if we return error, UL will hand the socket over. */
          return rc;
        }
        /* now alien_ni and new_sock are locked */

        /* Connect again, using new endpoint */
        carg->out_rc =
            ci_tcp_connect_lo_samestack(
                          alien_ni, SP_TO_TCP(alien_ni, new_sock_id),
                          tls_id, &stack_locked);
        if( stack_locked )
          ci_netif_unlock(alien_ni);
        ci_sock_unlock(alien_ni, SP_TO_WAITABLE(alien_ni, new_sock_id));
        carg->out_moved = 1;
        return 0;
      }

      case CITP_TCP_LOOPBACK_TO_NEWSTACK:
      {
        tcp_helper_resource_t *new_thr;
        ci_resource_onload_alloc_t alloc;
        oo_sp new_sock_id;
        ci_netif_config_opts *opts;

        memset(&alloc, 0, sizeof(alloc));

        opts = ci_alloc(sizeof(*opts));
        if( opts == NULL ) {
          ci_netif_unlock(&priv->thr->netif);
          oo_thr_ref_drop(alien_thr->ref, OO_THR_REF_APP);
          return -ECONNREFUSED;
        }
        memcpy(opts, &NI_OPTS(&priv->thr->netif), sizeof(*opts));

        /* create new stack
         * todo: no hardware interfaces are necessary */
        strcpy(alloc.in_version, ONLOAD_VERSION);
        strcpy(alloc.in_uk_intf_ver, oo_uk_intf_ver);

        /* There will be no more active connections in the new stack
         * - tcp_shared_local_ports is useless. */
        opts->tcp_shared_local_ports = 0;

        /* Note: we will not attempt to create tproxy mode interfaces */
        rc = tcp_helper_alloc_kernel(&alloc, opts, 0, &new_thr);
        ci_free(opts);
        if( rc != 0 ) {
          ci_netif_unlock(&priv->thr->netif);
          oo_thr_ref_drop(alien_thr->ref, OO_THR_REF_APP);
          return -ECONNREFUSED;
        }

        rc = ci_sock_trylock(&priv->thr->netif,
                             SP_TO_WAITABLE(&priv->thr->netif,
                                            priv->sock_id));
        if( rc == 0 ) {
          ci_netif_unlock(&priv->thr->netif);
          oo_thr_ref_drop(alien_thr->ref, OO_THR_REF_APP);
          oo_thr_ref_drop(new_thr->ref, OO_THR_REF_APP);
          return -ECONNREFUSED;
        }

        /* move connecting socket to the new stack */
        rc = efab_file_move_to_alien_stack(priv, &new_thr->netif, 1,
                                           &new_sock_id);
        if( rc != 0 ) {
          /* error - everything is already unlocked */
          oo_thr_ref_drop(alien_thr->ref, OO_THR_REF_APP);
          oo_thr_ref_drop(new_thr->ref, OO_THR_REF_APP);
          return -ECONNREFUSED;
        }
        /* now new_thr->netif is locked */
        carg->out_moved = 1;
        carg->out_rc = -ECONNREFUSED;

        /* now connect via CITP_TCP_LOOPBACK_TO_CONNSTACK */
        /* connect_lo_toconn unlocks new_thr->netif */
        carg->out_rc =
            ci_tcp_connect_lo_toconn(&new_thr->netif, new_sock_id,
                                     carg->dst_addr, alien_ni, tls_id);
        oo_thr_ref_drop(alien_thr->ref, OO_THR_REF_APP);
        ci_sock_unlock(&new_thr->netif,
                       SP_TO_WAITABLE(&new_thr->netif, new_sock_id));
        return 0;
      }
      }
    }
    else if( tls_id == OO_SP_INVALID ) {
      iterate_netifs_unlocked_dropref(alien_ni, OO_THR_REF_APP);
      break;
    }
  }

  ci_netif_unlock(&priv->thr->netif);
  return -ENOENT;
}

#endif
