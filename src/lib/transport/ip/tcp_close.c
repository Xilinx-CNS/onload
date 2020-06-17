/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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
#ifdef __KERNEL__
# include <onload/linux_onload.h>
#endif
#include <onload/sleep.h>
#include <onload/tmpl.h>

#define LPF "tcp_close: "

#if OO_DO_STACK_POLL


/* Transform a listening socket back to a normal socket. */
void __ci_tcp_listen_to_normal(ci_netif* netif, ci_tcp_socket_listen* tls)
{
  citp_waitable_obj* wo = SOCK_TO_WAITABLE_OBJ(&tls->s);
  ci_tcp_state* ts = &wo->tcp;
#if CI_CFG_IPV6
  int af = ipcache_af(&ts->s.pkt);
#endif

  ci_assert(tls->n_listenq == 0);
  ci_assert_equal(ci_tcp_acceptq_n(tls), 0);
  ci_assert_equal(ci_tcp_acceptq_not_empty(tls), 0);

  ci_ip_timer_clear(netif, &tls->listenq_tid);
  ci_ni_dllist_remove_safe(netif, &tls->s.b.post_poll_link);

#if CI_CFG_IPV6
  ts->s.cp.laddr = ip4_addr_any;
  /*
   * Convert IPv6-ipcache into IPv4 state if necessary because
   * ci_tcp_state_reinit() is supposed to re-initialize ipcache as IPv4.
   */
  ci_tcp_ipcache_convert(AF_INET, ts);
#endif

  ci_tcp_state_reinit(netif, ts);

#if CI_CFG_IPV6
  if( (ts->s.cp.sock_cp_flags & OO_SCP_BOUND_ADDR) ) {
    if( IS_AF_INET6(af) )
      ci_tcp_ipcache_convert(AF_INET6, ts);
    /* Restore local address */
    ts->s.cp.laddr = ts->s.laddr;
  }
  ci_sock_set_raddr_port(&ts->s, addr_any, 0);
#endif
}


int ci_tcp_add_fin(ci_tcp_state* ts, ci_netif* netif)
{
  ci_ip_pkt_queue* sendq = &ts->send;
  ci_ip_pkt_fmt* pkt;
  ci_tcp_hdr *tcp_hdr;

  ci_assert(ci_netif_is_locked(netif));

  LOG_TC(log(FNTS_FMT "sendq_num=%d cork=%d", FNTS_PRI_ARGS(netif, ts),
             sendq->num, !!(ts->s.s_aflags & CI_SOCK_AFLAG_CORK)));

  if( sendq->num ) {
    /* Bang the fin on the end of the send queue. */
    pkt = PKT_CHK(netif, sendq->tail);
    tcp_hdr = TX_PKT_IPX_TCP(ipcache_af(&ts->s.pkt), pkt);
    tcp_hdr->tcp_flags |= CI_TCP_FLAG_FIN | CI_TCP_FLAG_PSH;
    tcp_enq_nxt(ts) += 1;
    pkt->pf.tcp_tx.end_seq = tcp_enq_nxt(ts);
    pkt->flags &=~ CI_PKT_FLAG_TX_MORE;
    ci_tcp_tx_advance(ts, netif);
    return 0;
  }

  /* We MUST NOT call ci_netif_pkt_alloc_block() here, because we MUST NOT
   * release the stack lock when we've already moved the TCP state but have
   * not yet sent the FIN itself.  Processing packet in such inconsistent
   * state results in weirdness. */
  pkt = ci_netif_pkt_alloc(netif, CI_PKT_ALLOC_USE_NONB);

  if( pkt ) {
    ci_tcp_enqueue_no_data(ts, netif, pkt);
  }
  else {
    LOG_U(log(LNTS_FMT "%s: out of pkt bufs",
              LNTS_PRI_ARGS(netif, ts), __FUNCTION__));
    CITP_STATS_NETIF_INC(netif, tcp_cant_fin);
    return -ENOBUFS;
  }
  return 0;
}


int __ci_tcp_shutdown(ci_netif* netif, ci_tcp_state* ts, int how)
{
  int rc;

  /* Behaviour of shutdown() on Linux is a bit eccentric.
  **
  ** SHUT_RD seems to put recv()s into a non-blocking mode: If no data
  ** available, return 0, else return the data.  ie. It doesn't prevent
  ** further data getting through.
  */

  ci_assert(netif);
  ci_assert(ts);
  ci_assert(ci_netif_is_locked(netif));

#if CI_CFG_PIO
  /* Free up any associated templated sends */
  if( how == SHUT_WR || how == SHUT_RDWR )
    ci_tcp_tmpl_free_all(netif, ts);
#endif

  /* "Not connected" here means a FIN has gone both ways.  ie. TIME-WAIT,
  ** CLOSED, CLOSING, LAST-ACK.  Also LISTEN and SYN-SENT of course.
  */
  if( ts->s.b.state & CI_TCP_STATE_NOT_CONNECTED ) {
    switch( ts->s.b.state ) {
    case CI_TCP_SYN_SENT:
      ci_tcp_drop(netif, ts, ECONNRESET);
      ts->s.rx_errno = ENOTCONN;
      return 0;

    case CI_TCP_CLOSING:
    case CI_TCP_LAST_ACK:
      /* already shut down */
      return 0;

    default:
      return -ENOTCONN;
    }
  }

  /* SHUT_RD case */
  if( how == SHUT_RD ) {
    ts->s.rx_errno = CI_SHUT_RD;
    ci_tcp_wake_not_in_poll(netif, ts, CI_SB_FLAG_WAKE_RX);
    return 0;
  }


  /* Now we should do SHUT_WR; set CI_SHUT_RD  also if necessary */
  if( ts->s.tx_errno != 0 ) {
    if( how == SHUT_RDWR ) {
      ts->s.rx_errno = CI_SHUT_RD;
      ci_tcp_wake_not_in_poll(netif, ts, CI_SB_FLAG_WAKE_RX);
    }
    return 0;
  }

  /* Minimise race condtion with spinning poll/select/epoll:
   * ci_tcp_set_slow_state() sets write event, so we set read event just
   * after this.  See bug 22390. */
  if( ts->s.b.state == CI_TCP_CLOSE_WAIT ) {
    ci_tcp_set_slow_state(netif, ts, CI_TCP_LAST_ACK);
    /* peer is going to TIME_WAIT and
     * ISN for next connection needs to be recorded */
    ci_tcp_prev_seq_remember(netif, ts);
  }
  else {
    ci_tcp_set_slow_state(netif, ts, CI_TCP_FIN_WAIT1);
  }
  /* if not tied to an fd, make sure we leave this state at some point */
#if CI_CFG_FD_CACHING
  if( ts->s.b.sb_aflags & (CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_IN_CACHE) )
#else
  if( ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN )
#endif
    ci_netif_fin_timeout_enter(netif, ts);

  if( how == SHUT_RDWR )
    ts->s.rx_errno = CI_SHUT_RD;
  ts->s.tx_errno = EPIPE;

  /* Ensure that the is no send prequeue. */
  ci_tcp_sendmsg_enqueue_prequeue(netif, ts, CI_TRUE);
  ci_tcp_set_flags(ts, CI_TCP_FLAG_FIN | CI_TCP_FLAG_ACK);

  /* Add the FIN now. */
  if( (rc = ci_tcp_add_fin(ts, netif)) != 0 ) {
    ts->tcpflags |= CI_TCPT_FLAG_FIN_PENDING;
    tcp_enq_nxt(ts) += 1;
    if( ci_ip_queue_is_empty(&ts->retrans) )
      ci_tcp_rto_set(netif, ts);
  }

  ci_tcp_wake_not_in_poll(netif, ts,
                          CI_SB_FLAG_WAKE_TX |
                          (how == SHUT_RDWR ? CI_SB_FLAG_WAKE_RX : 0));
  return 0;
}


#if CI_CFG_FD_CACHING
#ifdef __KERNEL__
#include <onload/linux_onload_internal.h>


/* Closes a cached fd. In the typical case, this boils down to sys_close. */
static void uncache_fd(ci_netif* ni, ci_tcp_state* ts)
{
  int fd  = ts->cached_on_fd;
  int pid = ts->cached_on_pid;
  int cur_tgid = task_tgid_vnr(current);
  LOG_EP(ci_log("Uncaching fd %d on pid %d running pid %d:%s", fd,
                pid, cur_tgid, current->comm));
  /* No tasklets or other bottom-halves - we always have "current" */
  ci_assert(current);
  if( !(ts->s.b.sb_aflags & CI_SB_AFLAG_IN_CACHE_NO_FD) &&
       (~current->flags & PF_EXITING) ) {
    /* If the process is exiting, there is nothing to do.
     * Otherwise, we try to close fd. */
    /* There is peril here.  We don't currently have the NO_FD flag set, so
     * close the fd via the kernel - hope that the fd isn't currently being
     * replaced.  We can't tell whether this has happened, as we can't rely
     * on the close having completed on kernels using deferred fput.  It's
     * probably feasible to handle this with some furtling with the fdtable,
     * but for now we just don't handle that case.
     */
    /* Fixme: we re-enter timewait and restart the timer.  It is wrong.
     * We should reuse already-calculated values which were in use before
     * we've called ci_netif_timeout_remove() above. */
    struct file* filp;

#ifdef EFRM_DO_NAMESPACES
    if( ci_netif_check_namespace(ni) < 0 )
      return;
#endif

    if( current->files != NULL ) {
      if( pid != cur_tgid ) {
        NI_LOG(ni, RESOURCE_WARNINGS,
               "%s: pid mismatch: cached_on_pid=%d current=%d:%s", __func__,
               pid, cur_tgid, current->comm);
      }
      else if( (filp = fget(fd)) == NULL ) {
        NI_LOG(ni, RESOURCE_WARNINGS,
               "%s: pid %d does not has cached file under fd=%d",
               __func__, fd, pid);
      }
      else if( filp->f_op != &linux_tcp_helper_fops_tcp ) {
        NI_LOG(ni, RESOURCE_WARNINGS,
               "%s: pid %d has unexpected file under fd=%d",
               __func__, fd, pid);
        fput(filp);
      }
      else {
        fput(filp);
        efab_linux_sys_close(fd);
      }
    }
    else {
      /* This should not happen, as uncache_fd() must not be deferred. */
      ci_log("%s: called from workqueue - cannot close file descriptor %d.",
             __func__, fd);
      ci_assert(0);
    }
  }
}

ci_inline void clear_cached_state(ci_tcp_state *ts)
{
  ci_atomic32_and(&ts->s.b.sb_aflags,
                  ~(CI_SB_AFLAG_IN_CACHE|CI_SB_AFLAG_IN_PASSIVE_CACHE));
  ts->cached_on_fd = -1;
  ts->cached_on_pid = -1;
}


/* Uncache an EP.
 * This unsets the cache related state:
 * - cached_on_fd
 * - cached_on_pid
 * - removes from cache queue
 * - removes filters if we're in a state where they would otherwise have been
 *   removed already
 * - frees fd
 * It should now be handled as normal when we process the close via all fds
 * gone.
 *
 * If called with non-NULL tls, then this will remove the cached
 * sockets on the listening socket.  Else removes the cached sockets
 * on the stack a.k.a. active caching.
 */
static void uncache_ep(ci_netif *netif, ci_tcp_socket_listen* tls,
                       ci_tcp_state *ts)
{
  LOG_EP(ci_log("Uncaching ep %d", S_FMT(ts)));
  ci_assert( ci_tcp_is_cached(ts) );

  ci_ni_dllist_link_assert_valid(netif, &ts->epcache_link);
  ci_ni_dllist_remove_safe(netif, &ts->epcache_link);
  
  /* EPs on the cached list have hw filters present, even though notionally
   * they are 'freed'.  So we clear filters here.  Note that we leave the
   * filters in place for cached EPs on the acceptq or pending lists because
   * they still need to be closed down, and in the non-cached case have
   * filters.  We can tell whether the EP is on the cached list as opposed to
   * pending or accept-q, because it will be in the closed state if and only
   * if it is on the cache list.
   */
  if (ts->s.b.state == CI_TCP_CLOSED)
    ci_tcp_ep_clear_filters(netif, S_SP(ts), 0);

  /* After we clear CI_SB_AFLAG_IN_CACHE flag, we are not
   * ci_tcp_is_timeout_orphan() any more.  Do not confuse other
   * parts of code: get out from timewait list. */
  if ( ci_tcp_is_timeout_orphan(ts) )
    ci_netif_timeout_remove(netif, ts);

  clear_cached_state(ts);

  /* The philosophy governing uncache_fd() and uncache_ep() is that the former
   * is called first and closes the fd, and the latter is called subsequently
   * (perhaps having been deferred) and frees the endpoint. This would be fine,
   * except that deferred fput() means we can't guarantee that the fd has
   * actually been generic_tcp_helper_close()d yet, so neither can we free the
   * state yet. We get around this by letting whichever of the two paths runs
   * last (given that each will run precisely once) do the cleanup, and we
   * control this using [CI_SB_AFLAG_IN_CACHE_NO_FD_BIT]. */
  /* Fixme: what about timewait? */
  if( ci_bit_test_and_set(&ts->s.b.sb_aflags, CI_SB_AFLAG_IN_CACHE_NO_FD_BIT) )
    efab_tcp_helper_close_endpoint(netif2tcp_helper_resource(netif), S_SP(ts), 0);

  if( tls ) {
    /* increase per socket counter even if passive cache is shared */
    ci_atomic32_inc((volatile ci_uint32*)
                    CI_NETIF_PTR(netif, tls->epcache.avail_stack));
    ci_atomic32_inc(&tls->cache_avail_sock);

    ci_assert_le(netif->state->passive_cache_avail_stack,
                 netif->state->opts.sock_cache_max);
    if( ~NI_OPTS(netif).scalable_filter_mode & CITP_SCALABLE_MODE_PASSIVE )
      ci_assert_le(tls->cache_avail_sock,
                   netif->state->opts.per_sock_cache_max);
  }
  else if( ts->s.s_flags & CI_SOCK_FLAG_SCALPASSIVE ) {
    ci_atomic32_inc(&netif->state->passive_cache_avail_stack);
    /* we do not know tls, so per-socket statistic cannot be updated */
    ci_assert_le(netif->state->passive_cache_avail_stack,
                 netif->state->opts.sock_cache_max);
  }
  else {
    ci_netif_state* ns = netif->state;
    ci_atomic32_inc(&ns->active_cache_avail_stack);
    ci_assert_le(ns->active_cache_avail_stack, ns->opts.sock_cache_max);
  }
}


/* If called with non-NULL tls, then this will remove the cached
 * sockets on the listening socket.  Else removes the cached sockets
 * on the stack a.k.a. active caching.
 */
static void
uncache_ep_list(ci_netif *netif, ci_tcp_socket_listen* tls,
                ci_ni_dllist_t *thelist)
{
  ci_ni_dllist_link* l = ci_ni_dllist_start(netif, thelist);
  ci_assert(ci_netif_is_locked(netif));
  while( l != ci_ni_dllist_end(netif, thelist) ) {
    ci_tcp_state* cached_state = CI_CONTAINER(ci_tcp_state, epcache_link, l);
    ci_ni_dllist_iter(netif, l);
    ci_assert(cached_state);
    ci_assert(ci_tcp_is_cached(cached_state));
    ci_ni_dllist_link_assert_valid(netif, &cached_state->epcache_link);
    uncache_ep(netif, tls, cached_state);
  }
}


/* This function closes any cached fds associated with this listening socket.
 * Compare ci_tcp_listen_shutdown_queues(), which, amongst its other duties,
 * tears down all caching state *other* than the fds. The critical thing is
 * that that function requires the stack lock, and so may be deferred, and so
 * cannot be guaranteed to run in the context of the caching process, while
 * this function does not require the lock, and so can always be run in the
 * correct context. */
void ci_tcp_listen_uncache_fds(ci_netif* netif, ci_tcp_socket_listen* tls)
{
  /* For scalable passive there will be nothing to do here */
  ci_ni_dllist_link* l = ci_ni_dllist_concurrent_start(netif,
                                                       &tls->epcache.fd_states);

  if( tls->s.s_flags & CI_SOCK_FLAG_SCALPASSIVE )
    return;
  while( l != ci_ni_dllist_end(netif, &tls->epcache.fd_states) ) {
    ci_tcp_state* cached_state = CI_CONTAINER(ci_tcp_state, epcache_fd_link, l);
    ci_ni_dllist_iter(netif, l);

    /* We don't free up cached state directly.  We call uncache_fd(), which
     * will close the fd, resulting in all_fds_gone being called, and we'll
     * tidy up from there.
     *   Also, we can't assert that the link is valid here, as there may be (a
     * maximum of) one push to the list in progress. We are guaranteed that
     * it's safe to walk the list, however.
     */
    ci_assert(cached_state);
    ci_assert(ci_tcp_is_cached(cached_state));
    uncache_fd(netif, cached_state);
  }
}


/* Drop the socket cache by freeing up epcache_pending and epcache_cache */
void ci_tcp_epcache_drop_cache(ci_netif* ni)
{
  unsigned id;
  ci_assert(ci_netif_is_locked(ni));
  for( id = 0; id < ni->state->n_ep_bufs; ++id ) {
    citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(ni, id);
    if( wo->waitable.state == CI_TCP_LISTEN ) {
      citp_waitable* w = &wo->waitable;
      ci_sock_cmn* s = CI_CONTAINER(ci_sock_cmn, b, w);
      ci_tcp_socket_listen* tls = SOCK_TO_TCP_LISTEN(s);
      ci_tcp_listen_uncache_fds(ni, tls);
      uncache_ep_list(ni, tls, &tls->epcache.pending);
      uncache_ep_list(ni, tls, &tls->epcache.cache);
    }
  }
}


void ci_tcp_active_cache_drop_cache(ci_netif* ni)
{
  ci_netif_state* ns = ni->state;
  ci_assert(ci_netif_is_locked(ni));
  uncache_ep_list(ni, NULL, &ns->active_cache.pending);
  uncache_ep_list(ni, NULL, &ns->active_cache.cache);
}


void ci_tcp_passive_scalable_cache_drop_cache(ci_netif* ni)
{
  ci_netif_state* ns = ni->state;
  ci_assert(ci_netif_is_locked(ni));
  uncache_ep_list(ni, NULL, &ns->passive_scalable_cache.pending);
  uncache_ep_list(ni, NULL, &ns->passive_scalable_cache.cache);
}

#endif
#endif


#if OO_DO_STACK_POLL

#ifndef __KERNEL__
static
#endif
/* Wait for SO_LINGER timeout (or ACKed send queue).
 * Starts with the stack locked, exits with the stack unlocked. */
void ci_tcp_linger(ci_netif* ni, ci_tcp_state* ts)
{
  /* This is called at user-level when a socket is closed if linger is
  ** enabled and has a timeout, and there is TX data outstanding.
  **
  ** Our job is to block until all data is successfully sent and acked, or
  ** until timeout.
  */
  ci_uint64 sleep_seq;
  int rc = 0;
  ci_uint32 timeout = ts->s.so.linger * 1000;
  int flags = CI_SLEEP_NETIF_LOCKED;

  LOG_TC(log("%s: "NTS_FMT, __FUNCTION__, NTS_PRI_ARGS(ni, ts)));

  ci_assert(ci_netif_is_locked(ni));
#ifndef __KERNEL__
  ci_assert(ts->s.b.sb_aflags & CI_SB_AFLAG_IN_CACHE);
#endif
  ci_assert(ts->s.s_flags & CI_SOCK_FLAG_LINGER);
  ci_assert(ts->s.b.state != CI_TCP_LISTEN);

  while( 1 ) {
    sleep_seq = ts->s.b.sleep_seq.all;
    ci_rmb();
    if( SEQ_EQ(tcp_enq_nxt(ts), tcp_snd_una(ts)) ) {
      break;
    }
    rc = ci_sock_sleep(ni, &ts->s.b, CI_SB_FLAG_WAKE_TX, flags,
                       sleep_seq, &timeout);
    flags = 0;
    if( rc )
      break;
  }
  if( flags )
    ci_netif_unlock(ni);
}
#endif

#if OO_DO_STACK_POLL
#if defined(__KERNEL__)
static
#endif
int ci_tcp_close(ci_netif* netif, ci_tcp_state* ts)
{
  ci_assert(netif);
  ci_assert(ts);
  ci_assert(ci_netif_is_locked(netif));
  ci_assert(ts->s.b.state != CI_TCP_LISTEN);

  if( ts->s.b.state == CI_TCP_CLOSED ) {
    LOG_TV(ci_log(LPF "%d CLOSE already closed", S_FMT(ts)));
    /* Still must clear filters in case socket is clustered. */
    ci_tcp_ep_clear_filters(netif, S_SP(ts), 0);
    if( ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN )
      ci_tcp_state_free(netif, ts);
    return 0;
  }

  if( (ts->s.b.sb_flags & CI_SB_FLAG_MOVED) )
    goto drop;

#if CI_CFG_TCP_OFFLOAD_RECYCLER
  ci_ni_dllist_remove_safe(netif, &ts->recycle_link);
#endif

  if( tcp_rcv_usr(ts) != 0 ) {
    /* Linux specific behaviour: send reset and ditch
     * connection if all rx data not read.
     */
    CI_TCP_EXT_STATS_INC_TCP_ABORT_ON_CLOSE(netif);
    LOG_TV(log(LPF "%d CLOSE sent RST, as rx data present added %u "
               "delivered %u tcp_rcv_usr=%u", S_FMT(ts), ts->rcv_added,
               ts->rcv_delivered, tcp_rcv_usr(ts)));
    ci_tcp_send_rst(netif, ts);
    goto drop;
  }
  if( ts->snd_delegated != 0 ) {
    CI_TCP_EXT_STATS_INC_TCP_ABORT_ON_DELEGATED_SEND(netif);
    ci_tcp_send_rst(netif, ts);
    goto drop;
  }
  if( (ts->s.s_flags & CI_SOCK_FLAG_LINGER) && ts->s.so.linger == 0 ) {
    /* Linux calls sk_prot->disconnect() in this case.  And increments
     * LINUX_MIB_TCPABORTONDATA. */
    CI_TCP_EXT_STATS_INC_TCP_ABORT_ON_DATA(netif);
    if( ! (ts->s.b.state & CI_TCP_STATE_NOT_CONNECTED) ) {
      /* TCP abort, drop connection, send reset only if connected,
      ** rfc793 p62.
      */
      LOG_TV(log(LPF "%d ABORT sent reset", S_FMT(ts)));
      ci_tcp_send_rst(netif, ts);
    }

    /* Do not drop a connection which is already in TIME_WAIT */
    if( ts->s.b.state != CI_TCP_TIME_WAIT )
      goto drop;
  }

  if( CI_UNLIKELY( ts->tcpflags & CI_TCPT_FLAG_FIN_PENDING ) )
    ci_tcp_resend_fin(ts, netif);

  if( (ts->s.b.state == CI_TCP_TIME_WAIT) ||
      (ts->s.b.state == CI_TCP_CLOSING)   ||
      (ts->s.b.state == CI_TCP_LAST_ACK) )
    return 0;

  if( ! (ts->s.b.state & CI_TCP_STATE_NOT_CONNECTED) ) {
    int rc;

    if( ts->s.b.sb_aflags & CI_SB_AFLAG_TCP_IN_ACCEPTQ ) {
      ci_tcp_send_rst(netif, ts);
      /* set error state to placate ci_tcp_set_slow_state's debug checks */
      ts->s.so_error = ECONNRESET;
      ts->s.tx_errno = EPIPE;
      ts->s.rx_errno = CI_SHUT_RD;
      /* do managed transition to CLOSED in order to maintain counters and
       * reserved pkt buffers state */
      ci_tcp_set_slow_state(netif, ts, CI_TCP_CLOSED);
      ci_tcp_ep_clear_filters(netif, S_SP(ts), 0);
      ci_tcp_state_free(netif, ts);
      return 0;
    }

    rc = __ci_tcp_shutdown(netif, ts, SHUT_RDWR);

    if( (ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN) &&
        ts->s.b.state == CI_TCP_CLOSED ) {
      ci_tcp_state_free(netif, ts);
    }
#ifndef __KERNEL__
    /* Socket caching + SO_LINGER.  In-kernel case is handled in
     * efab_tcp_helper_close_endpoint() */
    else if(
             (ts->s.s_flags & CI_SOCK_FLAG_LINGER) &&
             ! SEQ_EQ(tcp_enq_nxt(ts), tcp_snd_una(ts))
#if ! CI_CFG_UL_INTERRUPT_HELPER
            && (ts->s.b.sb_aflags & CI_SB_AFLAG_IN_CACHE)
#else
            /* Fixme: we should guarantee that this is running the right
             * process.
             */
#endif
           ) {
        ci_assert(ts->s.so.linger != 0);
        ci_tcp_linger(netif, ts);
        ci_netif_lock(netif);
    }
#endif
    return rc;
  }

 drop:
  LOG_TC(log(LPF "%d drop connection in %s state", S_FMT(ts), 
              ci_tcp_state_str(ts->s.b.state)));
  /* ci_tcp_drop should really drop connection instead of leaking it,
   * because we can get here only when asyncronyously closing alien
   * non-accepted connection from listen socket closure. */
  ci_bit_clear(&ts->s.b.sb_aflags, CI_SB_AFLAG_TCP_IN_ACCEPTQ_BIT);
  ci_tcp_drop(netif, ts, ECONNRESET);
  return 0;
}
#endif /* OO_DO_STACK_POLL */


#if (defined(__KERNEL__) && ! CI_CFG_UL_INTERRUPT_HELPER) || (! defined(__KERNEL__) && CI_CFG_UL_INTERRUPT_HELPER) 
void ci_tcp_listen_shutdown_queues(ci_netif* netif, ci_tcp_socket_listen* tls)
{
  int synrecvs;

  /* we are going to lock/unlock stacks, so do not call this from interrupt
   * context */
  ci_assert(ci_netif_is_locked(netif));

  /* clear up synrecv queue */
  LOG_TV(ci_log("%s: %d clear out synrecv queue", __FUNCTION__,
		S_FMT(tls)));
  if( tls->n_listenq != 0 )
    ci_ip_timer_clear(netif, &tls->listenq_tid);
  synrecvs = ci_tcp_listenq_drop_all(netif, tls);
  ci_assert_equal(tls->n_listenq, synrecvs);
  ci_assert_le(tls->n_listenq_new, synrecvs);
  tls->n_listenq -= synrecvs;
  tls->n_listenq_new = 0;

  /*
  ** close each associated socket that is not already accepted
  ** and free resources associated with sockets on acceptq
  */
  LOG_TV(log("%s: %d clear out accept queue (%d entries)", __FUNCTION__,
             S_FMT(tls), ci_tcp_acceptq_n(tls)));

  while( ci_tcp_acceptq_not_empty(tls) ) {
    citp_waitable* w;
    ci_tcp_state* ats;    /* accepted ts */

    w = ci_tcp_acceptq_get(netif, tls);

#if defined(__KERNEL__) && CI_CFG_ENDPOINT_MOVE
    if( w->sb_aflags & CI_SB_AFLAG_MOVED_AWAY ) {
      tcp_helper_resource_t *thr = NULL;
      oo_sp sp;
      ci_uint32 stack_id;
      ci_netif *ani;        /* netif of the accepted socket */

#ifdef NDEBUG
      if( in_interrupt() ) {
        LOG_U(log("%s: invalid acceptq member", __FUNCTION__));
        citp_waitable_obj_free(netif, w);
        continue;
      }
#else
      ci_assert(!in_interrupt());
#endif

      sp = w->moved_to_sock_id;
      stack_id = w->moved_to_stack_id;
      citp_waitable_obj_free(netif, w);
      /* do not use w any more */

      LOG_TV(log("%s: alien socket %d:%d in accept queue %d:%d", __FUNCTION__,
                 stack_id, OO_SP_FMT(sp), NI_ID(netif), S_FMT(tls)));

      if( efab_thr_table_lookup(NULL, NULL, stack_id,
                                EFAB_THR_TABLE_LOOKUP_CHECK_USER,
                                OO_THR_REF_BASE, &thr) != 0 ) {
        LOG_U(log("%s: listening socket %d:%d can't find "
                  "acceptq memeber %d:%d", __FUNCTION__,
                  netif->state->stack_id, tls->s.b.bufid, stack_id, sp));
        continue;
      }
      ani = &thr->netif;

      if( !(SP_TO_WAITABLE(ani, sp)->state & CI_TCP_STATE_TCP) ||
          SP_TO_WAITABLE(ani, sp)->state == CI_TCP_LISTEN ) {
        LOG_U(log("%s: listening socket %d:%d has non-TCP "
                  "acceptq memeber %d:%d", __FUNCTION__,
                  netif->state->stack_id, tls->s.b.bufid, stack_id, sp));
        oo_thr_ref_drop(thr->ref, OO_THR_REF_BASE);
        continue;
      }
      ats = SP_TO_TCP(ani, sp);

      /* Do not remove IN_ACCEPTQ flag: ci_tcp_close should know that we
       * are sending RST, not FIN. */
      ci_bit_clear(&ats->s.b.sb_aflags, CI_SB_AFLAG_ORPHAN_BIT);
      efab_tcp_helper_close_endpoint(thr, sp, 0);
      oo_thr_ref_drop(thr->ref, OO_THR_REF_BASE);
      continue;
    }
#endif

    ats = &CI_CONTAINER(citp_waitable_obj, waitable, w)->tcp;

    ci_assert(ci_tcp_is_cached(ats) ||
              (ats->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN));
    ci_assert(ats->s.b.sb_aflags & CI_SB_AFLAG_TCP_IN_ACCEPTQ);

#if CI_CFG_FD_CACHING
    /* We leave the acceptq flag for cached eps - the state free will be
     * triggered from the close once we've closed the fd.
     */
    if( !ci_tcp_is_cached(ats) )
#endif
      /* Remove acceptq flag to allow state free on drop */
        ci_bit_clear(&ats->s.b.sb_aflags, CI_SB_AFLAG_TCP_IN_ACCEPTQ_BIT);

    if( ats->s.b.state != CI_TCP_CLOSED &&
        ats->s.b.state != CI_TCP_TIME_WAIT ) {
      LOG_TV(log("%s: send reset to accepted connection", __FUNCTION__));
      ci_tcp_send_rst(netif, ats);
    }

    ci_tcp_drop(netif, ats, ECONNRESET);

#if CI_CFG_FD_CACHING
    if( ci_tcp_is_cached(ats) ) {
      LOG_EP(ci_log ("listen_shutdown - uncache from acceptq"));
      uncache_ep(netif, tls, ats);

      /* Remove acceptq flag to allow state free on drop */
      ci_bit_clear(&ats->s.b.sb_aflags, CI_SB_AFLAG_TCP_IN_ACCEPTQ_BIT);
    }
#endif
  }

  ci_assert_equal(ci_tcp_acceptq_n(tls), 0);

#if CI_CFG_FD_CACHING
  /* Above we uncached and closed EPs on the accept q.  While an EP is cached
   * it will move across three queues: the pending queue, the cached queue,
   * then the accept queue.  Here we ensure that any EPs on cached on the
   * cached list are uncached (and freed).
   */
  /* There will be nothing to do here for scalable passive */
  LOG_EP(ci_log("listen_shutdown - uncache all on cache list"));
  uncache_ep_list(netif, tls, &tls->epcache.cache);
  LOG_EP(ci_log("listen_shutdown - uncache all on pending list"));
  uncache_ep_list(netif, tls, &tls->epcache.pending);
#endif
}
#endif

#if defined(__KERNEL__) && CI_CFG_FD_CACHING
void ci_tcp_listen_update_cached(ci_netif* netif, ci_tcp_socket_listen* tls)
{
  tcp_helper_endpoint_t * cached_ep;
  ci_ni_dllist_link *l;
  ci_tcp_state *cached_state;

  /* Before we clear our filters we must update the filters for any connected
   * sockets which were accepted from our cache.  We do not update the filter
   * at accept time, to avoid having to enter the kernel.  This means that
   * their details remain those of the original accepted socket.  This is fine
   * while they can share our wild filter, but the details need to be correct
   * before they get their own full match filter.
   */

  while( (l = ci_ni_dllist_try_pop(netif, &tls->epcache_connected)) ) {
    cached_state = CI_CONTAINER(ci_tcp_state, epcache_link, l);
    ci_ni_dllist_self_link(netif, &cached_state->epcache_link);

    if( tls->s.s_flags & CI_SOCK_FLAG_SCALPASSIVE )
      continue;
    cached_ep = ci_netif_ep_get(netif, cached_state->s.b.bufid);
    tcp_helper_endpoint_update_filter_details(cached_ep);
  }
  ci_assert(ci_ni_dllist_is_valid(netif, &tls->epcache_connected.l));
  ci_assert(ci_ni_dllist_is_empty(netif, &tls->epcache_connected));

  if( tls->s.s_flags & CI_SOCK_FLAG_SCALPASSIVE )
    return;

  /* We also need to update the filters for the pending list, so they can be
   * shutdown cleanly.
   */
  l = ci_ni_dllist_start(netif, &tls->epcache.pending);
  while( l != ci_ni_dllist_end(netif, &tls->epcache.pending) ) {
    cached_state = CI_CONTAINER(ci_tcp_state, epcache_link, l);
    cached_ep = ci_netif_ep_get(netif, cached_state->s.b.bufid);

    tcp_helper_endpoint_update_filter_details(cached_ep);
    ci_ni_dllist_iter(netif, l);
  }
  ci_assert(ci_ni_dllist_is_valid(netif, &tls->epcache.pending.l));
}

#endif

#if OO_DO_STACK_POLL
void __ci_tcp_listen_shutdown(ci_netif* netif, ci_tcp_socket_listen* tls)
{
  int rc;
#if CI_CFG_UL_INTERRUPT_HELPER
  int saved_errno = errno;
#endif

  ci_assert(netif);
  ci_assert(tls);
  ci_assert(tls->s.b.state == CI_TCP_LISTEN);
  /* unlocked when called from ci_tcp_all_fds_gone() */
  ci_assert(ci_sock_is_locked(netif, &tls->s.b) ||
            (tls->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN));

  LOG_TV(ci_log("%s: S_FMT=%d", __FUNCTION__, S_FMT(tls)));

  /* We should re-bind socket on the next use if the port was determined by
   * OS. */
  if( ! (tls->s.s_flags & CI_SOCK_FLAG_PORT_BOUND) )
    tls->s.s_flags &= ~CI_SOCK_FLAG_BOUND;
  /* Shutdown the OS socket and clear out the filters. */
# ifdef __KERNEL__
  rc = tcp_helper_endpoint_shutdown(netif2tcp_helper_resource(netif),
                                    S_SP(tls), SHUT_RDWR, CI_TCP_LISTEN);
  if( rc == -EINVAL )
    /* This means there is no O/S socket.  This is expected when socket has
     * been closed, as the O/S socket has already been shutdown and
     * released.
     */
    rc = 0;
# else
  rc = ci_tcp_helper_endpoint_shutdown(netif, S_SP(tls),
                                       SHUT_RDWR, CI_TCP_LISTEN);
# endif
#if CI_CFG_UL_INTERRUPT_HELPER
  if( rc == -1 && errno == EINVAL ) {
    /* See the comment above - the socket is already closed */
    rc = 0;
    errno = saved_errno;
  }
  ci_tcp_listen_shutdown_queues(netif, tls);
#endif
  if( rc < 0 )
    LOG_E(ci_log("%s: [%d:%d] shutdown(os_sock) failed %d",
                 __FUNCTION__, NI_ID(netif), S_FMT(tls), rc));
}


void ci_tcp_all_fds_gone_common(ci_netif* ni, ci_tcp_state* ts)
{
  /* All process references to this socket have gone.  So we should
   * shutdown() if necessary, and arrange for all resources to eventually
   * get cleaned up.
   *
   * ci_netif_poll() is called just
   * before calling this function, so we're up-to-date.
   */
  ci_assert(ci_netif_is_locked(ni));
  ci_assert(ts->s.b.state & CI_TCP_STATE_TCP);

  /* If we are in a state where we time out orphaned connections: */
  if( (ts->s.b.state & CI_TCP_STATE_TIMEOUT_ORPHAN) &&
      !(ts->s.b.sb_flags & CI_SB_FLAG_MOVED) )
    ci_netif_fin_timeout_enter(ni, ts);

  /* Orphaned sockets do not need keepalive */
  if( ts->s.s_flags & CI_SOCK_FLAG_KALIVE ) {
    ts->s.s_flags &=~ CI_SOCK_FLAG_KALIVE;
    ci_tcp_kalive_check_and_clear(ni, ts);
    ts->ka_probes = 0;
  }
}

void ci_tcp_listen_all_fds_gone(ci_netif* ni, ci_tcp_socket_listen* tls,
                                int do_free)
{
  /* All process references to this socket have gone.  So we should
   * shutdown() if necessary, and arrange for all resources to eventually
   * get cleaned up.
   *
   * This is called by the driver only.  ci_netif_poll() is called just
   * before calling this function, so we're up-to-date.
   */
  ci_assert(ci_netif_is_locked(ni));
  ci_assert_equal(tls->s.b.state, CI_TCP_LISTEN);

  __ci_tcp_listen_shutdown(ni, tls);
  __ci_tcp_listen_to_normal(ni, tls);
  if( do_free )
    citp_waitable_obj_free(ni, &tls->s.b);
}


void ci_tcp_all_fds_gone(ci_netif* ni, ci_tcp_state* ts, int do_free)
{
  ci_tcp_all_fds_gone_common(ni, ts);

  /* This frees [ts] if appropriate. */
  if( do_free )
    ci_tcp_close(ni, ts);
}
#endif


#endif
/*! \cidoxg_end */
