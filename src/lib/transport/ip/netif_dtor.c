/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */

#include <onload/netif_dtor.h>

#if OO_DO_STACK_DTOR

/* Release all the deferred packets */
void oo_deferred_free(ci_netif *ni)
{
  CI_DEBUG(int n = 0;)
  ci_ni_dllist_link* l = ci_ni_dllist_start(ni, &ni->state->deferred_list);

  while( l != ci_ni_dllist_end(ni, &ni->state->deferred_list) ) {
    struct oo_deferred_pkt* dpkt = CI_CONTAINER(struct oo_deferred_pkt,
                                                link, l);
    ci_ni_dllist_iter(ni, l);

    cicp_pkt_complete_fake(ni, PKT_CHK(ni, dpkt->pkt_id));
    CI_DEBUG(n++;)
  }

  /* Every deferred packet was handled somehow: */
  ci_assert_equal(ni->state->stats.tx_defer_pkt +
                  ni->state->stats.tx_defer_pkt_fast,
                  ni->state->stats.tx_defer_pkt_sent +
                  ni->state->stats.tx_defer_pkt_drop_timeout +
                  ni->state->stats.tx_defer_pkt_drop_arp_failed +
                  ni->state->stats.tx_defer_pkt_drop_failed + n);
}


static int is_expecting_events(ci_netif* ni)
{
  int intf_i;

  if(  ni->state->poll_work_outstanding || OO_PP_NOT_NULL(ni->state->looppkts) )
    return 1;
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    ci_netif_state_nic_t* nic = &ni->state->nic[intf_i];
    if( ci_netif_intf_has_event(ni, intf_i) || 
         nic->tx_dmaq_insert_seq != nic->tx_dmaq_done_seq ) {
      return 1;
    }
  }
  return 0;
}


#ifdef __KERNEL__
#include <onload/tcp_helper_fns.h>
#define KHZ(ni) oo_timesync_cpu_khz
#else
#define KHZ(ni) IPTIMER_STATE(ni)->khz
#endif

void oo_netif_dtor_pkts(ci_netif* ni)
{
  ci_uint64 start = ci_frc64_get();

  if( ni->error_flags )
    return;

  ci_assert(ci_netif_is_locked(ni));

  /* If we have some events or wait for TX complete events,
   * we should handle them all. */
  while( is_expecting_events(ni) ) {
    ci_netif_poll(ni);
    if( ci_frc64_get() - start > KHZ(ni) ) {
      ci_log("%s: WARNING: [%d] Failed to get TX complete events "
             "for some packets", __func__, NI_ID(ni));
      return;
    }
  }

  /* Check for packet leak */
  ci_assert_equal(ni->packets->n_pkts_allocated,
                  pkt_sets_n(ni) << CI_CFG_PKTS_PER_SET_S);
  ci_assert_equal(ni->packets->n_free + ni->state->n_rx_pkts +
                  ni->state->n_async_pkts,
                  ni->packets->n_pkts_allocated);
}

/* Called when all the user applications have gone.
 * Returns the number of orphaned sockets which can't be dropped yet
 * (TIME-WAIT and so on).
 */
ci_uint32 oo_netif_apps_gone(ci_netif* netif)
{
  unsigned i;
  ci_uint32 orphaned;

  ci_assert(ci_netif_is_locked(netif));

 again:
  for( i=0, orphaned=0; i < ep_tbl_n(netif); i++ ) {
    citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(netif, i);
    citp_waitable* w = &wo->waitable;

    /* We don't expect ACTIVE_WILD endpoints to be freed yet - they're not
     * associated with a user file descriptor.  We will free them once
     * all their users have gone in the stack dtor.
     */
    if( w->state == CI_TCP_STATE_FREE || w->state == CI_TCP_STATE_AUXBUF ||
        w->state == CI_TCP_STATE_ACTIVE_WILD )
      continue;

    if( w->state == CI_TCP_CLOSED ) {
#if CI_CFG_FD_CACHING
      LOG_E(ci_log("%s [%u]: ERROR endpoint %d leaked state "
                   "(cached=%d/%d flags %x)", __FUNCTION__, NI_ID(netif),
                   i, wo->tcp.cached_on_fd, wo->tcp.cached_on_pid,
                   w->sb_aflags));
#else
      LOG_E(ci_log("%s [%u:%d]: ERROR endpoint leaked (flags %x)",
                   __FUNCTION__, NI_ID(netif), i, w->sb_aflags));
#endif
      if( (w->sb_aflags & CI_SB_AFLAG_TCP_IN_ACCEPTQ) ) {
        /* It happens with TCP loopback as a result of race condition,
         * when the listening stack is teared down at the same time.
         * Let's drop the endpoint properly. */
        ci_bit_clear(&w->sb_aflags, CI_SB_AFLAG_TCP_IN_ACCEPTQ_BIT);
        ci_assert(w->sb_aflags & CI_SB_AFLAG_ORPHAN);
        ci_tcp_drop(netif, &wo->tcp, ECONNRESET);
      }
      else {
        w->state = CI_TCP_STATE_FREE;
      }
      continue;
    }

    /* All user files are closed; all FINs should be sent.
     * There are some cases when we fail to send FIN to passively-opened
     * connection (see ON-2108): reset such connections. */
    if( w->state & CI_TCP_STATE_TCP_CONN && wo->sock.tx_errno == 0 ) {
      if( OO_SP_IS_NULL(wo->tcp.local_peer) ||
          (~w->sb_aflags & CI_SB_AFLAG_TCP_IN_ACCEPTQ) ) {
        /* It is normal for EF_TCP_SERVER_LOOPBACK=2,4 if client closes
         * loopback connection before it is accepted. */
        LOG_E(ci_log("%s: %d:%d in %s state when stack is closed",
                     __func__, NI_ID(netif), i, ci_tcp_state_str(w->state)));
      }
      /* Make sure the receive queue is freed,
       * to avoid packet leak warning: */
      ci_bit_clear(&w->sb_aflags, CI_SB_AFLAG_TCP_IN_ACCEPTQ_BIT);
      ci_assert(w->sb_aflags & CI_SB_AFLAG_ORPHAN);
      ci_tcp_send_rst(netif, &wo->tcp);
      ci_tcp_drop(netif, &wo->tcp, ECONNRESET);
      if( OO_SP_NOT_NULL(wo->tcp.local_peer) ) {
        ci_netif_poll(netif); /* push RST through the stack */
        /* It closed the other end, which may be already counted in
         * n_ep_orphaned.  Let's start again */
        goto again;
      }
      continue;
    }

    LOG_NC(ci_log("%s [%u]: endpoint %d in state %s", __FUNCTION__,
                  NI_ID(netif), i, ci_tcp_state_str(w->state)));
    /* \TODO: validate connection,
     *          - do we want to mark as closed or leave to close?
     *          - timers OK ?
     * for now we we just check the ORPHAN flag
     */
    if( ! (w->sb_aflags & CI_SB_AFLAG_ORPHAN) ) {
      LOG_E(ci_log("%s [%u]: ERROR found non-orphaned endpoint %d in"
                   " state %s", __FUNCTION__, NI_ID(netif),
                   i, ci_tcp_state_str(w->state) ));
      ci_bit_set(&w->sb_aflags, CI_SB_AFLAG_ORPHAN_BIT);
    }
    ++orphaned;
  }

  LOG_NC(ci_log("%s: [%u] %d socket(s) closing", __FUNCTION__,
                NI_ID(netif), orphaned));
  return orphaned;
}

#endif /* OO_DO_STACK_DTOR */
