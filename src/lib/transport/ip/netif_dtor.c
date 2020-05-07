
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
#endif /* OO_DO_STACK_DTOR */
