/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: djr
**     Started: 2005/03/02
** Description: Packet buffer management.
** </L5_PRIVATE>
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */
#include "ip_internal.h"

#if !defined(__KERNEL__)
#include <onload/mmap.h>
#include <sys/shm.h>

pthread_mutex_t citp_pkt_map_lock = PTHREAD_MUTEX_INITIALIZER;

ci_ip_pkt_fmt* __ci_netif_pkt(ci_netif* ni, unsigned id)
{
  int rc;
  ci_ip_pkt_fmt* pkt = 0;
  unsigned setid = id >> CI_CFG_PKTS_PER_SET_S;
  void *p;

  ci_assert(id != (unsigned)(-1));

  pthread_mutex_lock(&citp_pkt_map_lock);
  /* Recheck the condition now we have the lock */
  if( PKT_BUFSET_U_MMAPPED(ni, setid) )
    /* The mapping appeared while we were waiting for the lock */
    goto got_pkt_out;

#if CI_CFG_PKTS_AS_HUGE_PAGES
  if( ni->packets->set[setid].shm_id >= 0 ) {
    p = shmat(ni->packets->set[setid].shm_id, NULL, 0);
    if( p == (void *)-1) {
      if( errno == EACCES ) {
        ci_log("Failed to mmap packet buffer for [%s] with errno=EACCES.\n"
               "Probably, you are using this stack from processes with "
               "different UIDs.\n"
               "Try either allowing user stack sharing: EF_SHARE_WITH=-1\n"
               "or turn off huge pages: EF_USE_HUGE_PAGES=0\n",
               ni->state->pretty_name);
      }
      else {
        ci_log("%s: shmat(0x%x) failed for pkt set %d (%d)", __FUNCTION__,
               ni->packets->set[setid].shm_id, setid, -errno);
      }
      goto out;
    }
  }
  else
#endif
  {
    rc = oo_resource_mmap(ci_netif_get_driver_handle(ni),
                          OO_MMAP_TYPE_NETIF,
                          CI_NETIF_MMAP_ID_PKTSET(setid),
                          CI_CFG_PKT_BUF_SIZE * PKTS_PER_SET,
                          OO_MMAP_FLAG_POPULATE,
                          &p);
    if( rc < 0 ) {
      ci_log("%s: oo_resource_mmap for pkt set %d failed (%d)",
             __FUNCTION__, setid, rc);
      goto out;
    }
  }
  ci_assert(p);
  ni->pkt_bufs[setid] = p;

 got_pkt_out:
  pkt = (ci_ip_pkt_fmt*) __PKT_BUF(ni, id);

 out:
  pthread_mutex_unlock(&citp_pkt_map_lock);
  if( CI_UNLIKELY(pkt == NULL) ) {
    ci_log("Failed to map packets!");
    ci_netif_unlock(ni);
    ci_fail(("Crashing..."));
  }
  return pkt;
}

#endif


int ci_netif_pktset_best(ci_netif* ni)
{
  int i, ret = -1, n_free = 0;
  
  for( i = 0; i < ni->packets->sets_n; i ++ ) {
    if( ni->packets->set[i].n_free > n_free ) {
      n_free = ni->packets->set[i].n_free;
      ret = i;
    }
    if( n_free >= CI_CFG_PKT_SET_HIGH_WATER ) {
      /* We've found a set which is almost-free.  Let's reuse it
       * to avoid pulling in any new sets, and keep all the used packets
       * in a small group of working sets. */
      return ret;
    }
  }
  return ret;
}


ci_ip_pkt_fmt* ci_netif_pkt_alloc_slow(ci_netif* ni, int flags)
{
  /* This is the slow path of ci_netif_pkt_alloc() and
  ** ci_netif_pkt_tx_tcp_alloc().  Either free pool is empty, or we have
  ** too few packets available to permit a tcp tx allocation.
  */
  ci_ip_pkt_fmt* pkt;
  int bufset_id;

  ci_assert(ci_netif_is_locked(ni));

  if( (flags & CI_PKT_ALLOC_USE_NONB) ||
      (ni->packets->n_free == 0 &&
       ni->packets->sets_n == ni->packets->sets_max) )
    if( (pkt = ci_netif_pkt_alloc_nonb(ni)) != NULL ) {
      --ni->state->n_async_pkts;
      CITP_STATS_NETIF_INC(ni, pkt_nonb_steal);
      pkt->flags &= ~CI_PKT_FLAG_NONB_POOL;
      return pkt;
    }

  if( flags & CI_PKT_ALLOC_FOR_TCP_TX )
    if(CI_UNLIKELY( ! ci_netif_pkt_tx_may_alloc(ni) ))
      return NULL;

  ci_assert_equal(ni->packets->id, NI_PKT_SET(ni));
  ci_assert_equal(ni->packets->set[NI_PKT_SET(ni)].n_free, 0);
  ci_assert(OO_PP_IS_NULL(ni->packets->set[NI_PKT_SET(ni)].free));
#if OO_DO_STACK_POLL
 again:
#endif
  bufset_id = ci_netif_pktset_best(ni);
  if( bufset_id != -1 ) {
    ci_netif_pkt_set_change(ni, bufset_id,
                            ci_netif_pkt_set_is_underfilled(ni, bufset_id));
    return ci_netif_pkt_get(ni, bufset_id);
  }

  while( ni->packets->sets_n < ni->packets->sets_max ) {
    int old_n_freepkts = ni->packets->n_free;
    int rc = ci_tcp_helper_more_bufs(ni);
    if( rc != 0 )
      break;
    CHECK_FREEPKTS(ni);
    if( old_n_freepkts == ni->packets->n_free )
      ci_assert_equal(ni->packets->sets_n, ni->packets->sets_max);
    if( ni->packets->n_free > 0 )
      break;
  }

#if OO_DO_STACK_POLL
  if( ! (flags & CI_PKT_ALLOC_NO_REAP) ) {
    if( ni->packets->n_free == 0 )
      ci_netif_try_to_reap(ni, 1);
    if( ni->packets->n_free > 0 )
      goto again;
  }
#endif

  return NULL;
}


ci_inline void __ci_dbg_poison_header(ci_ip_pkt_fmt* pkt, ci_uint32 pattern) 
{
  unsigned i;
  ci_uint32* pkt_u32 = (ci_uint32 *)oo_ether_hdr(pkt);
  ci_uint32 patn_u32 = CI_BSWAP_BE32(pattern);
  ci_uint32 len = (ETH_HLEN + ETH_VLAN_HLEN + 2) + sizeof(ci_ip4_hdr) + 
    sizeof(ci_tcp_hdr);
  for( i = 0; i < len/4; i++ )  pkt_u32[i] = patn_u32;
}


#if defined(__KERNEL__) && OO_DO_STACK_POLL
void ci_netif_set_merge_atomic_flag(ci_netif* ni)
{
  ci_uint64 val;
  int iter = 1000;
  while( 1 ) {
    val = ni->state->lock.lock;
    if( val & CI_EPLOCK_NETIF_MERGE_ATOMIC_COUNTERS )
      break;
    else if( ef_eplock_set_flags_if_locked(
                          &ni->state->lock,
                          CI_EPLOCK_NETIF_MERGE_ATOMIC_COUNTERS) ) {
      break;
    }
    else if(  ci_netif_trylock(ni) ) {
      ef_eplock_holder_set_flag(&ni->state->lock,
                                CI_EPLOCK_NETIF_MERGE_ATOMIC_COUNTERS);
      ci_netif_unlock(ni);
      break;
    }
    if( iter-- == 0 ) {
      ci_log("%s: [%d] failed to set MERGE_ATOMIC_COUNTERS flag, "
             "something nasty is going on with the shared state "
             "of the Onload stack", __func__, NI_ID(ni));
      break;
    }
  }
}
#endif

void ci_netif_pkt_free(ci_netif* ni, ci_ip_pkt_fmt* pkt
                       CI_KERNEL_ARG(int* p_netif_is_locked))
{
  ci_assert(pkt->refcount == 0);
#ifdef __KERNEL__
  ci_assert(p_netif_is_locked);
  ci_assert(!*p_netif_is_locked || ci_netif_is_locked(ni));
#else
  ci_assert(ci_netif_is_locked(ni));
#endif

  if( OO_PP_NOT_NULL(pkt->frag_next) ) {
#ifdef __KERNEL__
    ci_netif_pkt_release_mnl(ni, PKT_CHK(ni, pkt->frag_next),
                             p_netif_is_locked);
#else
    ci_netif_pkt_release(ni, PKT_CHK(ni, pkt->frag_next));
#endif
    pkt->frag_next = OO_PP_NULL;
  }

#if defined(__KERNEL__) && OO_DO_STACK_POLL
  if( CI_UNLIKELY( (! *p_netif_is_locked) &&
                   (~pkt->flags & CI_PKT_FLAG_NONB_POOL)) ) {
    /* It is useless to call ci_netif_lock(), because we can get here only
     * if previous call to ci_netif_lock() have failed with -ERESTARTSYS.
     * But we can try trylock(). */
    if( ci_netif_trylock(ni) ) {
      *p_netif_is_locked = 1;
    }
    else {
      /* We've failed to get the lock.  Release the packet to non-blocking
       * pool - it is better than nothing. */
      pkt->flags |= CI_PKT_FLAG_NONB_POOL;
    }
  }
#endif

  if( pkt->flags & CI_PKT_FLAG_RX )
    CI_NETIF_STATE_MOD(ni, *p_netif_is_locked, n_rx_pkts, -);
  __ci_netif_pkt_clean(pkt);
#if CI_CFG_POISON_BUFS
  if( NI_OPTS(ni).poison_rx_buf )
    __ci_dbg_poison_header(pkt, 0xDECEA5ED);
#endif

  if( pkt->flags & CI_PKT_FLAG_NONB_POOL ) { 
    ci_netif_pkt_free_nonb_list(ni, OO_PKT_P(pkt), pkt);
    CI_NETIF_STATE_MOD(ni, *p_netif_is_locked, n_async_pkts, +);
  }
  else {
    ci_assert(ci_netif_is_locked(ni));
    ci_netif_pkt_put(ni, pkt);
  }

#if defined(__KERNEL__) && OO_DO_STACK_POLL
  if( CI_UNLIKELY( ! *p_netif_is_locked ) ) {
    ci_netif_set_merge_atomic_flag(ni);
  }
#endif
}


#if OO_DO_STACK_POLL
int ci_netif_pkt_try_to_free(ci_netif* ni, int desperation, int stop_once_freed_n)
{
  unsigned id;
  int freed = 0;

  ci_assert(ci_netif_is_locked(ni));
  ci_assert_ge(desperation, 0);
  ci_assert_le(desperation, CI_NETIF_PKT_TRY_TO_FREE_MAX_DESP);

  /* We can't put arrays into the stats, so to avoid tests here we pretend
   * that we have an array.  This assertion should give some protection
   * against changes that break our assumption.
   */
  ci_assert(&ni->state->stats.pkt_scramble2 - &ni->state->stats.pkt_scramble0
            == CI_NETIF_PKT_TRY_TO_FREE_MAX_DESP);
  CITP_STATS_NETIF(++(&ni->state->stats.pkt_scramble0)[desperation]);

  for( id = 0; id < ni->state->n_ep_bufs; ++id ) {
    citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(ni, id);
    if( wo->waitable.state & CI_TCP_STATE_TCP_CONN )
      freed += ci_tcp_try_to_free_pkts(ni, &wo->tcp, desperation);
    else if( wo->waitable.state == CI_TCP_STATE_UDP )
      freed += ci_udp_try_to_free_pkts(ni, &wo->udp, desperation);
    if( freed >= stop_once_freed_n )
      return freed;
  }
  return freed;
}


int ci_netif_pkt_alloc_block(ci_netif* ni, ci_sock_cmn* s,
                             int* p_netif_locked,
                             int can_block,
                             ci_ip_pkt_fmt** p_pkt)
{
  int was_locked = *p_netif_locked;
  ci_ip_pkt_fmt* pkt;
  int rc;
  ci_tcp_state* ts = NULL;

 again:
  if( *p_netif_locked == 0 ) {
    if( (pkt = ci_netif_pkt_alloc_nonb(ni)) ) {
      *p_pkt = pkt;
      return 0;
    }
    if( ! ci_netif_trylock(ni) ) {
      rc = ci_netif_lock(ni);
      if(CI_UNLIKELY( ci_netif_lock_was_interrupted(rc) ))
        return rc;
      CITP_STATS_NETIF_INC(ni, udp_send_ni_lock_contends/*??*/);
    }
    *p_netif_locked = 1;
  }

  if( s->b.state & CI_TCP_STATE_TCP_CONN )
    ts = SOCK_TO_TCP(s);

  if( (pkt = ci_netif_pkt_tx_tcp_alloc(ni, ts)) ) {
    ++ni->state->n_async_pkts;
    if( ! was_locked ) {
      /* We would have preferred to have gotten this from the nonblocking
       * pool.  So arrange for it to be freed to that pool.
       */
      pkt->flags = CI_PKT_FLAG_NONB_POOL;
    }
    *p_pkt = pkt;
    return 0;
  }

  if( !can_block )
    return -ENOBUFS;
  
  *p_netif_locked = 0;
  rc = ci_netif_pkt_wait(ni, s, CI_SLEEP_NETIF_LOCKED);
  if( ci_netif_pkt_wait_was_interrupted(rc) )
    return rc;
  goto again;
}


int ci_netif_pkt_pass_to_kernel(ci_netif* ni, ci_ip_pkt_fmt* pkt)
{
  ci_assert(ci_netif_is_locked(ni));

#if CI_CFG_INJECT_PACKETS
#ifdef __KERNEL__
  if( ! (ni->flags & CI_NETIF_FLAG_MAY_INJECT_TO_KERNEL) )
#else
  if( ! (ni->state->flags & CI_NETIF_FLAG_DO_INJECT_TO_KERNEL) )
#endif
    return 0;

  if( pkt->intf_i < 0 || pkt->intf_i >= CI_CFG_MAX_INTERFACES ) {
    /* ignore loopback packets */
    CITP_STATS_NETIF_INC(ni, no_match_bad_intf_i);
    return 0;
  }

  /* Multicast packets can be replicated across multiple Onload stacks and so we
   * cannot simply inject non-matching multicast packets into the kernel.
   * However, in most cases we should not see kernel-destined multicast packets
   * anyway: the packet cannot have come via a MAC filter, since Onload only uses
   * unicast MAC filters, and if it matched an IP filter then it should be stolen
   * by Onload.  The only time we expect to be on this path, where a multicast
   * packet matched a hardware IP filter but did not match any socket, is when
   * the firmware is not capable of filtering by VLAN and the VLAN of the packet
   * is incorrect.  In this case the packet could usefully be delivered to the
   * kernel stack, but as cross-VLAN-stealing with low-latency firmware is a
   * long-standing limitation, and as this is a distinct problem from the one
   * that packet-injection was introduced to solve (namely the disruption of
   * kernel traffic resulting from the use of scalable filters), we make no
   * attempt to work around the aforementioned replication problem, and we just
   * drop the packet. */
  if( ci_eth_addr_is_multicast(oo_ether_dhost(pkt)) )
    return 0;

  /* offbuf for the first segment may be tweaked in attempt to deliver this
   * packet to Onload.  We have to restore it now. */
  oo_offbuf_set_start(&pkt->buf, oo_ether_hdr(pkt));

  /* Enqueue the packet for later injection into the kernel's network stack. */
  if( OO_PP_IS_NULL(ni->state->kernel_packets_head) ) {
    ci_assert(OO_PP_IS_NULL(ni->state->kernel_packets_tail));
    ci_assert_equal(ni->state->kernel_packets_pending, 0);
    ni->state->kernel_packets_head = OO_PKT_P(pkt);
  }
  else {
    PKT_CHK(ni, ni->state->kernel_packets_tail)->next = OO_PKT_P(pkt);
  }
  ++ni->state->kernel_packets_pending;
  ni->state->kernel_packets_tail = OO_PKT_P(pkt);
  pkt->next = OO_PP_NULL;

  return 1;
#else
  return 0;
#endif
}
#endif

/*! \cidoxg_end */
