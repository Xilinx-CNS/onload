/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Raw packet transmit.
**   \date  2003/08/19
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include "netif_tx.h"
#include <ci/tools/pktdump.h>
#include <ci/internal/pio_buddy.h>

#if OO_DO_STACK_POLL

static inline bool is_to_primary_vi(ci_ip_pkt_fmt* pkt)
{
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  return pkt->q_id == CI_Q_ID_NORMAL;
#else
  return true;
#endif
}


static inline int pkt_q_id(ci_ip_pkt_fmt* pkt)
{
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  return pkt->q_id;
#else
  return 0;
#endif
}


static inline void calc_csum_if_needed(ci_netif* ni, ef_vi* vi,
                                       ci_ip_pkt_fmt* pkt)
{
  /* Calculate packet checksum in case of AF_XDP */
  if( CI_UNLIKELY(vi->nic_type.arch == EF_VI_ARCH_AF_XDP &&
                  is_to_primary_vi(pkt)) ) {
    struct iovec my_iov[CI_IP_PKT_SEGMENTS_MAX];
    ci_uint8 protocol;

    ci_netif_pkt_to_host_iovec(ni, pkt, my_iov,
                               sizeof(my_iov) / sizeof(my_iov[0]));

    protocol = ipx_hdr_protocol(ci_ethertype2af(oo_tx_ether_type_get(pkt)),
                                oo_ipx_hdr(pkt));
    if( protocol == IPPROTO_TCP || protocol == IPPROTO_UDP )
      oo_pkt_calc_checksums(ni, pkt, my_iov);
  }
}


#if CI_CFG_CTPIO
static inline int tx_ctpio(ci_netif* ni, int intf_i, ef_vi* vi,
                           ci_ip_pkt_fmt* pkt, const ef_iovec *iov,
                           int iov_len)
{
  ci_netif_state_nic_t* nsn = &ni->state->nic[intf_i];
  struct iovec host_iov[CI_IP_PKT_SEGMENTS_MAX];
  int total_length;
  int rc;

  total_length = ci_netif_pkt_to_host_iovec(ni, pkt, host_iov,
                                      sizeof(host_iov) / sizeof(host_iov[0]));

  if( (nsn->oo_vi_flags & OO_VI_FLAGS_TX_CTPIO_ONLY) &&
      ef_vi_transmit_space_bytes(vi) < total_length)
    return -ENOSPC;

#ifdef __KERNEL__
  /* TODO EFCT The 'T' variant is reported by fake test hardware, which
     doesn't provide iomem.
   */
  if((vi->nic_type.arch == EF_VI_ARCH_EFCT) && (vi->nic_type.variant == 'T'))
    return -ENOSPC;
#endif

  oo_pkt_calc_checksums(ni, pkt, host_iov);
  ef_vi_transmitv_ctpio(vi, total_length, host_iov,
                        iov_len, nsn->ctpio_ct_threshold);
  CITP_STATS_NETIF_INC(ni, ctpio_pkts);
  rc = ef_vi_transmitv_ctpio_fallback(vi, iov, iov_len,
                                      OO_PKT_ID(pkt));
  ci_assert_equal(rc, 0);
  return rc;
}
#endif


/* [is_fresh] is a hint indicating that the requested TXs are latency-
 * sensitive. */
static void __ci_netif_dmaq_shove(ci_netif* ni, oo_pktq* dmaq, ef_vi* vi,
                                  int intf_i, int is_fresh)
{
  ci_ip_pkt_fmt* pkt = PKT_CHK(ni, dmaq->head);
  int rc;
#if CI_CFG_CTPIO
 #ifdef __KERNEL__
  int ctpio = 0;
 #else
  int ctpio = is_fresh;
 #endif

  /* In a non-CTPIO world, we don't need to track whether we've posted any DMA
   * descriptors because the caller has checked that we have available TXQ
   * space and so we're guaranteed to post some.  With CTPIO, though, we might
   * consume all of that space before trying DMAs, and so we need to keep track
   * of whether there are outstanding DMA descriptors to push at the end of the
   * function. */
  int posted_dma = 0;
#endif

  do {
    pkt = PKT_CHK(ni, dmaq->head);
    ci_assert(pkt->flags & CI_PKT_FLAG_TX_PENDING);
    ci_assert_equal(intf_i, pkt->intf_i);
    ci_assert_equal(dmaq, &ni->state->nic[intf_i].dmaq[pkt_q_id(pkt)]);
    {
      ef_iovec iov[CI_IP_PKT_SEGMENTS_MAX];
      int iov_len;

      calc_csum_if_needed(ni, vi, pkt);
      if( CI_UNLIKELY(vi->nic_type.arch == EF_VI_ARCH_EF100 &&
                      pkt->flags & CI_PKT_FLAG_INDIRECT) ) {
        ef_remote_iovec remote_iov[CI_IP_PKT_SEGMENTS_MAX];

        iov_len = ci_netif_pkt_to_remote_iovec(ni, pkt, remote_iov,
                                               sizeof(remote_iov) / sizeof(remote_iov[0]));
        rc = ef_vi_transmitv_init_extra(vi, NULL, remote_iov, iov_len, OO_PKT_ID(pkt));
#if CI_CFG_CTPIO
        if( rc >= 0 )
          posted_dma = 1;
#endif
      }
      else {
        iov_len = ci_netif_pkt_to_iovec(ni, pkt, iov,
                                        sizeof(iov) / sizeof(iov[0]));
        if( CI_UNLIKELY(iov_len < 0) )
          break;
#if CI_CFG_CTPIO
        if( ctpio && (iov_len < 1 || iov_len > CI_IP_PKT_SEGMENTS_MAX ||
                      ! ci_netif_may_ctpio(ni, intf_i, pkt->pay_len) ||
                      pkt->flags & CI_PKT_FLAG_INDIRECT) )
          ctpio = 0;
        ctpio |= !! (ni->state->nic[pkt->intf_i].oo_vi_flags & OO_VI_FLAGS_TX_CTPIO_ONLY);
        if( ctpio ) {
          ci_assert(! posted_dma);
          rc = tx_ctpio(ni, intf_i, vi, pkt, iov, iov_len);
        }
        else
#endif
        {
          rc = ef_vi_transmitv_init(vi, iov, iov_len, OO_PKT_ID(pkt));
#if CI_CFG_CTPIO
          if( rc >= 0 )
            posted_dma = 1;
#endif
        }
      }
      if( rc >= 0 ) {
        __oo_pktq_next(ni, dmaq, pkt, netif.tx.dmaq_next);
        CI_DEBUG(pkt->netif.tx.dmaq_next = OO_PP_NULL);
      }
      else {
        /* Descriptor ring is full. */
#if CI_CFG_STATS_NETIF
        if( (ci_uint32) dmaq->num > ni->state->stats.tx_dma_max )
          ni->state->stats.tx_dma_max = dmaq->num;
#endif
        break;
      }
    }
  }
  while( oo_pktq_not_empty(dmaq) );

#if CI_CFG_CTPIO
  /* If everything went out by CTPIO, there will be no outstanding DMA
   * descriptors to pushed, and we're finished.  Otherwise, we still need to
   * hit the doorbell for those DMA sends. */
  if( ! posted_dma )
    return;

  /* We're doing a DMA send, so there's no point attempting CTPIO now until
   * the TXQ has drained. */
  ci_netif_ctpio_desist(ni, intf_i);
#endif

  ef_vi_transmit_push(vi);
  CITP_STATS_NETIF_INC(ni, tx_dma_doorbells);
}


void ci_netif_dmaq_shove1(ci_netif* ni, int intf_i)
{
  ef_vi* vi = ci_netif_vi(ni, intf_i);
  if( ef_vi_transmit_space(vi) >= (ef_vi_transmit_capacity(vi) >> 1) )
    __ci_netif_dmaq_shove(ni, ci_netif_dmaq(ni, intf_i), vi, intf_i,
                          0 /*is_fresh*/);
}


void ci_netif_dmaq_shove2(ci_netif* ni, int intf_i, int is_fresh)
{
  ef_vi* vi = ci_netif_vi(ni, intf_i);
  if( ef_vi_transmit_space(vi) > CI_IP_PKT_SEGMENTS_MAX )
    __ci_netif_dmaq_shove(ni, ci_netif_dmaq(ni, intf_i), vi, intf_i, is_fresh);
}


void ci_netif_dmaq_shove_plugin(ci_netif* ni, int intf_i, int q_id)
{
  ef_vi* vi = &ni->nic_hw[intf_i].vis[q_id];
  ci_assert_ge(q_id, 1);
  if( ef_vi_transmit_space(vi) > CI_IP_PKT_SEGMENTS_MAX )
    __ci_netif_dmaq_shove(ni, &ni->state->nic[intf_i].dmaq[q_id], vi, intf_i,
                          0 /*is_fresh*/);
}


void __ci_netif_send(ci_netif* netif, ci_ip_pkt_fmt* pkt)
{
  int intf_i, rc;
  oo_pktq* dmaq;
  ef_vi* vi;
  ef_iovec iov[CI_IP_PKT_SEGMENTS_MAX];
  int iov_len;
#if CI_CFG_PIO
  ci_uint8 order;
  ci_int32 offset;
  ci_pio_buddy_allocator* buddy;
#endif

  ci_assert(netif);
  ci_assert(pkt);
  ci_assert(pkt->intf_i >= 0);
  ci_assert(pkt->intf_i < CI_CFG_MAX_INTERFACES);
  ci_assert_flags(pkt->flags, CI_PKT_FLAG_TX_PENDING);

  ___ci_netif_dmaq_insert_prep_pkt(netif, pkt);

  LOG_NT(log("%s: [%d] id=%d nseg=%d 0:["EF_ADDR_FMT":%d] dhost="
             CI_MAC_PRINTF_FORMAT, __FUNCTION__, NI_ID(netif),
             OO_PKT_FMT(pkt), pkt->n_buffers,
             pkt_dma_addr(netif, pkt, pkt->intf_i),
             pkt->buf_len, CI_MAC_PRINTF_ARGS(oo_ether_dhost(pkt))));

  /* Packets to non-primary VIs could be control messages to a plugin, so
   * there's no requirement that they be Ethernet (or any other recognisable
   * protocol). */
  ci_check( ! is_to_primary_vi(pkt) ||
            ! ci_eth_addr_is_zero((ci_uint8 *)oo_ether_dhost(pkt)));

  /*
   * Packets can be now be n fragments long. If the packet at the head of the
   * DMA overflow queue has multiple fragments we might succeed to add
   * this packet to the PT endpoint if we unconditional attempt to do this
   * (causing an out of order send). Therefore we have to check whether the
   * DMA overflow queue is empty before proceding
   */
  intf_i = pkt->intf_i;

  ci_assert_lt(pkt->q_id, CI_MAX_VIS_PER_INTF);
  dmaq = &netif->state->nic[intf_i].dmaq[pkt_q_id(pkt)];
  vi = &netif->nic_hw[intf_i].vis[pkt_q_id(pkt)];

  if( oo_pktq_is_empty(dmaq) && ! (pkt->flags & CI_PKT_FLAG_INDIRECT) ) {
#if CI_CFG_PIO
    /* pio_thresh is set to zero if PIO disabled on this stack, so don't
     * need to check NI_OPTS().pio here
     */
    order = ci_log2_ge(pkt->pay_len, CI_CFG_MIN_PIO_BLOCK_ORDER);
    buddy = &netif->state->nic[intf_i].pio_buddy;
    if( ! ci_netif_may_ctpio(netif, intf_i, pkt->pay_len) &&
        netif->state->nic[intf_i].oo_vi_flags & OO_VI_FLAGS_PIO_EN &&
        is_to_primary_vi(pkt) ) {
      if( pkt->pay_len <= NI_OPTS(netif).pio_thresh && pkt->n_buffers == 1 ) {
        if( (offset = ci_pio_buddy_alloc(netif, buddy, order)) >= 0 ) {
          rc = ef_vi_transmit_copy_pio(vi,
                                       offset, PKT_START(pkt), pkt->buf_len,
                                       OO_PKT_ID(pkt));
          if( rc == 0 ) {
            CITP_STATS_NETIF_INC(netif, pio_pkts);
            ci_assert(pkt->pio_addr == -1);
            pkt->pio_addr = offset;
            pkt->pio_order = order;
            goto done;
          }
          else {
            CITP_STATS_NETIF_INC(netif, no_pio_err);
            ci_pio_buddy_free(netif, buddy, offset, order);
            /* Continue and do normal send. */
          }
        }
        else {
          CI_DEBUG(CITP_STATS_NETIF_INC(netif, no_pio_busy));
        }
      }
      else {
        CI_DEBUG(CITP_STATS_NETIF_INC(netif, no_pio_too_long));
      }
    }
#endif
    calc_csum_if_needed(netif, vi, pkt);
    iov_len = ci_netif_pkt_to_iovec(netif, pkt, iov,
                                    sizeof(iov) / sizeof(iov[0]));

    /* CTPIO only NICs always claim to be able to do CTPIO, so the only
     * things that might stop them are packets that are split over multiple
     * buffers, which should be prevented by the declared MTU and indirect
     * packets, which aren't used with this NIC type.
     */
  if( netif->state->nic[pkt->intf_i].oo_vi_flags & OO_VI_FLAGS_TX_CTPIO_ONLY ) {
      ci_assert_gt(iov_len, 0);
      ci_assert_le(iov_len, CI_IP_PKT_SEGMENTS_MAX);
      ci_assert(is_to_primary_vi(pkt));
    }

#if CI_CFG_CTPIO
    if( (iov_len > 0) && (iov_len <= CI_IP_PKT_SEGMENTS_MAX) &&
        ci_netif_may_ctpio(netif, intf_i, pkt->pay_len) &&
        is_to_primary_vi(pkt) ) {
      rc = tx_ctpio(netif, intf_i, vi, pkt, iov, iov_len);
    }
    else
#endif
    if( (rc = ef_vi_transmitv(vi, iov, iov_len, OO_PKT_ID(pkt))) == 0 ) {
      /* After a DMA send, stop attempting CTPIO sends until the TXQ has
       * drained. */
      ci_netif_ctpio_desist(netif, intf_i);
      CITP_STATS_NETIF_INC(netif, tx_dma_doorbells);
    }
    if( rc == 0 ) {
      LOG_AT(ci_analyse_pkt(oo_ether_hdr(pkt), pkt->buf_len));
      LOG_DT(ci_hex_dump(ci_log_fn, oo_ether_hdr(pkt), pkt->buf_len, 0));
      goto done;
    }
  }

  /* drop to here if any of the above methods to send directly failed
   * - put it on the DMA queue instead
   */
  LOG_NT(log("%s: ENQ id=%d", __FUNCTION__, OO_PKT_FMT(pkt)));
  __ci_netif_dmaq_put(netif, dmaq, pkt);

 done:

  /* Poll every now and then to ensure we keep up with completions.  If we
   * don't do this then we can ignore completions for so long that we start
   * putting stuff on the overflow queue when we don't really need to.
   */
  if( netif->state->send_may_poll ) {
    ci_netif_state_nic_t* nsn = &netif->state->nic[intf_i];
    if( nsn->tx_dmaq_insert_seq - nsn->tx_dmaq_insert_seq_last_poll >
        NI_OPTS(netif).send_poll_thresh ) {
      nsn->tx_dmaq_insert_seq_last_poll = nsn->tx_dmaq_insert_seq;
      if( ci_netif_intf_has_event(netif, intf_i) ) {
        /* The poll call may get us back here, so we need to ensure that we
         * doesn't recurse back into another poll.
         */
        netif->state->send_may_poll = 0;
        ci_netif_poll_n(netif, NI_OPTS(netif).send_poll_max_events);
        netif->state->send_may_poll = 1;
      }
    }
  }
}


/* Transmit the given packet right now, failing if it can't be done
 * (ci_netif_send() will put deferrals on to the dmaq for later). This is a
 * low-level function used by VIs which are used for communicating with
 * plugins, where the caller typically has their own reliability policy and
 * hence they don't want automatic handling of it behind the scenes. */
bool ci_netif_send_immediate(ci_netif* netif, ci_ip_pkt_fmt* pkt,
                             const struct ef_vi_tx_extra* extra)
{
  int intf_i;
  ef_vi* vi;
  ef_iovec iov[CI_IP_PKT_SEGMENTS_MAX];
  int iov_len;

  ci_assert(netif);
  ci_assert(pkt);
  ci_assert_ge(pkt->intf_i, 0);
  ci_assert_lt(pkt->intf_i, CI_CFG_MAX_INTERFACES);
  ci_assert_flags(pkt->flags, CI_PKT_FLAG_TX_PENDING);
  ci_assert_nflags(pkt->flags, CI_PKT_FLAG_INDIRECT);

  LOG_NT(log("%s: [%d] id=%d nseg=%d 0:["EF_ADDR_FMT":%d] dhost="
             CI_MAC_PRINTF_FORMAT, __FUNCTION__, NI_ID(netif),
             OO_PKT_FMT(pkt), pkt->n_buffers,
             pkt_dma_addr(netif, pkt, pkt->intf_i),
             pkt->buf_len, CI_MAC_PRINTF_ARGS(oo_ether_dhost(pkt))));

  intf_i = pkt->intf_i;

  ci_assert_lt(pkt->q_id, CI_MAX_VIS_PER_INTF);
  vi = &netif->nic_hw[intf_i].vis[pkt_q_id(pkt)];

  iov_len = ci_netif_pkt_to_iovec(netif, pkt, iov,
                                  sizeof(iov) / sizeof(iov[0]));
  if( extra ) {
    int i;
    ef_remote_iovec riov[CI_IP_PKT_SEGMENTS_MAX];
    for( i = 0; i < iov_len; ++i) {
      riov[i] = (ef_remote_iovec){
        .iov_base = iov[i].iov_base,
        .iov_len = iov[i].iov_len,
        .flags = 0,
        .addrspace = EF_ADDRSPACE_LOCAL,
      };
    }
    if( ef_vi_transmitv_init_extra(vi, extra, riov, iov_len,
                                   OO_PKT_ID(pkt)) != 0 )
      return false;
    ef_vi_transmit_push(vi);
  }
  else {
    if( ef_vi_transmitv(vi, iov, iov_len, OO_PKT_ID(pkt)) != 0 )
      return false;
  }

  ___ci_netif_dmaq_insert_prep_pkt(netif, pkt);
  CITP_STATS_NETIF_INC(netif, tx_dma_doorbells);
  LOG_AT(ci_analyse_pkt(oo_ether_hdr(pkt), pkt->buf_len));
  LOG_DT(ci_hex_dump(ci_log_fn, oo_ether_hdr(pkt), pkt->buf_len, 0));

  return true;
}
#endif

/*! \cidoxg_end */
