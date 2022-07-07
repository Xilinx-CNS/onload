/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2008-2020 Xilinx, Inc. */
#ifndef __NETIF_TX_H__
#define __NETIF_TX_H__

#include <ci/efhw/common.h>


/**********************************************************************
 * Sending packet helper
 */

ci_inline void ci_netif_pkt_tx_assert_len(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                          unsigned n)
{
#ifndef NDEBUG
  ci_ip_pkt_fmt* first = pkt;
  int i, t = 0;
  for( i = 0; ; ) {
    t += pkt->buf_len;
    ci_assert_le(t, first->pay_len);
    if( ++i == n )
      break;
    pkt = PKT_CHK(ni, pkt->frag_next);
  }
  ci_assert_equal(t, first->pay_len);
#endif
}


ci_inline int
ci_netif_pkt_to_remote_iovec(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                             ef_remote_iovec** piov, uint32_t* prefix_len,
                             unsigned iovlen)
{
  int i, intf_i = pkt->intf_i;
  struct ci_pkt_zc_header* zch;
#if CI_CFG_TX_CRC_OFFLOAD
  struct ci_pkt_zc_payload* zcp;
  unsigned zcp_offset;
#endif
  ef_remote_iovec* iov;
  ef_remote_iovec* prefix_iov;
  char* prefix_start;
  char* prefix_end;

  ci_assert_flags(pkt->flags, CI_PKT_FLAG_INDIRECT);
  ci_assert_lt((unsigned) intf_i, CI_CFG_MAX_INTERFACES);
  ci_assert_ge(iovlen, pkt->n_buffers);

  zch = oo_tx_zc_header(pkt);

  /* The prefix is built up in the first iovec using the space reserved at the
   * end of the packet buffer, and everything else starts at the second iovec.
   * If it turns out that we don't have a prefix, we'll not return this first
   * iovec. */
  prefix_iov = *piov;
  prefix_start = (char*)pkt + CI_CFG_PKT_BUF_SIZE - zch->prefix_spc;
  prefix_end = prefix_start;
  iov = prefix_iov + 1;

  iov[0].iov_base = pkt_dma_addr(ni, pkt, intf_i) + pkt->pkt_start_off;
  iov[0].iov_len = pkt->buf_len;
  iov[0].addrspace = EF_ADDRSPACE_LOCAL;
  iov[0].flags = 0;

  ci_assert_equal(pkt->n_buffers, 1);
  /* One iovec for the inline data above, one reserved for the prefix if we
   * might need one, and one for each ZC payload. */
  ci_assert_ge(iovlen, 1 + (zch->prefix_spc > 0) + zch->segs);
  i = 1;
#if CI_CFG_TX_CRC_OFFLOAD
  zcp_offset = pkt->buf_len;
  OO_TX_FOR_EACH_ZC_PAYLOAD(ni, zch, zcp) {
    if( zcp->zcp_flags & ZC_PAYLOAD_FLAG_ACCUM_CRC &&
        ~pkt->flags & CI_PKT_FLAG_RTQ_RETRANS ) {
      ci_int8 prefix_size = ci_tcp_offload_zc_send_accum_crc(ni, pkt, zcp,
                                                              zcp_offset,
                                                              prefix_end);
      if( prefix_size < 0 ) {
        LOG_NT(log("%s: NVME plugin idp full, pkt id=%d", __FUNCTION__,
                   OO_PKT_ID(pkt)));
        /* The caller will free the IDs that we've allocated so far. */
        return -EAGAIN;
      }
      prefix_end += prefix_size;
    }
    if( zcp->zcp_flags & ZC_PAYLOAD_FLAG_INSERT_CRC )
      prefix_end += ci_tcp_offload_zc_send_insert_crc(ni, pkt, zcp, zcp_offset, prefix_end);
    zcp_offset += zcp->len;
    if( zcp->is_remote ) {
      iov[i].iov_base = zcp->remote.dma_addr[intf_i];
      iov[i].addrspace = zcp->remote.addr_space;
    } else {
      iov[i].iov_base = pkt_dma_addr(ni, pkt, intf_i) +
                                     (zcp->local - (char*)pkt->dma_start);
      iov[i].addrspace = EF_ADDRSPACE_LOCAL;
    }
    iov[i].flags = 0;
    iov[i].iov_len = zcp->len;
    ++i;
  }
#endif

  if( prefix_end > prefix_start ) {
    prefix_iov->iov_base = (pkt_dma_addr(ni, pkt, intf_i) -
                            CI_MEMBER_OFFSET(ci_ip_pkt_fmt, dma_start) +
                            CI_CFG_PKT_BUF_SIZE - zch->prefix_spc);
    prefix_iov->iov_len = prefix_end - prefix_start;
    ci_assert_le(prefix_iov->iov_len, zch->prefix_spc);
    prefix_iov->addrspace = EF_ADDRSPACE_LOCAL;
    prefix_iov->flags = 0;
#if ! CI_CFG_NVME_LOCAL_CRC_MODE
    *prefix_len = prefix_iov->iov_len;
    iov = prefix_iov;
    ++i;
#else
#ifndef __KERNEL__
    printf("%s: dumping %d byte prefix\n", __func__, prefix_iov->iov_len);
    ci_hex_dump(ci_log_fn, prefix_start, prefix_iov->iov_len, 0);
    printf("  packet: buf_len=%d iovcnt=%d  [ ", pkt->buf_len, i);
    {
      int j;
      for( j = 0; j < i; ++j )
        printf("%d ", iov[j].iov_len);
    }
    printf("]\n");
#endif
#endif
  }

  *piov = iov;
  return i;
}

ci_inline int ci_netif_pkt_to_iovec(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                    ef_iovec* iov, unsigned iovlen)
{
  int i, intf_i = pkt->intf_i;
  unsigned n = pkt->n_buffers;

  ci_assert_lt((unsigned) intf_i, CI_CFG_MAX_INTERFACES);
  ci_assert_ge(iovlen, n);

#if CI_CFG_NETIF_HARDEN
  if( n > iovlen )
    n = iovlen;
#endif

  iov[0].iov_base = pkt_dma_addr(ni, pkt, intf_i) + pkt->pkt_start_off;
  iov[0].iov_len = pkt->buf_len;

  if(CI_UNLIKELY( pkt->flags & CI_PKT_FLAG_INDIRECT )) {
    struct ci_pkt_zc_header* zch = oo_tx_zc_header(pkt);
    struct ci_pkt_zc_payload* zcp;

    ci_assert_equal(n, 1);
    ci_assert_ge(iovlen, 1 + zch->segs);
    i = 1;
    OO_TX_FOR_EACH_ZC_PAYLOAD(ni, zch, zcp) {
      if( zcp->is_remote ) {
        if(CI_UNLIKELY( zcp->remote.addr_space != EF_ADDRSPACE_LOCAL )) {
          LOG_E(log("%s: remote address spaces not supported on pre-EF100 hardware",
                    __FUNCTION__));
          return -1;
        }

        iov[i].iov_base = zcp->remote.dma_addr[intf_i];
      }
      else
        iov[i].iov_base = pkt_dma_addr(ni, pkt, intf_i) +
                          (zcp->local - (char*)pkt->dma_start);
      iov[i].iov_len = zcp->len;
      ++i;
    }
    return i;
  }

  ci_netif_pkt_tx_assert_len(ni, pkt, n);
  if(CI_UNLIKELY( n > 1 )) {
    for( i = 1; i < n; ++i ) {
      pkt = PKT_CHK(ni, pkt->frag_next);
      iov[i].iov_base = pkt_dma_addr(ni, pkt, intf_i) + pkt->pkt_start_off;
      iov[i].iov_len = pkt->buf_len;
    }
  }
  return n;
}


ci_inline unsigned ci_netif_pkt_to_host_iovec(ci_netif* ni,
                                              ci_ip_pkt_fmt* pkt,
                                              struct iovec* iov,
                                              unsigned iovlen)
{
  unsigned n = pkt->n_buffers;
  int i;
  unsigned total_length = 0;

  ci_assert_lt((unsigned) pkt->intf_i, CI_CFG_MAX_INTERFACES);
  ci_assert_ge(iovlen, n);

#if CI_CFG_NETIF_HARDEN
  if( n > iovlen )
    n = iovlen;
#endif

  ci_netif_pkt_tx_assert_len(ni, pkt, n);

  for( i = 0; ; ) {
    iov[i].iov_base = pkt->dma_start + pkt->pkt_start_off;
    iov[i].iov_len = pkt->buf_len;
    total_length += pkt->buf_len;
    if( ++i == n )
      return total_length;
    pkt = PKT_CHK(ni, pkt->frag_next);
  }
}

/**********************************************************************
 * CTPIO.
 */

ci_inline int /*bool*/ ci_netif_may_ctpio(ci_netif* ni, int intf_i,
                                          size_t frame_len)
{
#if CI_CFG_CTPIO
  const ci_netif_state_nic_t* nsn = &ni->state->nic[intf_i];
  /* On arches where CTPIO is the only option we always want to try it */
  if( nsn->oo_vi_flags & OO_VI_FLAGS_TX_CTPIO_ONLY )
    return 1;

 #ifndef __KERNEL__
  /* Only use CTPIO if not desisted, frame length is below threshold, and
   * TX ring is not very full.  (It is essential that we have room to post
   * a fallback).
   */
  {
    ef_vi* vi = ci_netif_vi(ni, intf_i);
    int max_fill;

    max_fill = ef_vi_transmit_capacity(vi) >> 2;
    return frame_len <= nsn->ctpio_frame_len_check &&
          ef_vi_transmit_fill_level(vi) < max_fill;
  }
 #else
  return 0;
 #endif
#else
  return 0;
#endif
}

ci_inline void ci_netif_ctpio_desist(ci_netif* ni, int intf_i)
{
#if CI_CFG_CTPIO
  ci_netif_state_nic_t* nsn = &ni->state->nic[intf_i];
  nsn->ctpio_frame_len_check = 0;
#endif
}

ci_inline void ci_netif_ctpio_resume(ci_netif* ni, int intf_i)
{
#if CI_CFG_CTPIO
  ci_netif_state_nic_t* nsn = &ni->state->nic[intf_i];
  nsn->ctpio_frame_len_check = nsn->ctpio_max_frame_len;
#endif
}

/**********************************************************************
 * DMA queues.
 */

/* Moves packets from the overflow queue to the hardware ring iff the
 * hardware queue has lots of space.
 */
extern void ci_netif_dmaq_shove1(ci_netif*, int intf_i);

/* Moves packets from the overflow queue to the hardware ring if the
 * hardware queue has at least space for one packet.
 */
extern void ci_netif_dmaq_shove2(ci_netif*, int intf_i, int is_fresh);

/* Moves packets from the non-first overflow queue (i.e. for communicating
 * with EF100 slice plugins) to the hardware ring if the hardware queue has at
 * least space for one packet.
 */
void ci_netif_dmaq_shove_plugin(ci_netif* ni, int intf_i, int q_id);


#define ci_netif_dmaq(ni, nic_i)  (&(ni)->state->nic[nic_i].dmaq[0])


#define ci_netif_dmaq_is_empty(ni, nic_i)               \
        oo_pktq_is_empty(ci_netif_dmaq((ni), (nic_i)))

#define ci_netif_dmaq_not_empty(ni, nic_i)               \
        oo_pktq_not_empty(ci_netif_dmaq((ni), (nic_i)))


#define __ci_netif_dmaq_put(ni, q, pkt)                         \
  do {                                                          \
    __oo_pktq_put((ni), (q), (pkt), netif.tx.dmaq_next);        \
    /* ?? pkt->usage += CI_CFG_BUFFER_TRACE_DMAQIN; */          \
  } while(0)


ci_inline void ci_netif_dmaq_and_vi_for_pkt(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                            oo_pktq** dmaq, ef_vi** vi) {
  ci_assert_equal(pkt->q_id, CI_Q_ID_NORMAL);
  *dmaq = ci_netif_dmaq(ni, pkt->intf_i);
  *vi = ci_netif_vi(ni, pkt->intf_i);
}

/* for use from __ci_netif_send() only */
#define ___ci_netif_dmaq_insert_prep_pkt(ni, pkt)                        \
  do {                                                                  \
    ++(ni)->state->nic[(pkt)->intf_i].tx_dmaq_insert_seq;               \
    (ni)->state->nic[(pkt)->intf_i].tx_bytes_added+=TX_PKT_LEN(pkt);    \
    if( oo_tcpdump_check(ni, pkt, (pkt)->intf_i) ) {                    \
      ci_frc64(&((pkt)->tstamp_frc));                                   \
      oo_tcpdump_dump_pkt(ni, pkt);                                     \
    }                                                                   \
  } while(0)

#define __ci_netif_dmaq_insert_prep_pkt(ni, pkt)                        \
  do {                                                                  \
    ci_assert( ! ((pkt)->flags & CI_PKT_FLAG_TX_PENDING) );             \
    (pkt)->flags |= CI_PKT_FLAG_TX_PENDING;                             \
    ___ci_netif_dmaq_insert_prep_pkt(ni, pkt);                          \
  } while(0)


#define __ci_netif_dmaq_insert_prep_pkt_warm_undo(ni, pkt)              \
  do {                                                                  \
    (pkt)->flags &=~ (CI_PKT_FLAG_TX_PENDING | CI_PKT_FLAG_MSG_WARM);   \
    --(ni)->state->nic[(pkt)->intf_i].tx_dmaq_insert_seq;               \
    (ni)->state->nic[(pkt)->intf_i].tx_bytes_added-=TX_PKT_LEN(pkt);    \
    ci_netif_pkt_release(ni, pkt);                                      \
  } while(0)


#endif  /* __NETIF_TX_H__ */
