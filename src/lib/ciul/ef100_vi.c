#include "ef_vi_internal.h"
#include <ci/efhw/common.h>
#include <ci/efhw/ef100.h>
#include "logging.h"
#include "memcpy_to_io.h"


/* TX descriptor for both physical and virtual packet transfers */
typedef ci_oword_t ef_vi_ef100_dma_tx_desc;
/* RX descriptor for both physical and virtual packet transfers */
typedef ci_qword_t ef_vi_ef100_dma_rx_desc;


ef_vi_inline void
ef100_rx_desc_fill(uint64_t dest_addr,
			 ef_vi_ef100_dma_rx_desc* desc, int bytes)
{
  LWCHK(ESF_GZ_RX_BUF_ADDR_LBN, ESF_GZ_RX_BUF_ADDR_WIDTH);
  CI_POPULATE_QWORD_1(*desc, ESF_GZ_RX_BUF_ADDR, dest_addr);
}

ef_vi_inline void
ef100_tx_send_desc_fill(ef_vi* vi, unsigned n_segs,
                        uint64_t src_dma_addr, unsigned bytes,
                        ef_vi_ef100_dma_tx_desc *dp)
{
  LWCHK(ESF_GZ_TX_SEND_ADDR_LBN, ESF_GZ_TX_SEND_ADDR_WIDTH);

  RANGECHCK(bytes, ESF_GZ_TX_SEND_LEN_WIDTH);
  RANGECHCK(n_segs, ESF_GZ_TX_SEND_NUM_SEGS_WIDTH);

  CI_POPULATE_OWORD_6(*dp,
                      ESF_GZ_TX_SEND_NUM_SEGS, n_segs,
                      ESF_GZ_TX_SEND_LEN, bytes,
                      ESF_GZ_TX_SEND_ADDR, src_dma_addr,
                      ESF_GZ_TX_DESC_TYPE, ESE_GZ_TX_DESC_TYPE_SEND,
                      ESF_GZ_TX_SEND_CSO_OUTER_L3, !(vi->vi_flags & EF_VI_TX_IP_CSUM_DIS),
                      ESF_GZ_TX_SEND_CSO_OUTER_L4, !(vi->vi_flags & EF_VI_TX_TCPUDP_CSUM_DIS));
}

ef_vi_inline void
ef100_tx_segment_desc_fill(uint64_t src_dma_addr, unsigned bytes,
                           ef_addrspace addr_space, uint32_t flags,
                           ef_vi_ef100_dma_tx_desc *dp)
{
  int translate_addr = (flags & EF_RIOV_FLAG_TRANSLATE_ADDR) != 0;
  int as_override = addr_space != EF_ADDRSPACE_LOCAL;
  LWCHK(ESF_GZ_TX_SEG_ADDR_LBN, ESF_GZ_TX_SEG_ADDR_WIDTH);
  RANGECHCK(bytes, ESF_GZ_TX_SEG_LEN_WIDTH);

  CI_POPULATE_OWORD_6(*dp,
                      ESF_GZ_TX_SEG_LEN, bytes,
                      ESF_GZ_TX_SEG_ADDR, src_dma_addr,
                      ESF_GZ_TX_SEG_ADDR_SPC, as_override ? addr_space : 0,
                      ESF_GZ_TX_SEG_ADDR_SPC_EN, as_override,
                      ESF_GZ_TX_SEG_TRANSLATE_ADDR, translate_addr,
                      ESF_GZ_TX_DESC_TYPE, ESE_GZ_TX_DESC_TYPE_SEG);
}

static int ef100_ef_vi_transmitv_init(ef_vi* vi, const ef_iovec* iov,
				     int iov_len, ef_request_id dma_id)
{
  ef_vi_txq* q = &vi->vi_txq;
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  ef_vi_ef100_dma_tx_desc* dp;
  unsigned di, n_segs = iov_len;

  EF_VI_BUG_ON((iov_len <= 0));
  EF_VI_BUG_ON(iov == NULL);
  EF_VI_BUG_ON((dma_id & EF_REQUEST_ID_MASK) != dma_id);
  EF_VI_BUG_ON(dma_id == 0xffffffff);

  /* Check for enough space in the queue */
  if( qs->added + n_segs - qs->removed >= q->mask )
    return -EAGAIN;

  /* Generate a SEND descriptor which includes the first segment of data */
  di = qs->added++ & q->mask;
  dp = (ef_vi_ef100_dma_tx_desc*) q->descriptors + di;

  ef100_tx_send_desc_fill(vi, n_segs,
                          iov->iov_base,
                          iov->iov_len, dp);
  iov++;
  n_segs--;

  while( n_segs > 0 ) {
    di = qs->added++ & q->mask;
    dp = (ef_vi_ef100_dma_tx_desc*) q->descriptors + di;

    ef100_tx_segment_desc_fill(iov->iov_base,
                               iov->iov_len,
                               EF_ADDRSPACE_LOCAL, 0,
                               dp);
    iov++;
    n_segs--;
  }

  EF_VI_BUG_ON(q->ids[di] != EF_REQUEST_ID_MASK);
  q->ids[di] = dma_id;
  return 0;
}

static int ef100_ef_vi_transmitv_init_extra(ef_vi* vi,
                                            const struct ef_vi_tx_extra* extra,
                                            const ef_remote_iovec* iov,
                                            int iov_len, ef_request_id dma_id)
{
  ef_vi_txq* q = &vi->vi_txq;
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  ef_vi_ef100_dma_tx_desc* dp;
  unsigned di, n_segs = iov_len;

  EF_VI_BUG_ON((iov_len <= 0));
  EF_VI_BUG_ON(iov == NULL);
  EF_VI_BUG_ON((dma_id & EF_REQUEST_ID_MASK) != dma_id);
  EF_VI_BUG_ON(dma_id == 0xffffffff);
  EF_VI_BUG_ON(iov[0].addrspace != EF_ADDRSPACE_LOCAL);
  EF_VI_BUG_ON((iov[0].flags & EF_RIOV_FLAG_TRANSLATE_ADDR) != 0);

  if( CI_UNLIKELY(extra != NULL) )
    n_segs++;

  /* Check for enough space in the queue */
  if( qs->added + n_segs - qs->removed >= q->mask )
    return -EAGAIN;

  if( CI_UNLIKELY(extra != NULL) ) {
    di = qs->added++ & q->mask;
    dp = (ef_vi_ef100_dma_tx_desc*) q->descriptors + di;
    n_segs--;

    CI_POPULATE_OWORD_7(*dp,
                        ESF_GZ_TX_PREFIX_MARK_EN,
                        (extra->flags & EF_VI_TX_EXTRA_MARK) != 0,

                        ESF_GZ_TX_PREFIX_INGRESS_MPORT_EN,
                        (extra->flags & EF_VI_TX_EXTRA_INGRESS_MPORT) != 0,

                        ESF_GZ_TX_PREFIX_INLINE_CAPSULE_META,
                        (extra->flags & EF_VI_TX_EXTRA_CAPSULE_METADATA) != 0,

                        ESF_GZ_TX_PREFIX_EGRESS_MPORT_EN,
                        (extra->flags & EF_VI_TX_EXTRA_EGRESS_MPORT) != 0,

                        ESF_GZ_TX_PREFIX_EGRESS_MPORT, extra->egress_mport,
                        ESF_GZ_TX_PREFIX_INGRESS_MPORT, extra->ingress_mport,
                        ESF_GZ_TX_PREFIX_MARK, extra->mark);
  }

  /* Generate a SEND descriptor which includes the first segment of data */
  di = qs->added++ & q->mask;
  dp = (ef_vi_ef100_dma_tx_desc*) q->descriptors + di;

  ef100_tx_send_desc_fill(vi, n_segs,
                          iov->iov_base,
                          iov->iov_len, dp);
  iov++;
  n_segs--;

  while( n_segs > 0 ) {
    di = qs->added++ & q->mask;
    dp = (ef_vi_ef100_dma_tx_desc*) q->descriptors + di;

    ef100_tx_segment_desc_fill(iov->iov_base,
                               iov->iov_len,
                               iov->addrspace,
                               iov->flags, dp);
    iov++;
    n_segs--;
  }

  EF_VI_BUG_ON(q->ids[di] != EF_REQUEST_ID_MASK);
  q->ids[di] = dma_id;
  return 0;
}

static void ef_vi_transmit_push_doorbell(ef_vi* vi)
{
  uint32_t* doorbell = (void*) (vi->io + ER_GZ_TX_RING_DOORBELL);
  /* FIXME: ERF_GZ_IDX_LBN
   * firmwaresrc/tools/rhsim/target.c (fs_process_target_writes) */
  writel((vi->ep_state->txq.added & vi->vi_txq.mask) << ERF_GZ_TX_RING_PIDX_LBN, doorbell);
  mmiowb();
}


static void ef100_ef_vi_transmit_push(ef_vi* vi)
{
  ef_vi_txq_state* qs = &vi->ep_state->txq;

  /* TODO: do it more like for EF10 */
  ef_vi_transmit_push_doorbell(vi);
  EF_VI_BUG_ON(qs->previous == qs->added);
  qs->previous = qs->added;
}


static int ef100_ef_vi_transmit(ef_vi* vi, ef_addr base, int len,
                               ef_request_id dma_id)
{
  ef_iovec iov = { base, len };
  int rc = ef100_ef_vi_transmitv_init(vi, &iov, 1, dma_id);
  if( rc == 0 ) {
    wmb();
    ef100_ef_vi_transmit_push(vi);
  }
  return rc;
}


static int ef100_ef_vi_receive_init(ef_vi* vi, ef_addr addr,
                                   ef_request_id dma_id)
{
  ef_vi_rxq* q = &vi->vi_rxq;
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  unsigned di;

  if( ef_vi_receive_space(vi) ) {
    ef_vi_ef100_dma_rx_desc* dp;

    di = qs->added++ & q->mask;
    EF_VI_BUG_ON(q->ids[di] !=  EF_REQUEST_ID_MASK);
    q->ids[di] = dma_id;

    dp =(ef_vi_ef100_dma_rx_desc*)q->descriptors + di;
    ef100_rx_desc_fill(addr, dp, vi->rx_buffer_len);

    return 0;
  }
  return -EAGAIN;
}

static void ef100_ef_vi_receive_push(ef_vi* vi)
{
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;

  if(likely( qs->added != qs->posted )) {
    /* FIXME: ERF_GZ_IDX_LBN
     * firmwaresrc/tools/rhsim/target.c (fs_process_target_writes) */
    writel((qs->added & vi->vi_rxq.mask) << ERF_GZ_RX_RING_PIDX_LBN, vi->io + ER_GZ_RX_RING_DOORBELL);
    qs->posted = qs->added;
    mmiowb();
  }
}


static int ef100_ef_vi_transmitv(ef_vi* vi, const ef_iovec* iov, int iov_len,
                                ef_request_id dma_id)
{
  int rc = ef100_ef_vi_transmitv_init(vi, iov, iov_len, dma_id);
  if( rc == 0 ) {
    wmb();
    ef100_ef_vi_transmit_push(vi);
  }
  return rc;
}


ef_vi_inline void
ef100_pio_set_desc(ef_vi* vi, ef_vi_txq* q, ef_vi_txq_state* qs,
                  int offset, int len, ef_request_id dma_id)
{
  ef100_unsupported_msg(__FUNCTION__);
}


static inline void ef100_pio_push(ef_vi* vi, ef_vi_txq_state* qs)
{
  ef100_unsupported_msg(__FUNCTION__);
}


static int ef100_ef_vi_transmit_pio(ef_vi* vi, int offset, int len,
				   ef_request_id dma_id)
{
  ef100_unsupported_msg(__FUNCTION__);
  return -1;
}


static int ef100_ef_vi_transmit_copy_pio(ef_vi* vi, int offset,
					const void* src_buf, int len,
					ef_request_id dma_id)
{
  ef100_unsupported_msg(__FUNCTION__);
  return -1;
}


static void ef100_ef_vi_transmit_pio_warm(ef_vi* vi)
{
  ef100_unsupported_msg(__FUNCTION__);
}


static void ef100_ef_vi_transmit_copy_pio_warm(ef_vi* vi, int pio_offset,
                                              const void* src_buf, int len)
{
  ef100_unsupported_msg(__FUNCTION__);
}


static void
  ef100_ef_vi_transmitv_ctpio_not_supp(ef_vi* vi, size_t frame_len,
                                      const struct iovec* iov, int iovcnt,
                                      unsigned threshold)
{
  ef100_unsupported_msg(__FUNCTION__);
}

static int ef100_ef_vi_transmit_alt_select(ef_vi* vi, unsigned alt_id)
{
  ef100_unsupported_msg(__FUNCTION__);
  return -1;
}


static int ef100_ef_vi_transmit_alt_select_normal(ef_vi* vi)
{
  ef100_unsupported_msg(__FUNCTION__);
  return -1;
}


static int ef100_ef_vi_transmit_alt_stop(ef_vi* vi, unsigned alt_id)
{
  ef100_unsupported_msg(__FUNCTION__);
  return -1;
}


static int ef100_ef_vi_transmit_alt_discard(ef_vi* vi, unsigned alt_id)
{
  ef100_unsupported_msg(__FUNCTION__);
  return -1;
}


static int ef100_ef_vi_transmit_alt_go(ef_vi* vi, unsigned alt_id)
{
  ef100_unsupported_msg(__FUNCTION__);
  return -1;
}


static void ef100_vi_initialise_ops(ef_vi* vi)
{
  vi->ops.transmit               = ef100_ef_vi_transmit;
  vi->ops.transmitv              = ef100_ef_vi_transmitv;
  vi->ops.transmitv_init         = ef100_ef_vi_transmitv_init;
  vi->ops.transmit_push          = ef100_ef_vi_transmit_push;
  vi->ops.transmit_pio           = ef100_ef_vi_transmit_pio;
  vi->ops.transmit_copy_pio      = ef100_ef_vi_transmit_copy_pio;
  vi->ops.transmit_pio_warm      = ef100_ef_vi_transmit_pio_warm;
  vi->ops.transmit_copy_pio_warm = ef100_ef_vi_transmit_copy_pio_warm;
  vi->ops.transmitv_ctpio        = ef100_ef_vi_transmitv_ctpio_not_supp;
  vi->ops.transmit_alt_select    = ef100_ef_vi_transmit_alt_select;
  vi->ops.transmit_alt_select_default = ef100_ef_vi_transmit_alt_select_normal;
  vi->ops.transmit_alt_stop      = ef100_ef_vi_transmit_alt_stop;
  vi->ops.transmit_alt_go        = ef100_ef_vi_transmit_alt_go;
  vi->ops.transmit_alt_discard   = ef100_ef_vi_transmit_alt_discard;
  vi->ops.receive_init           = ef100_ef_vi_receive_init;
  vi->ops.receive_push           = ef100_ef_vi_receive_push;
  vi->ops.eventq_poll            = ef100_ef_eventq_poll;
  vi->ops.eventq_prime           = ef100_ef_eventq_prime;
  vi->ops.eventq_timer_prime     = ef100_ef_eventq_timer_prime;
  vi->ops.eventq_timer_run       = ef100_ef_eventq_timer_run;
  vi->ops.eventq_timer_clear     = ef100_ef_eventq_timer_clear;
  vi->ops.eventq_timer_zero      = ef100_ef_eventq_timer_zero;
  vi->ops.transmitv_init_extra   = ef100_ef_vi_transmitv_init_extra;
}

void ef100_vi_init(ef_vi* vi)
{
  vi->rx_buffer_len = EF100_RX_USR_BUF_SIZE;

  vi->rx_pkt_len_offset = 0;
  vi->rx_pkt_len_mask = (1 << ESF_GZ_RX_PREFIX_LENGTH_WIDTH) - 1;

  /* Set default rx_discard_mask for EF100 */
  vi->rx_discard_mask = 0;

  /* EF100 uses phase bits in event queues */
  vi->evq_phase_bits = 1;

  ef100_vi_initialise_ops(vi);
}

/*! \cidoxg_end */
