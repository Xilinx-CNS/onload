/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

/*
 * \author  djr
 *  \brief  Packet-mode transmit interface.
 *   \date  2003/04/02
 */

/*! \cidoxg_lib_ef */
#include <etherfabric/pio.h>
#include "ef_vi_internal.h"
#include "logging.h"
#include "memcpy_to_io.h"


int ef_vi_transmit_init(ef_vi* vi, ef_addr base, int len, ef_request_id dma_id)
{
  ef_iovec iov = { base, len };
  return ef_vi_transmitv_init(vi, &iov, 1, dma_id);
}


void ef_vi_transmit_init_undo(ef_vi* vi)
{
  ef_vi_txq* q = &vi->vi_txq;
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  while ( qs->added != qs->previous ) {
    unsigned di = --qs->added & q->mask;
    q->ids[di] = EF_REQUEST_ID_MASK;
  }
}


int ef_vi_transmit_unbundle(ef_vi* vi, const ef_event* ev,
			    ef_request_id* ids)
{
  ef_request_id* ids_in = ids;
  ef_vi_txq* q = &vi->vi_txq;
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  unsigned i, stop = ev->tx.desc_id & q->mask;

  EF_VI_BUG_ON(EF_EVENT_TYPE(*ev) != EF_EVENT_TYPE_TX &&
               EF_EVENT_TYPE(*ev) != EF_EVENT_TYPE_TX_ERROR);

  /* Shouldn't be batching more than 128 descriptors, and should not go
  ** backwards. See comment 7 on bug 44002. */
  EF_VI_BUG_ON(((ev->tx.desc_id - qs->removed) & q->mask) > 128);
  /* Should not complete more than we've posted. */
  EF_VI_BUG_ON(((ev->tx.desc_id - qs->removed) & q->mask) >
               qs->added - qs->removed);

  for( i = qs->removed & q->mask; i != stop; i = ++qs->removed & q->mask )
    if( q->ids[i] != EF_REQUEST_ID_MASK ) {
      *ids++ = q->ids[i];
      q->ids[i] = EF_REQUEST_ID_MASK;
    }

  /* This is a count of packets, not descriptors. Again, see comment 7 on
   * bug 44002. */
  EF_VI_BUG_ON(ids - ids_in > EF_VI_TRANSMIT_BATCH);
  return (int) (ids - ids_in);
}


int ef_pio_memcpy(ef_vi* vi, const void* base, int offset, int len)
{
  /* PIO region on NIC is write only, and to avoid silicon bugs must
   * only be hit with writes at are 64-bit aligned and a multiple of
   * 64-bits in size.
   */
  ef_pio* pio = vi->linked_pio;

  EF_VI_ASSERT(offset + len <= pio->pio_len);

  memcpy(pio->pio_buffer + offset, base, len);

  len += CI_OFFSET(offset, MEMCPY_TO_PIO_ALIGN);
  offset = CI_ROUND_DOWN(offset, MEMCPY_TO_PIO_ALIGN);
  len = CI_ROUND_UP(len, MEMCPY_TO_PIO_ALIGN);

  /* To ensure that the resulting TLPs are aligned and have all their
   * byte-enable bits set, we must ensure that the data in the WC buffer is
   * always contiguous.  See bug49906.  However, all previous writes to the
   * PIO region conclude with wmb_wc(), so there's no need here for a further
   * barrier.
   */

  memcpy_to_pio_aligned(pio->pio_io + offset, pio->pio_buffer + offset, len);
  return 0;
}


unsigned ef_vi_transmit_alt_num_ids(ef_vi* vi)
{
  return vi->tx_alt_num;
}


int ef_vi_transmit_ctpio_fallback(ef_vi* vi, ef_addr dma_addr, size_t len,
                                  ef_request_id dma_id)
{
  if( vi->vi_flags & EF_VI_TX_CTPIO )
    return ef_vi_transmit(vi, dma_addr, len, dma_id);
  else
    return -EOPNOTSUPP;
}


int ef_vi_transmitv_ctpio_fallback(ef_vi* vi, const ef_iovec* dma_iov,
                                   int dma_iov_len, ef_request_id dma_id)
{
  if( vi->vi_flags & EF_VI_TX_CTPIO )
    return ef_vi_transmitv(vi, dma_iov, dma_iov_len, dma_id);
  else
    return -EOPNOTSUPP;
}


/*! \cidoxg_end */
