/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

/* The reason this is in quotes and rather than angle brackets is
 * caused by https://gcc.gnu.org/bugzilla/show_bug.cgi?id=80005.
 * In this case, linux gets defined as 1 earlier and gets expanded
 * within the macro.
 */
#ifdef __has_include
# if __has_include("linux/if_xdp.h")
#  define HAVE_AF_XDP
# endif
#endif

#include "ef_vi_internal.h"

#ifdef HAVE_AF_XDP

#include <linux/if_xdp.h>
#include "af_xdp_defs.h"
#include "logging.h"

/* Currently, AF_XDP requires a system call to start transmitting.
 *
 * There is a limit (undocumented, so we can't rely on it being 16) to the
 * number of packets which will be sent each time. We use the "previous"
 * field to store the last packet known to be sent; if this does not cover
 * all those in the queue, we will try again once a send has completed.
 */
#define AF_XDP_TX_BATCH_MAX 16
static int efxdp_tx_need_kick(ef_vi* vi)
{
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  return qs->previous != qs->added;
}

static void efxdp_tx_kick(ef_vi* vi)
{
  if( vi->xdp_kick(vi) == 0 ) {
    ef_vi_txq_state* qs = &vi->ep_state->txq;
    qs->previous = qs->added;
  }
}

/* Access the AF_XDP rings, using the offsets provided in the mapped memory.
 * The (fake) event queue pointer must be initialised to point to the start
 * of this memory in order to access the offsets.
 */
static struct efab_af_xdp_offsets* xdp_offsets(ef_vi* vi)
{
  return (struct efab_af_xdp_offsets*)vi->evq_base;
}

#define RING_THING(vi, ring, thing) \
  ((void*)(vi->evq_base + xdp_offsets(vi)->rings.ring.thing))

#define RING_PRODUCER(vi, ring) \
  ((volatile uint32_t*)RING_THING(vi, ring, producer))

#define RING_CONSUMER(vi, ring) \
  ((volatile uint32_t*)RING_THING(vi, ring, consumer))

#define RING_DESC(vi, ring) RING_THING(vi, ring, desc)

static int efxdp_ef_vi_transmitv_init(ef_vi* vi, const ef_iovec* iov,
                                      int iov_len, ef_request_id dma_id)
{
  ef_vi_txq* q = &vi->vi_txq;
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  struct xdp_desc* dq = RING_DESC(vi, tx);
  int i;

  if( iov_len != 1 )
    return -EINVAL; /* Multiple buffers per packet not supported */

  if( qs->added - qs->removed >= q->mask )
    return -EAGAIN;

  i = qs->added++ & q->mask;
  dq[i].addr = iov->iov_base;
  dq[i].len = iov->iov_len;
  EF_VI_BUG_ON(q->ids[i] != EF_REQUEST_ID_MASK);
  q->ids[i] = dma_id;
  return 0;
}

static void efxdp_ef_vi_transmit_push(ef_vi* vi)
{
  *RING_PRODUCER(vi, tx) = vi->ep_state->txq.added;
  /* Kicking TX is very expensinve, hence the need to moderate it.
   *  Two cases are allowed:
   *  * if there is nothing or almost nothing in the TX queue
   *    - as we cannot rely on interrupt to pick TX up
   *    - we kick after 1st and 2nd packet to make sure latency is low
   *      for typical ping-pong usecases even if interrupts are moderated.
   *  * at least every packets if queue is half stuffed.
   */
  EF_VI_BUG_ON(vi->ep_state->txq.added == vi->ep_state->txq.previous);
  if( vi->ep_state->txq.added - vi->ep_state->txq.removed < 3 ||
      (vi->ep_state->txq.added ^ vi->ep_state->txq.previous) /
      (AF_XDP_TX_BATCH_MAX >> 1) )
    efxdp_tx_kick(vi);
}

static int efxdp_ef_vi_transmit(ef_vi* vi, ef_addr base, int len,
                                ef_request_id dma_id)
{
  ef_iovec iov = { base, len };
  int rc = efxdp_ef_vi_transmitv_init(vi, &iov, 1, dma_id);
  if( rc == 0 ) {
    wmb();
    efxdp_ef_vi_transmit_push(vi);
  }
  return rc;
}

static int efxdp_ef_vi_transmitv(ef_vi* vi, const ef_iovec* iov, int iov_len,
                                 ef_request_id dma_id)
{
  int rc = efxdp_ef_vi_transmitv_init(vi, iov, iov_len, dma_id);
  if( rc == 0 ) {
    wmb();
    efxdp_ef_vi_transmit_push(vi);
  }
  return rc;
}

static int efxdp_ef_vi_transmit_pio(ef_vi* vi, int offset, int len,
                                    ef_request_id dma_id)
{
  return -EOPNOTSUPP;
}

static int efxdp_ef_vi_transmit_copy_pio(ef_vi* vi, int offset,
                                         const void* src_buf, int len,
                                         ef_request_id dma_id)
{
  return -EOPNOTSUPP;
}

static void efxdp_ef_vi_transmit_pio_warm(ef_vi* vi)
{
  /* PIO is unsupported so do nothing */
}

static void efxdp_ef_vi_transmit_copy_pio_warm(ef_vi* vi, int pio_offset,
                                               const void* src_buf, int len)
{
  /* PIO is unsupported so do nothing */
}

static void efxdp_ef_vi_transmitv_ctpio(ef_vi* vi, size_t frame_len,
                                        const struct iovec* iov, int iovcnt,
                                        unsigned threshold)
{
  /* CTPIO is unsupported so do nothing. Fallback will send the packet. */
}

static void efxdp_ef_vi_transmitv_ctpio_copy(ef_vi* vi, size_t frame_len,
                                             const struct iovec* iov, int iovcnt,
                                             unsigned threshold, void* fallback)
{
  // TODO copy to fallback
}

static int efxdp_ef_vi_transmit_alt_select(ef_vi* vi, unsigned alt_id)
{
  return -EOPNOTSUPP;
}

static int efxdp_ef_vi_transmit_alt_select_normal(ef_vi* vi)
{
  return -EOPNOTSUPP;
}

static int efxdp_ef_vi_transmit_alt_stop(ef_vi* vi, unsigned alt_id)
{
  return -EOPNOTSUPP;
}

static int efxdp_ef_vi_transmit_alt_discard(ef_vi* vi, unsigned alt_id)
{
  return -EOPNOTSUPP;
}

static int efxdp_ef_vi_transmit_alt_go(ef_vi* vi, unsigned alt_id)
{
  return -EOPNOTSUPP;
}

/* Note: for AF_XDP devices dma_id is disregarded */
static int efxdp_ef_vi_receive_init(ef_vi* vi, ef_addr addr,
                                    ef_request_id dma_id)
{
  ef_vi_rxq* q = &vi->vi_rxq;
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  uint64_t* dq = RING_DESC(vi, fr);
  int i;

  if( qs->added - qs->removed >= q->mask )
    return -EAGAIN;

  i = qs->added++ & q->mask;
  dq[i] = addr;
  return 0;
}

static void efxdp_ef_vi_receive_push(ef_vi* vi)
{
  wmb();
  *RING_PRODUCER(vi, fr) = vi->ep_state->rxq.added;
}

static void efxdp_ef_eventq_prime(ef_vi* vi)
{
  // TODO
}

int efxdp_ef_eventq_check_event(const ef_vi* _vi, int look_ahead)
{
  ef_vi* vi = (ef_vi*) _vi; /* drop const */
  EF_VI_ASSERT(vi->evq_base);
  EF_VI_BUG_ON(look_ahead < 0);
  return *RING_CONSUMER(vi, rx) - *RING_PRODUCER(vi, rx) +
         *RING_CONSUMER(vi, cr) - *RING_PRODUCER(vi, cr)
         > look_ahead;
}


static int efxdp_ef_eventq_poll(ef_vi* vi, ef_event* evs, int evs_len)
{
  int n = 0;

  /* rx_buffer_len is power of two */
  EF_VI_ASSERT(((vi->rx_buffer_len - 1) & vi->rx_buffer_len) == 0);

  /* Check rx ring, which won't exist on tx-only interfaces */
  if( n < evs_len && ef_vi_receive_capacity(vi) != 0 ) {
    uint32_t cons = *RING_CONSUMER(vi, rx);
    uint32_t prod = *RING_PRODUCER(vi, rx);

    if( cons != prod ) {
      ef_vi_rxq* q = &vi->vi_rxq;
      ef_vi_rxq_state* qs = &vi->ep_state->rxq;
      struct xdp_desc* dq = RING_DESC(vi, rx);

      do {
        unsigned desc_i = qs->removed++ & q->mask;

        evs[n].rx.type = EF_EVENT_TYPE_RX;
        evs[n].rx.q_id = 0;

        /* AF_XDP devices do not use dma_ids as
         * FIFO behaviour of rx ring is not guaranteed (Zerocopy).
         * However, based on the device specifics, that is:
         *  * dma addr space is contiguous, and
         *  * buffers are fixed size
         * we produce here buffer number withing that dma addr space
         * for the client to resolve themselves. */
        evs[n].rx.rq_id = dq[desc_i].addr / vi->rx_buffer_len;

        q->ids[desc_i] = EF_REQUEST_ID_MASK;  /* Debug only? */

        /* FIXME: handle jumbo, multicast */
        evs[n].rx.flags = EF_EVENT_FLAG_SOP;
        /* In case of AF_XDP offset of the placement of payload from
         * the beginning of the packet buffer may vary. */
        evs[n].rx.ofs = dq[desc_i].addr & (vi->rx_buffer_len - 1); 
        evs[n].rx.len = dq[desc_i].len;

        ++n;
        ++cons;
      } while( cons != prod && n != evs_len );

      /* Full memory barrier needed to ensure the descriptors aren't overwritten
       * by incoming packets before the read accesses above */
      ci_mb();
      *RING_CONSUMER(vi, rx) = cons;
    }
  }

  /* Check tx completion ring */
  if( n < evs_len ) {
    uint32_t cons = *RING_CONSUMER(vi, cr);
    uint32_t prod = *RING_PRODUCER(vi, cr);

    if( cons != prod ) {
      do {
        if( prod - cons <= EF_VI_TRANSMIT_BATCH )
          cons = prod;
        else
          cons += EF_VI_TRANSMIT_BATCH;

        evs[n].tx.type = EF_EVENT_TYPE_TX;
        evs[n].tx.desc_id = cons;
        evs[n].tx.flags = 0;
        evs[n].tx.q_id = 0;
        ++n;
      } while( cons != prod && n != evs_len );

      /* No memory barrier needed as we aren't accessing the descriptor data.
       * We just recorded the value of 'cons` for later use to access `q->ids`
       * from `ef_vi_transmit_unbundle`. */
      *RING_CONSUMER(vi, cr) = cons;

    }
  }
  if( efxdp_tx_need_kick(vi) )
    efxdp_tx_kick(vi);

  return n;
}

static void efxdp_ef_eventq_timer_prime(ef_vi* vi, unsigned v)
{
  // TODO
}

static void efxdp_ef_eventq_timer_run(ef_vi* vi, unsigned v)
{
  // TODO
}

static void efxdp_ef_eventq_timer_clear(ef_vi* vi)
{
  // TODO
}

static void efxdp_ef_eventq_timer_zero(ef_vi* vi)
{
  // TODO
}

void efxdp_vi_init(ef_vi* vi)
{
  EF_VI_BUILD_ASSERT(EFAB_AF_XDP_DESC_BYTES == sizeof(struct xdp_desc));

  vi->ops.transmit               = efxdp_ef_vi_transmit;
  vi->ops.transmitv              = efxdp_ef_vi_transmitv;
  vi->ops.transmitv_init         = efxdp_ef_vi_transmitv_init;
  vi->ops.transmit_push          = efxdp_ef_vi_transmit_push;
  vi->ops.transmit_pio           = efxdp_ef_vi_transmit_pio;
  vi->ops.transmit_copy_pio      = efxdp_ef_vi_transmit_copy_pio;
  vi->ops.transmit_pio_warm      = efxdp_ef_vi_transmit_pio_warm;
  vi->ops.transmit_copy_pio_warm = efxdp_ef_vi_transmit_copy_pio_warm;
  vi->ops.transmitv_ctpio        = efxdp_ef_vi_transmitv_ctpio;
  vi->ops.transmitv_ctpio_copy   = efxdp_ef_vi_transmitv_ctpio_copy;
  vi->ops.transmit_alt_select    = efxdp_ef_vi_transmit_alt_select;
  vi->ops.transmit_alt_select_default = efxdp_ef_vi_transmit_alt_select_normal;
  vi->ops.transmit_alt_stop      = efxdp_ef_vi_transmit_alt_stop;
  vi->ops.transmit_alt_go        = efxdp_ef_vi_transmit_alt_go;
  vi->ops.transmit_alt_discard   = efxdp_ef_vi_transmit_alt_discard;
  vi->ops.receive_init           = efxdp_ef_vi_receive_init;
  vi->ops.receive_push           = efxdp_ef_vi_receive_push;
  vi->ops.eventq_poll            = efxdp_ef_eventq_poll;
  vi->ops.eventq_prime           = efxdp_ef_eventq_prime;
  vi->ops.eventq_timer_prime     = efxdp_ef_eventq_timer_prime;
  vi->ops.eventq_timer_run       = efxdp_ef_eventq_timer_run;
  vi->ops.eventq_timer_clear     = efxdp_ef_eventq_timer_clear;
  vi->ops.eventq_timer_zero      = efxdp_ef_eventq_timer_zero;

  vi->rx_buffer_len = 2048;
  vi->rx_prefix_len = 0;
  vi->evq_phase_bits = 1; /* We set this flag for ef_eventq_has_event */
}

long efxdp_vi_mmap_bytes(ef_vi* vi)
{
  return xdp_offsets(vi)->mmap_bytes;
}
#else
void efxdp_vi_init(ef_vi* vi) {}
long efxdp_vi_mmap_bytes(ef_vi* vi) { return 0; }
int efxdp_ef_eventq_check_event(const ef_vi* _vi, int look_ahead) { return 0; }
#endif
