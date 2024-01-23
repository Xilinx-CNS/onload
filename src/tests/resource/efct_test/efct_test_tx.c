/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2021 Xilinx, Inc. */

#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <ci/tools.h>
#include <ci/tools/bitfield.h>
#include <ci/driver/efab/hardware/efct.h>
#include <ci/driver/kernel_compat.h>

#include "efct_test_device.h"

#define EFCT_TX_APERTURE 4096

struct efct_tx_ctpio_header
{
  unsigned packet_length;
  unsigned ct_thresh;
  unsigned timestamp_flag;
  unsigned warm_flag;
  unsigned action;
};


static void efct_test_inject_pkt(struct net_device *dev, struct iovec* iov,
                                 size_t iov_len, size_t total_len)
{
  struct sk_buff* skb;
  uint8_t *skb_data;
  int i;

  /* Allocate an skb for the kernel's consumption. */
  skb = netdev_alloc_skb(dev, total_len);
  if( skb == NULL )
    return;

  skb_put(skb, total_len);

  skb_data = skb->data;
  /* Copy the Ethernet payload into the skb. */
  for( i = 0; i < iov_len; i++ ) {
    memcpy(skb_data, iov[i].iov_base, iov[i].iov_len);
    skb_data += iov[i].iov_len;
  }

  /* Infer the protocol from the Ethernet payload. */
  skb->protocol = eth_type_trans(skb, dev);

  /* Inject the skb into the kernel.  The return value indicates whether the
   * kernel decided to drop the packet, but we don't need to check that. */
  ci_netif_rx_non_irq(skb);
}


ci_qword_t* evq_next_desc(struct efct_test_evq *evq)
{
  return (ci_qword_t*) &evq->q_base[evq->ptr & evq->mask];
}


unsigned evq_next_phase(struct efct_test_evq *evq)
{
  if( (evq->ptr & (evq->mask + 1)) == 0 )
    return 0;
  else
    return 1;
}


static void
evq_push_tx(struct efct_test_evq *evq, uint32_t pkt_cnt)
{
  CI_POPULATE_QWORD_4(*evq_next_desc(evq),
              EFCT_TX_EVENT_LABEL, 0,
              EFCT_TX_EVENT_SEQUENCE,
              pkt_cnt & ((1 << EFCT_TX_EVENT_SEQUENCE_WIDTH) - 1),
              EFCT_EVENT_TYPE, EFCT_EVENT_TYPE_TX,
              EFCT_EVENT_PHASE, evq_next_phase(evq));
  evq->ptr++;
}


void evq_push_tx_flush_complete(struct efct_test_evq *evq, int txq)
{
  CI_POPULATE_QWORD_5(*evq_next_desc(evq),
              EFCT_CTRL_SUBTYPE, EFCT_CTRL_EV_FLUSH,
              EFCT_EVENT_TYPE, EFCT_EVENT_TYPE_CONTROL,
              EFCT_FLUSH_TYPE, EFCT_FLUSH_TYPE_TX,
              EFCT_FLUSH_LABEL, txq,
              EFCT_EVENT_PHASE, evq_next_phase(evq));
  evq->ptr++;
}


static void decode_efct_tx_header(ci_qword_t *desc,
                                  struct efct_tx_ctpio_header *header)
{
  header->packet_length = CI_QWORD_FIELD(*desc, EFCT_TX_HEADER_PACKET_LENGTH);
  header->ct_thresh = CI_QWORD_FIELD(*desc, EFCT_TX_HEADER_CT_THRESH);
  header->timestamp_flag = CI_QWORD_FIELD(*desc,
                                          EFCT_TX_HEADER_TIMESTAMP_FLAG);
  header->warm_flag = CI_QWORD_FIELD(*desc, EFCT_TX_HEADER_WARM_FLAG);
  header->action = CI_QWORD_FIELD(*desc, EFCT_TX_HEADER_ACTION);
}


static bool efct_test_poll_tx(struct efct_test_txq *txq)
{
  ci_qword_t *tail_ptr;
  ci_qword_t *header_ptr;
  struct efct_tx_ctpio_header header;
  uint32_t total_length;
  struct efct_test_device *tdev = txq->tdev;
  struct efct_test_evq *evq = &tdev->evqs[txq->evq];
  bool got_pkt = false;
  struct iovec pkt_data[2];
  int pkt_start;
  int pkt_tail;
  int pkt_end;
  bool wrapped;
  size_t pkt_length;

  /* This code is taken from zf_emu. There the CTPIO aperture is populated
   * with all bits set, and the emu detects a packet being written when this
   * changes.
   */
  header_ptr = (ci_qword_t*) &txq->ctpio[txq->ptr % EFCT_TX_APERTURE];
  if( header_ptr->u64[0] != 0xffffffffffffffffLL ) {
    decode_efct_tx_header(header_ptr, &header);

    total_length = CI_ROUND_UP(header.packet_length + EFCT_TX_HEADER_BYTES,
                               EFCT_TX_ALIGNMENT);

    pkt_start = (txq->ptr + EFCT_TX_HEADER_BYTES) % EFCT_TX_APERTURE;
    pkt_tail = (txq->ptr + total_length - sizeof(uint64_t)) % EFCT_TX_APERTURE;
    pkt_end = (txq->ptr + total_length) % EFCT_TX_APERTURE;
    pkt_length = total_length - EFCT_TX_HEADER_BYTES;

    /* If the last qword is all ones, this means that the
     * client has not written all the packet data yet.
     *
     * TODO: There is currently a danger of never processing the
     * packet if it ends on a 64-bytes boundary with 64 set bits.
     */
    tail_ptr = (ci_qword_t*) &txq->ctpio[pkt_tail];
    rmb();
    if( tail_ptr->u64[0]  == 0xffffffffffffffffLL )
      return false;

    pkt_data[0].iov_base = &txq->ctpio[pkt_start];
    wrapped = pkt_start + header.packet_length > EFCT_TX_APERTURE;
    if( wrapped ) {
      pkt_data[0].iov_len = EFCT_TX_APERTURE - pkt_start;
      pkt_data[1].iov_base = txq->ctpio;
      pkt_data[1].iov_len = pkt_end;
    }
    else {
      pkt_data[0].iov_len = pkt_length;
    }
    efct_test_inject_pkt(tdev->net_dev, pkt_data, wrapped ? 2 : 1, pkt_length);

    memset(header_ptr, 0xff, EFCT_TX_HEADER_BYTES);
    memset(pkt_data[0].iov_base, 0xff, pkt_data[0].iov_len);
    if( wrapped )
      memset(pkt_data[1].iov_base, 0xff, pkt_data[1].iov_len);

    txq->ptr += total_length;
    evq_push_tx(evq, txq->pkt_ctr);
    txq->pkt_ctr += 1;
    got_pkt = true;
  }

  return got_pkt;
}

#define EFCT_TX_POLL_BATCH 1000
void efct_test_tx_timer(struct work_struct *work)
{
  struct efct_test_txq *txq = container_of(work, struct efct_test_txq,
                                           timer.work);
  int n_polls = 0;

  while( efct_test_poll_tx(txq) && n_polls < EFCT_TX_POLL_BATCH )
    n_polls++;

  if( atomic_read(&txq->timer_running) )
    schedule_delayed_work(&txq->timer, 100);
}

