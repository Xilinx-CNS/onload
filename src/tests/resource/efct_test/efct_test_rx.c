/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: Copyright (C) 2024, Advanced Micro Devices, Inc. */

#include "efct_test_device.h"
#include "efct_test_tx.h"

#include <ci/tools.h>
#include <ci/tools/bitfield.h>
#include <ci/driver/efab/hardware/ef10ct.h>
#include <ci/driver/efab/hardware/efct.h>

static const unsigned char fake_pkt[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x08, 0x00,
  /* IP hdr: */
  0x45, 0x00, 0x00, 0x21, 0x3f, 0xba, 0x40, 0x00, 0x40, 0x11, 0xfd, 0x0e,
  0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x02,
  /* UDP hdr: */
  0x92, 0x55, 0x30, 0x39, 0x00, 0x0d, 0x4d, 0x68,
  /* payload: */
  0x74, 0x65, 0x73, 0x74, 0x0a,
  /* Extra padding so other bits are nicely aligned from efsink */
  0x00,
};

static void
evq_push_rx(struct efct_test_evq *evq, uint32_t pkt_cnt)
{
  CI_POPULATE_QWORD_6(*evq_next_desc(evq),
                      EFCT_TEST_RX_EVENT_NUM_PACKETS, pkt_cnt,
                      EFCT_TEST_RX_EVENT_LABEL, 0,
                      EFCT_TEST_RX_EVENT_ROLLOVER, 0,
                      EFCT_TEST_RX_EVENT_FLOW_LOOKUP, 1,
                      EFCT_EVENT_PHASE, evq_next_phase(evq),
                      EFCT_EVENT_TYPE, EFCT_EVENT_TYPE_RX);
  evq->ptr++;
}

void evq_push_rx_flush_complete(struct efct_test_evq *evq, int rxq)
{
  CI_POPULATE_QWORD_5(*evq_next_desc(evq),
              EFCT_CTRL_SUBTYPE, EFCT_CTRL_EV_FLUSH,
              EFCT_EVENT_TYPE, EFCT_EVENT_TYPE_CONTROL,
              EFCT_FLUSH_TYPE, EFCT_FLUSH_TYPE_RX,
              EFCT_FLUSH_LABEL, rxq,
              EFCT_EVENT_PHASE, evq_next_phase(evq));
  evq->ptr++;
}

static struct efct_test_suberbuf* get_current_buff(struct efct_test_rxq *rxq)
{
  return &rxq->buffers[rxq->curr_bid % EFCT_TEST_MAX_SUPERBUFS];
}


static struct efct_test_suberbuf* get_next_buff(struct efct_test_rxq *rxq)
{
  return &rxq->buffers[rxq->next_bid % EFCT_TEST_MAX_SUPERBUFS];
}

/* return value: Did we write the packet? */
static bool write_fake_packet(struct efct_test_rxq *rxq)
{
  char * buf;
  int ix;
  char *dst;

  /* Are we in a valid superbuf? If not, return early. */
  if(rxq->curr_bid >= rxq->next_bid)
      return false; 

  buf = (char *)get_current_buff(rxq)->page;
  ix = rxq->pkt % EFCT_TEST_PKTS_PER_SUPERBUF;
  dst = buf + ix * EFCT_TEST_PKT_BYTES + 64; /* 64 bytes for metadata*/

  /* 2 byte offset so that ip header is nicely aligned */
  memset(dst, 0, 2);
  dst+=2;

  /* Copy the packet */
  memcpy(dst, fake_pkt, sizeof(fake_pkt));
  
  /* Also include pkt and curr_bid in the packet*/
  memcpy(dst + sizeof(fake_pkt), &rxq->pkt, sizeof(rxq->pkt));
  memcpy(dst + sizeof(fake_pkt) + sizeof(rxq->pkt), &rxq->curr_bid,
         sizeof(rxq->curr_bid));

  return true;
}

static void write_real_fake_metadata(struct efct_test_rxq *rxq)
{
  char *buf;
  int ix;
  ci_oword_t meta = {}; /* Zero initialise */
  ci_oword_t *meta_dst;
  bool sentinel;
  unsigned packet_length;

  /* A most likely unnecessary check since this will be called after
    * write_fake_packet. */
  if(rxq->curr_bid >= rxq->next_bid)
    return;

  buf = (char *)get_current_buff(rxq)->page;
  ix = rxq->pkt % EFCT_TEST_PKTS_PER_SUPERBUF;
  sentinel = get_current_buff(rxq)->sentinel;
  meta_dst = (ci_oword_t *)(buf + ix * EFCT_TEST_PKT_BYTES);
  packet_length = sizeof(fake_pkt) + sizeof(rxq->pkt) + sizeof(rxq->curr_bid);
  CI_POPULATE_OWORD_4(meta,
                      EFCT_RX_HEADER_PACKET_LENGTH, packet_length,
                      EFCT_RX_HEADER_NEXT_FRAME_LOC, 1,
                      EFCT_RX_HEADER_L4_CLASS, 1, /* Test packet is udp */
                      EFCT_RX_HEADER_SENTINEL, sentinel);

  
  WRITE_ONCE(meta_dst->u64[1], meta.u64[1]);
  wmb();
  WRITE_ONCE(meta_dst->u64[0], meta.u64[0]);
}


static void write_forced_rollover_metadata(struct efct_test_rxq *rxq)
{
  char *buf;
  int ix;
  char *dst;
  ci_oword_t meta = {}; /* Zero initialise */
  ci_oword_t *meta_dst;
  bool sentinel;

  if(rxq->curr_bid >= rxq->next_bid)
    return;

  buf = (char *)get_current_buff(rxq)->page;
  ix = rxq->pkt % EFCT_TEST_PKTS_PER_SUPERBUF;
  sentinel = get_current_buff(rxq)->sentinel;
  dst = buf + ix * EFCT_TEST_PKT_BYTES + 64;
  meta_dst = (ci_oword_t *)(buf + ix * EFCT_TEST_PKT_BYTES);
  CI_POPULATE_OWORD_10(meta,
                       EFCT_RX_HEADER_PACKET_LENGTH, 0,
                       EFCT_RX_HEADER_NEXT_FRAME_LOC, 1,
                       EFCT_RX_HEADER_L2_CLASS, 0x11,
                       EFCT_RX_HEADER_L3_CLASS, 0x11,
                       EFCT_RX_HEADER_L4_CLASS, 0x11,
                       EFCT_RX_HEADER_L2_STATUS, 0x11,
                       EFCT_RX_HEADER_L3_STATUS, 1,
                       EFCT_RX_HEADER_L4_STATUS, 1,
                       EFCT_RX_HEADER_ROLLOVER, 1,
                       EFCT_RX_HEADER_SENTINEL, sentinel);

  memset(dst, 0, 64); /* This doesn't need two bytes of padding */
  wmb(); /* is this necessary ? */
  WRITE_ONCE(meta_dst->u64[1], meta.u64[1]);
  wmb();
  WRITE_ONCE(meta_dst->u64[0], meta.u64[0]);
}

static void do_rollover(struct efct_test_rxq *rxq, bool forced)
{
  if( rxq->curr_bid + 1 == rxq->next_bid ) {
    printk(KERN_INFO "%s no free superbufs\n", __func__);
    return;
  }

  if( forced ) {
    printk(KERN_INFO "%s curr_bid = %u, next_bid = %u\n",
           __func__, rxq->curr_bid, rxq->next_bid);
    while( rxq->curr_bid < rxq->next_bid - 1 ) {
      /* We need to write a new rollover metadata thing to the current
      * superbuf. Then we can start using the next superbuf. I don't think
      * there are any weird corner cases where a forced rollover happens "at
      * the same time" as a natural one. curr_bid should always have room for
      * metadata. */
      write_forced_rollover_metadata(rxq);
      memset(get_current_buff(rxq), 0, sizeof(struct efct_test_suberbuf));
      rxq->curr_bid++;
    }
  } else {
    /* I feel like it should be possible to remove the duplication in this
     * if/else branch. Too lazy to think about it now. */
    memset(get_current_buff(rxq), 0, sizeof(struct efct_test_suberbuf));
    rxq->curr_bid++;
  }

  printk(KERN_INFO "%s superbuf rollover\n", __func__);
  rxq->pkt = 0;
}

enum hrtimer_restart efct_rx_tick(struct hrtimer *hr)
{
  struct efct_test_rxq *rxq = container_of(hr, struct efct_test_rxq, rx_tick);
  struct efct_test_device *tdev = rxq->tdev;
  struct efct_test_evq *evq = &tdev->evqs[rxq->evq];

  if( !rxq->num_pkts || rxq->curr_pkts == rxq->num_pkts )
      goto out;

  /* Should we write a forced metadata packet? */
  /* TODO: Decide whether we want this, and if so should it be periodic? user
   * configurable? */
  if( 0 ) {
    struct efct_test_suberbuf *old_buff = get_current_buff(rxq);
    /* Do a forced rollover of a single buffer */
    if( rxq->curr_bid + 1 == rxq->next_bid ) {
        printk(KERN_INFO "%s no free superbufs\n", __func__);
        goto out;
    }
    write_forced_rollover_metadata(rxq);
    rxq->curr_bid++;
    rxq->pkt = 0;
    memset(old_buff, 0, sizeof(struct efct_test_suberbuf));
  }

  /* Write a packet */
  if( !write_fake_packet(rxq) ) {
    printk(KERN_ERR "%s failed to write the fake packet."
           " Are there enough sbufs? curr_bid = %u next_bid = %u\n",
           __func__, rxq->curr_bid, rxq->next_bid);
    goto out;
  }

  /* Don't increment rxq->pkt yet */

  /* Write the corresponding metadata */
  write_real_fake_metadata(rxq);

  /* Push event to queue*/
  evq_push_rx(evq, 1);

  /* We have to wait until after the metadata is written before we can
  * increment pkt, otherwise the frame and the metadata would end up in
  * different packet buffers */
  rxq->pkt++;

  if( rxq->pkt >= EFCT_TEST_PKTS_PER_SUPERBUF ) {
    do_rollover(rxq, 0);
  }

  rxq->curr_pkts++;

out:
  hrtimer_forward_now(hr, ms_to_ktime(rxq->ms_per_pkt));
  return HRTIMER_RESTART;
}

void efct_test_rx_timer(struct work_struct *work)
{
  struct efct_test_rxq *rxq = container_of(work, struct efct_test_rxq,
                                            timer.work);

  /* Similar to efct_test_poll_tx this code assumes that if the buffer post
   * "register" is all zeros that means it hasn't been written to, otherwise
   * it should be a valid value.
   * This isn't a completely correct approach, if the "register" is written to
   * multiple times between timer ticks then only the last value will be seen.
   * This can be resolved by adding some logic to onload that will poll the
   * "register" until it equals 0. We obviously won't want this with an actual
   * nic, but (hopefully) it should be sufficient for the test_driver where we
   * want functionality but not necessarily performance. */

  mb();
  if( rxq->post_register->u64[0] != 0x0ULL ) {
    ci_qword_t buffer_start = *rxq->post_register;
    struct efct_test_suberbuf *buffer;
    uint64_t phys_addr;

    if(rxq->next_bid > rxq->curr_bid &&
      (rxq->next_bid % EFCT_TEST_MAX_SUPERBUFS == 
       rxq->curr_bid % EFCT_TEST_MAX_SUPERBUFS) ) {
        printk(KERN_ERR "%s superbuf fifo is full!"
                        " next_bid = %u curr_bid = %u\n",
                        __func__, rxq->next_bid, rxq->curr_bid);
        goto out;
      }
    
    printk(KERN_INFO "%s: received buffer 0x%llx\n",
           __func__, buffer_start.u64[0]);

    buffer = get_next_buff(rxq);

    phys_addr = CI_QWORD_FIELD(buffer_start, EFCT_TEST_PAGE_ADDRESS);
    buffer->page = phys_to_virt(phys_addr << 12);
    buffer->rollover = CI_QWORD_FIELD(buffer_start, EFCT_TEST_ROLLOVER);
    buffer->sentinel = CI_QWORD_FIELD(buffer_start, EFCT_TEST_SENTINEL_VALUE);

    rxq->next_bid++;
    if( buffer->rollover )
      do_rollover(rxq, 1);

    memset(rxq->post_register, 0x00, sizeof(*rxq->post_register));
  }

out:
  if( atomic_read(&rxq->timer_running) )
    schedule_delayed_work(&rxq->timer, 100);
}
