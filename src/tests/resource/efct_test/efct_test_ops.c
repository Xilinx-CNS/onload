/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2021 Xilinx, Inc. */

#include <linux/mm.h>
#include <linux/slab.h>
#include <asm/cacheflush.h>
#include <linux/random.h>
#include <linux/hrtimer.h>
#include <linux/mm.h>
#ifdef __has_include
#if __has_include(<linux/set_memory.h>)
#include <linux/set_memory.h>
#endif
#if __has_include(<asm/set_memory.h>)
#include <asm/set_memory.h>
#endif
#endif
#include <asm/io.h>

#include <ci/driver/ci_aux.h>
#include <ci/driver/ci_ef10ct_test.h>
#include <ci/compat.h>
#include <ci/efrm/debug_linux.h>
#include <etherfabric/internal/efct_uk_api.h>
#include <ci/tools.h>
#include <ci/tools/byteorder.h>
#include <ci/tools/bitfield.h>
#include <ci/efhw/mc_driver_pcol.h>

/* Avoid including the real aux header, which conflicts with the test one */
#define _EFX_AUXBUS_H
#include <ci/efhw/ef10ct.h>
#undef _EFX_AUXBUS_H

#include "efct_test_device.h"
#include "efct_test_ops.h"
#include "efct_test_tx.h"
#include "efct_test_rx.h"

#include "../../../lib/efhw/mcdi_common.h"

#ifndef page_to_virt
/* Only RHEL7 doesn't have this macro */
#define page_to_virt(x)        __va(PFN_PHYS(page_to_pfn(x)))
#endif


static struct efx_auxdev_client*
efct_test_open(struct auxiliary_device *adev, efx_auxdev_event_handler func,
               unsigned int events_requested)
{
  struct efx_auxdev_client *client;
  struct efct_test_device *tdev;

  printk(KERN_INFO "%s\n", __func__);

  /* Currently support exactly one test device, which should be opened at most
   * once by the efct driver.
   */
  tdev = container_of(adev, struct efct_test_device, dev.auxdev);
  BUG_ON(tdev->client);

  client = kzalloc(sizeof(*client), GFP_KERNEL);
  if( !client )
    return ERR_PTR(-ENOMEM);

  client->event_handler = func;
  client->net_dev = tdev->net_dev;
  tdev->client = client;
  client->tdev = tdev;

  return client;
}


static void efct_test_close(struct efx_auxdev_client *handle)
{
  struct efct_test_device *tdev = handle->tdev;
  printk(KERN_INFO "%s\n", __func__);

  if( ! tdev ) {
    printk(KERN_ERR "%s: ERROR: closing unopened device\n", __func__);
    return;
  }

  tdev->client = NULL;
  kfree(handle);
}

static int efct_test_evq_window_addr(struct efx_auxdev_client *handle,
                                     struct efx_auxiliary_io_window *queue_io_wnd)
{
  struct efct_test_device *tdev = handle->tdev;
  int evq = ef10ct_get_queue_num(queue_io_wnd->qid_in);

  queue_io_wnd->base = virt_to_phys(tdev->evq_window + 0x1000 * evq);
  queue_io_wnd->size = 0x1000;
  return 0;
}

static int efct_test_ctpio_addr(struct efx_auxdev_client *handle,
                                struct efx_auxiliary_io_window *queue_io_wnd)
{
  struct efct_test_device *tdev = handle->tdev;
  int txq = ef10ct_get_queue_num(queue_io_wnd->qid_in);

  printk(KERN_INFO "%s: txq %d evq %d\n", __func__, txq, tdev->txqs[txq].evq);

  if( tdev->txqs[txq].evq < 0 )
    return -EINVAL;

  queue_io_wnd->base = virt_to_phys(tdev->txqs[txq].ctpio);
  queue_io_wnd->size = 0x1000;
  return 0;
}

static int efct_test_buffer_post_addr(struct efx_auxdev_client *handle,
                               struct efx_auxiliary_io_window *queue_io_wnd)
{
  /* Give onload the address of the RX_POST_BUFFER register for this queue,
   * rather than forcing them to calculate the location based off an offset from
   * the BAR. */
  struct efct_test_device *tdev = handle->tdev;
  int rxq = ef10ct_get_queue_num(queue_io_wnd->qid_in);
  
  /* FIXME EF10CT when we support multi-queue dynamic attach can re-instate
   * these checks. */
#if 0
  if( rxq < 0 || rxq >= EFCT_TEST_RXQS_N)
    return -EINVAL;

  if( tdev->rxqs[rxq].evq < 0 )
    return -EINVAL;
#endif

  queue_io_wnd->base = virt_to_phys(tdev->rxqs[rxq].post_register);
  queue_io_wnd->size = 0x1000;

  return 0;
}


static void efct_test_design_param(struct efx_auxdev_client *handle,
                                   struct efx_design_params *dp)
{
  /* Caller is trusted and should be providing us with a valid pointer */
  EFRM_ASSERT(dp);

  dp->rx_stride = 4096;
  /* NIC reports value to be multiplied by 4k */
  dp->rx_buffer_len = 256 * 4096;
  dp->rx_queues = EFCT_TEST_RXQS_N;
  dp->tx_apertures = EFCT_TEST_TXQS_N;
  dp->rx_buf_fifo_size = 128;
  dp->frame_offset_fixed = 0;
  dp->rx_metadata_len = 16;
  dp->tx_max_reorder = 1024;
  dp->tx_aperture_size = 4096;
  dp->tx_fifo_size = 0x8000;
  dp->ts_subnano_bit = 2;
  dp->unsol_credit_seq_mask = 0x7f;
  dp->l4_csum_proto = 0;
  dp->max_runt = 60;
  dp->ev_queues = EFCT_TEST_EVQS_N;
  dp->evq_sizes = 0x7f;
  dp->evq_stride = 0x1000;
  dp->num_filters = 8192;
  dp->user_bits_width = 0;
  dp->timestamp_set_sync = 1;
  dp->ev_label_width = 8;
  dp->meta_location = 1;
  dp->rollover_zeros_pkt = 1;
}


static int efct_test_get_param(struct efx_auxdev_client *handle,
                               enum efx_auxiliary_param p,
                               union efx_auxiliary_param_value *arg)
{
  int rc = -ENOSYS;

  printk(KERN_INFO "%s: param %d\n", __func__, p);

  switch(p) {
   case EFX_NETDEV:
    arg->net_dev = handle->net_dev;
    rc = 0;
    break;
   case EFX_PCI_DEV:
    arg->pci_dev = NULL;
    rc = 0;
    break;
   case EFX_PCI_DEV_DEVICE:
    arg->value = 0xffff;
    rc = 0;
    break;
   case EFX_DEVICE_REVISION:
    arg->value = 1;
    rc = 0;
    break;
   case EFX_AUXILIARY_EVQ_WINDOW:
    rc = efct_test_evq_window_addr(handle, &arg->queue_io_wnd);
    break;
   case EFX_AUXILIARY_CTPIO_WINDOW:
    rc = efct_test_ctpio_addr(handle, &arg->queue_io_wnd);
    break;
   case EFX_AUXILIARY_RXQ_WINDOW:
    rc = efct_test_buffer_post_addr(handle, &arg->queue_io_wnd);
    break;
   case EFX_DESIGN_PARAM:
    efct_test_design_param(handle, arg->design_params);
    rc = 0;
    break;
   default:
    break;
  };

  return rc;
}


static int efct_test_set_param(struct efx_auxdev_client *handle,
                               enum efx_auxiliary_param p,
                               union efx_auxiliary_param_value *arg)
{
  int rc = -ENOSYS;

  printk(KERN_INFO "%s: param %d\n", __func__, p);

  return rc;
}


static int efct_test_init_evq(struct efx_auxdev_client *handle,
                              struct efx_auxdev_rpc *rpc)
{
  struct efct_test_evq *evq;
  size_t q_size;
  dma_addr_t dma;
  int qid;

  if(WARN_ON( rpc->cmd != MC_CMD_INIT_EVQ ||
              rpc->inbuf == NULL ||
              rpc->inlen != MC_CMD_INIT_EVQ_V2_IN_LEN(1) ||
              rpc->outbuf == NULL ||
              rpc->outlen != MC_CMD_INIT_EVQ_V2_OUT_LEN ))
    return -EINVAL;

  qid = EFHW_MCDI_DWORD(rpc->inbuf, INIT_EVQ_V2_IN_INSTANCE);
  qid = ef10ct_get_queue_num(qid);
  evq = &handle->tdev->evqs[qid];

  printk(KERN_INFO "%s: qid %d\n", __func__, qid);
  if( evq->inited )
    return -EBUSY;

  q_size = EFHW_MCDI_DWORD(rpc->inbuf, INIT_EVQ_V2_IN_SIZE);
  dma = EFHW_MCDI_QWORD(rpc->inbuf, INIT_EVQ_V2_IN_DMA_ADDR);

  BUG_ON(evq->txqs != 0);

  evq->inited = true;
  evq->q_base = page_to_virt(pfn_to_page(dma >> PAGE_SHIFT));
  evq->entries = q_size;
  evq->ptr = 0;
  evq->mask = evq->entries - 1;

  EFHW_MCDI_POPULATE_DWORD_4(
    (ci_dword_t*)rpc->outbuf,
    INIT_EVQ_V2_OUT_FLAGS,
    INIT_EVQ_V2_OUT_FLAG_RXQ_FORCE_EV_MERGING, 0,
    INIT_EVQ_V2_OUT_FLAG_CUT_THRU, 0,
    INIT_EVQ_V2_OUT_FLAG_TX_MERGE,
    EFHW_MCDI_DWORD_FIELD(rpc->inbuf, INIT_EVQ_V2_IN_FLAG_TX_MERGE),
    INIT_EVQ_V2_OUT_FLAG_RX_MERGE,
    EFHW_MCDI_DWORD_FIELD(rpc->inbuf, INIT_EVQ_V2_IN_FLAG_RX_MERGE)
  );

  rpc->outlen_actual = MC_CMD_INIT_EVQ_V2_OUT_LEN;

  return 0;
}


static int efct_test_free_evq(struct efx_auxdev_client *handle,
                              struct efx_auxdev_rpc *rpc)
{
  int evq;

  if(WARN_ON( rpc->cmd != MC_CMD_FINI_EVQ ||
              rpc->inbuf == NULL ||
              rpc->inlen != MC_CMD_FINI_EVQ_IN_LEN ))
    return -EINVAL;

  evq = EFHW_MCDI_DWORD(rpc->inbuf, FINI_EVQ_IN_INSTANCE);
  evq = ef10ct_get_queue_num(evq);

  printk(KERN_INFO "%s: qid %d\n", __func__, evq);
  WARN(!handle->tdev->evqs[evq].inited,
       "%s: Error freeing q %d but not inited\n", __func__, evq);

  WARN(handle->tdev->evqs[evq].txqs != 0,
       "%s: Error freeing evq %d, but still bound to txqs %x\n",
       __func__, evq, handle->tdev->evqs[evq].txqs);

  handle->tdev->evqs[evq].inited = false;

  return 0;
}


static int efct_test_init_txq(struct efx_auxdev_client *handle,
                              struct efx_auxdev_rpc *rpc)
{
  struct efct_test_device *tdev = handle->tdev;
  struct efct_test_txq *txq;
  int txq_idx, evq;

  if(WARN_ON( rpc->cmd != MC_CMD_INIT_TXQ ||
              rpc->inbuf == NULL ||
              rpc->inlen != MC_CMD_INIT_TXQ_EXT_IN_LEN ))
    return -EINVAL;

  txq_idx = EFHW_MCDI_DWORD(rpc->inbuf, INIT_TXQ_EXT_IN_INSTANCE);
  txq_idx = ef10ct_get_queue_num(txq_idx);
  evq = EFHW_MCDI_DWORD(rpc->inbuf, INIT_TXQ_EXT_IN_TARGET_EVQ);
  evq = ef10ct_get_queue_num(evq);

  printk(KERN_INFO "%s: evq %d\n", __func__, evq);
  if( !tdev->evqs[evq].inited )
    return -EINVAL;

  txq = &tdev->txqs[txq_idx];

  txq->ctpio = kmalloc(0x1000, GFP_KERNEL);
  if( !txq->ctpio )
    return -ENOMEM;
  memset(txq->ctpio, 0xff, 0x1000);
  set_memory_wc((unsigned long)txq->ctpio, 1);

  atomic_set(&txq->timer_running, 1);
  INIT_DELAYED_WORK(&txq->timer, efct_test_tx_timer);
  schedule_delayed_work(&txq->timer, 100);

  txq->evq = evq;
  txq->tdev = tdev;
  tdev->evqs[evq].txqs |= 1 << txq_idx;
  txq->ptr = 0;
  txq->pkt_ctr = 0;

  printk(KERN_INFO "%s: bound txq %d to evq %d\n", __func__, txq_idx,
         evq);

  return 0;
}


static int efct_test_free_txq(struct efx_auxdev_client *handle,
                              struct efx_auxdev_rpc *rpc)
{
  struct efct_test_device *tdev = handle->tdev;
  struct efct_test_txq *txq;
  int txq_idx, evq;

  if(WARN_ON( rpc->cmd != MC_CMD_FINI_TXQ ||
              rpc->inbuf == NULL ||
              rpc->inlen != MC_CMD_FINI_TXQ_IN_LEN ))
    return -EINVAL;

  txq_idx = EFHW_MCDI_DWORD(rpc->inbuf, FINI_TXQ_IN_INSTANCE);
  txq_idx = ef10ct_get_queue_num(txq_idx);
  txq = &tdev->txqs[txq_idx];
  evq = txq->evq;

  printk(KERN_INFO "%s: txq %d\n", __func__, txq_idx);
  WARN(evq < 0,
       "%s: Error: freeing q %d, but not bound to evq\n", __func__, txq_idx);

  atomic_set(&txq->timer_running, 0);
  cancel_delayed_work_sync(&txq->timer);

  evq_push_tx_flush_complete(&tdev->evqs[evq], txq_idx);

  tdev->evqs[evq].txqs &= ~(1 << txq_idx);
  txq->evq = -1;
  set_memory_wb((unsigned long)txq->ctpio, 1);

  kfree(txq->ctpio);

  return 0;
}


static int efct_test_init_rxq(struct efx_auxdev_client *handle,
                              struct efx_auxdev_rpc *rpc)
{
  struct efct_test_device *tdev = handle->tdev;
  struct efct_test_rxq *rxq;
  int rxq_idx, evq;
  void *rxq_window;
  int rc;

  if(WARN_ON( rpc->cmd != MC_CMD_INIT_RXQ ||
              rpc->inbuf == NULL ||
              rpc->inlen != MC_CMD_INIT_RXQ_V5_IN_LEN ))
    return -EINVAL;

  rxq_idx = EFHW_MCDI_DWORD(rpc->inbuf, INIT_RXQ_V4_IN_INSTANCE);
  rxq_idx = ef10ct_get_queue_num(rxq_idx);
  evq = EFHW_MCDI_DWORD(rpc->inbuf, INIT_RXQ_V4_IN_TARGET_EVQ);
  evq = ef10ct_get_queue_num(evq);

  printk(KERN_INFO "%s: evq %d\n", __func__, evq);

  /* Check evq is valid */
  if( !tdev->evqs[evq].inited )
    return -EINVAL;

  if( rxq_idx < 0 )
    return -EINVAL;

  rxq = &tdev->rxqs[rxq_idx];

  rxq_window = kzalloc(0x1000, GFP_KERNEL);
  if( !rxq_window )
    return -ENOMEM;
  rc = set_memory_uc((unsigned long)rxq_window, 1);
  if( rc ) {
    kfree(rxq_window);
    return rc;
  }

  atomic_set(&rxq->timer_running, 1);
  INIT_DELAYED_WORK(&rxq->timer, efct_test_rx_timer);
  schedule_delayed_work(&rxq->timer, 100);

  hrtimer_init(&tdev->rxqs[rxq_idx].rx_tick, CLOCK_MONOTONIC,
               HRTIMER_MODE_REL);
  tdev->rxqs[rxq_idx].rx_tick.function = efct_rx_tick;

  /* Set fields */
  rxq->evq = evq;
  rxq->tdev = tdev;
  tdev->evqs[evq].rxqs |= 1 << rxq_idx;
  rxq->events_suppressed = true;
  rxq->post_register = (ci_qword_t*)rxq_window;

  /* Everything should be memset to 0, but I want to be sure */
  if(rxq->next_bid != 0)
    return -1;
  if(rxq->curr_bid != 0)
    return -1;
  if(rxq->pkt != 0)
    return -1;

  printk(KERN_INFO "%s: bound rxq %d to evq %d\n", __func__, rxq_idx, evq);

  return 0;
}


static int efct_test_free_rxq(struct efx_auxdev_client *handle,
                              struct efx_auxdev_rpc *rpc)
{
  struct efct_test_device *tdev = handle->tdev;
  struct efct_test_rxq *rxq;
  int rxq_idx, evq;

  if(WARN_ON( rpc->cmd != MC_CMD_FINI_RXQ ||
              rpc->inbuf == NULL ||
              rpc->inlen != MC_CMD_FINI_RXQ_IN_LEN ))
    return -EINVAL;

  rxq_idx = EFHW_MCDI_DWORD(rpc->inbuf, FINI_RXQ_IN_INSTANCE);
  rxq_idx = ef10ct_get_queue_num(rxq_idx);
  rxq = &tdev->rxqs[rxq_idx];
  evq = rxq->evq;

  printk(KERN_INFO "%s: rxq %d\n", __func__, rxq_idx);
  WARN(evq < 0,
       "%s: Error: freeing q %d, but not bound to evq\n", __func__, rxq_idx);

  atomic_set(&rxq->timer_running, 0);
  cancel_delayed_work_sync(&rxq->timer);

  hrtimer_cancel(&rxq->rx_tick);

  evq_push_rx_flush_complete(&tdev->evqs[evq], rxq_idx);

  tdev->evqs[evq].rxqs &= ~(1 << rxq_idx);
  kfree(rxq->post_register);
  set_memory_wb((unsigned long)rxq->post_register, 1);

  memset(rxq, 0, sizeof(*rxq));
  rxq->evq = -1;

  return 0;
}

static const uint32_t supported_filter_types[] = {
  /* IP match full */
  EFHW_MCDI_MATCH_FIELD_BIT(ETHER_TYPE) | EFHW_MCDI_MATCH_FIELD_BIT(SRC_IP) |
  EFHW_MCDI_MATCH_FIELD_BIT(SRC_PORT) | EFHW_MCDI_MATCH_FIELD_BIT(DST_IP) |
  EFHW_MCDI_MATCH_FIELD_BIT(DST_PORT) | EFHW_MCDI_MATCH_FIELD_BIT(IP_PROTO),
  /* IP match wild */
  EFHW_MCDI_MATCH_FIELD_BIT(ETHER_TYPE) | EFHW_MCDI_MATCH_FIELD_BIT(DST_IP) |
  EFHW_MCDI_MATCH_FIELD_BIT(DST_PORT) | EFHW_MCDI_MATCH_FIELD_BIT(IP_PROTO),
  /* Non-TCP/UDP+VLAN */
  EFHW_MCDI_MATCH_FIELD_BIT(ETHER_TYPE) | EFHW_MCDI_MATCH_FIELD_BIT(IP_PROTO) |
  EFHW_MCDI_MATCH_FIELD_BIT(OUTER_VLAN),
  /* Non-TCP/UDP */
  EFHW_MCDI_MATCH_FIELD_BIT(ETHER_TYPE) | EFHW_MCDI_MATCH_FIELD_BIT(IP_PROTO),
  /* MAC+Non-IP+VLAN */
  EFHW_MCDI_MATCH_FIELD_BIT(DST_MAC) | EFHW_MCDI_MATCH_FIELD_BIT(ETHER_TYPE) |
  EFHW_MCDI_MATCH_FIELD_BIT(OUTER_VLAN),
  /* MAC+Non-IP */
  EFHW_MCDI_MATCH_FIELD_BIT(DST_MAC) | EFHW_MCDI_MATCH_FIELD_BIT(ETHER_TYPE),
  /* MACVLAN */
  EFHW_MCDI_MATCH_FIELD_BIT(DST_MAC) | EFHW_MCDI_MATCH_FIELD_BIT(OUTER_VLAN),
  /* MAC */
  EFHW_MCDI_MATCH_FIELD_BIT(DST_MAC),
  /* Non-IP+VLAN */
  EFHW_MCDI_MATCH_FIELD_BIT(ETHER_TYPE) | EFHW_MCDI_MATCH_FIELD_BIT(OUTER_VLAN),
  /* Non-IP */
  EFHW_MCDI_MATCH_FIELD_BIT(ETHER_TYPE)
};

static const uint32_t num_filter_types = CI_ARRAY_SIZE(supported_filter_types);

static bool check_match_fields(const uint32_t match_fields)
{
  int i;
  for (i = 0; i < num_filter_types; i++) {
    if (match_fields == supported_filter_types[i])
      return true;
  }
  return false;
}


static int efct_test_filter_op(struct efx_auxdev_client *handle,
                               struct efx_auxdev_rpc *rpc)
{
  struct efct_test_device *tdev = handle->tdev;
  uint32_t filter_handle = EFHW_MCDI_DWORD(rpc->inbuf, FILTER_OP_IN_HANDLE_LO);
  uint32_t filter_meta = EFHW_MCDI_DWORD(rpc->inbuf, FILTER_OP_IN_HANDLE_HI);
  uint32_t op = EFHW_MCDI_DWORD(rpc->inbuf, FILTER_OP_IN_OP);
  uint32_t match_fields = EFHW_MCDI_DWORD(rpc->inbuf,
                                          FILTER_OP_IN_MATCH_FIELDS);
  int rc;

  /* This is super dumb and does no validation or parsing. We just use a counter
   * to generate new filter handles on insert/subscribe, and check that a
   * remove handle is within the range we've already dished out. */
  switch(op) {
   case MC_CMD_FILTER_OP_IN_OP_INSERT:
   case MC_CMD_FILTER_OP_IN_OP_SUBSCRIBE:
    if (!check_match_fields(match_fields)) {
      printk(KERN_ERR "%s: ERROR: filter requested unsupported match fields %x\n",
             __func__, match_fields);
      rc = -EINVAL;
      break;
    }
    EFHW_MCDI_SET_DWORD(rpc->outbuf, FILTER_OP_OUT_OP, op);
    EFHW_MCDI_SET_DWORD(rpc->outbuf, FILTER_OP_OUT_HANDLE_LO,
                        tdev->filter_handle++);
    EFHW_MCDI_SET_DWORD(rpc->outbuf, FILTER_OP_OUT_HANDLE_HI, op);
    rc = 0;
    break;
   case MC_CMD_FILTER_OP_IN_OP_REMOVE:
   case MC_CMD_FILTER_OP_IN_OP_UNSUBSCRIBE:
    if( ((op == MC_CMD_FILTER_OP_IN_OP_REMOVE) &&
         (filter_meta != MC_CMD_FILTER_OP_IN_OP_INSERT)) ||
        ((op == MC_CMD_FILTER_OP_IN_OP_UNSUBSCRIBE) &&
         (filter_meta != MC_CMD_FILTER_OP_IN_OP_SUBSCRIBE)) ) {
      printk(KERN_ERR "%s: ERROR: filter insert op %u removed with %u\n",
             __func__, filter_meta, op);
      rc = -EINVAL;
      break;
    }
    if( filter_handle > tdev->filter_handle ) {
      printk(KERN_ERR "%s: ERROR: filter handle %x outside expected range\n",
             __func__, filter_handle);
      rc = -EINVAL;
      break;
    }
    rc = 0;
    break;
   default:
     rc = -EOPNOTSUPP;
     break;
  }

  return rc;
}

static int efct_test_get_supported_filters(struct efx_auxdev_client *handle,
                                           struct efx_auxdev_rpc *rpc)
{
  int i;
  int op;

  if(WARN_ON( rpc->inbuf == NULL || rpc->outbuf == NULL ||
              rpc->inlen != MC_CMD_GET_PARSER_DISP_INFO_IN_LEN ))
    return -EINVAL;

  op = EFHW_MCDI_DWORD(rpc->inbuf, GET_PARSER_DISP_INFO_IN_OP);
  if( op != MC_CMD_GET_PARSER_DISP_INFO_IN_OP_GET_SUPPORTED_LL_RX_MATCHES )
    return -EINVAL;

  if( rpc->outlen < MC_CMD_GET_PARSER_DISP_INFO_OUT_LEN(num_filter_types) )
    return -ENOSPC;

  EFHW_MCDI_SET_DWORD(rpc->outbuf, GET_PARSER_DISP_INFO_OUT_OP, op);
  EFHW_MCDI_SET_DWORD(rpc->outbuf,
                      GET_PARSER_DISP_INFO_OUT_NUM_SUPPORTED_MATCHES,
                      num_filter_types);
  for( i = 0; i < num_filter_types; i++) {
    EFHW_MCDI_SET_ARRAY_DWORD(rpc->outbuf,
                              GET_PARSER_DISP_INFO_OUT_SUPPORTED_MATCHES,
                              i, supported_filter_types[i]);
  }

  rpc->outlen_actual = MC_CMD_GET_PARSER_DISP_INFO_OUT_LEN(num_filter_types);

  return 0;
}


static int efct_test_fw_rpc(struct efx_auxdev_client *handle,
                            struct efx_auxdev_rpc *rpc)
{
  int rc;

  printk(KERN_INFO "%s: cmd %d\n", __func__, rpc->cmd);

  switch(rpc->cmd) {
   case MC_CMD_INIT_EVQ:
    rc = efct_test_init_evq(handle, rpc);
    break;
   case MC_CMD_FINI_EVQ:
    rc = efct_test_free_evq(handle, rpc);
    break;
   case MC_CMD_INIT_TXQ:
    rc = efct_test_init_txq(handle, rpc);
    break;
   case MC_CMD_FINI_TXQ:
    rc = efct_test_free_txq(handle, rpc);
    break;
   case MC_CMD_INIT_RXQ:
    rc = efct_test_init_rxq(handle, rpc);
    break;
   case MC_CMD_FINI_RXQ:
    rc = efct_test_free_rxq(handle, rpc);
    break;
   case MC_CMD_FILTER_OP:
     rc = efct_test_filter_op(handle, rpc);
     break;
   case MC_CMD_GET_PARSER_DISP_INFO:
     rc = efct_test_get_supported_filters(handle, rpc);
     break;
   default:
    rc = -ENOSYS;
  };

  printk(KERN_INFO "%s: cmd %d rc %d\n", __func__, rpc->cmd, rc);

  return rc;
}

const char *efct_test_queue_name(enum ef10ct_queue_handle_type type)
{
  switch(type) {
    case EF10CT_QUEUE_HANDLE_TYPE_TXQ:
      return "TXQ";
    case EF10CT_QUEUE_HANDLE_TYPE_RXQ:
      return "RXQ";
    case EF10CT_QUEUE_HANDLE_TYPE_EVQ:
      return "EVQ";
  }

  return "unknown";
}

static int efct_test_queue_alloc(uint64_t *free,
                                 enum ef10ct_queue_handle_type type)
{
  int qid;

  if( *free == 0)
    return -ENOSPC;

  qid = __ffs(*free);
  *free &= ~(1 << qid);

  printk(KERN_INFO "%s: alloced %s qid %d, free mask now %llx\n",
         __func__, efct_test_queue_name(type), qid, *free);
  return ef10ct_reconstruct_queue_handle(qid, type);
}

static void efct_test_queue_free(uint64_t *free, int channel_nr,
                                 enum ef10ct_queue_handle_type type)
{
  channel_nr = ef10ct_get_queue_num(channel_nr);
  if( (1 << channel_nr) & *free )
    printk(KERN_ERR "%s: ERROR freeing %s qid %d, current free mask %llx\n",
           __func__, efct_test_queue_name(type), channel_nr, *free);

  *free |= 1 << channel_nr;
}

static int efct_test_channel_alloc(struct efx_auxdev_client *handle)
{
  return efct_test_queue_alloc(&handle->tdev->free_evqs,
                               EF10CT_QUEUE_HANDLE_TYPE_EVQ);
}

static void efct_test_channel_free(struct efx_auxdev_client *handle, int channel_nr)
{
  return efct_test_queue_free(&handle->tdev->free_evqs, channel_nr,
                              EF10CT_QUEUE_HANDLE_TYPE_EVQ);
}

static struct efx_auxdev_irq*
efct_test_irq_alloc(struct efx_auxdev_client *handle)
{
  return NULL;
}

static void efct_test_irq_free(struct efx_auxdev_client *handle,
                        struct efx_auxdev_irq *irq)
{
}

static int efct_test_txq_alloc(struct efx_auxdev_client *handle)
{
  return efct_test_queue_alloc(&handle->tdev->free_txqs,
                               EF10CT_QUEUE_HANDLE_TYPE_TXQ);
}

static void efct_test_txq_free(struct efx_auxdev_client *handle, int txq_nr)
{
  efct_test_queue_free(&handle->tdev->free_txqs, txq_nr,
                       EF10CT_QUEUE_HANDLE_TYPE_TXQ);
}

static int efct_test_rxq_alloc(struct efx_auxdev_client *handle)
{
  return efct_test_queue_alloc(&handle->tdev->free_rxqs,
                               EF10CT_QUEUE_HANDLE_TYPE_RXQ);
}

static void efct_test_rxq_free(struct efx_auxdev_client *handle, int rxq_nr)
{
  efct_test_queue_free(&handle->tdev->free_rxqs, rxq_nr,
                       EF10CT_QUEUE_HANDLE_TYPE_RXQ);
}


const struct efx_auxdev_ops test_base_devops = {
  .open = efct_test_open,
  .close = efct_test_close,
  .get_param = efct_test_get_param,
  .set_param = efct_test_set_param,
  .fw_rpc = efct_test_fw_rpc,
};

const struct efx_auxdev_llct_ops test_devops = {
  .base_ops = &test_base_devops,
  .channel_alloc = efct_test_channel_alloc,
  .channel_free = efct_test_channel_free,
  .irq_alloc = efct_test_irq_alloc,
  .irq_free = efct_test_irq_free,
  .txq_alloc = efct_test_txq_alloc,
  .txq_free = efct_test_txq_free,
  .rxq_alloc = efct_test_rxq_alloc,
  .rxq_free = efct_test_rxq_free,
};

