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
#include <ci/driver/ci_efct.h>
#include <ci/compat.h>
#include <etherfabric/internal/efct_uk_api.h>
#include <ci/tools/byteorder.h>
#include <ci/tools/bitfield.h>

#include "efct_test_device.h"
#include "efct_test_ops.h"
#include "efct_test_tx.h"

#ifndef page_to_virt
/* Only RHEL7 doesn't have this macro */
#define page_to_virt(x)        __va(PFN_PHYS(page_to_pfn(x)))
#endif

struct xlnx_efct_client {
  struct efct_test_device *tdev;
  const struct xlnx_efct_drvops *drvops;
  void* drv_priv;
};

#define EFCT_TEST_PKT_BYTES          2048
#define EFCT_TEST_PKTS_PER_SUPERBUF  \
                          (EFCT_RX_SUPERBUF_BYTES / EFCT_TEST_PKT_BYTES)

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
};


static void do_rollover(struct efct_test_device *tdev, struct efct_test_rxq *q)
{
  int sbid = -1;

  if( q->current_sbid >= 0 )
    __change_bit(q->current_sbid, q->curr_sentinel);

  if( q->target_n_hugepages ) {
    sbid = find_first_bit(q->freelist, EFCT_TEST_MAX_SUPERBUFS);
    if( sbid == EFCT_TEST_MAX_SUPERBUFS ) {
      printk(KERN_INFO "q%d: no free superbufs\n", q->ix);
      sbid = -1;
    }
    else {
      __clear_bit(sbid, q->freelist);
      tdev->client->drvops->buffer_start(tdev->client->drv_priv, q->ix,
                                         q->sbseq, sbid,
                                         test_bit(sbid, q->curr_sentinel));
    }
  }
  printk(KERN_DEBUG "q%d: superbuf rollover %d -> %d\n",
         q->ix, q->current_sbid, sbid);
  ++q->sbseq;
  q->current_sbid = sbid;
  q->next_pkt = round_up(q->next_pkt, EFCT_TEST_PKTS_PER_SUPERBUF);
}

static void* superbuf_ptr(struct efct_test_rxq *q)
{
  return (char*)page_to_virt(q->hugepages[q->current_sbid/2].page) +
         q->current_sbid % 2 * EFCT_RX_SUPERBUF_BYTES;
}

enum hrtimer_restart efct_rx_tick(struct hrtimer *hr)
{
  /* Totally artificially do superbuf rollover once a second */
  struct efct_test_rxq* q = container_of(hr, struct efct_test_rxq, rx_tick);
  struct efct_test_device* tdev = container_of(q, struct efct_test_device,
                                               rxqs[q->ix]);

  tdev->client->drvops->poll(tdev->client->drv_priv, q->ix, 9999);

  if( q->current_sbid >= 0 ) {
    char *buf = superbuf_ptr(q);
    int ix = q->next_pkt % EFCT_TEST_PKTS_PER_SUPERBUF;
    char *dst = buf + ix * EFCT_TEST_PKT_BYTES + 64;
    /* packet data actually starts 2 bytes in to the cache line, so L3 header
     * ends up 4-byte aligned. */
    memset(dst, 0, 2);
    dst += 2;
    /* NB: doesn't necessarily copy forwards. Never mind */
    memcpy(dst, fake_pkt, sizeof(fake_pkt));
    memcpy(dst + sizeof(fake_pkt), &q->next_pkt, sizeof(q->next_pkt));
  }

  ++q->next_pkt;
  if( q->next_pkt % EFCT_TEST_PKTS_PER_SUPERBUF == 0 )
    do_rollover(tdev, q);

  if( q->current_sbid >= 0 ) {
    char *buf = superbuf_ptr(q);
    int ix = q->next_pkt % EFCT_TEST_PKTS_PER_SUPERBUF;
    ci_oword_t meta;
    ci_oword_t *dst = (ci_oword_t*)(buf + ix * EFCT_TEST_PKT_BYTES);
    CI_POPULATE_OWORD_4(meta,
                        EFCT_RX_HEADER_PACKET_LENGTH, sizeof(fake_pkt) +
                                                      sizeof(q->next_pkt),
                        EFCT_RX_HEADER_NEXT_FRAME_LOC, 1,
                        EFCT_RX_HEADER_L4_CLASS, 1,
                        EFCT_RX_HEADER_SENTINEL,
                                  test_bit(q->current_sbid, q->curr_sentinel));
    WRITE_ONCE(dst->u64[1], meta.u64[1]);
    wmb();
    WRITE_ONCE(dst->u64[0], meta.u64[0]);
  }

  hrtimer_forward_now(hr, ms_to_ktime(q->ms_per_pkt));
  return HRTIMER_RESTART;
}


static struct xlnx_efct_client* efct_test_open(struct auxiliary_device *adev,
                                            const struct xlnx_efct_drvops *ops,
                                            void *driver_data)
{
  struct xlnx_efct_client *client;
  struct efct_test_device *tdev;

  printk(KERN_INFO "%s\n", __func__);

  /* Currently support exactly one test device, which should be opened at most
   * once by the efct driver.
   */
  tdev = container_of(adev, struct efct_test_device, dev.adev);
  BUG_ON(tdev->client);

  client = kzalloc(sizeof(*client), GFP_KERNEL);
  if( !client )
    return ERR_PTR(-ENOMEM);

  client->drvops = ops;
  client->drv_priv = driver_data;
  tdev->client = client;
  client->tdev = tdev;

  return client;
}


static int efct_test_close(struct xlnx_efct_client *handle)
{
  struct efct_test_device *tdev = handle->tdev;
  int rxq;
  printk(KERN_INFO "%s\n", __func__);

  if( ! tdev )
    return -EINVAL;

  for( rxq = 0; rxq < EFCT_TEST_RXQS_N; ++rxq ) {
    int i;
    if( tdev->rxqs[rxq].current_n_hugepages == 0 )
      continue;
    for( i = 0; i < ARRAY_SIZE(tdev->rxqs[rxq].hugepages); ++i )
      if( tdev->rxqs[rxq].hugepages[i].page )
        handle->drvops->free_hugepage(handle->drv_priv,
                                      &tdev->rxqs[rxq].hugepages[i]);
  }

  tdev->client = NULL;
  kfree(handle);

  return 0;
}


static int efct_test_get_param(struct xlnx_efct_client *handle,
                               enum xlnx_efct_param p,
                               union xlnx_efct_param_value *arg)
{
  int rc = -ENOSYS;

  printk(KERN_INFO "%s: param %d\n", __func__, p);

  switch(p) {
   case XLNX_EFCT_NETDEV:
    arg->net_dev = handle->tdev->net_dev;
    rc = 0;
    break;
   case XLNX_EFCT_VARIANT:
    arg->variant = 'T';
    rc = 0;
    break;
   case XLNX_EFCT_REVISION:
    arg->value = 1;
    rc = 0;
    break;
   case XLNX_EFCT_NIC_RESOURCES:
    arg->nic_res.evq_min = 0;
    arg->nic_res.evq_lim = EFCT_TEST_EVQS_N - 1;
    rc = 0;
    break;
   default:
    break;
  };

  return rc;
}


static int efct_test_set_param(struct xlnx_efct_client *handle,
                               enum xlnx_efct_param p,
                               union xlnx_efct_param_value *arg)
{
  int rc = -ENOSYS;

  printk(KERN_INFO "%s: param %d\n", __func__, p);

  return rc;
}


static int efct_test_fw_rpc(struct xlnx_efct_client *handle,
                            struct xlnx_efct_rpc *rpc)
{
  printk(KERN_INFO "%s: cmd %d\n", __func__, rpc->cmd);
  return -ENOSYS;
}


static int efct_test_init_evq(struct xlnx_efct_client *handle,
                              struct xlnx_efct_evq_params *params)
{
  struct efct_test_evq *evq = &handle->tdev->evqs[params->qid];

  printk(KERN_INFO "%s: qid %d\n", __func__, params->qid);
  if( evq->inited )
    return -EBUSY;

  BUG_ON(evq->txqs != 0);

  evq->inited = true;
  evq->q_base = page_to_virt(params->q_page);
  evq->entries = params->entries;
  evq->ptr = 0;
  evq->mask = evq->entries - 1;

  return 0;
}


static void efct_test_free_evq(struct xlnx_efct_client *handle, int evq)
{
  printk(KERN_INFO "%s: qid %d\n", __func__, evq);
  WARN(!handle->tdev->evqs[evq].inited,
       "%s: Error freeing q %d but not inited\n", __func__, evq);

  WARN(handle->tdev->evqs[evq].txqs != 0,
       "%s: Error freeing evq %d, but still bound to txqs %x\n",
       __func__, evq, handle->tdev->evqs[evq].txqs);

  handle->tdev->evqs[evq].inited = false;
}


static int efct_test_alloc_txq(struct xlnx_efct_client *handle,
                               struct xlnx_efct_txq_params *params)
{
  struct efct_test_device *tdev = handle->tdev;
  struct efct_test_txq *txq;
  int txq_idx = -1;
  int i;

  printk(KERN_INFO "%s: evq %d\n", __func__, params->evq);
  if( !tdev->evqs[params->evq].inited )
    return -EINVAL;

  /* Onload allocate vis (and hence EVQs) through a buddy allocator, so we can
   * just allocate linearly and should end up testing differing EVQ and TXQ
   * ids.
   */
  for( i = 0; i < EFCT_TEST_TXQS_N; i++ )
    if( tdev->txqs[i].evq < 0 ) {
      txq_idx = i;
      break;
    }

  if( txq_idx < 0 )
    return -EBUSY;

  txq = &tdev->txqs[txq_idx];

  txq->ctpio = kmalloc(0x1000, GFP_KERNEL);
  if( !txq->ctpio )
    return -ENOMEM;
  memset(txq->ctpio, 0xff, 0x1000);
  set_memory_wc((unsigned long)txq->ctpio, 1);

  atomic_set(&txq->timer_running, 1);
  INIT_DELAYED_WORK(&txq->timer, efct_test_tx_timer);
  schedule_delayed_work(&txq->timer, 100);

  txq->evq = params->evq;
  txq->tdev = tdev;
  tdev->evqs[params->evq].txqs |= 1 << txq_idx;
  txq->ptr = 0;
  txq->pkt_ctr = 0;

  printk(KERN_INFO "%s: bound txq %d to evq %d\n", __func__, txq_idx,
         params->evq);

  return txq_idx;
}


static void efct_test_free_txq(struct xlnx_efct_client *handle, int txq_idx)
{
  struct efct_test_device *tdev = handle->tdev;
  int evq = tdev->txqs[txq_idx].evq;
  struct efct_test_txq *txq = &tdev->txqs[txq_idx];

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
}


static int efct_test_ctpio_addr(struct xlnx_efct_client *handle, int txq,
                                resource_size_t *addr, size_t *size)
{
  struct efct_test_device *tdev = handle->tdev;

  printk(KERN_INFO "%s\n", __func__);

  if( tdev->txqs[txq].evq < 0 )
    return -EINVAL;

  *addr = virt_to_phys(tdev->txqs[txq].ctpio);
  *size = 0x1000;
  return 0;
}


static int efct_test_bind_rxq(struct xlnx_efct_client *handle,
                              struct xlnx_efct_rxq_params *params)
{
  struct efct_test_device *tdev = handle->tdev;
  int qid = params->qid;
  int i, j;
  int n_hugepages = params->n_hugepages;
  struct efct_test_rxq* q;
  struct xlnx_efct_hugepage* new_pages;

  printk(KERN_INFO "%s q=%d ts=%d hp=%zu\n", __func__, params->qid,
         params->timestamp_req, params->n_hugepages);

  if( qid < 0 )
    qid = get_random_int() % EFCT_TEST_RXQS_N;
  if( qid >= EFCT_TEST_RXQS_N )
    return -EINVAL;

  q = &tdev->rxqs[qid];
  n_hugepages = q->target_n_hugepages + n_hugepages - q->current_n_hugepages;
  if( n_hugepages > 0 ) {
    new_pages = kmalloc_array(n_hugepages, sizeof(*new_pages), GFP_KERNEL);
    if( ! new_pages )
      return -ENOMEM;

    for( i = 0; i < n_hugepages; ++i ) {
      int rc = tdev->client->drvops->alloc_hugepage(handle->drv_priv,
                                                    &new_pages[i]);
      if( rc ) {
        for( --i; i >= 0; --i )
          tdev->client->drvops->free_hugepage(handle->drv_priv, &new_pages[i]);
        kfree(new_pages);
        return rc;
      }
    }
    for( i = 0, j = 0; i < ARRAY_SIZE(q->hugepages) && j < n_hugepages; ++i ) {
      if( ! q->hugepages[i].page ) {
        ++q->current_n_hugepages;
        q->hugepages[i] = new_pages[j++];
        __set_bit(i * 2, q->freelist);
        __set_bit(i * 2 + 1, q->freelist);
        __set_bit(i * 2, q->curr_sentinel);
        __set_bit(i * 2 + 1, q->curr_sentinel);
      }
    }
    for( ; j < n_hugepages; ++j )
      tdev->client->drvops->free_hugepage(handle->drv_priv, &new_pages[j]);
    kfree(new_pages);
  }
  q->target_n_hugepages += params->n_hugepages;

  return qid;
}

static int efct_test_rollover_rxq(struct xlnx_efct_client *handle, int rxq)
{
  printk(KERN_INFO "%s q=%d\n", __func__, rxq);
  return 0;
}

static void efct_test_free_rxq(struct xlnx_efct_client *handle, int rxq,
                               size_t n_hugepages)
{
  struct efct_test_device *tdev = handle->tdev;
  struct efct_test_rxq* q = &tdev->rxqs[rxq];
  size_t i;

  printk(KERN_INFO "%s q=%d hp=%zu\n", __func__, rxq, n_hugepages);
  if( q->target_n_hugepages < n_hugepages )
    printk(KERN_ERR "%s BAD DECREMENT\n", __func__);
  q->target_n_hugepages -= n_hugepages;
  for( i = 0; i < ARRAY_SIZE(q->hugepages) &&
              q->current_n_hugepages > q->target_n_hugepages; ++i ) {
    /* This check is all nastily racey. Whatever */
    if( test_bit(i * 2, q->freelist) && test_bit(i * 2 + 1, q->freelist) &&
        q->current_sbid != i * 2 && q->current_sbid != i * 2 + 1 ) {
      __clear_bit(i * 2, q->freelist);
      __clear_bit(i * 2 + 1, q->freelist);
      tdev->client->drvops->free_hugepage(handle->drv_priv, &q->hugepages[i]);
      q->hugepages[i] = (struct xlnx_efct_hugepage){};
      --q->current_n_hugepages;
    }
  }
}

static int efct_test_get_hugepages(struct xlnx_efct_client *handle, int rxq,
                                   struct xlnx_efct_hugepage *pages,
                                   size_t n_pages)
{
  struct efct_test_device *tdev = handle->tdev;
  printk(KERN_INFO "%s q=%d n=%zu\n", __func__, rxq, n_pages);
  memset(pages, 0, sizeof(*pages) * n_pages);
  memcpy(pages, tdev->rxqs[rxq].hugepages,
         min(n_pages, ARRAY_SIZE(tdev->rxqs[rxq].hugepages)) * sizeof(*pages));
  return 0;
}


static void efct_test_release_superbuf(struct xlnx_efct_client *handle,
                                       int rxq, int sbid)
{
  struct efct_test_device *tdev = handle->tdev;
  printk(KERN_INFO "%s q=%d sb=%d\n", __func__, rxq, sbid);
  if( rxq < 0 || sbid < 0 || rxq >= EFCT_TEST_RXQS_N ||
      sbid >= EFCT_TEST_MAX_SUPERBUFS )
    printk(KERN_ERR "%s BAD PARAMETER\n", __func__);
  else if( test_bit(sbid, tdev->rxqs[rxq].freelist) )
    printk(KERN_ERR "%s DOUBLE FREE\n", __func__);
  else
    __set_bit(sbid, tdev->rxqs[rxq].freelist);
}


const struct xlnx_efct_devops test_devops = {
  .open = efct_test_open,
  .close = efct_test_close,
  .get_param = efct_test_get_param,
  .set_param = efct_test_set_param,
  .fw_rpc = efct_test_fw_rpc,
  .init_evq = efct_test_init_evq,
  .free_evq = efct_test_free_evq,
  .alloc_txq = efct_test_alloc_txq,
  .free_txq = efct_test_free_txq,
  .bind_rxq = efct_test_bind_rxq,
  .rollover_rxq = efct_test_rollover_rxq,
  .free_rxq = efct_test_free_rxq,
  .ctpio_addr = efct_test_ctpio_addr,
  .get_hugepages = efct_test_get_hugepages,
  .release_superbuf = efct_test_release_superbuf,
};

