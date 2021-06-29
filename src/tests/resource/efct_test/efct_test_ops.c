/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/set_memory.h>
#include <linux/random.h>

#include <ci/driver/ci_aux.h>
#include <ci/driver/ci_efct.h>

#include "efct_test_device.h"
#include "efct_test_ops.h"


struct xlnx_efct_client {
  struct efct_test_device *tdev;
  const struct xlnx_efct_drvops *drvops;
  void* drv_priv;
};


enum hrtimer_restart efct_rx_tick(struct hrtimer *hr)
{
  /* Totally artificially do superbuf rollover once a second */
  struct efct_test_rxq* q = container_of(hr, struct efct_test_rxq, rx_tick);
  struct efct_test_device* tdev = container_of(q, struct efct_test_device,
                                               rxqs[q->ix]);
  int sbid;
  printk(KERN_DEBUG "q%d: superbuf rollover\n", q->ix);

  tdev->client->drvops->poll(tdev->client->drv_priv, q->ix, 9999);
  if( q->target_n_hugepages ) {
    sbid = find_first_bit(q->freelist, EFCT_TEST_MAX_SUPERBUFS);
    if( sbid == EFCT_TEST_MAX_SUPERBUFS )
      printk(KERN_INFO "q%d: no free superbufs\n", q->ix);
    else {
      __clear_bit(sbid, q->freelist);
      tdev->client->drvops->buffer_start(tdev->client->drv_priv, q->ix, sbid,
                                         false);
    }
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
    arg->variant = 'A';
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

  evq->inited = true;
  evq->q_base = page_to_virt(params->q_page);
  evq->entries = params->entries;

  return 0;
}


static void efct_test_free_evq(struct xlnx_efct_client *handle, int evq)
{
  printk(KERN_INFO "%s: qid %d\n", __func__, evq);
  if( !handle->tdev->evqs[evq].inited )
    printk(KERN_INFO "%s: Error freeing q %d but not inited\n", __func__, evq);

  if( handle->tdev->evqs[evq].txqs != 0 )
    printk(KERN_INFO "%s: Error freeing evq %d, but still bound to txqs %x\n",
           __func__, evq, handle->tdev->evqs[evq].txqs);

  handle->tdev->evqs[evq].inited = false;
}


static int efct_test_alloc_txq(struct xlnx_efct_client *handle,
                               struct xlnx_efct_txq_params *params)
{
  struct efct_test_device *tdev = handle->tdev;
  int txq = -1;
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
      txq = i;
      break;
    }

  if( txq < 0 )
    return -EBUSY;

  tdev->txqs[txq].ctpio = kzalloc(0x1000, GFP_KERNEL);
  if( !tdev->txqs[txq].ctpio )
    return -ENOMEM;
  set_memory_wc((unsigned long)tdev->txqs[txq].ctpio, 1);

  tdev->txqs[txq].evq = params->evq;
  tdev->evqs[params->evq].txqs |= 1 << txq;

  printk(KERN_INFO "%s: bound txq %d to evq %d\n", __func__, txq, params->evq);

  return txq;
}


static void efct_test_free_txq(struct xlnx_efct_client *handle, int txq)
{
  struct efct_test_device *tdev = handle->tdev;
  int evq = tdev->txqs[txq].evq;

  printk(KERN_INFO "%s: txq %d\n", __func__, txq);
  if( evq < 0 )
    printk(KERN_INFO "%s: Error: freeing q %d, but not bound to evq\n",
           __func__, txq);

  tdev->evqs[evq].txqs &= ~(1 << txq);
  tdev->txqs[txq].evq = -1;
  set_memory_wb((unsigned long)tdev->txqs[txq].ctpio, 1);
  kfree(tdev->txqs[txq].ctpio);
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
    qid = get_random_u32() % EFCT_TEST_RXQS_N;
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
    if( test_bit(i * 2, q->freelist) && test_bit(i * 2 + 1, q->freelist) ) {
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

