/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */

#include <linux/slab.h>

#include <ci/driver/ci_aux.h>
#include <ci/driver/ci_efct.h>

#include "efct_test_device.h"
#include "efct_test_ops.h"


struct sfc_efct_client {
  struct efct_test_device *tdev;
  const struct sfc_efct_drvops *drvops;
  void* drv_priv;
};


static struct sfc_efct_client* efct_test_open(struct auxiliary_device *adev,
                                             const struct sfc_efct_drvops *ops)
{
  struct sfc_efct_client *client;
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
  tdev->client = client;
  client->tdev = tdev;

  return client;
}


static int efct_test_close(struct sfc_efct_client *handle)
{
  printk(KERN_INFO "%s\n", __func__);

  if( !handle->tdev )
    return -EINVAL;

  handle->tdev->client = NULL;
  kfree(handle);

  return 0;
}


static int efct_test_get_param(struct sfc_efct_client *handle,
                               enum sfc_efct_param p,
                               union sfc_efct_param_value *arg)
{
  int rc = -ENOSYS;

  printk(KERN_INFO "%s: param %d\n", __func__, p);

  switch(p) {
   case SFC_EFCT_NETDEV:
    arg->net_dev = handle->tdev->net_dev;
    rc = 0;
    break;
   case SFC_EFCT_VARIANT:
    arg->variant = 'A';
    rc = 0;
    break;
   case SFC_EFCT_REVISION:
    arg->value = 1;
    rc = 0;
    break;
   case SFC_EFCT_NIC_RESOURCES:
    arg->nic_res.evq_min = 0;
    arg->nic_res.evq_lim = EFCT_TEST_EVQS_N - 1;
    rc = 0;
    break;
   case SFC_EFCT_DRIVER_DATA:
    arg->ptr = handle->drv_priv;
    rc = 0;
    break;
   default:
    break;
  };

  return rc;
}


static int efct_test_set_param(struct sfc_efct_client *handle,
                               enum sfc_efct_param p,
                               union sfc_efct_param_value *arg)
{
  int rc = -ENOSYS;

  printk(KERN_INFO "%s: param %d\n", __func__, p);

  switch(p) {
   case SFC_EFCT_DRIVER_DATA:
    handle->drv_priv = arg->ptr;
    rc = 0;
    break;
   default:
    break;
  };

  return rc;
}


static int efct_test_fw_rpc(struct sfc_efct_client *handle,
                            struct sfc_efct_rpc *rpc)
{
  printk(KERN_INFO "%s: cmd %d\n", __func__, rpc->cmd);
  return -ENOSYS;
}


static int efct_test_init_evq(struct sfc_efct_client *handle,
                              struct sfc_efct_evq_params *params)
{
  printk(KERN_INFO "%s: qid %d\n", __func__, params->qid);
  if( handle->tdev->evqs[params->qid].inited )
    return -EBUSY;

  handle->tdev->evqs[params->qid].inited = true;
  return 0;
}


static void efct_test_free_evq(struct sfc_efct_client *handle, int evq)
{
  printk(KERN_INFO "%s: qid %d\n", __func__, evq);
  if( !handle->tdev->evqs[evq].inited )
    printk(KERN_INFO "%s: Error freeing q %d but not inited\n", __func__, evq);

  if( handle->tdev->evqs[evq].txqs != 0 )
    printk(KERN_INFO "%s: Error freeing evq %d, but still bound to txqs %x\n",
           __func__, evq, handle->tdev->evqs[evq].txqs);

  handle->tdev->evqs[evq].inited = false;
}


static int efct_test_alloc_txq(struct sfc_efct_client *handle,
                               struct sfc_efct_txq_params *params)
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

  tdev->txqs[txq].evq = params->evq;
  tdev->evqs[params->evq].txqs |= 1 << txq;

  printk(KERN_INFO "%s: bound txq %d to evq %d\n", __func__, txq, params->evq);

  return txq;
}


static void efct_test_free_txq(struct sfc_efct_client *handle, int txq)
{
  struct efct_test_device *tdev = handle->tdev;
  int evq = tdev->txqs[txq].evq;

  printk(KERN_INFO "%s: txq %d\n", __func__, txq);
  if( evq < 0 )
    printk(KERN_INFO "%s: Error: freeing q %d, but not bound to evq\n",
           __func__, txq);

  tdev->evqs[evq].txqs &= ~(1 << txq);
  tdev->txqs[txq].evq = -1;
  kfree(tdev->txqs[txq].ctpio);
}


static int efct_test_ctpio_addr(struct sfc_efct_client *handle, int txq,
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


const struct sfc_efct_devops test_devops = {
  .open = efct_test_open,
  .close = efct_test_close,
  .get_param = efct_test_get_param,
  .set_param = efct_test_set_param,
  .fw_rpc = efct_test_fw_rpc,
  .init_evq = efct_test_init_evq,
  .free_evq = efct_test_free_evq,
  .alloc_txq = efct_test_alloc_txq,
  .free_txq = efct_test_free_txq,
  .ctpio_addr = efct_test_ctpio_addr,
};

