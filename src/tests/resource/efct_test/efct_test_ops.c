/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */

#include "auxiliary_bus.h"
#include "sfc_efct.h"

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

  printk(KERN_INFO "%s\n", __func__);

  switch(p) {
   case SFC_EFCT_NETDEV:
    arg->net_dev = handle->tdev->net_dev;
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

  printk(KERN_INFO "%s\n", __func__);

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


const struct sfc_efct_devops test_devops = {
  .open = efct_test_open,
  .close = efct_test_close,
  .get_param = efct_test_get_param,
  .set_param = efct_test_set_param,
  .fw_rpc = efct_test_fw_rpc,
};

