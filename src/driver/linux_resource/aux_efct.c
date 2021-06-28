/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */

#include <ci/efrm/efrm_client.h>
#include <ci/efhw/nic.h>
#include <ci/tools/sysdep.h>

#include "linux_resource_internal.h"
#include "efrm_internal.h"
#include <ci/driver/ci_efct.h>

#if CI_HAVE_EFCT_AUX

static int efct_handle_event(void *driver_data,
                             const struct sfc_efct_event *event)
{
  return -ENOSYS;
}

struct sfc_efct_drvops efct_ops = {
  .name = "sfc_resource",
  .handle_event = efct_handle_event,
};


static int efct_devtype_init(struct sfc_efct_device *edev,
                             struct sfc_efct_client *client,
                             struct efhw_device_type *dev_type)
{
  union sfc_efct_param_value val;
  int rc;

  dev_type->arch = EFHW_ARCH_EFCT;
  dev_type->function = EFHW_FUNCTION_PF;

  rc = edev->ops->get_param(client, SFC_EFCT_VARIANT, &val);
  if( rc < 0 )
    return rc;
  dev_type->variant = val.variant;

  rc = edev->ops->get_param(client, SFC_EFCT_REVISION, &val);
  if( rc < 0 )
    return rc;
  dev_type->revision = val.value;

  return 0;
}

static int efct_resource_init(struct sfc_efct_device *edev,
                              struct sfc_efct_client *client,
                              struct vi_resource_dimensions *res_dim)
{
  union sfc_efct_param_value val;
  int rc;

  rc = edev->ops->get_param(client, SFC_EFCT_NIC_RESOURCES, &val);
  if( rc < 0 )
    return rc;

  res_dim->vi_min = val.nic_res.evq_min;
  res_dim->vi_lim = val.nic_res.evq_lim;
  res_dim->mem_bar = VI_RES_MEM_BAR_UNDEFINED;

  return 0;
}

int efct_probe(struct auxiliary_device *auxdev,
               const struct auxiliary_device_id *id)
{
  struct sfc_efct_device *edev = to_sfc_efct_device(auxdev);
  struct vi_resource_dimensions res_dim = {};
  struct efhw_device_type dev_type;
  struct sfc_efct_client *client;
  union sfc_efct_param_value val;
  struct linux_efhw_nic *lnic = NULL;
  struct net_device *net_dev;
  struct efhw_nic *nic;
  int rc;

  EFRM_NOTICE("%s name %s", __func__, id->name);

  client = edev->ops->open(auxdev, &efct_ops, NULL);
  if( IS_ERR(client) )
    return PTR_ERR(client);

  rc = edev->ops->get_param(client, SFC_EFCT_NETDEV, &val);
  if( rc < 0 )
    goto fail;

  net_dev = val.net_dev;
  EFRM_NOTICE("%s probe of dev %s", __func__, net_dev->name);

  if( efhw_nic_find(net_dev) ) {
    EFRM_TRACE("%s: netdev %s already registered", __func__, net_dev->name);
    rc = -EBUSY;
    goto fail;
  }

  rc = efct_devtype_init(edev, client, &dev_type);
  if( rc < 0 )
    goto fail;

  rc = efct_resource_init(edev, client, &res_dim);
  if( rc < 0 )
    goto fail;

  rc = efrm_nic_add(client, &auxdev->dev, &dev_type, 0, net_dev, &lnic,
                    &res_dim, 0);
  if( rc < 0 )
    goto fail;

  nic = &lnic->efrm_nic.efhw_nic;
  nic->mtu = net_dev->mtu + ETH_HLEN;

  efrm_notify_nic_probe(net_dev);
  return 0;

 fail:
  edev->ops->close(client);
  EFRM_ERR("%s rc %d", __func__, rc);
  return rc;
}


void efct_remove(struct auxiliary_device *auxdev)
{
  struct sfc_efct_device *edev = to_sfc_efct_device(auxdev);
  struct sfc_efct_client *client;
  struct linux_efhw_nic *lnic;
  struct net_device *net_dev;
  struct efhw_nic* nic;

  EFRM_NOTICE("%s", __func__);

  nic = efhw_nic_find_by_dev(&auxdev->dev);
  if( !nic )
    return;

  lnic = linux_efhw_nic(nic);
  client = (struct sfc_efct_client*)lnic->drv_device;
  if( !client )
    return;

  net_dev = efhw_nic_get_net_dev(nic);
  efrm_notify_nic_remove(net_dev);
  dev_put(net_dev);

  /* flush all outstanding dma queues */
  efrm_nic_flush_all_queues(nic, 0);

  lnic->drv_device = NULL;
  /* Wait for all in-flight driverlink calls to finish.  Since we
   * have already cleared [lnic->drv_device], no new calls can
   * start. */
  efhw_nic_flush_drv(nic);
  efrm_nic_unplug(nic);

  /* Absent hardware is treated as a protracted reset. */
  efrm_nic_reset_suspend(nic);
  ci_atomic32_or(&nic->resetting, NIC_RESETTING_FLAG_UNPLUGGED);

  edev->ops->close(client);
}


static const struct auxiliary_device_id efct_id_table[] = {
  { .name = "efct_test." SFC_EFCT_DEVNAME, },
  {},
};
MODULE_DEVICE_TABLE(auxiliary, efct_id_table);


struct auxiliary_driver efct_drv = {
  .name = "efct",
  .probe = efct_probe,
  .remove = efct_remove,
  .id_table = efct_id_table,
};

#endif
