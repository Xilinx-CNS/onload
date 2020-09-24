/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */
/* This file contains the resource driver management for non driverlink
 * devices. */

#include "linux_resource_internal.h"
#include <ci/driver/kernel_compat.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/nondl.h>
#include <linux/rtnetlink.h>

static int efrm_nondl_register_device(struct efrm_nondl_device *device)
{
  int rc;

  ASSERT_RTNL();
  EFRM_ERR("%s: register %s", __func__, device->netdev->name);
  rc = efrm_nic_add_device(device->netdev, device->n_vis);

  return rc;
}

static void efrm_nondl_unregister_device(struct efrm_nondl_device *device)
{
  ASSERT_RTNL();
  EFRM_ERR("%s: unregister %s", __func__, device->netdev->name);
  efrm_nic_del_device(device->netdev);
}

static struct efrm_nondl_driver efrm_nondl_driver = {
  .register_device = efrm_nondl_register_device,
  .unregister_device = efrm_nondl_unregister_device,
};

extern void efrm_nondl_register(void)
{
  efrm_nondl_register_driver(&efrm_nondl_driver);
}

extern void efrm_nondl_unregister(void)
{
  efrm_nondl_unregister_driver(&efrm_nondl_driver);
}
