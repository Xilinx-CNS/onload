/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */
/* This file contains the resource driver management for non driverlink
 * devices. */

#include "linux_resource_internal.h"
#include <ci/driver/kernel_compat.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/nondl.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/af_xdp.h>
#include <linux/rtnetlink.h>

#ifdef EFHW_HAS_AF_XDP

static int efrm_nondl_add_device(struct net_device *net_dev, int n_vis)
{
  struct vi_resource_dimensions res_dim = {};
  struct efx_dl_ef10_resources *ef10_res = NULL;
  struct linux_efhw_nic *lnic = NULL;
  unsigned timer_quantum_ns = 0;
  struct efhw_nic *nic;
  struct efhw_device_type dev_type;
  int rc;

  ASSERT_RTNL();

  if( efhw_nic_find(net_dev) ) {
    EFRM_TRACE("efrm_nic_add_ifindex: netdev %s already registered",
               netdev_name(net_dev));
    return -EALREADY;
  }

  ef10_res = kmalloc(sizeof(*ef10_res), GFP_KERNEL);
  memset(ef10_res, 0, sizeof(*ef10_res));
  ef10_res->rss_channel_count = 1;
  ef10_res->vi_min = 0;
  ef10_res->vi_lim = n_vis;
  ef10_res->hdr.type = EFX_DL_EF10_RESOURCES;
  timer_quantum_ns = ef10_res->timer_quantum_ns = 60000;

  res_dim.efhw_ops = &af_xdp_char_functional_units;
  res_dim.vi_min = ef10_res->vi_min;
  res_dim.vi_lim = ef10_res->vi_lim;
  res_dim.rss_channel_count = ef10_res->rx_channel_count;
  res_dim.vi_base = ef10_res->vi_base;
  res_dim.vi_shift = ef10_res->vi_shift;

  EFRM_TRACE("Using VI range %d+(%d-%d)<<%d", res_dim.vi_base, res_dim.vi_min,
             res_dim.vi_lim, res_dim.vi_shift);

  rc = efhw_nondl_device_type_init(&dev_type);
  if( rc < 0 ) {
    EFRM_ERR("%s: efhw_device_type_init failed %d", __func__, rc);
    return rc;
  }
  EFRM_NOTICE("%s type=%d:%c%d ifindex=%d", netdev_name(net_dev),
              dev_type.arch, dev_type.variant, dev_type.revision,
              net_dev->ifindex);

  rc = efrm_nic_add(NULL, NULL, &dev_type, 0, net_dev, &lnic, &res_dim,
                    timer_quantum_ns);
  if (rc != 0)
    return rc;

  lnic->efrm_nic.dl_dev_info = &ef10_res->hdr;

  nic = &lnic->efrm_nic.efhw_nic;
  nic->mtu = net_dev->mtu + ETH_HLEN; /* ? + ETH_VLAN_HLEN */

  return 0;
}

static int efrm_nondl_register_device(struct efrm_nondl_device *device)
{
  int rc;

  ASSERT_RTNL();
  EFRM_ERR("%s: register %s", __func__, device->netdev->name);
  rc = efrm_nondl_add_device(device->netdev, device->n_vis);

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

#endif /* EFHW_HAS_AF_XDP */

extern void efrm_nondl_register(void)
{
#ifdef EFHW_HAS_AF_XDP
  efrm_nondl_register_driver(&efrm_nondl_driver);
#endif
}

extern void efrm_nondl_unregister(void)
{
#ifdef EFHW_HAS_AF_XDP
  efrm_nondl_unregister_driver(&efrm_nondl_driver);
#endif
}
