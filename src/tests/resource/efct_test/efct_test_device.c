/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>

#include <ci/driver/ci_aux.h>

#include "efct_test_device.h"
#include "efct_test_ops.h"


static void release_aux_dev(struct device* dev)
{
  struct efct_test_device* tdev;
  tdev = container_of(dev, struct efct_test_device, dev.adev.dev);
  kfree(tdev);
}

static int init_aux_dev(struct auxiliary_device* adev,
                        struct device* parent)
{
  adev->name = SFC_EFCT_DEVNAME;
  adev->dev.parent = parent;
  adev->dev.release = release_aux_dev;

  return auxiliary_device_init(adev);
}

/**
 * Create a new test dev and add it to the auxiliary bus
 * @parent: A parent device to associate this test device with.
 * @net_dev: The net device to dummy.
 *
 * Returns &struct efct_test_device pointer on success, or ERR_PTR() on error.
 */
struct efct_test_device* efct_test_add_test_dev(struct device* parent,
                                                struct net_device* net_dev)
{
  struct efct_test_device* tdev;
  struct auxiliary_device* adev;
  int rc;

  tdev = kzalloc(sizeof(*tdev), GFP_KERNEL);
  if( !tdev ) {
    return ERR_PTR(-ENOMEM);
  }

  tdev->dev.ops = &test_devops;
  dev_hold(net_dev);
  tdev->net_dev = net_dev;
  adev = &tdev->dev.adev;

  /* TODO EFCT look into dma handling - can we set the auxdev up so that the
   * auxdev itself can be used for mapping, or will we need to provide a
   * separate device for dma?
   */
  tdev->dev.adev.dev.dma_mask = &tdev->dma_mask;
  rc = dma_set_mask_and_coherent(&tdev->dev.adev.dev, 0x7fffffffull);
  if (rc)
    printk(KERN_INFO "could not find a suitable DMA mask\n");

  /* Once we have successfully initted the aux dev then the lifetime of the
   * wrapping test dev must be associated with the aux device. This means
   * that the responsibility for cleanup devolves to the aux dev uninit
   * callback.
   */
  rc = init_aux_dev(adev, parent);
  if( rc != 0 ) {
    printk(KERN_INFO "Failed to init aux device %d\n", rc);
    dev_put(tdev->net_dev);
    kfree(tdev);
    return ERR_PTR(rc);
  }

  rtnl_lock();
  rc = auxiliary_device_add(adev);
  rtnl_unlock();
  if( rc != 0 ) {
    printk(KERN_INFO "Failed to add aux device %d\n", rc);
    auxiliary_device_uninit(adev);
    return ERR_PTR(rc);
  }

  return tdev;
}

/**
 * Removes a test dev from the bus and destroys it.
 * @tdev: The test dev to remove and destroy.
 */
void efct_test_remove_test_dev(struct efct_test_device* tdev)
{
  struct auxiliary_device* adev = &tdev->dev.adev;

  dev_put(tdev->net_dev);
  rtnl_lock();
  auxiliary_device_delete(adev);
  rtnl_unlock();
  auxiliary_device_uninit(adev);
}

