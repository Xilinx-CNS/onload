/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */

#include <linux/init.h>
#include <linux/module.h>
#include "auxiliary_bus.h"

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
 *
 * Returns &struct efct_test_device pointer on success, or ERR_PTR() on error.
 */
struct efct_test_device* efct_test_add_test_dev(struct device* parent)
{
  struct efct_test_device* tdev;
  struct auxiliary_device* adev;
  int rc;

  tdev = kzalloc(sizeof(*tdev), GFP_KERNEL);
  if( !tdev ) {
    return ERR_PTR(-ENOMEM);
  }

  tdev->dev.ops = &test_devops;
  adev = &tdev->dev.adev;

  /* Once we have successfully initted the aux dev then the lifetime of the
   * wrapping test dev must be associated with the aux device. This means
   * that the responsibility for cleanup devolves to the aux dev uninit
   * callback.
   */
  rc = init_aux_dev(adev, parent);
  if( rc != 0 ) {
    printk(KERN_INFO "Failed to init aux device %d\n", rc);
    kfree(tdev);
    return ERR_PTR(rc);
  }

  rc = auxiliary_device_add(adev);
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

  auxiliary_device_delete(adev);
  auxiliary_device_uninit(adev);
}

