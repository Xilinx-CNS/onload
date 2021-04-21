/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */

#include <linux/device.h>
#include <linux/init.h>
#include <linux/module.h>
#include "auxiliary_bus.h"

#include "efct_test_device.h"

/* We need a parent device to associate our aux devices with. We create one
 * on module load to be shared between any aux devices we create.
 */
struct class* cls;
struct device* dev;

/* Currently only support creation of one test device with a static config. */
struct efct_test_device* tdev;


static int __init efct_test_init(void)
{
  int rc;

  printk(KERN_INFO "efct_test init\n");

  cls = class_create(THIS_MODULE, "efct_test");
  if( IS_ERR(cls) ) {
    rc = PTR_ERR(cls);
    printk(KERN_INFO "Failed to create class rc %d\n", rc);
    goto fail_class;
  }

  dev = device_create(cls, NULL, 0, NULL, "efct_test_parent");
  if( IS_ERR(dev) ) {
    rc = PTR_ERR(dev);
    printk(KERN_INFO "Failed to create dev rc %d\n", rc);
    goto fail_dev;
  }

  tdev = efct_test_add_test_dev(dev);
  if( IS_ERR(tdev) ) {
    rc = PTR_ERR(tdev);
    printk(KERN_INFO "Failed to add test dev rc %d\n", rc);
    goto fail_add;
  }

  return 0;

 fail_add:
  device_destroy(cls, 0);
 fail_dev:
  class_destroy(cls);
 fail_class:

  return rc;
}

static void __exit efct_test_exit(void)
{
  efct_test_remove_test_dev(tdev);

  device_destroy(cls, 0);
  class_destroy(cls);
}

module_init(efct_test_init);
module_exit(efct_test_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("efct_test aux bus test interface");
