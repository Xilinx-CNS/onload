/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */

#include <linux/device.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netdevice.h>

#include <ci/driver/ci_aux.h>

#include "efct_test_device.h"
#include "configfs.h"

/* We need a parent device to associate our aux devices with. We create one
 * on module load to be shared between any aux devices we create.
 */
struct class* cls;
struct device* dev;

/* Currently only support creation of one test device with a static config. */
struct efct_test_device* tdev;

static int check_netdev(const char* func, struct net_device* net_dev)
{
  if( ! tdev ) {
    printk(KERN_INFO "%s: no test dev registered\n", func);
    return -EBUSY;
  }

  if( tdev->net_dev != net_dev ) {
    printk(KERN_INFO "%s: %s not registered\n", func, net_dev->name);
    return -EBUSY;
  }
  return 0;
}

int efct_test_add_netdev(struct net_device* net_dev)
{
  int rc = 0;

  printk(KERN_INFO "%s: add %s\n", __func__, net_dev->name);

  if(tdev) {
    printk(KERN_INFO "%s: can't add %s, in use\n", __func__, net_dev->name);
    return -EBUSY;
  }

  tdev = efct_test_add_test_dev(dev, net_dev);
  if( IS_ERR(tdev) ) {
    rc = PTR_ERR(tdev);
    printk(KERN_INFO "%s: Failed to add test dev %s rc %d\n", __func__,
           net_dev->name, rc);
    tdev = NULL;
  }

  return rc;
}

int efct_test_remove_netdev(struct net_device* net_dev)
{
  int rc;

  printk(KERN_INFO "efct_test remove %s\n", net_dev->name);
  if( (rc = check_netdev(__func__, net_dev)) < 0 )
    return rc;

  efct_test_remove_test_dev(tdev);
  tdev = NULL;

  return 0;
}

int efct_test_netdev_set_rxq_ms_per_pkt(struct net_device* net_dev, int rxq,
                                        int ms_per_pkt)
{
  int rc;

  printk(KERN_INFO "efct_test ms_per_pkt dev=%s q=%d ms=%d\n",
         net_dev->name, rxq, ms_per_pkt);
  if( (rc = check_netdev(__func__, net_dev)) < 0 )
    return rc;

  return efct_test_set_rxq_ms_per_pkt(tdev, rxq, ms_per_pkt);
}

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

  efct_test_install_configfs_entries();
  return 0;

 fail_dev:
  class_destroy(cls);
 fail_class:

  return rc;
}

static void __exit efct_test_exit(void)
{
  efct_test_remove_configfs_entries();

  if(tdev)
    efct_test_remove_test_dev(tdev);

  device_destroy(cls, 0);
  class_destroy(cls);
}

module_init(efct_test_init);
module_exit(efct_test_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("efct_test aux bus test interface");
