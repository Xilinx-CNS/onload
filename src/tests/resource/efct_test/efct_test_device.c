/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#ifdef __has_include
#if __has_include(<linux/set_memory.h>)
#include <linux/set_memory.h>
#endif
#if __has_include(<asm/set_memory.h>)
#include <asm/set_memory.h>
#endif
#endif

#include <ci/driver/ci_aux.h>

#include "efct_test_device.h"
#include "efct_test_ops.h"


static void release_aux_dev(struct device* dev)
{
  struct efct_test_device* tdev;
  tdev = container_of(dev, struct efct_test_device, dev.auxdev.dev);
  kfree(tdev);
}

static int init_aux_dev(struct auxiliary_device* adev,
                        struct device* parent)
{
  adev->name = EFX_LLCT_DEVNAME ".test";
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
  int i;

  tdev = kzalloc(sizeof(*tdev), GFP_KERNEL);
  if( !tdev ) {
    return ERR_PTR(-ENOMEM);
  }

  tdev->evq_window = kmalloc(0x1000 * EFCT_TEST_EVQS_N, GFP_KERNEL);
  if( !tdev->evq_window ) {
    kfree(tdev);
    return ERR_PTR(-ENOMEM);
  }
  set_memory_wc((unsigned long)tdev->evq_window, 1);

  tdev->dev.ops = &test_devops;
  dev_hold(net_dev);
  tdev->net_dev = net_dev;
  adev = &tdev->dev.auxdev;
  for( i = 0; i < EFCT_TEST_TXQS_N; i++ )
    tdev->txqs[i].evq = -1;
  for( i = 0; i < EFCT_TEST_RXQS_N; i++)
    tdev->rxqs[i].evq = -1;

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
  struct auxiliary_device* adev = &tdev->dev.auxdev;

  dev_put(tdev->net_dev);
  rtnl_lock();
  auxiliary_device_delete(adev);
  rtnl_unlock();
  auxiliary_device_uninit(adev);

  set_memory_wb((unsigned long)tdev->evq_window, 1);
  kfree(tdev->evq_window);
}

int efct_test_set_rxq_ms_per_pkt(struct efct_test_device* tdev, int rxq,
                                 int ms_per_pkt)
{
  struct efct_test_rxq* q = &tdev->rxqs[rxq];

  if( rxq < 0 || rxq >= EFCT_TEST_RXQS_N || ms_per_pkt < 0 || q->evq == -1 )
    return -EINVAL;
  hrtimer_cancel(&q->rx_tick);

  q->ms_per_pkt = ms_per_pkt;
  if( ms_per_pkt ){
    hrtimer_start(&q->rx_tick, ms_to_ktime(ms_per_pkt), HRTIMER_MODE_REL);
  }
  return 0;
}

int efct_test_set_rxq_num_pkts(struct efct_test_device* tdev, int rxq,
                                 int num_pkts)
{
  struct efct_test_rxq* q = &tdev->rxqs[rxq];

  if( rxq < 0 || rxq >= EFCT_TEST_RXQS_N || num_pkts < 0 )
    return -EINVAL;

  q->num_pkts = num_pkts;
  q->curr_pkts = 0;
  return 0;
}
