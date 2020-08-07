/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */


#include <linux/rtnetlink.h>
#include <ci/efhw/nic.h>
#include <ci/efrm/nic_notifier.h>
#include <ci/efrm/nic_table.h>
#include "linux_resource_internal.h"


static struct efrm_nic_notifier *registered_notifier;


struct nic_dev {
  struct net_device* net_dev;
  struct list_head list;
};


void efrm_notify_for_each_nic(void(notify_op(const struct net_device*)))
{
  struct efhw_nic* nic;
  int nic_index;

  struct nic_dev* nic_dev;
  struct nic_dev* temp;
  struct list_head nics;

  INIT_LIST_HEAD(&nics);

  ASSERT_RTNL();

  /* Obtain a list of net_devs that we need to notify. Thi is a two stage
   * process, because we can't do the notify itself with the nic table lock
   * held.
   */
  spin_lock_bh(&efrm_nic_tablep->lock);
  EFRM_FOR_EACH_NIC(nic_index, nic) {
    struct net_device* net_dev = efhw_nic_get_net_dev(nic);
    if( net_dev ) {
      nic_dev = kzalloc(sizeof(*nic_dev), GFP_ATOMIC);

      if( nic_dev ) {
        nic_dev->net_dev = net_dev;
        list_add(&nic_dev->list, &nics);
      }
      else {
        EFRM_ERR("Failed to notify change of %s", net_dev->name);
      }
    }
    else {
      EFRM_ERR("Failed to obtain net dev for notify of nic %d", nic->index);
    }
  }
  spin_unlock_bh(&efrm_nic_tablep->lock);
 
  list_for_each_entry_safe_reverse(nic_dev, temp, &nics, list) {
    notify_op(nic_dev->net_dev);
    dev_put(nic_dev->net_dev);
    list_del(&nic_dev->list);
    kfree(nic_dev);
  }
}

void efrm_register_nic_notifier(struct efrm_nic_notifier* notifier)
{
  EFRM_ASSERT(!registered_notifier);

  /* We need the rtnl lock here to avoid the list of nics changing while we're
   * doing the actual notify, and to avoid a double notification if a nic
   * appears between setting the notifier and notifying existing nics.
   */
  rtnl_lock();
  registered_notifier = notifier;

  efrm_notify_for_each_nic(efrm_notify_nic_probe);
  rtnl_unlock();
}
EXPORT_SYMBOL(efrm_register_nic_notifier);


void efrm_unregister_nic_notifier(struct efrm_nic_notifier* notifier)
{
  EFRM_ASSERT(registered_notifier == notifier);

  rtnl_lock();
  efrm_notify_for_each_nic(efrm_notify_nic_remove);

  registered_notifier = NULL;
  rtnl_unlock();
}
EXPORT_SYMBOL(efrm_unregister_nic_notifier);


void efrm_notify_nic_probe(const struct net_device* netdev)
{
  if( registered_notifier )
    registered_notifier->probe(netdev);
}


void efrm_notify_nic_remove(const struct net_device* netdev)
{
  if( registered_notifier )
    registered_notifier->remove(netdev);
}
