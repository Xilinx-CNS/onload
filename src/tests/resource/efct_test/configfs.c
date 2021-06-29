/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */

#include <ci/driver/kernel_compat.h>
#include <linux/configfs.h>

#include "efct_test_driver.h"
#include "efct_test_device.h"

struct efct_configfs_rxq_item {
  struct config_group group;
  int ix;
};

struct efct_configfs_dev_item {
  struct config_group group;
  struct net_device *dev;
  struct efct_configfs_rxq_item rxqs[EFCT_TEST_RXQS_N];
};

static const struct config_item_type dev_item_type;
static const struct config_item_type rxq_item_type;

static struct efct_configfs_dev_item* to_dev_item(struct config_item *item)
{
  return container_of(item, struct efct_configfs_dev_item, group.cg_item);
}

static struct efct_configfs_rxq_item* to_rxq_item(struct config_item *item)
{
  return container_of(item, struct efct_configfs_rxq_item, group.cg_item);
}

/* Look for the named network device in the current process's network
 * namespace. Return a reference to it if found, or NULL if not found.
 *
 * This assumes that it's being called from process context. */
static struct net_device *find_netdev(const char *ifname)
{
  struct net *netns;
  struct net_device *dev;

  netns = get_net_ns_by_pid(task_pid_nr(current));
  if( IS_ERR(netns) )
    return NULL;

  dev = dev_get_by_name(netns, ifname);

  put_net(netns);
  return dev;
}

static struct config_group* efct_test_register_interface(
                                 struct config_group *group, const char *name)
{
  int i;
  int rc;
  struct net_device *dev;
  struct efct_configfs_dev_item *item;

  dev = find_netdev(name);
  if( ! dev )
    return ERR_PTR(-ENOENT);

  item = kzalloc(sizeof(*item), GFP_KERNEL);
  if( ! item ) {
    rc = -ENOMEM;
    goto fail1;
  }
  item->dev = dev;
  config_group_init_type_name(&item->group, name, &dev_item_type);

  for( i = 0; i < EFCT_TEST_RXQS_N; ++i ) {
    char rxname[8];
    item->rxqs[i].ix = i;
    sprintf(rxname, "rx%d", i);
    config_group_init_type_name(&item->rxqs[i].group, rxname, &rxq_item_type);
    configfs_add_default_group(&item->rxqs[i].group, &item->group);
  }

  rc = efct_test_add_netdev(dev);
  if( rc < 0 )
    goto fail2;

  return &item->group;

 fail2:
  kfree(item);
 fail1:
  dev_put(dev);
  return ERR_PTR(rc);
}

static void efct_test_unregister_interface(struct config_item *cfs_item)
{
  struct efct_configfs_dev_item *item = to_dev_item(cfs_item);

  efct_test_remove_netdev(item->dev);
  dev_put(item->dev);
}

static ssize_t rxq_index_show(struct config_item *item, char *page)
{
  return sprintf(page, "%d\n", to_rxq_item(item)->ix);
}

CONFIGFS_ATTR_RO(rxq_, index);

static struct configfs_attribute *rxq_attrs[] = {
  &rxq_attr_index,
  NULL,
};

static const struct config_item_type rxq_item_type = {
  .ct_attrs = rxq_attrs,
  .ct_owner = THIS_MODULE,
};

static ssize_t dev_ifindex_show(struct config_item *item, char *page)
{
  return sprintf(page, "%d\n", to_dev_item(item)->dev->ifindex);
}

CONFIGFS_ATTR_RO(dev_, ifindex);

static struct configfs_attribute *dev_attrs[] = {
  &dev_attr_ifindex,
  NULL,
};

static struct configfs_item_operations dev_item_ops = {
  .release = efct_test_unregister_interface,
};

static const struct config_item_type dev_item_type = {
  .ct_item_ops = &dev_item_ops,
  .ct_attrs = dev_attrs,
  .ct_owner = THIS_MODULE,
};

static struct configfs_group_operations interfaces_group_ops = {
  .make_group = efct_test_register_interface,
};

static const struct config_item_type interfaces_type = {
  .ct_group_ops = &interfaces_group_ops,
  .ct_owner = THIS_MODULE,
};

static struct configfs_subsystem efct_configfs_root = {
  .su_group = {
    .cg_item = {
      .ci_namebuf = "efct_test",
      .ci_type = &interfaces_type,
    },
  },
};

static bool efct_cfs_inited = false;

/* Install configfs files on module load. */
int efct_test_install_configfs_entries(void)
{
  int rc;

  config_group_init(&efct_configfs_root.su_group);
  mutex_init(&efct_configfs_root.su_mutex);
  rc = configfs_register_subsystem(&efct_configfs_root);
  efct_cfs_inited = rc >= 0;
  return rc;
}

/* Remove configfs files on module unload. */
void efct_test_remove_configfs_entries(void)
{
  if( efct_cfs_inited )
    configfs_unregister_subsystem(&efct_configfs_root);
}
