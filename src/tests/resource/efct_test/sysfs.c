/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */

#include <ci/driver/kernel_compat.h>

#include "efct_test_driver.h"

/* Name of our sysfs directory.  */
#define SYSFS_DIR_NAME "interfaces"

/* Root directory containing our sysfs stuff. */
static struct kobject *sysfs_dir;

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

/* Handle userspace reading from the "register" or "unregister"
 * pseudo-files. We have nothing to return except an empty line. */
static ssize_t empty_show(struct kobject *kobj, struct kobj_attribute *attr,
                          char *buffer)
{
  buffer[0] = '\n';
  return 1;
}


/* Handle userspace writing to the pseudo-file.
 *
 * We expect a line of the form
 *
 *    "<interface-name>\n"
 *
 * Note that the incoming buffer is guaranteed to be null-terminated.
 * (https://lwn.net/Articles/178634/)
 */
static struct net_device* netdev_from_store(struct kobject *kobj,
                                            const char *buffer,
                                            size_t length)
{
  const char *lf;
  char ifname[IFNAMSIZ];
  struct net_device *dev = NULL;

  /* Parse arguments and check for validity. */
  lf = memchr(buffer, '\n', length);
  if(!lf)
    return ERR_PTR(-EINVAL);
  if((lf - buffer) > (IFNAMSIZ - 1))
    return ERR_PTR(-EINVAL);

  snprintf(ifname, sizeof ifname, "%.*s", (int)(lf - buffer), buffer);

  /* Our arguments are OK. Look for the named network device. */
  dev = find_netdev(ifname);
  if(!dev)
    return ERR_PTR(-ENOENT);

  return dev;
}

static ssize_t efct_test_register_store(struct kobject *kobj,
                                        struct kobj_attribute *attr,
                                        const char *buffer,
                                        size_t length)
{
  int rc;

  struct net_device *dev = netdev_from_store(kobj, buffer, length);
  if( IS_ERR(dev) )
    return PTR_ERR(dev);

  rc = efct_test_add_netdev(dev);
  dev_put(dev);

  if( rc < 0 )
    return rc;
  else
    return length;
}

static ssize_t efct_test_unregister_store(struct kobject *kobj,
                                          struct kobj_attribute *attr,
                                          const char *buffer,
                                          size_t length)
{
  int rc;

  struct net_device *dev = netdev_from_store(kobj, buffer, length);
  if( IS_ERR(dev) )
    return PTR_ERR(dev);

  rc = efct_test_remove_netdev(dev);
  dev_put(dev);

  if( rc < 0 )
    return rc;
  else
    return length;
}

static struct kobj_attribute efct_test_register = __ATTR(register, 0600,
                                                         empty_show,
                                                         efct_test_register_store);

static struct kobj_attribute efct_test_unregister = __ATTR(unregister, 0600,
                                                           empty_show,
                                                           efct_test_unregister_store);

static struct kobj_attribute *efct_test_attrs[] = {
  &efct_test_register,
  &efct_test_unregister,
  NULL
};

static struct attribute_group efct_test_group = {
  .attrs = (struct attribute **)efct_test_attrs,
};

/* Install sysfs files on module load. */
int efct_test_install_sysfs_entries(void)
{
  int rc;

  sysfs_dir = kobject_create_and_add(SYSFS_DIR_NAME,
                                     &(THIS_MODULE->mkobj.kobj));
  if(!sysfs_dir) {
    printk(KERN_ERR "%s: can't create sysfs directory", __func__);
    return -ENOMEM;
  }

  rc = sysfs_create_group(sysfs_dir, &efct_test_group);
  if(rc < 0) {
    printk(KERN_ERR "%s: can't create sysfs files: %d", __func__, rc);
    kobject_put(sysfs_dir);
    sysfs_dir = NULL;
  }

  return rc;
}

/* Remove sysfs files on module unload. */
void efct_test_remove_sysfs_entries(void)
{
  if(sysfs_dir != NULL) {
    sysfs_remove_group(sysfs_dir, &efct_test_group);
    kobject_put(sysfs_dir);
    sysfs_dir = NULL;
  }
}
