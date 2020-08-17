/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */
/* This file implements Onload's sysfs hierarchy.
 * Currently only for non-driverlink devices and specifically
 * AF_XDP ones */

#include "linux_resource_internal.h"
#include "kernel_compat.h"
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/nondl.h>
#include <linux/rtnetlink.h>

/* Name of our sysfs directory. 
 *
 * A currently only afxdp devices are handled the name reflects that.
 */
#define SYSFS_DIR_NAME "afxdp"

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

        ASSERT_RTNL();

        netns = get_net_ns_by_pid(task_pid_nr(current));
        if(!netns)
                return NULL;

        dev = dev_get_by_name(netns, ifname);

        put_net(netns);
        return dev;
}

/* Handle userspace reading from the "register" or "unregister"
 * pseudo-files. We have nothing to return except an empty line. */
static ssize_t empty_show(struct kobject *kobj,
                          struct kobj_attribute *attr,
                          char *buffer)
{
        buffer[0] = '\n';
        return 1;
}

/* Handle userspace writing to the "register" pseudo-file.
 *
 * We expect a line of the form
 *
 *    "<interface-name>[ <number-of-vis>]\n"
 *
 * Note that the incoming buffer is guaranteed to be null-terminated.
 * (https://lwn.net/Articles/178634/)
 */
static ssize_t nondl_register_store(struct kobject *kobj,
                                   struct kobj_attribute *attr,
                                   const char *buffer,
                                   size_t length)
{
        const char *end, *space;
        char ifname[IFNAMSIZ];
        unsigned long n_vis = 0;
        int rc;
        struct net_device *dev;

        /* Parse arguments and check for validity. */

        end = memchr(buffer, '\n', length);
        if(!end)
                return -EINVAL;

        space = memchr(buffer, ' ', (end - buffer));
        if(space) {
                rc = kstrtoul(space + 1, 10, &n_vis);
                if(rc < 0)
                        return rc;

                end = space;
        }

        if((end - buffer) > (IFNAMSIZ - 1))
                return -EINVAL;

        snprintf(ifname, sizeof ifname, "%.*s", (int)(end - buffer), buffer);

        /* Our arguments are OK. Look for the named network device. */

        rtnl_lock();

        dev = find_netdev(ifname);
        if(!dev) {
                rtnl_unlock();
                return -ENOENT;
        }

        if(n_vis == 0) {
                /* TODO AF_XDP: push this detection down to device initialisation */
                struct ethtool_channels channels = { .cmd = ETHTOOL_GCHANNELS };
                rc = -EOPNOTSUPP;

                if (dev->ethtool_ops->get_channels) {
                        dev->ethtool_ops->get_channels(dev, &channels);
                        n_vis = channels.combined_count;
                }
        }
        if(n_vis == 0) {
                n_vis = 1;
                EFRM_WARN("%s: cannot detect number of channels for device %s assuming 1", __func__, ifname);
        }

        rc = efrm_nondl_register_netdev(dev, n_vis);

        dev_put(dev);
        rtnl_unlock();

        if(rc < 0)
                return rc;
        else
                return length;
}

/* Handle userspace writing to the "unregister" pseudo-file.
 *
 * We expect a line of the form
 *
 *    "<interface-name>\n"
 *
 * Note that the incoming buffer is guaranteed to be null-terminated.
 * (https://lwn.net/Articles/178634/)
 */
static ssize_t nondl_unregister_store(struct kobject *kobj,
                                     struct kobj_attribute *attr,
                                     const char *buffer,
                                     size_t length)
{
        const char *lf;
        char ifname[IFNAMSIZ];
        struct net_device *dev;
        int rc;

        /* Parse arguments and check for validity. */

        lf = memchr(buffer, '\n', length);
        if(!lf)
                return -EINVAL;
        if((lf - buffer) > (IFNAMSIZ - 1))
                return -EINVAL;

        snprintf(ifname, sizeof ifname, "%.*s", (int)(lf - buffer), buffer);

        /* Our arguments are OK. Look for the named network device. */

        rtnl_lock();

        dev = find_netdev(ifname);
        if(!dev) {
                rtnl_unlock();
                return -ENOENT;
        }

        rc = efrm_nondl_unregister_netdev(dev);

        dev_put(dev);
        rtnl_unlock();

        if(rc < 0)
                return rc;
        else
                return length;
}

/* TODO: these are useful for manual testing, however they should
 * probably be removed at some point */
static ssize_t nondl_up_store(struct kobject *kobj,
                             struct kobj_attribute *attr,
                             const char *buffer,
                             size_t length)
{
        efrm_nondl_start_all();
        return length;
}

static ssize_t nondl_down_store(struct kobject *kobj,
                               struct kobj_attribute *attr,
                               const char *buffer,
                               size_t length)
{
        efrm_nondl_stop_all();
        return length;
}

static struct kobj_attribute nondl_register = __ATTR(register, 0660,
                                                    empty_show,
                                                    nondl_register_store);

static struct kobj_attribute nondl_unregister = __ATTR(unregister, 0660,
                                                      empty_show,
                                                      nondl_unregister_store);

static struct kobj_attribute nondl_up = __ATTR(up, 0660,
                                              empty_show,
                                              nondl_up_store);

static struct kobj_attribute nondl_down = __ATTR(down, 0660,
                                                empty_show,
                                                nondl_down_store);

static struct kobj_attribute *nondl_attrs[] = {
        &nondl_register,
        &nondl_unregister,
        &nondl_up,
        &nondl_down,
        NULL
};

static struct attribute_group nondl_group = {
        .attrs = (struct attribute **)&nondl_attrs,
};

/* Install sysfs files on module load. */
void efrm_install_sysfs_entries(void)
{
        int rc;

        sysfs_dir = kobject_create_and_add(SYSFS_DIR_NAME,
                                           &(THIS_MODULE->mkobj.kobj));
        if(sysfs_dir == NULL) {
                EFRM_ERR("%s: can't create sysfs directory", __func__);
                return;
        }

        rc = sysfs_create_group(sysfs_dir, &nondl_group);

        if(rc) {
                EFRM_ERR("%s: can't create sysfs files: %d", __func__, rc);
                kobject_put(sysfs_dir);
                sysfs_dir = NULL;
                return;
        }
}

/* Remove sysfs files on module unload. */
void efrm_remove_sysfs_entries(void)
{
        if(sysfs_dir != NULL) {
                sysfs_remove_group(sysfs_dir, &nondl_group);
                kobject_put(sysfs_dir);
                sysfs_dir = NULL;
        }
}
