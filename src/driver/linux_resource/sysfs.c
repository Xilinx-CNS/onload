/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */
/* This file implements Onload's sysfs hierarchy. */

#include "linux_resource_internal.h"
#include <ci/driver/kernel_compat.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/nondl.h>
#include <linux/rtnetlink.h>
#include <linux/ethtool.h>
#include "sfcaffinity.h"

#ifdef EFHW_HAS_AF_XDP

/* Name of our AF_XDP sysfs directory.  */
#define SYSFS_DIR_NAME "afxdp"

/* Root directory containing our sysfs stuff. */
static struct kobject *sysfs_dir;

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

        dev = dev_get_by_name(current->nsproxy->net_ns, ifname);
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

        dev = dev_get_by_name(current->nsproxy->net_ns, ifname);
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

static struct kobj_attribute nondl_register = __ATTR(register, 0600,
                                                    empty_show,
                                                    nondl_register_store);

static struct kobj_attribute nondl_unregister = __ATTR(unregister, 0600,
                                                      empty_show,
                                                      nondl_unregister_store);

static struct kobj_attribute *nondl_attrs[] = {
        &nondl_register,
        &nondl_unregister,
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
#endif


static ssize_t enable_store(struct device *dev,
			    struct device_attribute *attr,
			    const char *buf, size_t count)
{
	struct efhw_nic* nic;
	bool enable;
	nic = efhw_nic_find_by_dev(dev);
	if (!nic)
		return -ENOENT;
	if (kstrtobool(buf, &enable) < 0) {
		EFRM_ERR("%s: Cannot parse data written to %s/sfc_resource/enable.",
		         __func__, to_net_dev(dev)->name);
		return -EINVAL;
	}
	efrm_nic_set_accel_allowed(nic, enable);
	return count;
}


static ssize_t enable_show(struct device *dev,
			   struct device_attribute *attr,
			   char *buf_out)
{
	struct efhw_nic* nic;
	int enabled;
	nic = efhw_nic_find_by_dev(dev);
	if (!nic)
		return -ENOENT;
	enabled = efrm_nic_get_accel_allowed(nic);
	return scnprintf(buf_out, PAGE_SIZE, "%d\n", enabled);
}


static ssize_t cpu2rxq_store(struct device *dev,
			    struct device_attribute *attr,
			    const char *buf, size_t count)
{
	struct efhw_nic* nic;
	nic = efhw_nic_find_by_dev(dev);
	if (!nic)
		return -ENOENT;
	return efrm_affinity_store_cpu2rxq(linux_efhw_nic(nic), buf, count);
}


static ssize_t cpu2rxq_show(struct device *dev,
			   struct device_attribute *attr,
			   char *buf_out)
{
	struct efhw_nic* nic;
	nic = efhw_nic_find_by_dev(dev);
	if (!nic)
		return -ENOENT;
	return efrm_affinity_show_cpu2rxq(linux_efhw_nic(nic), buf_out);
}


/* sysfs device attributes that may be exposed, depending on architecture
 * If adding more attributes, increment EFRM_NIC_MAX_SYSFS_ATTRS and
 * update enum efrm_nic_sysfs_attr_flags */
static DEVICE_ATTR_RW(enable);
static DEVICE_ATTR_RW(cpu2rxq);

/* Maximum number of sysfs attributes we might expose */
#define EFRM_NIC_MAX_SYSFS_ATTRS 2
#define EFRM_NIC_SYSFS_GROUP_NAME "sfc_resource"

void efrm_nic_add_sysfs(const struct net_device* net_dev, struct device *dev,
			unsigned int attr_flags)
{
	struct attribute *attrs[EFRM_NIC_MAX_SYSFS_ATTRS + 1] = { NULL };
	struct attribute_group attr_group = {
		.name = EFRM_NIC_SYSFS_GROUP_NAME,
		.attrs = attrs,
	};
	int attrs_i = 0;
	int rc;

	if (attr_flags & EFRM_NIC_SYSFS_ENABLE)
		attrs[attrs_i++] = &dev_attr_enable.attr;
	if (attr_flags & EFRM_NIC_SYSFS_CPU2RXQ)
		attrs[attrs_i++] = &dev_attr_cpu2rxq.attr;

	EFRM_ASSERT((attrs_i <= sizeof(attrs) / sizeof(attrs[0])) && attrs[attrs_i] == NULL);

	/* We expect callers to include at least one attribute */
	if (attrs_i == 0)
		EFRM_WARN("%s: Adding sysfs group `%s` with no attributes intf=%s.",
			  __func__, EFRM_NIC_SYSFS_GROUP_NAME, net_dev->name);
	rc = sysfs_create_group(&dev->kobj, &attr_group);
	if (!rc)
		return;
	EFRM_WARN("%s: Sysfs group `%s` creation failed intf=%s, rc=%d.",
		  __func__, EFRM_NIC_SYSFS_GROUP_NAME, net_dev->name, rc);
}

void efrm_nic_del_sysfs(struct device *dev)
{
	/* Build the full attribute list for removal. We include all possible
	 * attributes; the kernel handles removing only what exists. */
	static struct attribute *attrs[] = {
		&dev_attr_enable.attr,
		&dev_attr_cpu2rxq.attr,
		NULL,
	};
	static const struct attribute_group sfc_resource_group = {
		.name = EFRM_NIC_SYSFS_GROUP_NAME,
		.attrs = attrs,
	};
	EFRM_ASSERT((sizeof(attrs) / sizeof(attrs[0])) == (EFRM_NIC_MAX_SYSFS_ATTRS + 1));
	sysfs_remove_group(&dev->kobj, &sfc_resource_group);
}
