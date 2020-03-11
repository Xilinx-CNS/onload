/****************************************************************************
* Driverlink client for testing filter handling
* Copyright 2013-2014 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
*/
#include <linux/module.h>
#include <linux/string.h>
#include <linux/netdevice.h>
#include <linux/capability.h>
#include <linux/cdev.h>
#include <linux/rwsem.h>

#include "config.h"
#include "kernel_compat.h"

#include "driverlink_api.h"
#include "filter.h"
#include "arb_filter_ioctl.h"

static char *sfc_aftm_dev_name;
static struct efx_dl_device *sfc_aftm_efx_dev;
static int sfc_aftm_dev_major;
/* Either our chrdev has been setup
 * Or sfc_aftm_efx_dev == NULL
 * Or sfc_aftm_devsem is held for writing
 */
static DECLARE_RWSEM(sfc_aftm_devsem);

static long sfc_aftm_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	enum efx_dl_filter_block_kernel_type block = EFX_DL_FILTER_BLOCK_KERNEL_MCAST;
	struct efx_filter_spec filter_spec;
	struct sfc_aftm_vport_add vport;
	struct sfc_aftm_redirect redir;
	int filter_id;
	int rc = 0;

	down_read(&sfc_aftm_devsem);
	if (!sfc_aftm_efx_dev) {
		rc = -ENODEV;
		goto out;
	}
	if (!capable(CAP_NET_ADMIN)) {
		rc = -EPERM;
		goto out;
	}
	switch (cmd) {
	case SFC_AFTM_IOCSINSERT:
		if (copy_from_user(&filter_spec, (void __user *)arg,
				   sizeof(filter_spec))) {
			rc = -EFAULT;
			goto out;
		}
		rc = efx_dl_filter_insert(sfc_aftm_efx_dev, &filter_spec, false);
		break;
	case SFC_AFTM_IOCSREINSERT:
		if (copy_from_user(&filter_spec, (void __user *)arg,
				   sizeof(filter_spec))) {
			rc = -EFAULT;
			goto out;
		}
		rc = efx_dl_filter_insert(sfc_aftm_efx_dev, &filter_spec, true);
		break;
	case SFC_AFTM_IOCSREDIRECT:
		if (copy_from_user(&redir, (void __user *)arg,
				   sizeof(struct sfc_aftm_redirect))) {
			rc = -EFAULT;
			goto out;
		}
		rc = efx_dl_filter_redirect(sfc_aftm_efx_dev, redir.filter_id,
					    redir.rxq_id, 0);
		break;
	case SFC_AFTM_IOCSREMOVE:
		filter_id = (int)arg;
		rc = efx_dl_filter_remove(sfc_aftm_efx_dev, filter_id);
		break;
	case SFC_AFTM_IOCSBLOCK:
		switch (arg) {
		case SFC_AFTM_BLOCK_ADD:
			rc = efx_dl_filter_block_kernel(sfc_aftm_efx_dev,
					EFX_DL_FILTER_BLOCK_KERNEL_UCAST);
			if (rc < 0)
				break;
			rc = efx_dl_filter_block_kernel(sfc_aftm_efx_dev,
					EFX_DL_FILTER_BLOCK_KERNEL_MCAST);
			if (rc < 0) // undo UC block
				efx_dl_filter_unblock_kernel(sfc_aftm_efx_dev,
					EFX_DL_FILTER_BLOCK_KERNEL_UCAST);
			break;
		case SFC_AFTM_BLOCK_RM:
			efx_dl_filter_unblock_kernel(sfc_aftm_efx_dev,
					EFX_DL_FILTER_BLOCK_KERNEL_UCAST);
			efx_dl_filter_unblock_kernel(sfc_aftm_efx_dev,
					EFX_DL_FILTER_BLOCK_KERNEL_MCAST);
			break;
		default:
			rc = -EINVAL;
			break;
		}
		break;
	case SFC_AFTM_IOCSUCBLK:
		block = EFX_DL_FILTER_BLOCK_KERNEL_UCAST;
		/* fallthrough */
	case SFC_AFTM_IOCSMCBLK:
		switch (arg) {
		case SFC_AFTM_BLOCK_ADD:
			rc = efx_dl_filter_block_kernel(sfc_aftm_efx_dev, block);
			break;
		case SFC_AFTM_BLOCK_RM:
			efx_dl_filter_unblock_kernel(sfc_aftm_efx_dev, block);
			break;
		default:
			rc = -EINVAL;
			break;
		}
		break;
	case SFC_AFTM_IOCSVPORT_ADD:
		if (copy_from_user(&vport, (void __user *)arg,
				   sizeof(struct sfc_aftm_vport_add))) {
			rc = -EFAULT;
			goto out;
		}
		rc = efx_dl_vport_new(sfc_aftm_efx_dev, vport.vlan,
				      vport.vlan_restrict);
		break;
	case SFC_AFTM_IOCSVPORT_DEL:
		rc = efx_dl_vport_free(sfc_aftm_efx_dev, (int)arg);
		break;
	default:
		rc = -ENOTTY;
		break;
	}
out:
	up_read(&sfc_aftm_devsem);
	return rc;
}

static const struct file_operations sfc_aftm_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= sfc_aftm_ioctl,
};

static int sfc_aftm_probe(struct efx_dl_device *efx_dev,
	const struct net_device *net_dev,
	const struct efx_dl_device_info *dev_info,
	const char *silicon_rev)
{
	int rc;

	if (!sfc_aftm_dev_name)
		return -ENODEV;
	if (strcmp(net_dev->name, sfc_aftm_dev_name))
		return -ENODEV;
	down_write(&sfc_aftm_devsem);
	if (sfc_aftm_efx_dev) {
		netdev_warn(net_dev, "sfc_aftm: found multiple devices\n");
		rc = -EEXIST;
		goto fail1;
	}
#ifdef EFX_HAVE___REGISTER_CHRDEV
	rc = __register_chrdev(0, 0, 1, "sfc_aftm", &sfc_aftm_fops);
	if (rc < 0)
		goto fail1;
	sfc_aftm_dev_major = rc;
#else
    /* this is really horrible - it takes an entire major number */
    sfc_aftm_dev_major = 254;
yeuch:
    rc = register_chrdev(sfc_aftm_dev_major, "sfc_aftm", &sfc_aftm_fops);
    if (rc == -EBUSY)
        if(sfc_aftm_dev_major--)
            goto yeuch;
    if (rc < 0)
        goto fail1;
#endif
	sfc_aftm_efx_dev = efx_dev;
	rc = 0;
	goto out;
fail1:
	netdev_err(net_dev, "sfc_aftm: failed device setup %d\n", rc);
out:
	up_write(&sfc_aftm_devsem);
	return rc;
}

static void sfc_aftm_remove(struct efx_dl_device *efx_dev)
{
	down_write(&sfc_aftm_devsem);
	if (sfc_aftm_efx_dev == efx_dev) {
#ifdef EFX_HAVE___REGISTER_CHRDEV
		__unregister_chrdev(sfc_aftm_dev_major, 0, 1, "sfc_aftm");
#else
        unregister_chrdev(sfc_aftm_dev_major, "sfc_aftm");
#endif
		sfc_aftm_efx_dev = NULL;
	}
	up_write(&sfc_aftm_devsem);
}

static struct efx_dl_driver sfc_aftm_driver = {
	.name = "sfc_aftm",
	.probe = sfc_aftm_probe,
	.remove = sfc_aftm_remove,
	.flags = EFX_DL_DRIVER_CHECKS_FALCON_RX_USR_BUF_SIZE |
		 EFX_DL_DRIVER_CHECKS_MEDFORD2_VI_STRIDE,
};

static int __init sfc_aftm_init_module(void)
{
	return efx_dl_register_driver(&sfc_aftm_driver);
}

static void __exit sfc_aftm_exit_module(void)
{
	efx_dl_unregister_driver(&sfc_aftm_driver);
}

module_init(sfc_aftm_init_module);
module_exit(sfc_aftm_exit_module);

MODULE_AUTHOR("Solarflare Communications");
MODULE_DESCRIPTION("Driverlink client for testing filter handling");
MODULE_LICENSE("GPL");

module_param_named(dev, sfc_aftm_dev_name, charp, 0644);
MODULE_PARM_DESC(dev, "Name of device to act on");
