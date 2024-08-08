/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/module.h>
#ifndef EFX_USE_KCOMPAT
#include <linux/mtd/mtd.h>
#else
#include "linux_mtd_mtd.h"
#endif
#include <linux/slab.h>
#ifndef EFX_USE_KCOMPAT
#include <linux/rtnetlink.h>
#endif

#include "net_driver.h"
#include "efx.h"

/* Some partitions should only be written during manufacturing.  Not
 * only should they not be rewritten later, but exposing all of them
 * can easily fill up the MTD table (16 or 32 entries).
 */
bool efx_allow_nvconfig_writes;
#ifdef EFX_NOT_UPSTREAM
module_param(efx_allow_nvconfig_writes, bool, 0644);
MODULE_PARM_DESC(efx_allow_nvconfig_writes,
		 "Allow access to static config and backup firmware");
#endif /* EFX_NOT_UPSTREAM */

/* MTD interface */

int efx_mtd_init(struct efx_nic *efx)
{
	efx->mtd_struct = kzalloc(sizeof(*efx->mtd_struct), GFP_KERNEL);
	if (!efx->mtd_struct)
		return -ENOMEM;

	efx->mtd_struct->efx = efx;
	INIT_LIST_HEAD(&efx->mtd_struct->list);

#ifdef EFX_WORKAROUND_87308
	atomic_set(&efx->mtd_struct->probed_flag, 0);
	INIT_DELAYED_WORK(&efx->mtd_struct->creation_work,
			   efx_mtd_creation_work);
#endif

	return 0;
}

void efx_mtd_free(struct efx_nic *efx)
{
	if (efx->mtd_struct)
		kfree(efx->mtd_struct);

	efx->mtd_struct = NULL;
}

static int efx_mtd_erase(struct mtd_info *mtd, struct erase_info *erase)
{
	struct efx_mtd_partition *part = mtd->priv;
	struct efx_nic *efx = part->mtd_struct->efx;
	int rc;

	rc = efx->type->mtd_erase(mtd, erase->addr, erase->len);
#if defined(EFX_USE_KCOMPAT) && defined(MTD_ERASE_DONE)
	erase->state = rc ? MTD_ERASE_FAILED : MTD_ERASE_DONE;
	mtd_erase_callback(erase);
#endif
	return rc;
}

static void efx_mtd_sync(struct mtd_info *mtd)
{
	struct efx_mtd_partition *part = mtd->priv;
	struct efx_nic *efx = part->mtd_struct->efx;
	int rc;

	rc = efx->type->mtd_sync(mtd);
	if (rc)
		pr_err("%s: %s sync failed (%d)\n",
		       part->name, part->dev_type_name, rc);
}

static void efx_mtd_free_parts(struct kref *kref)
{
	struct efx_mtd *mtd_struct = container_of(kref, struct efx_mtd, parts_kref);

	kfree(mtd_struct->parts);
	mtd_struct->parts = NULL;
}

static void efx_mtd_scrub(struct efx_mtd_partition *part)
{
	/* Clear the MTD type to prevent new files being opened for the
	 * device. Clear the partition name so that user space tools will
	 * not find a match for it.
	 */
	part->mtd.type = MTD_ABSENT;
	part->name[0] = '\0';

	/* The MTD wrappers check for NULL, except for the read
	 * function. We render that harmless by setting the
	 * size to 0.
	 */
	part->mtd._erase = NULL;
	part->mtd._write = NULL;
	part->mtd._sync = NULL;

	part->mtd.priv = NULL;
	part->mtd.size = 0;
}

#ifdef EFX_NOT_UPSTREAM
/* Free the MTD device after all references have gone away. */
static void efx_mtd_release_partition(struct device *dev)
{
	struct mtd_info *mtd = dev_get_drvdata(dev);
	struct efx_mtd_partition *part = mtd->priv;

	/* Call mtd_release to remove the /dev/mtdXro node */
	if (dev->type && dev->type->release)
		(dev->type->release)(dev);

	efx_mtd_scrub(part);
	list_del(&part->node);
	kref_put(&part->mtd_struct->parts_kref, efx_mtd_free_parts);
}
#endif

static void efx_mtd_remove_partition(struct efx_mtd *mtd_struct,
				     struct efx_mtd_partition *part)
{
	int rc;
#ifdef EFX_WORKAROUND_63680
	unsigned retry;

	if (!part->mtd.size)
		return;

	for (retry = 15; retry; retry--) {
#else
	for (;;) {
#endif
		rc = mtd_device_unregister(&part->mtd);
		if (rc != -EBUSY)
			break;
#ifdef EFX_WORKAROUND_63680
		/* Try to disown the other process */
		if ((retry <= 5) && (part->mtd.usecount > 0)) {
			if (mtd_struct->efx)
				netif_err(mtd_struct->efx, hw, mtd_struct->efx->net_dev,
					  "MTD device %s stuck for %d seconds, disowning it\n",
					  part->name, 15-retry);
			else
				printk(KERN_ERR
				       "sfc: MTD device %s stuck for %d seconds, disowning it\n",
				       part->name, 15-retry);
			part->mtd.usecount--;
		}
#endif
		ssleep(1);
	}
#ifdef EFX_WORKAROUND_63680
	if (rc || !retry) {
#else
	if (rc) {
#endif
		if (mtd_struct->efx)
			netif_err(mtd_struct->efx, hw, mtd_struct->efx->net_dev,
				  "Error %d removing MTD device %s. A reboot is needed to fix this\n",
				  rc, part->name);
		else
			printk(KERN_ERR
			       "sfc: Error %d removing MTD device %s. A reboot is needed to fix this\n",
			       rc, part->name);
		part->name[0] = '\0';
	}

#ifndef EFX_NOT_UPSTREAM
	efx_mtd_scrub(part);
	list_del(&part->node);
	kref_put(&mtd_struct->parts_kref, efx_mtd_free_parts);
#endif
}

int efx_mtd_add(struct efx_nic *efx, struct efx_mtd_partition *parts,
		size_t n_parts)
{
	struct efx_mtd_partition *part;
	struct efx_mtd *mtd_struct = efx->mtd_struct;
	size_t i;

	mtd_struct->parts = parts;
	kref_init(&mtd_struct->parts_kref);

	for (i = 0; i < n_parts; i++) {
		part = &parts[i];
		part->mtd_struct = mtd_struct;
		if (!part->mtd.writesize)
			part->mtd.writesize = 1;

		if (efx_allow_nvconfig_writes &&
		    !(part->mtd.flags & MTD_NO_ERASE))
			part->mtd.flags |= MTD_WRITEABLE;

		part->mtd.owner = THIS_MODULE;
		part->mtd.priv = part;
		part->mtd.name = part->name;

		part->mtd._erase = efx_mtd_erase;
		part->mtd._read = efx->type->mtd_read;
		part->mtd._write = efx->type->mtd_write;
		part->mtd._sync = efx_mtd_sync;

		efx->type->mtd_rename(part);

		if (mtd_device_register(&part->mtd, NULL, 0))
			goto fail;

		kref_get(&mtd_struct->parts_kref);

#ifdef EFX_NOT_UPSTREAM
		/* The core MTD functionality does not comply completely with
		 * the device API. When it does we may need to change the way
		 * our data is cleaned up.
		 */
		WARN_ON_ONCE(part->mtd.dev.release);
		part->mtd.dev.release = efx_mtd_release_partition;
#endif

		/* Add to list in order - efx_mtd_remove() depends on this */
		list_add_tail(&part->node, &mtd_struct->list);
	}

	return 0;

fail:
	netif_err(mtd_struct->efx, hw, mtd_struct->efx->net_dev,
		  "MTD device creation for %s FAILED\n", part->name);
	while (i--)
		efx_mtd_remove_partition(mtd_struct, &parts[i]);
	kref_put(&mtd_struct->parts_kref, efx_mtd_free_parts);

	/* Failure is unlikely here, but probably means we're out of memory */
	return -ENOMEM;
}

void efx_mtd_remove(struct efx_nic *efx)
{
	struct efx_mtd_partition *part, *next;
	struct efx_mtd *mtd_struct = efx->mtd_struct;

	/* This is done here because it can't be performed when the
	 *  mtd_struct is actually freed as efx might not exist
	 */
	if (list_empty(&mtd_struct->list))
		return;

	list_for_each_entry_safe(part, next, &mtd_struct->list, node)
		efx_mtd_remove_partition(mtd_struct, part);
	kref_put(&mtd_struct->parts_kref, efx_mtd_free_parts);
}

void efx_mtd_rename(struct efx_nic *efx)
{
	struct efx_mtd *mtd_struct = efx->mtd_struct;
	struct efx_mtd_partition *part;

	ASSERT_RTNL();

#if defined(EFX_WORKAROUND_87308)
	if (atomic_read(&efx->mtd_struct->probed_flag) == 0)
		return;
#endif
	list_for_each_entry(part, &mtd_struct->list, node)
		efx->type->mtd_rename(part);
}

#if defined(CONFIG_SFC_MTD) && defined(EFX_WORKAROUND_87308)
void efx_mtd_creation_work(struct work_struct *data)
{
	struct efx_mtd *mtd_struct = container_of(data, struct efx_mtd,
					   creation_work.work);

	if (atomic_xchg(&mtd_struct->probed_flag, 1) != 0)
		return;

	rtnl_lock();
	(void)efx_mtd_probe(mtd_struct->efx);
	rtnl_unlock();
}
#endif
