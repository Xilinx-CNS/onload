/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2006-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains the VI resource manager.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 * Certain parts of the driver were implemented by
 *          Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 *          OKTET Labs Ltd, Russia,
 *          http://oktetlabs.ru, <info@oktetlabs.ru>
 *          by request of Solarflare Communications
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

#include <ci/efrm/nic_table.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efrm/private.h>
#include <ci/efrm/vi_resource_private.h>
#include "efrm_internal.h"


void efrm_nic_vi_ctor(struct efrm_nic_vi *nvi)
{
	INIT_LIST_HEAD(&nvi->rx_flush_waiting_list);
	INIT_LIST_HEAD(&nvi->rx_flush_outstanding_list);
	INIT_LIST_HEAD(&nvi->tx_flush_outstanding_list);
	INIT_LIST_HEAD(&nvi->efct_rx_flush_outstanding_list);
	nvi->rx_flush_outstanding_count = 0;
	INIT_LIST_HEAD(&nvi->close_pending);
	INIT_WORK(&nvi->work_item, efrm_vi_rm_delayed_free);
	INIT_DELAYED_WORK(&nvi->flush_work_item, efrm_vi_check_flushes);
}


void efrm_nic_vi_dtor(struct efrm_nic_vi *nvi)
{
	flush_workqueue(efrm_vi_manager->workqueue);

	/* Now that workqueue and flush timer have gone check that there
	 * aren't any pending flushes. NIC removal should have seen to
	 * this.
	 */
	spin_lock_bh(&efrm_vi_manager->rm.rm_lock);
	EFRM_ASSERT(nvi->rx_flush_outstanding_count == 0);
	EFRM_ASSERT(list_empty(&nvi->tx_flush_outstanding_list));
	EFRM_ASSERT(list_empty(&nvi->efct_rx_flush_outstanding_list));
	spin_unlock_bh(&efrm_vi_manager->rm.rm_lock);

#ifdef EFX_USE_CANCEL_DELAYED_WORK_SYNC
	cancel_delayed_work_sync(&nvi->flush_work_item);
#else
	/* Flush work item will not respawn because there is nothing
	 * outstanding. */
	cancel_delayed_work(&nvi->flush_work_item);
	flush_workqueue(efrm_vi_manager->workqueue);
#endif

	EFRM_ASSERT(list_empty(&nvi->close_pending));
}


/*** Resource manager creation/destruction *******************************/

static void efrm_vi_rm_dtor(struct efrm_resource_manager *rm);

static int
efrm_create_or_destroy_vi_resource_manager(
				struct efrm_resource_manager **rm_in_out,
				bool destroy)
{
	int rc;

	EFRM_ASSERT(rm_in_out);

	if (destroy)
		goto destroy;

	efrm_vi_manager = kmalloc(sizeof(*efrm_vi_manager), GFP_KERNEL);
	if (efrm_vi_manager == NULL) {
		rc = -ENOMEM;
		goto fail_alloc;
	}

	memset(efrm_vi_manager, 0, sizeof(*efrm_vi_manager));

	efrm_vi_manager->workqueue = alloc_workqueue("sfc_vi", WQ_SYSFS, 0);
	if (efrm_vi_manager->workqueue == NULL) {
		rc = -ENOMEM;
		goto fail_create_workqueue;
	}

	/* NB.  This must be the last step to avoid things getting tangled.
	 * efrm_resource_manager_dtor calls the vi_rm_dtor which ends up in
	 * this function. */
	rc = efrm_resource_manager_ctor(&efrm_vi_manager->rm, efrm_vi_rm_dtor,
					"VI", EFRM_RESOURCE_VI);
	if (rc < 0)
		goto fail_rm_ctor;

	*rm_in_out = &efrm_vi_manager->rm;
	return 0;

destroy:
	rc = 0;
	EFRM_RESOURCE_MANAGER_ASSERT_VALID(*rm_in_out);

fail_rm_ctor:
	/* Complete outstanding closes. */
	destroy_workqueue(efrm_vi_manager->workqueue);
fail_create_workqueue:

	if (destroy)
		return 0;

	EFRM_DO_DEBUG(memset(efrm_vi_manager, 0, sizeof(*efrm_vi_manager)));
	kfree(efrm_vi_manager);
fail_alloc:

	*rm_in_out = NULL;
	EFRM_ERR("%s: failed rc=%d", __FUNCTION__, rc);
	return rc;
}

int
efrm_create_vi_resource_manager(struct efrm_resource_manager **rm_out)
{
	return efrm_create_or_destroy_vi_resource_manager(rm_out, false);
}

static void efrm_vi_rm_dtor(struct efrm_resource_manager *rm)
{
	efrm_create_or_destroy_vi_resource_manager(&rm, true);
}
