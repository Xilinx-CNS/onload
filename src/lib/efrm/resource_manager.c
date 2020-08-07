/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains generic code for resources and resource managers.
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

#include <ci/efrm/debug.h>
#include <ci/efrm/nic_table.h>
#include <ci/efhw/iopage.h>
#include <ci/efrm/driver_private.h>
#include <ci/efrm/private.h>
#include "efrm_internal.h"
#include "efrm_vi_set.h"
#include "efrm_vi.h"
#include "efrm_pd.h"
#include "efrm_pio.h"

#include <ci/efrm/vi_resource_manager.h>
#include <ci/efrm/vi_set.h>
#include <ci/efrm/pd.h>
#include <ci/efrm/pio.h>


/**********************************************************************
 * struct efrm_resource_manager
 */

void efrm_resource_manager_dtor(struct efrm_resource_manager *rm)
{
	EFRM_RESOURCE_MANAGER_ASSERT_VALID(rm);

	/* call destructor */
	EFRM_DO_DEBUG(if (rm->rm_resources)
		      EFRM_ERR("%s: %s leaked %d resources",
			       __FUNCTION__, rm->rm_name, rm->rm_resources));
	EFRM_ASSERT(rm->rm_resources == 0);
	EFRM_ASSERT(list_empty(&rm->rm_resources_list));

	rm->rm_dtor(rm);

	/* clear out things built by efrm_resource_manager_ctor */
	spin_lock_destroy(&rm->rm_lock);

	/* and the free the memory */
	EFRM_DO_DEBUG(memset(rm, 0, sizeof(*rm)));
	kfree(rm);
}

/* Construct a resource manager.  Resource managers are singletons. */
int
efrm_resource_manager_ctor(struct efrm_resource_manager *rm,
			   void (*dtor)(struct efrm_resource_manager *),
			   const char *name, unsigned type)
{
	EFRM_ASSERT(rm);
	EFRM_ASSERT(dtor);

	rm->rm_name = name;
	EFRM_DO_DEBUG(rm->rm_type = type);
	rm->rm_dtor = dtor;
	spin_lock_init(&rm->rm_lock);
	rm->rm_resources = 0;
	rm->rm_resources_hiwat = 0;
        rm->rm_resources_total = -1;
	INIT_LIST_HEAD(&rm->rm_resources_list);
	EFRM_RESOURCE_MANAGER_ASSERT_VALID(rm);
	return 0;
}


static void __efrm_resource_manager_add_resource(struct efrm_resource *rs)
{
	struct efrm_resource_manager *rm;
	rm = efrm_rm_table[rs->rs_type];
	++rm->rm_resources;
	list_add(&rs->rs_manager_link, &rm->rm_resources_list);
	if (rm->rm_resources > rm->rm_resources_hiwat)
		rm->rm_resources_hiwat = rm->rm_resources;
}


void efrm_resource_manager_add_resource(struct efrm_resource *rs)
{
	spin_lock_bh(&efrm_nic_tablep->lock);
	__efrm_resource_manager_add_resource(rs);
	spin_unlock_bh(&efrm_nic_tablep->lock);
}


static void __efrm_resource_manager_remove_resource(struct efrm_resource *rs)
{
	struct efrm_resource_manager *rm;
	rm = efrm_rm_table[rs->rs_type];
	EFRM_ASSERT(rm->rm_resources > 0);
	--rm->rm_resources;
	list_del(&rs->rs_manager_link);
}


void efrm_client_add_resource(struct efrm_client *client,
			      struct efrm_resource *rs)
{
	EFRM_ASSERT(client != NULL);
	EFRM_ASSERT(rs != NULL);

	spin_lock_bh(&efrm_nic_tablep->lock);
	__efrm_resource_manager_add_resource(rs);
	rs->rs_client = client;
	++client->ref_count;
	list_add(&rs->rs_client_link, &client->resources);
	spin_unlock_bh(&efrm_nic_tablep->lock);
}


void efrm_resource_ref(struct efrm_resource *rs)
{
	spin_lock_bh(&efrm_nic_tablep->lock);
	++rs->rs_ref_count;
	spin_unlock_bh(&efrm_nic_tablep->lock);
}
EXPORT_SYMBOL(efrm_resource_ref);


int __efrm_resource_release(struct efrm_resource *rs)
{
	int free_rs;

	spin_lock_bh(&efrm_nic_tablep->lock);
	free_rs = --rs->rs_ref_count == 0;
	if (free_rs) {
		__efrm_resource_manager_remove_resource(rs);
		if (rs->rs_client != NULL)
			list_del(&rs->rs_client_link);
	}
	spin_unlock_bh(&efrm_nic_tablep->lock);
	return free_rs;
}
EXPORT_SYMBOL(__efrm_resource_release);


void efrm_resource_release(struct efrm_resource *rs)
{
	if (__efrm_resource_release(rs) == 0)
		return;
	switch (rs->rs_type) {
	case EFRM_RESOURCE_VI:
		efrm_vi_resource_free(efrm_vi(rs));
		break;
	case EFRM_RESOURCE_VI_SET:
		efrm_vi_set_free(efrm_vi_set_from_resource(rs));
		break;
	case EFRM_RESOURCE_PD:
		efrm_pd_free(efrm_pd_from_resource(rs));
		break;
	case EFRM_RESOURCE_PIO:
		efrm_pio_free(efrm_pio_from_resource(rs), true);
		break;
	default:
		EFRM_ASSERT(0);
		break;
	}
}
EXPORT_SYMBOL(efrm_resource_release);


void efrm_resource_manager_add_total(int rs_type, int n_avail)
{
	struct efrm_resource_manager *rm = efrm_rm_table[rs_type];

	spin_lock_bh(&efrm_nic_tablep->lock);
        if( rm->rm_resources_total == -1 )
                rm->rm_resources_total = n_avail;
        else
                rm->rm_resources_total += n_avail;
	spin_unlock_bh(&efrm_nic_tablep->lock);
}


void efrm_resource_manager_del_total(int rs_type, int n_avail)
{
	struct efrm_resource_manager *rm = efrm_rm_table[rs_type];

	spin_lock_bh(&efrm_nic_tablep->lock);
        EFRM_ASSERT(rm->rm_resources_total >= n_avail);
        rm->rm_resources_total -= n_avail;
	spin_unlock_bh(&efrm_nic_tablep->lock);
}

/*
 * vi: sw=8:ai:aw
 */
