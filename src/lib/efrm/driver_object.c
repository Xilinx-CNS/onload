/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains support for the global driver variables.
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
#include <ci/efrm/resource.h>
#include <ci/efrm/debug.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/efrm_nic.h>
#include <ci/efrm/driver_private.h>
#include <ci/efrm/pd.h>
#include <ci/efrm/vi_resource.h>
#include <ci/driver/resource/linux_efhw_nic.h>
#include <ci/driver/ci_efct.h>
#include <linux/nsproxy.h>
#include "efrm_internal.h"
#include "debugfs.h"


/* These routines are all methods on the architecturally singleton
   global variables: efrm_nic_table, efrm_rm_table.

   I hope we never find a driver model that does not allow global
   structure variables :) (but that would break almost every driver I've
   ever seen).
*/

/*! Exported driver state */
static struct efrm_nic_table efrm_nic_table;
struct efrm_nic_table *efrm_nic_tablep;
EXPORT_SYMBOL(efrm_nic_tablep);


/* Internal table with resource managers. */
struct efrm_resource_manager *efrm_rm_table[EFRM_RESOURCE_NUM];


/* List of registered nics. */
static LIST_HEAD(efrm_nics);


void efrm_driver_ctor(void)
{
	efrm_nic_tablep = &efrm_nic_table;
	spin_lock_init(&efrm_nic_tablep->lock);
	EFRM_TRACE("%s: driver created", __FUNCTION__);
}

void efrm_driver_stop(void)
{
	/* Take the nic table down so that users of EFRM_FOR_EACH_NIC()
	 * don't see any NICs */
	efrm_nic_table.down = 1;
	smp_wmb();
	while (efrm_nic_table_held())
		cpu_relax();
}


void efrm_driver_dtor(void)
{
	EFRM_ASSERT(efrm_nic_table_down());

	spin_lock_destroy(&efrm_nic_tablep->lock);
	memset(&efrm_nic_table, 0, sizeof(efrm_nic_table));
	memset(&efrm_rm_table, 0, sizeof(efrm_rm_table));
	EFRM_TRACE("%s: driver deleted", __FUNCTION__);
}


int efrm_nic_ctor(struct efrm_nic *efrm_nic,
		  const struct vi_resource_dimensions *res_dim)
{
	unsigned max_vis;
	int rc;

	if (!(efrm_nic->efhw_nic.devtype.arch == EFHW_ARCH_EF10 ||
	      efrm_nic->efhw_nic.devtype.arch == EFHW_ARCH_EFCT ||
	      efrm_nic->efhw_nic.devtype.arch == EFHW_ARCH_EF10CT ||
	      efrm_nic->efhw_nic.devtype.arch == EFHW_ARCH_AF_XDP)) {
		EFRM_ERR("%s: unknown efhw device architecture %u)",
			 __FUNCTION__, efrm_nic->efhw_nic.devtype.arch);
		rc = -EINVAL;
		goto fail1;
	}

	max_vis = res_dim->vi_lim;
	efrm_nic->max_vis = max_vis;
	efrm_nic->vis = vmalloc(max_vis * sizeof(efrm_nic->vis[0]));
	if (efrm_nic->vis == NULL) {
		EFRM_ERR("%s: Out of memory (max_vis=%u)",
			 __FUNCTION__, max_vis);
		rc = -ENOMEM;
		goto fail1;
	}
	memset(efrm_nic->vis, 0, max_vis * sizeof(efrm_nic->vis[0]));

	/* We request ids based on 1, as we use a 0 owner_id within Onload to 
	 * show we're using physical addressing mode.  On ef10 0 is part of
	 * our available owner id space, so we will map owner id back to 0
	 * based before passing through MCDI.
	 */
	efrm_nic->owner_ids = efrm_pd_owner_ids_ctor(1, max_vis);
	if (efrm_nic->owner_ids == NULL) {
		EFRM_ERR("%s: Out of memory (max_vis=%u)",
			 __FUNCTION__, max_vis);
		rc = -ENOMEM;
		goto fail2;
	}

	rc = efrm_interrupt_vectors_ctor(efrm_nic, res_dim);
	if (rc < 0) {
		EFRM_ERR("%s: efrm_interrupt_vectors_ctor failed (%d)",
			 __FUNCTION__, rc);
		goto fail3;
	}

	spin_lock_init(&efrm_nic->lock);
	INIT_LIST_HEAD(&efrm_nic->clients);
	efrm_nic->rx_sniff_rxq = EFRM_PORT_SNIFF_NO_OWNER;
	efrm_nic->tx_sniff_rxq = EFRM_PORT_SNIFF_NO_OWNER;

	mutex_init(&efrm_nic->dmaq_state.lock);
	INIT_LIST_HEAD(&efrm_nic->dmaq_state.q[EFHW_EVQ]);
	INIT_LIST_HEAD(&efrm_nic->dmaq_state.q[EFHW_RXQ]);
	INIT_LIST_HEAD(&efrm_nic->dmaq_state.q[EFHW_TXQ]);

	efrm_nic->rss_channel_count = res_dim->rss_channel_count;

	return 0;

fail3:
	efrm_pd_owner_ids_dtor(efrm_nic->owner_ids);
fail2:
	vfree(efrm_nic->vis);
fail1:
	return rc;
}


void efrm_nic_dtor(struct efrm_nic *efrm_nic)
{
	/* Things have gone very wrong if there are any driver clients */
	EFRM_ASSERT(list_empty(&efrm_nic->clients));

	EFRM_ASSERT(list_empty(&efrm_nic->dmaq_state.q[EFHW_EVQ]));
	EFRM_ASSERT(list_empty(&efrm_nic->dmaq_state.q[EFHW_RXQ]));
	EFRM_ASSERT(list_empty(&efrm_nic->dmaq_state.q[EFHW_TXQ]));

	efrm_interrupt_vectors_dtor(efrm_nic);
	efrm_pd_owner_ids_dtor(efrm_nic->owner_ids);
	vfree(efrm_nic->vis);

	/* Nobble some fields. */
	efrm_nic->vis = NULL;
}


int efrm_driver_register_nic(struct efrm_nic *rnic)
{
	struct efhw_nic *nic = &rnic->efhw_nic;
	int nic_index, rc = 0;

	spin_lock_bh(&efrm_nic_tablep->lock);

	if (efrm_nic_table_held()) {
		EFRM_ERR("%s: driver object is in use", __FUNCTION__);
		rc = -EBUSY;
		goto done;
	}

	/* Find a slot in the nic table. */
	for (nic_index = 0; nic_index < EFHW_MAX_NR_DEVS; ++nic_index)
		if (efrm_nic_tablep->nic[nic_index] == NULL)
			break;
	if (nic_index == EFHW_MAX_NR_DEVS) {
		EFRM_ERR("%s: filled up NIC table size %d", __FUNCTION__,
			 EFHW_MAX_NR_DEVS);
		rc = -E2BIG;
		goto done;
	}

	efrm_nic_tablep->nic[nic_index] = nic;
	nic->index = nic_index;
	list_add(&rnic->link, &efrm_nics);
	efrm_nic_vi_ctor(&rnic->nvi);
	spin_unlock_bh(&efrm_nic_tablep->lock);
	efhw_init_debugfs_nic(nic);

	return 0;

done:
	spin_unlock_bh(&efrm_nic_tablep->lock);
	return rc;
}


void efrm_driver_unregister_nic(struct efrm_nic *rnic)
{
	struct efhw_nic *nic = &rnic->efhw_nic;
	int nic_index = nic->index;

	EFRM_ASSERT(nic_index >= 0);

	efrm_nic_vi_dtor(&rnic->nvi);

	efhw_fini_debugfs_nic(nic);
	spin_lock_bh(&efrm_nic_tablep->lock);
	EFRM_ASSERT(efrm_nic_tablep->nic[nic_index] == nic);
	list_del(&rnic->link);
	nic->index = -1;
	efrm_nic_tablep->nic[nic_index] = NULL;
	spin_unlock_bh(&efrm_nic_tablep->lock);
}

#ifdef __KERNEL__


/* At hot-unplug, we shut down queues forcibly.  An intervening reset would
 * bring those queues back up again, which would be problematic, so the
 * EFRM_CLIENT_DISABLE_POST_RESET flag can be used to prevent post-reset
 * processing in such situations.
 *     These functions clear and set that flag.  There is no explicit
 * synchronisation as the intended callers (i.e. driverlink probe and removal
 * hooks) are already serialised. */

void efrm_nic_enable_post_reset(struct efhw_nic* nic)
{
	struct efrm_nic *rnic = efrm_nic(nic);
	struct efrm_client *client;
	struct list_head *client_link;

	spin_lock_bh(&efrm_nic_tablep->lock);
	list_for_each(client_link, &rnic->clients) {
		client = container_of(client_link, struct efrm_client, link);
		client->flags &= ~EFRM_CLIENT_DISABLE_POST_RESET;
	}
	spin_unlock_bh(&efrm_nic_tablep->lock);
}

void efrm_client_disable_post_reset(struct efrm_client* client)
{
	client->flags |= EFRM_CLIENT_DISABLE_POST_RESET;
}
EXPORT_SYMBOL(efrm_client_disable_post_reset);


int efrm_nic_post_reset(struct efhw_nic *nic)
{
	struct efrm_nic *rnic = efrm_nic(nic);
	struct efrm_client *client;
	struct list_head *client_link;
	struct list_head reset_list;

	INIT_LIST_HEAD(&reset_list);

	spin_lock_bh(&efrm_nic_tablep->lock);
	list_for_each(client_link, &rnic->clients) {
		client = container_of(client_link, struct efrm_client, link);
		if (client->flags & EFRM_CLIENT_DISABLE_POST_RESET) {
			EFRM_TRACE("%s: post-reset disabled", __FUNCTION__);
		}
		/* can't call post_reset directly as we're holding a
		 * spin lock and it may block (on EF10).  So just take
		 * a reference and call post_reset below 
		 */
		else if (client->callbacks->post_reset) {
			++client->ref_count;
			list_add(&client->reset_link, &reset_list);
		}
	}
	spin_unlock_bh(&efrm_nic_tablep->lock);

	while (!list_empty(&reset_list)) {
		client = list_entry(list_pop(&reset_list), struct efrm_client, 
				    reset_link);
		client->callbacks->post_reset(client, client->user_data);
		/* drop reference we took above */
		efrm_client_put(client);
	}

	return 0;
}


int efrm_nic_reset_suspend(struct efhw_nic *nic)
{
	struct efrm_nic *rnic = efrm_nic(nic);
	struct efrm_client *client;
	struct list_head *client_link;

	spin_lock_bh(&efrm_nic_tablep->lock);
	list_for_each(client_link, &rnic->clients) {
		client = container_of(client_link, struct efrm_client, link);
		client->callbacks->reset_suspend(client, client->user_data);
	}
	spin_unlock_bh(&efrm_nic_tablep->lock);

	return 0;
}


static void efrm_client_nullcb(struct efrm_client *client, void *user_data)
{
}


static struct efrm_client_callbacks efrm_null_callbacks = {
	efrm_client_nullcb,
	efrm_client_nullcb,
};

static void efrm_client_init_from_nic(struct efrm_nic *rnic,
				      struct efrm_client *client)
{
	client->nic = &rnic->efhw_nic;
	client->ref_count = 1;
	client->flags = 0;
	INIT_LIST_HEAD(&client->resources);
	list_add(&client->link, &rnic->clients);
}

static int efrm_client_get_by_foo(nic_match_func match, const void *match_data,
				  struct efrm_client_callbacks *callbacks,
				  void *user_data,
				  struct efrm_client **client_out)
{
	struct efrm_nic *n, *rnic = NULL;
	struct list_head *link;
	struct efrm_client *client;

	if (callbacks == NULL)
		callbacks = &efrm_null_callbacks;

	client = kmalloc(sizeof(*client), GFP_KERNEL);
	if (client == NULL)
		return -ENOMEM;

	spin_lock_bh(&efrm_nic_tablep->lock);
	list_for_each(link, &efrm_nics) {
		n = container_of(link, struct efrm_nic, link);
		if (match(&n->efhw_nic, match_data)) {
			rnic = n;
			break;
		}
	}
	if (rnic) {
		client->user_data = user_data;
		client->callbacks = callbacks;
		efrm_client_init_from_nic(rnic, client);
	}
	spin_unlock_bh(&efrm_nic_tablep->lock);

	if (rnic == NULL) {
		kfree(client);
		return -ENODEV;
	}

	*client_out = client;
	return 0;
}


static bool efrm_client_matches_nic(const struct efhw_nic *nic,
				    const void *data)
{
	return (nic == data);
}


/* This variant is called at NIC probe time by the onload driver, to get a
 * client to associated with a newly probed interface. */
int efrm_client_get_by_nic(const struct efhw_nic *nic,
			   struct efrm_client_callbacks *callbacks,
			   void *user_data, struct efrm_client **client_out)
{
	return efrm_client_get_by_foo(efrm_client_matches_nic, nic,
				      callbacks, user_data, client_out);
}
EXPORT_SYMBOL(efrm_client_get_by_nic);


struct client_match_data {
	const struct net_device *net_dev;
	uint64_t nic_flags;
	uint64_t nic_flags_mask;
};
static bool efrm_client_matches_net_dev(const struct efhw_nic *nic,
					const void *data)
{
	const struct client_match_data *match = data;
	return !match->net_dev ||
	       ((nic->net_dev == match->net_dev) &&
		((nic->flags & match->nic_flags_mask) == match->nic_flags));
}


/* This variant is called for each user of this interface, to get a client to
 * use for onload or ef_vi. In the case a negative ifindex is passed we just
 * select any old NIC for historical compatibility. */
int efrm_client_get(int ifindex, uint64_t nic_flags, uint64_t nic_flags_mask,
		    struct efrm_client_callbacks *callbacks,
		    void *user_data, struct efrm_client **client_out)
{
	int rc;
	struct net_device *dev = NULL;
	struct client_match_data match = {
		.nic_flags = nic_flags,
		.nic_flags_mask = nic_flags_mask,
	};

	if (ifindex >= 0) {
		dev = dev_get_by_index(current->nsproxy->net_ns, ifindex);
		if (!dev)
			return -ENODEV;
	}
	match.net_dev = dev;
	rc = efrm_client_get_by_foo(efrm_client_matches_net_dev, &match,
				    callbacks, user_data, client_out);
#if ! CI_HAVE_EFCT_AUX
	if( rc == -ENODEV ) {
		if (dev && dev->dev.parent && dev_is_pci(dev->dev.parent)) {
			struct pci_dev* pci_dev = to_pci_dev(dev->dev.parent);
			if (pci_dev->vendor == 0x10ee && pci_dev->device == 0x5084) {
				EFRM_ERR("%s: device %s (ifindex %d) is an X3, "
				         "but this Onload was built without X3 support",
				         __func__, dev->name, dev->ifindex);
				rc = -EOPNOTSUPP;
			}
		}
	}
#endif
	if (dev)
		dev_put(dev);
	return rc;
}
EXPORT_SYMBOL(efrm_client_get);


void efrm_client_set_callbacks(struct efrm_client *client,
                               struct efrm_client_callbacks *callbacks,
                               void *user_data)
{
	if (callbacks == NULL)
		callbacks = &efrm_null_callbacks;
	spin_lock_bh(&efrm_nic_tablep->lock);
	client->user_data = user_data;
	client->callbacks = callbacks;
	spin_unlock_bh(&efrm_nic_tablep->lock);
}
EXPORT_SYMBOL(efrm_client_set_callbacks);


void efrm_client_put(struct efrm_client *client)
{
	EFRM_ASSERT(client->ref_count > 0);

	spin_lock_bh(&efrm_nic_tablep->lock);
	if (--client->ref_count > 0)
		client = NULL;
	else
		list_del(&client->link);
	spin_unlock_bh(&efrm_nic_tablep->lock);
	kfree(client);
}
EXPORT_SYMBOL(efrm_client_put);


void efrm_client_add_ref(struct efrm_client *client)
{
	EFRM_ASSERT(client->ref_count > 0);
	spin_lock_bh(&efrm_nic_tablep->lock);
	++client->ref_count;
	spin_unlock_bh(&efrm_nic_tablep->lock);
}
EXPORT_SYMBOL(efrm_client_add_ref);


struct efhw_nic *efrm_client_get_nic(struct efrm_client *client)
{
	return client->nic;
}
EXPORT_SYMBOL(efrm_client_get_nic);


int efrm_client_get_ifindex(struct efrm_client *client)
{
	int ifindex = -1;
	struct efhw_nic* nic = client->nic;

	spin_lock_bh(&nic->pci_dev_lock);
	if (nic->net_dev)
		ifindex = nic->net_dev->ifindex;
	spin_unlock_bh(&nic->pci_dev_lock);
	return ifindex;
}
EXPORT_SYMBOL(efrm_client_get_ifindex);


int efrm_client_accel_allowed(struct efrm_client *client)
{
	int result;
	struct efrm_nic* nic = efrm_nic(client->nic);

	spin_lock_bh(&nic->lock);
	result = (nic->rnic_flags & EFRM_NIC_FLAG_ADMIN_ENABLED) != 0;
	spin_unlock_bh(&nic->lock);
	return result;
}
EXPORT_SYMBOL(efrm_client_accel_allowed);


struct efhw_nic* efhw_nic_find(const struct net_device *dev,
                               uint64_t require_flags, uint64_t reject_flags)
{
	struct efhw_nic *result = NULL;
	struct efrm_nic *nic;

	spin_lock_bh(&efrm_nic_tablep->lock);
	list_for_each_entry(nic, &efrm_nics, link) {
		if ((nic->efhw_nic.net_dev == dev) &&
                    ((nic->efhw_nic.flags & require_flags) == require_flags) &&
                    ((nic->efhw_nic.flags & reject_flags) == 0)) {
			result = &nic->efhw_nic;
			break;
		}
	}
	spin_unlock_bh(&efrm_nic_tablep->lock);

	return result;
}
EXPORT_SYMBOL(efhw_nic_find);

struct efhw_nic* efhw_nic_find_by_dev(const struct device *dev)
{
	struct efhw_nic *result = NULL;
	struct efrm_nic *nic;

	spin_lock_bh(&efrm_nic_tablep->lock);
	list_for_each_entry(nic, &efrm_nics, link) {
		if (nic->efhw_nic.dev && nic->efhw_nic.dev == dev) {
			result = &nic->efhw_nic;
			break;
		}
	}
	spin_unlock_bh(&efrm_nic_tablep->lock);

	return result;
}
EXPORT_SYMBOL(efhw_nic_find_by_dev);

struct efhw_nic* efhw_nic_find_by_foo(nic_match_func match,
                                      const void *match_data)
{
	struct efhw_nic *result = NULL;
	struct efrm_nic *nic;

	spin_lock_bh(&efrm_nic_tablep->lock);
	list_for_each_entry(nic, &efrm_nics, link) {
		if (match(&nic->efhw_nic, match_data)) {
			result = &nic->efhw_nic;
			break;
		}
	}
	spin_unlock_bh(&efrm_nic_tablep->lock);

	return result;
}
EXPORT_SYMBOL(efhw_nic_find_by_foo);

/* Arguably this should be in lib/efhw.  However, right now this function
 * is a layer violation because it assumes that the efhw_nic is embedded in
 * a linux_efhw_nic.  That is only necessarily true in the resource driver.
 *     If this function returns non-NULL, it will return holding a semaphore,
 * which the caller must release by calling efhw_nic_release_dl_device().  A
 * consequence of this is that this function and that function have
 * locking/unlocking semantics, with all of the usual consequences for
 * lock-ordering etc.  In particular, since this function is sometimes called
 * with the RTNL lock held, it is not safe to attempt to take that lock in
 * between calls to this function and efhw_nic_release_dl_device().
 */
void* efhw_nic_acquire_drv_device(struct efhw_nic* efhw_nic)
{
	struct linux_efhw_nic* lnic = linux_efhw_nic(efhw_nic);
	void* drv_device;

	/* Acquire the lock if the driverlink device is live, taking care to
	 * avoid races against it changing under our feet. */
	drv_device = READ_ONCE(lnic->drv_device);
	if (drv_device != NULL) {
		down_read(&lnic->drv_sem);

		/* A flush might have occurred between the first check and
		 * obtaining the lock, so we must re-obtain the handle. */
		drv_device = READ_ONCE(lnic->drv_device);
		if (drv_device == NULL) {
			up_read(&lnic->drv_sem);
			return NULL;
		}
	}

	return drv_device;
}


/* Releases a driverlink device handle acquired by
 * efhw_nic_acquire_drv_device().  This is safe to call even if the handle is
 * NULL. */
void efhw_nic_release_drv_device(struct efhw_nic* efhw_nic,
				 void* drv_device)
{
	if( drv_device != NULL )
		up_read(&linux_efhw_nic(efhw_nic)->drv_sem);
}


/* Waits until there are no outstanding holders of the driverlink device for
 * the NIC.  This suffers from the usual reader-writer-lock starvation problem;
 * callers might wish to take measures to prevent further acquisitions of the
 * semaphore before calling this function. */
void efhw_nic_flush_drv(struct efhw_nic* efhw_nic)
{
	struct linux_efhw_nic* lnic = linux_efhw_nic(efhw_nic);
	down_write(&lnic->drv_sem);
	up_write(&lnic->drv_sem);
}

#endif  /* __KERNEL__ */
