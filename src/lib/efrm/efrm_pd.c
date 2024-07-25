/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2012-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *
 * This file provides public API for protection domain resource.
 *
 * Copyright 2011-2011: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
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
#include <ci/driver/driverlink_api.h>
#include <ci/efrm/vi_resource_manager.h>
#include <ci/efrm/private.h>
#include <ci/efrm/pd.h>
#include <ci/efrm/buffer_table.h>
#include <ci/efrm/efrm_filter.h>
#include <ci/efhw/ef10.h>
#include <ci/efhw/af_xdp.h>
#include <ci/efhw/nic.h>
#include <ci/tools/utils.h>
#include "efrm_internal.h"
#include "bt_manager.h"
#include "efrm_pd.h"


#define N_OWNER_IDS_PER_WORD  	 (sizeof(unsigned long) * 8)
#define OWNER_ID_WORD_ALLOCATED  ((unsigned long) -1)

#define OWNER_ID_ALLOC_FAIL      -1

#define EFRM_PD_VPORT_ID_NONE    0 /* following driverlink handle */

struct efrm_pd {
	struct efrm_resource rs;
	/* [owner_id] is a token used by the NIC to authenticate access to
	 * the buffer table by a VI.  All VIs and memory regions in a
	 * protection domain use the same owner_id.
	 *
	 * If the [owner_id] is negative then the protection domain uses
	 * physical addresses.
	 */
	int owner_id;

	/* OS-specific data */
	void *os_data;

	/* This is the minimun alignment that all packet buffers to be
	 * mapped in should meet. */
	int min_nic_order;

	u16 vport_handle; /* vport handle from driverlink */

	/* stack_id required for self-traffic suppression during hw
	 * multicast loopback */
	int stack_id;

	/* Unique ID allocated by the NIC for all NIC resources in this pd */
	uint32_t nic_client_id;

	/* cookie used to claim exclusive ownership of an efct RXQ. */
	unsigned exclusive_rxq_token; 

	/* serializes remapping of buffers on NIC reset */
	struct mutex remap_lock;

	/* Buffer table manager.  Needed iff vf==NULL.
	 * For Huntington, we'll need separate managers for different
	 * page orders.*/
	CI_DECLARE_FLEX_ARRAY(struct efrm_bt_manager, bt_managers);

	/* !! DANGER !!  Do not add any fields here; bt_managers must be
	 * the last field.
	 */
};


struct efrm_pd_manager {
	struct efrm_resource_manager rm;
	/* TODO: ensure this doesn't wrap */
	unsigned next_instance;
};


struct efrm_pd_owner_ids {
	/* An owner id block allows allocation of n owner_ids.  The absolute
	 * value of the owner_id is relative to value base.  This allows
	 * a single owner_id space to be shared across pds on siena by basing
	 * owner_ids on base VI ID.  On ef10 all owner_ids are 0 based as they
	 * are function relative. */
	int base, n;
	union {
		unsigned long padding;
		CI_DECLARE_FLEX_ARRAY(unsigned long, used_ids);
	};
	/* When allocating an owner id block enough memory is allocated to
	 * continue the used_ids array sufficiently to contain n owner ids.
	 */
};


static struct efrm_pd_manager *pd_manager;


#define efrm_pd(rs1)  container_of((rs1), struct efrm_pd, rs)


static int efrm_pd_owner_id_alloc(struct efrm_pd_owner_ids* owner_ids)
{
	/* Must hold pd_manager lock. */
	int i;
	int n_owner_id_words = DIV_ROUND_UP(owner_ids->n, N_OWNER_IDS_PER_WORD);
	for (i = 0; i < n_owner_id_words; ++i)
		if (owner_ids->used_ids[i] != OWNER_ID_WORD_ALLOCATED) {
			i *= N_OWNER_IDS_PER_WORD;
			while (test_bit(i, owner_ids->used_ids))
				++i;
			if( i < owner_ids->n ) {
				__set_bit(i, owner_ids->used_ids);
				return i + owner_ids->base;
			}
			else {
				return OWNER_ID_ALLOC_FAIL;
			}
		}
	return OWNER_ID_ALLOC_FAIL;
}


static void efrm_pd_owner_id_free(struct efrm_pd_owner_ids* owner_ids,
				  int owner_id)
{
	/* Must hold pd_manager lock. */
	EFRM_ASSERT(test_bit(owner_id - owner_ids->base, owner_ids->used_ids));
	__clear_bit(owner_id - owner_ids->base, owner_ids->used_ids);
}


struct efrm_pd_owner_ids *efrm_pd_owner_ids_ctor(int base, int n)
{
	int extra_words = DIV_ROUND_UP(n, N_OWNER_IDS_PER_WORD) - 1;
	struct efrm_pd_owner_ids *owner_ids = kmalloc(
		sizeof(*owner_ids) + (extra_words * sizeof(owner_ids[0])),
		GFP_KERNEL);

	if( owner_ids ) {
		memset(owner_ids, 0, sizeof(*owner_ids) +
					(extra_words * sizeof(owner_ids[0])));
		owner_ids->n = n;
		owner_ids->base = base;
	}

	return owner_ids;
}


void efrm_pd_owner_ids_dtor(struct efrm_pd_owner_ids* owner_ids)
{
	kfree(owner_ids);
}


/***********************************************************************/
/* Stack ids */
/***********************************************************************/

static int efrm_pd_stack_id_alloc(struct efrm_pd *pd)
{
	struct efrm_nic *nic = efrm_nic(pd->rs.rs_client->nic);
	const int word_bitcount = sizeof(*nic->stack_id_usage) * 8;
	int i, v, bitno, id;

	spin_lock(&nic->lock);
	for (i = 0; i < sizeof(nic->stack_id_usage) /
		     sizeof(*nic->stack_id_usage) &&
		     ((v = nic->stack_id_usage[i]) == ~0u); ++i)
		;
	bitno = v ? ci_ffs64(~v) - 1 : 0;
	id = i * word_bitcount + bitno + 1;
	if (id <= EFRM_MAX_STACK_ID)
		nic->stack_id_usage[i] |= 1 << bitno;
	spin_unlock(&nic->lock);

	if (id > EFRM_MAX_STACK_ID) {
		/* we run out of stack ids suppression of self traffic
		 * is not possible. */
		EFRM_TRACE("%s: WARNING: no free stack ids", __FUNCTION__);
		pd->stack_id = 0;
		return -ENOMEM;
	}
	pd->stack_id = id;
	return 0;
}


static void efrm_pd_stack_id_free(struct efrm_pd *pd)
{
	if (pd->stack_id != 0) {
		struct efrm_nic *nic = efrm_nic(pd->rs.rs_client->nic);
		const int word_bitcount = sizeof(*nic->stack_id_usage) * 8;
		int id = pd->stack_id - 1;
		int i = id / word_bitcount;
		int bitno = id % word_bitcount;
		spin_lock(&nic->lock);
		nic->stack_id_usage[i] &= ~(1 << bitno);
		spin_unlock(&nic->lock);
	}
}


unsigned efrm_pd_stack_id_get(struct efrm_pd *pd)
{
	return pd->stack_id;
}
EXPORT_SYMBOL(efrm_pd_stack_id_get);

unsigned efrm_pd_exclusive_rxq_token_get(struct efrm_pd *pd)
{
       return pd->exclusive_rxq_token;
}
EXPORT_SYMBOL(efrm_pd_exclusive_rxq_token_get);

/***********************************************************************/

int efrm_pd_alloc(struct efrm_pd **pd_out, struct efrm_client *client_opt,
		          int flags)
{
	struct efrm_pd *pd;
	int rc, instance;
	struct efrm_pd_owner_ids *owner_ids;
	int orders_num = 0;
	int use_buffer_table = (flags & EFRM_PD_ALLOC_FLAG_PHYS_ADDR_MODE) == 0;

	/* Support for SRIOV VF was removed (see bug 84927). */
	EFRM_ASSERT(client_opt != NULL);
	if ((flags &
	    ~(EFRM_PD_ALLOC_FLAG_PHYS_ADDR_MODE |
	    EFRM_PD_ALLOC_FLAG_HW_LOOPBACK |
	    EFRM_PD_ALLOC_FLAG_WITH_CLIENT_ID |
	    EFRM_PD_ALLOC_FLAG_WITH_CLIENT_ID_OPT)) != 0) {
		rc = -EINVAL;
		goto fail1;
	}

	/* NICs that do not use a buffer table will report 0 orders. For
	 * compatability we don't care whether buffer table or phys mode has
	 * been requested as packet hardware addresses are not visible to
	 * userspace when using these NICs.
	 */
	orders_num = efhw_nic_buffer_table_orders_num(client_opt->nic);
	if( orders_num == 0 )
		use_buffer_table = 0;

	if (use_buffer_table) {
		EFRM_ASSERT(orders_num);
		/* FIXME EF100: The only buffer table order supported in
		 * Riverhead is 9. But EF100 will have orders starting from 0
		 * in the future. */
		if( client_opt->nic->devtype.arch != EFHW_ARCH_EF100 )
			EFRM_ASSERT(efhw_nic_buffer_table_orders(
						client_opt->nic)[0] == 0);
	}
	pd = kmalloc(sizeof(*pd) + orders_num * sizeof(pd->bt_managers[0]),
		     GFP_KERNEL);
	if (pd == NULL) {
		rc = -ENOMEM;
		goto fail1;
	}
	pd->stack_id = 0;
	pd->nic_client_id = EFRM_NIC_CLIENT_ID_NONE;

	if (flags & EFRM_PD_ALLOC_FLAG_WITH_CLIENT_ID) {
		rc = efhw_nic_client_alloc(client_opt->nic, EFRM_NIC_CLIENT_ID_NONE,
		                           &pd->nic_client_id);
		if (rc) {
			if (!(flags & EFRM_PD_ALLOC_FLAG_WITH_CLIENT_ID_OPT)) {
				EFRM_ERR("%s: ERROR: couldn't allocate client ID (%d)",
				         __FUNCTION__, rc);
				goto fail2;
			}
			/* Let's say ENOSYS is inherently uninteresting because it's what
			 * you get on a non-EF100 */
			if (rc != -ENOSYS)
				EFRM_NOTICE("%s: NOTICE: couldn't allocate client ID (%d)",
				            __FUNCTION__, rc);
			pd->nic_client_id = EFRM_NIC_CLIENT_ID_NONE;
			rc = 0;
		}
	}

	spin_lock_bh(&pd_manager->rm.rm_lock);
	instance = pd_manager->next_instance++;
	pd->exclusive_rxq_token = pd_manager->next_instance;

	if (!use_buffer_table) {
		pd->owner_id = OWNER_ID_PHYS_MODE;
	}
	else {
		owner_ids = efrm_nic_from_client(client_opt)->owner_ids;
		EFRM_ASSERT(owner_ids != NULL);
		pd->owner_id = efrm_pd_owner_id_alloc(owner_ids);
	}
	spin_unlock_bh(&pd_manager->rm.rm_lock);
	if (pd->owner_id == OWNER_ID_ALLOC_FAIL) {
		rc = -EBUSY;
		goto fail3;
	}

	if (use_buffer_table) {
		int ord;
		for (ord = 0; ord < orders_num; ord++) {
			efrm_bt_manager_ctor(
				&pd->bt_managers[ord], pd->owner_id,
				efhw_nic_buffer_table_orders(
						client_opt->nic)[ord]
				);
		}
	}
	efrm_resource_init(&pd->rs, EFRM_RESOURCE_PD, instance);
	efrm_client_add_resource(client_opt, &pd->rs);

	pd->os_data = efrm_pd_os_stats_ctor(pd);
	pd->min_nic_order = 0;

	pd->vport_handle = EFRM_PD_VPORT_ID_NONE;

	mutex_init(&pd->remap_lock);
	if (flags & EFRM_PD_ALLOC_FLAG_HW_LOOPBACK) {
		if ((rc = efrm_pd_stack_id_alloc(pd)) != 0) {
			efrm_pd_release(pd);
			return rc;
		}
	}

	*pd_out = pd;
	return 0;


fail3:
	if (pd->nic_client_id != EFRM_NIC_CLIENT_ID_NONE)
		efhw_nic_client_free(client_opt->nic, pd->nic_client_id);
fail2:
	kfree(pd);
fail1:
	return rc;
}
EXPORT_SYMBOL(efrm_pd_alloc);


void efrm_pd_release(struct efrm_pd *pd)
{
	if (__efrm_resource_release(&pd->rs))
		efrm_pd_free(pd);
}
EXPORT_SYMBOL(efrm_pd_release);


void efrm_pd_free(struct efrm_pd *pd)
{
	struct efrm_pd_owner_ids *owner_ids;

	mutex_destroy(&pd->remap_lock);

	efrm_pd_os_stats_dtor(pd, pd->os_data);

	if (efrm_pd_has_vport(pd))
		efrm_vport_free(pd->rs.rs_client, pd->vport_handle);

	efrm_pd_stack_id_free(pd);

	spin_lock_bh(&pd_manager->rm.rm_lock);
	if (pd->owner_id != OWNER_ID_PHYS_MODE) {
		owner_ids = efrm_nic_from_rs(&pd->rs)->owner_ids;
		EFRM_ASSERT(owner_ids != NULL);
		efrm_pd_owner_id_free(owner_ids, pd->owner_id);
	}
	spin_unlock_bh(&pd_manager->rm.rm_lock);

	if (pd->nic_client_id != EFRM_NIC_CLIENT_ID_NONE)
		efhw_nic_client_free(&efrm_nic_from_rs(&pd->rs)->efhw_nic,
		                     pd->nic_client_id);

	if (pd->owner_id != OWNER_ID_PHYS_MODE) {
		int ord;
		for (ord = 0;
		     ord < efhw_nic_buffer_table_orders_num(
					pd->rs.rs_client->nic);
		     ord++)
			efrm_bt_manager_dtor(&pd->bt_managers[ord]);
	}
	efrm_client_put(pd->rs.rs_client);
	kfree(pd);
}


struct efrm_resource * efrm_pd_to_resource(struct efrm_pd *pd)
{
	return &pd->rs;
}
EXPORT_SYMBOL(efrm_pd_to_resource);


struct efrm_pd * efrm_pd_from_resource(struct efrm_resource *rs)
{
	return efrm_pd(rs);
}
EXPORT_SYMBOL(efrm_pd_from_resource);


int efrm_pd_owner_id(struct efrm_pd *pd)
{
	return pd->owner_id;
}
EXPORT_SYMBOL(efrm_pd_owner_id);


void efrm_pd_set_min_align(struct efrm_pd *pd, int alignment)
{
	pd->min_nic_order = __ffs((alignment) >> EFHW_NIC_PAGE_SHIFT);
}
EXPORT_SYMBOL(efrm_pd_set_min_align);


int efrm_pd_get_min_align(struct efrm_pd *pd)
{
	return ((1 << pd->min_nic_order) << EFHW_NIC_PAGE_SHIFT);
}
EXPORT_SYMBOL(efrm_pd_get_min_align);


uint32_t efrm_pd_get_nic_client_id(struct efrm_pd *pd)
{
	return pd->nic_client_id;
}
EXPORT_SYMBOL(efrm_pd_get_nic_client_id);


int
efrm_pd_has_vport(struct efrm_pd *pd)
{
	return pd->vport_handle != EFRM_PD_VPORT_ID_NONE;
}
EXPORT_SYMBOL(efrm_pd_has_vport);


unsigned
efrm_pd_get_vport_id(struct efrm_pd *pd)
{
	return pd->vport_handle;
}
EXPORT_SYMBOL(efrm_pd_get_vport_id);


int
efrm_pd_vport_alloc(struct efrm_pd *pd, int vlan_id)
{
	u16 vport_handle;
	int rc;

	if (pd->vport_handle != EFRM_PD_VPORT_ID_NONE)
		return -EBUSY;
	rc = efrm_vport_alloc(pd->rs.rs_client, vlan_id, &vport_handle);
	if (rc == 0)
		pd->vport_handle = vport_handle;
	return rc;
}
EXPORT_SYMBOL(efrm_pd_vport_alloc);


/**********************************************************************/

#define NIC_ORDER_TO_BYTES(nic_order) \
  ((size_t)EFHW_NIC_PAGE_SIZE << (size_t)(nic_order))

static void efrm_pd_dma_unmap_pci(struct device *dev,
				  int n_pages, int nic_order,
				  dma_addr_t *pci_addrs)
{
	while (--n_pages >= 0) {
		dma_unmap_single(dev, *pci_addrs,
				 NIC_ORDER_TO_BYTES(nic_order),
				 DMA_BIDIRECTIONAL);
		++pci_addrs;
	}
}


static int efrm_pd_dma_map_pci(struct device *dev,
			       int n_pages, int nic_order,
			       void **addrs, dma_addr_t *pci_addrs)
{
	int i;

	for (i = 0; i < n_pages; ++i) {
		pci_addrs[i] = dma_map_single(dev, addrs[i],
					      NIC_ORDER_TO_BYTES(nic_order),
					      DMA_BIDIRECTIONAL);
		if (dma_mapping_error(dev, pci_addrs[i])) {
			EFRM_ERR("%s: ERROR: dma_map_single failed",
				 __FUNCTION__);
			goto fail;
		}
	}
	return 0;

fail:
	efrm_pd_dma_unmap_pci(dev, i, nic_order,
			      pci_addrs);
	return -ENOMEM;
}

static int efrm_pd_dma_map_nonpci(
			       int n_pages, int nic_order,
			       void **addrs, dma_addr_t *pci_addrs)
{
	int i;
	for (i = 0; i < n_pages; ++i)
		pci_addrs[i] = (dma_addr_t)addrs[i];
	return 0;
}

static void efrm_pd_dma_unmap_nic(struct efrm_pd *pd,
				  int n_pages, int nic_order,
				  dma_addr_t *pci_addrs)
{
	struct efhw_nic* nic = efrm_client_get_nic(pd->rs.rs_client);
	struct device* dev;
	switch (nic->devtype.arch) {
	case EFHW_ARCH_EF10:
	case EFHW_ARCH_EF100:
		dev = efhw_nic_get_dev(nic);
		if (dev) {
			efrm_pd_dma_unmap_pci(dev, n_pages, nic_order,
					      pci_addrs);
			put_device(dev);
		}
		break;
	case EFHW_ARCH_EFCT:
	case EFHW_ARCH_AF_XDP:
		break;
	};
}


static int efrm_pd_dma_map_nic(struct efrm_pd *pd,
			       int n_pages, int nic_order,
			       void **addrs, dma_addr_t *pci_addrs,
			       dma_addr_t *free_addrs)
{
	struct efhw_nic* nic = efrm_client_get_nic(pd->rs.rs_client);
	struct device* dev;
	int rc = -ENODEV;
	switch (nic->devtype.arch) {
	case EFHW_ARCH_EF10:
	case EFHW_ARCH_EF100:
		dev = efhw_nic_get_dev(nic);
		if( dev ) {
			rc = efrm_pd_dma_map_pci(dev, n_pages, nic_order,
						 addrs, free_addrs);
			put_device(dev);
			if (rc == 0)
				rc = efhw_nic_translate_dma_addrs(nic,
								  free_addrs,
								  pci_addrs,
								  n_pages);
		}
		break;
	case EFHW_ARCH_EFCT:
	case EFHW_ARCH_AF_XDP:
		rc = efrm_pd_dma_map_nonpci(n_pages, nic_order, addrs,
					    pci_addrs);
		memcpy(free_addrs, pci_addrs, n_pages * sizeof(pci_addrs[0]));
		break;
	};

	return rc;
}


static inline int efrm_pd_bt_find_order_idx(struct efrm_pd *pd,
					    int max_order)
{
	int ord_idx;

	ord_idx = efhw_nic_buffer_table_orders_num(pd->rs.rs_client->nic) - 1;
	while (pd->bt_managers[ord_idx].order > max_order) {
		ord_idx--;
		EFRM_ASSERT(ord_idx >= 0);
	}

	return ord_idx;
}

static void efrm_pd_dma_unmap_bt(struct efrm_pd *pd,
				 struct efrm_bt_collection *bt_alloc,
				 int reset_pending)
{
	int ord_idx;
	int i;

	for (i = 0; i < bt_alloc->num_allocs; i++) {
		if (bt_alloc->allocs[i].bta_size == 0)
			break;
		ord_idx = efrm_pd_bt_find_order_idx(
				pd, bt_alloc->allocs[i].bta_order);

		efrm_bt_manager_free(efrm_client_get_nic(pd->rs.rs_client),
				     &pd->bt_managers[ord_idx],
				     &bt_alloc->allocs[i],
				     reset_pending);
	}

	kfree(bt_alloc->allocs);
}


static int
efrm_pd_bt_program(struct efrm_pd *pd, int nic_order, dma_addr_t *pci_addrs,
		   struct efrm_bt_collection *bt_alloc)
{
	int i, rc, rc1 = 0;
	int bt_num;
	dma_addr_t page_offset;
	dma_addr_t *dma_addrs;
	int dma_size = 0;

	EFRM_ASSERT(pd->owner_id != OWNER_ID_PHYS_MODE);

	for (bt_num = 0; bt_num < bt_alloc->num_allocs; bt_num++) {
		if (bt_alloc->allocs[bt_num].bta_size == 0)
			break;
		if (dma_size < bt_alloc->allocs[bt_num].bta_size)
			dma_size = bt_alloc->allocs[bt_num].bta_size;
	}
	dma_addrs = vmalloc(dma_size * sizeof(dma_addr_t));
	/* We should not get this far without setting up at least one
	 * buffer table allocation.
	 */
	EFRM_ASSERT(dma_size != 0);
	if (dma_addrs == NULL)
		return -ENOMEM;

	/* Program dma address for the buffer table entries. */
	page_offset = 0;
	for (bt_num = 0; bt_num < bt_alloc->num_allocs; bt_num++) {
		if (bt_alloc->allocs[bt_num].bta_size == 0)
			break;
		for (i = 0; i < bt_alloc->allocs[bt_num].bta_size; i++) {
			dma_addrs[i] = *pci_addrs + page_offset;
			page_offset += NIC_ORDER_TO_BYTES(
				bt_alloc->allocs[bt_num].bta_order);
			if (page_offset == NIC_ORDER_TO_BYTES(nic_order)) {
				page_offset = 0;
				pci_addrs++;
			}
		}
		rc = efrm_bt_nic_set(efrm_client_get_nic(pd->rs.rs_client),
				     &bt_alloc->allocs[bt_num], dma_addrs);
		if( rc != 0 ) {
			if( ~bt_alloc->allocs[bt_num].bta_flags & 
			    EFRM_BTA_FLAG_IN_RESET ) {
				vfree(dma_addrs);
				return rc;
			}
			rc1 = rc;
		}
	}
	vfree(dma_addrs);

	return rc1;
}


static void
efrm_pd_bt_write_user_addrs(struct efrm_pd *pd, uint64_t *user_addrs,
			    int user_addrs_stride,
			    void (*user_addr_put)(uint64_t, uint64_t *),
			    struct efrm_bt_collection *bt_alloc)
{
	int i, n, first;
	uint64_t user_addr;
	struct efhw_buffer_table_block *block;
	int bt_num;

	EFRM_ASSERT(pd->owner_id != OWNER_ID_PHYS_MODE);

	for (bt_num = 0; bt_num < bt_alloc->num_allocs; bt_num++) {
		if (bt_alloc->allocs[bt_num].bta_size == 0)
			break;
		block = bt_alloc->allocs[bt_num].bta_blocks;
		n = bt_alloc->allocs[bt_num].bta_size;
		first = bt_alloc->allocs[bt_num].bta_first_entry_offset;
		do {
			user_addr = block->btb_vaddr +
				(first << (EFHW_NIC_PAGE_SHIFT +
					   bt_alloc->allocs[bt_num].bta_order));
			first = 0;
			for (i = 0;
			     i < min(n, EFHW_BUFFER_TABLE_BLOCK_SIZE) <<
					bt_alloc->allocs[bt_num].bta_order;
			     i++) {
				user_addr_put(user_addr, user_addrs);
				user_addrs = (void *)((char *)user_addrs +
						      user_addrs_stride);
				user_addr += EFHW_NIC_PAGE_SIZE;
			}
			block = block->btb_next;
			n -= EFHW_BUFFER_TABLE_BLOCK_SIZE;
		} while (n > 0);
	}
}


static int efrm_pd_bt_map(struct efrm_pd *pd, int nic_order,
			  dma_addr_t *pci_addrs,
			  uint64_t *user_addrs, int user_addrs_stride,
			  void (*user_addr_put)(uint64_t, uint64_t *),
			  struct efrm_bt_collection *bt_alloc,
			  int reset_pending)
{
	int rc = 0;

	EFRM_ASSERT(pd->owner_id != OWNER_ID_PHYS_MODE);

	/* The first half of this function's job is to program physical
	 * addresses to the allocated buffer-table entries.  We can't (and
	 * needn't) do that if there's a reset pending. */
	if (! reset_pending) {
		rc = efrm_pd_bt_program(pd, nic_order, pci_addrs, bt_alloc);
		/* Failure here doesn't prevent us from continuing, but we
		 * should report the failure to the caller. */
	}

	/* The rest of the work is to copy buftable addresses to user.  This
	 * needs to be done even if we're awaiting reset.  In that case, the
	 * addresses are potentially invalid and will be rewritten when the
	 * reset happens, but they are at least in-range and so will avoid
	 * upsetting later sanity checks. */
	efrm_pd_bt_write_user_addrs(pd, user_addrs, user_addrs_stride,
				    user_addr_put, bt_alloc);

	return rc;
}


/* Check that PCI addresses are properly aligned for the buffer table
 * pages we have selected. */
static inline int
efrm_pd_nic_order_fixup(struct efrm_pd *pd, int ord_idx, int n_pages,
			dma_addr_t *pci_addrs)
{
	dma_addr_t pci_addr_or = 0;
	int i;

	if (ord_idx == 0)
		return 0;

	for (i =0; i < n_pages; i++)
		pci_addr_or |= *pci_addrs++;
	EFRM_ASSERT((pci_addr_or & (EFHW_NIC_PAGE_SIZE - 1)) == 0);
	pci_addr_or >>= EFHW_NIC_PAGE_SHIFT;

	if (pci_addr_or & ((1 << pd->bt_managers[ord_idx].order) - 1))
		return efrm_pd_bt_find_order_idx(pd, __ffs(pci_addr_or));

	return ord_idx;
}

static inline int efrm_pd_bt_alloc(struct efrm_pd *pd, size_t bytes,
				   int ord_idx,
				   struct efrm_buffer_table_allocation *bt,
				   int reset_pending)
{
	return efrm_bt_manager_alloc(efrm_client_get_nic(pd->rs.rs_client),
				    &pd->bt_managers[ord_idx],
				    bytes >> (EFHW_NIC_PAGE_SHIFT +
					      pd->bt_managers[ord_idx].order),
				    bt, reset_pending);
}

static int
efrm_pd_bt_alloc_unaligned(struct efrm_pd *pd, int n_pages, int nic_order,
			   dma_addr_t *pci_addrs,
			   struct efrm_bt_collection *bt_alloc,
			   int ord_idx, int ord_idx_min, int reset_pending)
{
	int ord_idx_mid = ord_idx;
	int bt_num, i;
	int rc = 0;
	dma_addr_t mask = (EFHW_NIC_PAGE_SIZE <<
			   pd->bt_managers[ord_idx].order) - 1;
	dma_addr_t mask_mid = mask;

	/* ord_idx_min: bt order which can always be used: everything is
	 * aligned.
	 * ord_idx: bt order we'd like to use if the dma address is
	 * aligned.
	 * Else we map non-aligned parts with ord_idx_min, and
	 * use ord_idx or (ord_idx-1) for the middle.
	 */
	bt_alloc->num_allocs = n_pages * 3;
	if (nic_order == pd->bt_managers[ord_idx].order) {
		ord_idx_mid = ord_idx - 1;
		mask_mid = NIC_ORDER_TO_BYTES(
				pd->bt_managers[ord_idx_mid].order) - 1;
		if (ord_idx_mid == ord_idx_min)
			bt_alloc->num_allocs = n_pages;
	}
	EFRM_ASSERT(ord_idx_mid >= ord_idx_min);

	bt_alloc->allocs = kmalloc(
			sizeof(struct efrm_buffer_table_allocation) *
						bt_alloc->num_allocs,
			GFP_ATOMIC);
	memset(bt_alloc->allocs, 0,
	       sizeof(struct efrm_buffer_table_allocation) *
	       bt_alloc->num_allocs);
	if (bt_alloc->allocs == NULL)
		return -ENOMEM;

	bt_num = 0;
	for (i = 0; i < n_pages; i++) {
		if ((pci_addrs[i] & mask) == 0) {
			/* Aligned page: map it */
			rc = efrm_pd_bt_alloc(
				pd, NIC_ORDER_TO_BYTES(nic_order), ord_idx,
				&bt_alloc->allocs[bt_num++], reset_pending);
			if( rc != 0 )
				break;
		}
		else if ((pci_addrs[i] & mask_mid) == 0) {
			/* Aligned page, smaller order: map it */
			rc = efrm_pd_bt_alloc(pd, NIC_ORDER_TO_BYTES(nic_order),
					      ord_idx_mid,
					      &bt_alloc->allocs[bt_num++],
					      reset_pending);
			if( rc != 0 )
				break;
		}
		else {
			/* Non-aligned page: map non-aligned pieces
			 * separately. */
			rc = efrm_pd_bt_alloc(
				pd,
				((mask_mid + 1) - ((pci_addrs[i]) & mask_mid)),
				ord_idx_min,
				&bt_alloc->allocs[bt_num++], reset_pending);
			if (rc != 0)
				break;
			rc = efrm_pd_bt_alloc(
				pd,
				NIC_ORDER_TO_BYTES(nic_order) - (mask_mid + 1),
				ord_idx_mid,
				&bt_alloc->allocs[bt_num++], reset_pending);
			if (rc != 0)
				break;
			rc = efrm_pd_bt_alloc(
				pd,
				((pci_addrs[i]) & mask_mid),
				ord_idx_min,
				&bt_alloc->allocs[bt_num++], reset_pending);
			if (rc != 0)
				break;
		}
		EFRM_ASSERT(bt_num <= bt_alloc->num_allocs);
	}

	if (rc != 0)
		efrm_pd_dma_unmap_bt(pd, bt_alloc, reset_pending);
	return rc;
}

static int efrm_pd_dma_map_bt(struct efrm_pd *pd, int n_pages, int nic_order,
			      dma_addr_t *pci_addrs,
			      uint64_t *user_addrs, int user_addrs_stride,
			      void (*user_addr_put)(uint64_t, uint64_t *),
			      struct efrm_bt_collection *bt_alloc,
			      int reset_pending, int *page_order)
{
	int rc = 0;
	int ord_idx, ord_idx_min;
	struct efhw_nic* nic = efrm_client_get_nic(pd->rs.rs_client);

	ord_idx = efrm_pd_bt_find_order_idx(pd, nic_order);
	if (nic->devtype.arch == EFHW_ARCH_EF10) {
		ord_idx_min = efrm_pd_nic_order_fixup(pd, ord_idx, n_pages,
						pci_addrs);
	}
	else {
		/* EF100 doesn't require aligned PCI addresses */
		ord_idx_min = ord_idx;
	}

	if (pd->min_nic_order > pd->bt_managers[ord_idx_min].order) {
		EFRM_ERR("%s: ERROR: insufficient DMA mapping alignment "
			 "(required=%d got=%d)", __FUNCTION__,
			 pd->min_nic_order, pd->bt_managers[ord_idx_min].order);
		return -EFAULT;
	}
	if (page_order)
		*page_order = pd->bt_managers[ord_idx_min].order;

	if (ord_idx == ord_idx_min) {
		bt_alloc->num_allocs = 1;
		bt_alloc->allocs = kmalloc(
			sizeof(struct efrm_buffer_table_allocation),
			GFP_ATOMIC);
		if (bt_alloc->allocs == NULL)
			return -ENOMEM;
		rc = efrm_pd_bt_alloc(
				pd, n_pages * NIC_ORDER_TO_BYTES(nic_order),
				ord_idx, &bt_alloc->allocs[0], reset_pending);
	}
	else {
		rc = efrm_pd_bt_alloc_unaligned(pd, n_pages, nic_order,
						pci_addrs, bt_alloc,
						ord_idx, ord_idx_min,
						reset_pending);
	}

	if (rc < 0) {
		EFRM_ERR_LIMITED
			 ("%s: ERROR: buffer table entry allocation failed "
			 "(%d pages nic_order %d) rc=%d",
			 __FUNCTION__, n_pages, nic_order, rc);
		return rc;
	}

        EFRM_ASSERT(rc == 0);

	rc = efrm_pd_bt_map(pd, nic_order, pci_addrs,
			    user_addrs, user_addrs_stride, user_addr_put,
			    bt_alloc, reset_pending);
	if (rc == 0)
		return rc;

	/* Error: free already-allocated buftable entries */
	EFRM_ASSERT(! reset_pending);
	efrm_pd_dma_unmap_bt(pd, bt_alloc, reset_pending);
	return rc;
}


static int efrm_pd_check_pci_addr_alignment(struct efrm_pd *pd,
					    void* virt_addr_0, dma_addr_t *pci_addrs,
					    int n_pages, int *page_order)
{
	dma_addr_t prev = 0, pci_addr_or;
	int pci_addr_ord;
	int i;
	dma_addr_t page_size;

	page_size = PAGE_SIZE << compound_order(virt_to_page(virt_addr_0));
	prev = pci_addrs[0];
	pci_addr_or = pci_addrs[0];
	/* Find and account for any discontinuities in the linearity: */
   	for (i = 1; i < n_pages; i++) {
		if (pci_addrs[i] != prev + page_size)
			pci_addr_or |= (prev + page_size) | pci_addrs[i];
		prev = pci_addrs[i];
	}
	/* Additionally mix in a 'fake' end address, to account for the
	 * possibility that the base address is over-aligned, i.e. if the base
	 * happens to be aligned to order 42 then we still don't want to report
	 * that the order is greater than the total memory size requested. */
	pci_addr_or |= prev + page_size;
	EFRM_ASSERT((pci_addr_or & (EFHW_NIC_PAGE_SIZE - 1)) == 0);
	pci_addr_ord = __ffs(pci_addr_or >> EFHW_NIC_PAGE_SHIFT);
	if (page_order)
		*page_order = pci_addr_ord;

	if (pd->min_nic_order > pci_addr_ord) {
		EFRM_ERR("%s: ERROR: insufficient DMA mapping alignment "
			 "(required=%d got=%d)", __FUNCTION__,
			 pd->min_nic_order, pci_addr_ord);
		return -EPROTO;
	}
	return 0;
}


static void efrm_pd_copy_user_addrs(struct efrm_pd *pd,
			    int n_pages, int nic_order,
			    dma_addr_t *pci_addrs,
			    uint64_t *user_addrs, int user_addrs_stride,
			    void (*user_addr_put)(uint64_t, uint64_t *))
{
	int i, j;

	/* user_addrs is for pages of size EFHW_NIC_PAGE_SIZE, always */
	for (i = 0; i < n_pages; ++i) {
		for (j = 0; j < 1 << nic_order; j++) {
			user_addr_put(pci_addrs[i] + EFHW_NIC_PAGE_SIZE * j,
				      user_addrs);
			user_addrs = (void *)((char *)user_addrs +
					      user_addrs_stride);
		}
	}
}


int efrm_pd_dma_remap_bt(struct efrm_pd *pd, int n_pages, int nic_order,
			 dma_addr_t *pci_addrs, dma_addr_t *free_addrs,
			 uint64_t *user_addrs, int user_addrs_stride,
			 void (*user_addr_put)(uint64_t, uint64_t *),
			 struct efrm_bt_collection *bt_alloc)
{
	struct efhw_nic* nic = efrm_client_get_nic(pd->rs.rs_client);
	int rc, rc1 = 0;
	int bt_num;

	if (pd->owner_id == OWNER_ID_PHYS_MODE)
		return -ENOSYS;

	rc = efhw_nic_translate_dma_addrs(nic, free_addrs, pci_addrs, n_pages);
	if (rc)
		return rc;

	mutex_lock(&pd->remap_lock);

	for (bt_num = 0; bt_num < bt_alloc->num_allocs; bt_num++) {
		int ord_idx;
		if (bt_alloc->allocs[bt_num].bta_size == 0)
			break;
		ord_idx = efrm_pd_bt_find_order_idx(
				pd, bt_alloc->allocs[bt_num].bta_order);
		rc = efrm_bt_manager_realloc(
				efrm_client_get_nic(pd->rs.rs_client),
				&pd->bt_managers[ord_idx],
				&bt_alloc->allocs[bt_num]);
		if (rc != 0 && rc1 == 0)
			rc1 = rc;
	}
        rc = rc1;
	if (rc == 0)
		rc = efrm_pd_bt_map(pd, nic_order, pci_addrs,
				    user_addrs, user_addrs_stride, user_addr_put,
				    bt_alloc, 0);
        mutex_unlock(&pd->remap_lock);
        return rc;
}
EXPORT_SYMBOL(efrm_pd_dma_remap_bt);


int efrm_pd_dma_map(struct efrm_pd *pd, int n_pages, int nic_order,
		    void **addrs, dma_addr_t *pci_addrs,
		    dma_addr_t *free_addrs,
		    uint64_t *user_addrs, int user_addrs_stride,
		    void (*user_addr_put)(uint64_t, uint64_t *),
		    struct efrm_bt_collection *bt_alloc, int reset_pending,
		    int *page_order)
{
	int rc;

	/* This checks that physical memory meets the alignment
	 * requirement.  We also check that the DMA addresses meet the
	 * alignment requirements further below: in
	 * efrm_pd_dma_map_bt() and efrm_pd_check_pci_addr_alignment().
	 */
	if (pd->min_nic_order > nic_order) {
		EFRM_ERR("%s: ERROR: min_nic_order(%d) > nic_order(%d)",
			 __FUNCTION__, pd->min_nic_order, nic_order);
		return -EPROTO;
	}

	rc = efrm_pd_dma_map_nic(pd, n_pages, nic_order,
				 addrs, pci_addrs, free_addrs);
	if (rc < 0)
		goto fail1;

	if (pd->owner_id != OWNER_ID_PHYS_MODE) {
		rc = efrm_pd_dma_map_bt(pd, n_pages, nic_order, pci_addrs,
					user_addrs, user_addrs_stride,
					user_addr_put, bt_alloc, reset_pending,
					page_order);
		if (rc < 0)
			goto fail2;
	} else {
		rc = efrm_pd_check_pci_addr_alignment(
			pd, addrs[0], pci_addrs, n_pages, page_order);
		if (rc < 0)
			goto fail2;
		efrm_pd_copy_user_addrs(pd, n_pages, nic_order, pci_addrs,
					user_addrs, user_addrs_stride,
					user_addr_put);
	}
	return 0;


fail2:
		efrm_pd_dma_unmap_nic(pd, n_pages, nic_order, free_addrs);
fail1:
	return rc;
}
EXPORT_SYMBOL(efrm_pd_dma_map);


void efrm_pd_dma_unmap(struct efrm_pd *pd, int n_pages, int nic_order,
		       dma_addr_t *free_addrs,
		       struct efrm_bt_collection *bt_alloc, int reset_pending)
{
	if (pd->owner_id != OWNER_ID_PHYS_MODE)
		efrm_pd_dma_unmap_bt(pd, bt_alloc, reset_pending);

	efrm_pd_dma_unmap_nic(pd, n_pages, nic_order,
			      free_addrs);
}
EXPORT_SYMBOL(efrm_pd_dma_unmap);

/**********************************************************************/

static void efrm_pd_rm_dtor(struct efrm_resource_manager *rm)
{
}


int
efrm_create_pd_resource_manager(struct efrm_resource_manager **rm_out)
{
	struct efrm_pd_manager *rm;
	int rc;

	rm = kmalloc(sizeof(*rm), GFP_KERNEL);
	if (rm == NULL)
		return -ENOMEM;
	memset(rm, 0, sizeof(*rm));

	rc = efrm_resource_manager_ctor(&rm->rm, efrm_pd_rm_dtor,
					"PD", EFRM_RESOURCE_PD);
	if (rc < 0)
		goto fail1;

	pd_manager = rm;
	*rm_out = &rm->rm;
	return 0;

fail1:
	kfree(rm);
	return rc;
}


struct efrm_bt_manager *
efrm_pd_bt_manager_next(struct efrm_pd *pd, struct efrm_bt_manager *prev)
{
	int i;

	if (prev == NULL)
		return &pd->bt_managers[0];

	for (i = 0;
	     i < efhw_nic_buffer_table_orders_num(pd->rs.rs_client->nic) - 1;
	     i++) {
		if (prev == &pd->bt_managers[i])
			return &pd->bt_managers[i+1];
	}

	return NULL;
}

