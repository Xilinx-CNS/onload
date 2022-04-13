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

#include <ci/efrm/private.h>
#include <ci/efrm/pio.h>
#include <ci/efrm/pd.h>
#include <ci/efrm/vi_resource_manager.h>
#include <ci/driver/resource/linux_efhw_nic.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efhw/ef10.h>
#include "efrm_pio.h"
#include "efrm_internal.h"


#define efrm_pio(rs1)  container_of((rs1), struct efrm_pio, epio_rs)

/* Given an existing PIO and VI resource, reallocate the PIO and link
 * them together.  This assumes the efrm referencing is already done
 */
int efrm_pio_realloc(struct efrm_pd *pd, struct efrm_pio *pio, 
		     struct efrm_vi *vi)
{
	struct efhw_nic *pio_nic, *vi_nic;
	struct efhw_nic *nic;
	struct efrm_client *client;
	int rc;

	client = efrm_pd_to_resource(pd)->rs_client;
	nic = client->nic;

	pio_nic = pio->epio_rs.rs_client->nic;
	vi_nic = efrm_pd_to_resource(vi->pd)->rs_client->nic;
	if (pio_nic != nic || vi_nic != nic) {
		EFRM_ERR("%s: VI and PIO belong to different pds",
			 __FUNCTION__);
		return -EINVAL;
	}

	if (nic->devtype.arch != EFHW_ARCH_EF10) {
		EFRM_ERR("%s: Only ef10 supports PIO."
			 "  Expected arch=%d but got %d\n", __FUNCTION__,
			 EFHW_ARCH_EF10, nic->devtype.arch);
		return -EINVAL;
	}

	EFRM_ASSERT(pio->epio_pd == pd);
	EFRM_ASSERT(pio->epio_len == nic->pio_size);

	pio->epio_handle = 0;

	rc = ef10_nic_piobuf_alloc(nic, &pio->epio_handle);
	if (rc < 0) {
		if( rc == -ENOSPC )
			EFRM_TRACE("%s: ef10_nic_piobuf_alloc failed: %d\n",
				 __FUNCTION__, rc);
		else
			EFRM_ERR("%s: ef10_nic_piobuf_alloc failed: %d\n",
				 __FUNCTION__, rc);
		pio->epio_handle = -1;
		return rc;
	}
	EFRM_ASSERT(pio->epio_handle != -1);

	rc = ef10_nic_piobuf_link(nic, vi->rs.rs_instance, pio->epio_handle);
	if (rc < 0) {
		EFRM_ERR("%s: ef10_nic_piobuf_link failed: %d\n",
			 __FUNCTION__, rc);
		return rc;
	}
	vi->pio = pio;

	return 0;
}
EXPORT_SYMBOL(efrm_pio_realloc);



int efrm_pio_alloc(struct efrm_pd *pd, struct efrm_pio **pio_out)
{
	struct efhw_nic *nic;
	struct efrm_client *client;
	struct efrm_pio *pio;
	int rc;

	client = efrm_pd_to_resource(pd)->rs_client;
	nic = client->nic;

	if (efrm_is_pio_enabled() == 0) {
		EFRM_TRACE("%s: PIO support is disabled.", __FUNCTION__);
		EFRM_TRACE("%s: Check sfc_resource driver's pio module param",
			   __FUNCTION__);
		return -EPERM;
	}

	if (nic->devtype.arch != EFHW_ARCH_EF10) {
		EFRM_TRACE("%s: Only EF10 NIC supports PIO."
			   "  Expected arch=%d but got %d\n", __FUNCTION__,
			   EFHW_ARCH_EF10, nic->devtype.arch);
		return -EOPNOTSUPP;
	}

	if ((pio = kmalloc(sizeof(*pio), GFP_KERNEL)) == NULL)
		return -ENOMEM;
	memset(pio, 0, sizeof(*pio));

	pio->epio_pd = pd;
	pio->epio_len = nic->pio_size;

	rc = ef10_nic_piobuf_alloc(nic, &pio->epio_handle);
	if (rc < 0) {
		if( rc == -ENOSPC || rc == -ENETDOWN || rc == -EPERM )
			EFRM_TRACE("%s: ef10_nic_piobuf_alloc failed: %d\n",
				 __FUNCTION__, rc);
		else
			EFRM_ERR("%s: ef10_nic_piobuf_alloc failed: %d\n",
				 __FUNCTION__, rc);
		goto fail;
	}

	EFRM_ASSERT(pio->epio_handle != -1);
	efrm_resource_init(&pio->epio_rs, EFRM_RESOURCE_PIO, pio->epio_handle);
	efrm_client_add_resource(client, &pio->epio_rs);
	efrm_resource_ref(efrm_pd_to_resource(pd));
	*pio_out = pio;
	return 0;

fail:
	kfree(pio);
	return rc;
}
EXPORT_SYMBOL(efrm_pio_alloc);


int efrm_pio_link_vi(struct efrm_pio *pio, struct efrm_vi *vi)
{
	struct efhw_nic *pio_nic, *vi_nic;
	int rc;

	pio_nic = pio->epio_rs.rs_client->nic;
	vi_nic = efrm_pd_to_resource(vi->pd)->rs_client->nic;

	if (pio_nic != vi_nic) {
		EFRM_ERR("%s: VI and PIO belong to different pds",
			 __FUNCTION__);
		return -EINVAL;
	}

	EFRM_ASSERT(pio->epio_handle != -1);
	rc = ef10_nic_piobuf_link(pio_nic, vi->rs.rs_instance,
				  pio->epio_handle);
	if (rc < 0) {
		EFRM_ERR("%s: ef10_nic_piobuf_link failed: %d\n",
			 __FUNCTION__, rc);
		return rc;
	}
	efrm_resource_ref(efrm_pio_to_resource(pio));
	vi->pio = pio;

	return 0;
}
EXPORT_SYMBOL(efrm_pio_link_vi);


int efrm_pio_unlink_vi(struct efrm_pio *pio, struct efrm_vi *vi,
		       bool* freed_resource_out)
{
	struct efhw_nic *nic;
	int rc, freed_resource;

	nic = efrm_pd_to_resource(vi->pd)->rs_client->nic;

	/* Unlink can fail if the associated txq has already been
	 * flushed. */
	rc = ef10_nic_piobuf_unlink(nic, vi->rs.rs_instance);
	freed_resource = efrm_pio_release(pio, rc != -EALREADY);
	if (freed_resource_out != NULL)
		*freed_resource_out = freed_resource;
	vi->pio = NULL;

	return rc;
}
EXPORT_SYMBOL(efrm_pio_unlink_vi);


void efrm_pio_free_buffer(struct efrm_pio *pio)
{
	struct efhw_nic *nic;
	int rc;

	nic = pio->epio_rs.rs_client->nic;

	rc = ef10_nic_piobuf_free(nic, pio->epio_handle);
		if (rc < 0)
			EFRM_ERR("%s: ef10_nic_piobuf_free failed: %d\n",
				 __FUNCTION__, rc);
}


void efrm_pio_free(struct efrm_pio *pio, bool free_piobuf)
{
	/* If the epio_handle has been marked as bad, don't try to
	 * free the non-existent hardware resources 
	 */
	if (free_piobuf && pio->epio_handle != -1)
		efrm_pio_free_buffer(pio);

	efrm_pd_release(pio->epio_pd);
	efrm_client_put(pio->epio_rs.rs_client);
	kfree(pio);
}


bool efrm_pio_release(struct efrm_pio *pio, bool free_piobuf)
{
	if (__efrm_resource_release(efrm_pio_to_resource(pio))) {
		efrm_pio_free(pio, free_piobuf);
		return true;
	}

	return false;
}
EXPORT_SYMBOL(efrm_pio_release);


struct efrm_resource* efrm_pio_to_resource(struct efrm_pio *pio)
{
	return &pio->epio_rs;
}
EXPORT_SYMBOL(efrm_pio_to_resource);


struct efrm_pio* efrm_pio_from_resource(struct efrm_resource *rs)
{
	return efrm_pio(rs);
}
EXPORT_SYMBOL(efrm_pio_from_resource);


static void efrm_pio_rm_dtor(struct efrm_resource_manager *rm)
{
	/* NOP */
}


int efrm_create_pio_resource_manager(struct efrm_resource_manager **rm_out)
{
	struct efrm_resource_manager *rm;
	int rc;

	rm = kmalloc(sizeof(*rm), GFP_KERNEL);
	if (rm == NULL)
		return -ENOMEM;
	memset(rm, 0, sizeof(*rm));

	rc = efrm_resource_manager_ctor(rm, efrm_pio_rm_dtor, "PIO",
					EFRM_RESOURCE_PIO);
	if (rc < 0)
		goto fail;

	*rm_out = rm;
	return 0;

fail:
	kfree(rm);
	return rc;
}


int efrm_pio_map_kernel(struct efrm_vi *vi, void **io)
{
	const size_t VI_WINDOW_PIO_OFFSET = 4096;
	struct efhw_nic* nic = vi->rs.rs_client->nic;
	size_t bar_off, bar_page_off;
	bar_off = ef10_tx_dma_page_base(nic->vi_stride, vi->rs.rs_instance);
	bar_off += VI_WINDOW_PIO_OFFSET;
	bar_page_off = bar_off & PAGE_MASK;
	*io = ioremap_wc(nic->ctr_ap_addr + bar_page_off, PAGE_SIZE);
	if( *io == NULL )
		return -EINVAL;
	*io = (char*) *io + (bar_off & (PAGE_SIZE - 1u));
	return 0;
}
EXPORT_SYMBOL(efrm_pio_map_kernel);


void efrm_pio_unmap_kernel(struct efrm_vi *vi, void *io)
{
	iounmap((void*) ((unsigned long) io & PAGE_MASK));
}
EXPORT_SYMBOL(efrm_pio_unmap_kernel);


int efrm_pio_get_size(struct efrm_pio *pio)
{
	return pio->epio_len;
}
EXPORT_SYMBOL(efrm_pio_get_size);


int efrm_ctpio_map_kernel(struct efrm_vi *vi, void **io)
{
	struct efhw_nic* nic = vi->rs.rs_client->nic;
	resource_size_t ctpio_addr;
	size_t ctpio_page_off;
	int rc;

	rc = efhw_nic_ctpio_addr(nic, efrm_vi_qid(vi, EFHW_TXQ), &ctpio_addr);
	if( rc < 0 )
		return rc;

	ctpio_page_off = ctpio_addr & PAGE_MASK;
	*io = ioremap_wc(ctpio_page_off, PAGE_SIZE);
	if( *io == NULL )
		return -EINVAL;
	*io = (char*) *io + (ctpio_addr & (PAGE_SIZE - 1u));
	return 0;
}
EXPORT_SYMBOL(efrm_ctpio_map_kernel);


void efrm_ctpio_unmap_kernel(struct efrm_vi *vi, void *io)
{
	iounmap((void*) ((unsigned long) io & PAGE_MASK));
}
EXPORT_SYMBOL(efrm_ctpio_unmap_kernel);
