/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2011-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *
 * This file provides an allocator for Virtual Interfaces (VIs).
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
#include <ci/efrm/efrm_nic.h>
#include <ci/efrm/driver_private.h>
#include <ci/efrm/buddy.h>
#include <ci/efrm/debug.h>
#include <ci/efhw/common.h>
#include <ci/efhw/efhw_types.h>
#include <ci/driver/efab/hardware.h>
#include "efrm_internal.h"


int efrm_vi_allocator_ctor(struct efrm_nic *efrm_nic,
			   const struct vi_resource_dimensions *dims)
{
	int rc;
	unsigned vi_min, vi_lim;

	if (efrm_nic->efhw_nic.devtype.arch == EFHW_ARCH_EF10 ||
	    efrm_nic->efhw_nic.devtype.arch == EFHW_ARCH_AF_XDP ||
	    efrm_nic->efhw_nic.devtype.arch == EFHW_ARCH_EF100 ||
	    efrm_nic->efhw_nic.devtype.arch == EFHW_ARCH_EFCT) {
		vi_min = dims->vi_min;
		vi_lim = dims->vi_lim;
	} else {
		rc = -EINVAL;
		EFRM_ERR("%s: unknown efhw device architecture %u",
			 __FUNCTION__, efrm_nic->efhw_nic.devtype.arch);
		goto fail;
	}

	if (vi_lim > vi_min) {
		rc = efrm_buddy_range_ctor(&efrm_nic->vi_allocator, vi_min, vi_lim);
		if (rc < 0) {
			EFRM_ERR("%s: efrm_buddy_range_ctor(%d, %d) "
				 "failed (%d)",
				 __FUNCTION__, vi_min, vi_lim, rc);
			goto fail;
		}
	}
	else {
		EFRM_ERR("%s: No VIs, not handling", __FUNCTION__);
		rc = -ERANGE;
		goto fail;
        }

	return 0;

fail:
	return rc;
}


void efrm_vi_allocator_dtor(struct efrm_nic *efrm_nic)
{
	efrm_buddy_dtor(&efrm_nic->vi_allocator);
}


struct alloc_vi_constraints {
	struct efhw_nic *efhw_nic;
	int channel;
	int min_vis_in_set;
	int has_rss_context;
};


static bool accept_vi_constraints(int low, unsigned order, void* arg)
{
	struct efrm_alloc_vi_constraints *avc = arg;
	struct efhw_vi_constraints evc = {
		.channel = avc->channel,
		.min_vis_in_set = avc->min_vis_in_set,
		.has_rss_context = avc->has_rss_context,
		.want_txq = avc->want_txq,
	};
	return efhw_nic_accept_vi_constraints(avc->efhw_nic, low, order, &evc);
}


int  efrm_vi_allocator_alloc_set(struct efrm_nic *efrm_nic,
				 struct efrm_alloc_vi_constraints *avc,
				 struct efrm_vi_allocation *set_out)
{
	int rc;

	EFRM_ASSERT(efrm_nic->vi_allocator.orders != NULL);

	if (avc->min_vis_in_set < 1)
		return -EINVAL;

	set_out->order = fls(avc->min_vis_in_set - 1);
	spin_lock_bh(&efrm_nic->lock);
	set_out->instance = efrm_buddy_alloc_special(&efrm_nic->vi_allocator,
						     set_out->order,
						     accept_vi_constraints,
						     avc);
	spin_unlock_bh(&efrm_nic->lock);
	rc = (set_out->instance >= 0) ? 0 : -EBUSY;
	return rc;
}


void efrm_vi_allocator_free_set(struct efrm_nic *efrm_nic,
				struct efrm_vi_allocation *set)
{
	EFRM_ASSERT(set->instance >= 0);

	spin_lock_bh(&efrm_nic->lock);
	efrm_buddy_free(&efrm_nic->vi_allocator, set->instance, set->order);
	spin_unlock_bh(&efrm_nic->lock);
}
