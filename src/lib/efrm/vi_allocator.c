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
#include <ci/efrm/debug.h>
#include <ci/efhw/common.h>
#include <ci/efhw/efhw_types.h>
#include <ci/driver/efab/hardware.h>
#include "efrm_internal.h"

struct alloc_vi_constraints {
	struct efhw_nic *efhw_nic;
	int channel;
	int min_vis_in_set;
	int has_rss_context;
};


int efrm_vi_allocator_alloc_set(struct efrm_nic *efrm_nic,
				 struct efrm_alloc_vi_constraints *avc,
				 struct efrm_vi_allocation *set_out)
{
	struct efhw_vi_constraints evc = {
		.channel = avc->channel,
		.min_vis_in_set = avc->min_vis_in_set,
		.has_rss_context = avc->has_rss_context,
		.want_txq = avc->want_txq,
	};

	if (avc->min_vis_in_set < 1)
		return -EINVAL;

	set_out->n_vis = avc->min_vis_in_set;
	spin_lock_bh(&efrm_nic->lock);
	set_out->instance = efhw_nic_vi_alloc(avc->efhw_nic, &evc, set_out->n_vis);
	spin_unlock_bh(&efrm_nic->lock);
	return (set_out->instance >= 0) ? 0 : set_out->instance;
}


void efrm_vi_allocator_free_set(struct efrm_nic *efrm_nic,
				struct efrm_vi_allocation *set)
{
	EFRM_ASSERT(set->instance >= 0);

	spin_lock_bh(&efrm_nic->lock);
	efhw_nic_vi_free(&efrm_nic->efhw_nic, set->instance, set->n_vis);
	spin_unlock_bh(&efrm_nic->lock);
}
