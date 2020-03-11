/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *
 * This file provides internal API for buffer table manager.
 *
 * Copyright 2012-2012: Solarflare Communications Inc,
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

#ifndef __EFRM_BT_MANAGER_H__
#define __EFRM_BT_MANAGER_H__

#include <ci/efrm/buffer_table.h>

static inline void
efrm_bt_manager_ctor(struct efrm_bt_manager *manager, int owner, int order)
{
	manager->btm_block = NULL;
	spin_lock_init(&manager->btm_lock);
	manager->owner = owner;
	manager->order = order;
	atomic_set(&manager->btm_blocks, 0);
	atomic_set(&manager->btm_entries, 0);
}
static inline void
efrm_bt_manager_dtor(struct efrm_bt_manager *manager)
{
	EFRM_ASSERT(manager->btm_block == NULL);
	EFRM_ASSERT(atomic_read(&manager->btm_blocks) == 0);
	EFRM_ASSERT(atomic_read(&manager->btm_entries) == 0);
	spin_lock_destroy(&manager->btm_lock);
}

extern int
efrm_bt_manager_alloc(struct efhw_nic *nic,
		      struct efrm_bt_manager *manager, int size,
		      struct efrm_buffer_table_allocation *a,
		      int reset_pending);
extern int
efrm_bt_manager_realloc(struct efhw_nic *nic,
			struct efrm_bt_manager *manager,
			struct efrm_buffer_table_allocation *a);
extern void
efrm_bt_manager_free(struct efhw_nic *nic, struct efrm_bt_manager *manager,
		     struct efrm_buffer_table_allocation *a,
		     int reset_pending);
extern int
efrm_bt_nic_set(struct efhw_nic *nic, struct efrm_buffer_table_allocation *a,
		dma_addr_t *dma_addrs);

#endif /* __EFRM_BT_MANAGER_H__ */
