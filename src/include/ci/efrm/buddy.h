/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides private API for buddy allocator.  This API is not
 * designed for use outside of SFC resource driver.
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

#ifndef __CI_EFRM_BUDDY_H__
#define __CI_EFRM_BUDDY_H__

#include <ci/efrm/sysdep.h>

/*! Comment? */
struct efrm_buddy_allocator {
	struct list_head *free_lists;	/* array[order+1] */
	struct list_head *links;	/* array[1<<order] */
	uint8_t *orders;		/* array[1<<order] */
	unsigned order;		/*!< total size == (1 << order) */
	/* ?? Consider recording largest available order + for each order the
	 ** smallest available order that is big enough.
	 */
};

extern int efrm_buddy_ctor(struct efrm_buddy_allocator *b, unsigned order);
extern int efrm_buddy_range_ctor(struct efrm_buddy_allocator *b,
				 int low, int high);
extern void efrm_buddy_dtor(struct efrm_buddy_allocator *b);
extern int efrm_buddy_alloc(struct efrm_buddy_allocator *b, unsigned order);
extern int efrm_buddy_alloc_special(struct efrm_buddy_allocator *b,
				    unsigned order,
				    bool (*)(int low, unsigned order,
					     void* arg),
				    void* arg);
extern void efrm_buddy_free(struct efrm_buddy_allocator *b, unsigned addr,
			    unsigned order);


#endif /* __CI_EFRM_BUDDY_H__ */
