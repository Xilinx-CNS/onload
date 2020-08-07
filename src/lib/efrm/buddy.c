/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */

/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains implementation of a buddy allocator.
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

#include <ci/efrm/buddy.h>
#include <ci/efhw/common.h>
#include <ci/efrm/sysdep.h>
#include <ci/efrm/debug.h>

#if 1
#define DEBUG_ALLOC(x)
#else
#define DEBUG_ALLOC(x) x
#endif

/*
 * The purpose of the following inline functions is to give the
 * understandable names to the simple actions.
 */
static inline void
efrm_buddy_free_list_add(struct efrm_buddy_allocator *b,
			 unsigned order, unsigned addr)
{
	list_add(&b->links[addr], &b->free_lists[order]);
	b->orders[addr] = (uint8_t) order;
}
static inline void
efrm_buddy_free_list_del(struct efrm_buddy_allocator *b, unsigned addr)
{
	list_del(&b->links[addr]);
	b->links[addr].next = NULL;
}
static inline int
efrm_buddy_free_list_empty(struct efrm_buddy_allocator *b, unsigned order)
{
	return list_empty(&b->free_lists[order]);
}
static inline unsigned
efrm_buddy_free_list_pop(struct efrm_buddy_allocator *b, unsigned order)
{
	struct list_head *l = list_pop(&b->free_lists[order]);
	l->next = NULL;
	return (unsigned)(l - b->links);
}
static inline int
efrm_buddy_addr_in_free_list(struct efrm_buddy_allocator *b, unsigned addr)
{
	return b->links[addr].next != NULL;
}
static inline unsigned
efrm_buddy_free_list_first(struct efrm_buddy_allocator *b, unsigned order)
{
	return (unsigned)(b->free_lists[order].next - b->links);
}


int efrm_buddy_ctor(struct efrm_buddy_allocator *b, unsigned order)
{
	unsigned o;
	unsigned size = 1 << order;

	DEBUG_ALLOC(EFRM_NOTICE("%s(%u)", __FUNCTION__, order));
	EFRM_ASSERT(b);
	EFRM_ASSERT(order <= sizeof(unsigned) * 8 - 1);

	b->order = order;
	b->free_lists = kmalloc((order + 1) * sizeof(b->free_lists[0]),
				GFP_KERNEL);
	if (b->free_lists == NULL)
		goto fail1;

	b->links = vmalloc(size * sizeof(b->links[0]));
	if (b->links == NULL)
		goto fail2;

	b->orders = vmalloc(size * sizeof(b->orders[0]));
	if (b->orders == NULL)
		goto fail3;

	memset(b->links, 0, size * sizeof(b->links[0]));

	for (o = 0; o <= b->order; ++o)
		INIT_LIST_HEAD(b->free_lists + o);

	efrm_buddy_free_list_add(b, b->order, 0);

	return 0;

fail3:
	vfree(b->links);
fail2:
	kfree(b->free_lists);
fail1:
	return -ENOMEM;
}


int efrm_buddy_range_ctor(struct efrm_buddy_allocator *b, int low, int high)
{
	int i, rc, log2_n;
	log2_n = fls(high - 1);
	if ((rc = efrm_buddy_ctor(b, log2_n)) < 0 )
		return rc;
	for (i = 0; i < (1 << log2_n); ++i) {
		rc = efrm_buddy_alloc(b, 0);
		EFRM_ASSERT(rc >= 0);
		EFRM_ASSERT(rc < (1 << log2_n));
	}
	for (i = low; i < high; ++i)
		efrm_buddy_free(b, i, 0);
	return 0;
}


void efrm_buddy_dtor(struct efrm_buddy_allocator *b)
{
	EFRM_ASSERT(b);

	kfree(b->free_lists);
	vfree(b->links);
	vfree(b->orders);
}


int efrm_buddy_alloc(struct efrm_buddy_allocator *b, unsigned order)
{
	unsigned smallest;
	unsigned addr;

	DEBUG_ALLOC(EFRM_NOTICE("%s(%u)", __FUNCTION__, order));
	EFRM_ASSERT(b);

	/* Find smallest chunk that is big enough.  ?? Can optimise this by
	 ** keeping array of pointers to smallest chunk for each order.
	 */
	smallest = order;
	while (smallest <= b->order &&
	       efrm_buddy_free_list_empty(b, smallest))
		++smallest;

	if (smallest > b->order) {
		DEBUG_ALLOC(EFRM_NOTICE
			    ("buddy - alloc order %d failed - max order %d",
			     order, b->order););
		return -ENOMEM;
	}

	/* Split blocks until we get one of the correct size. */
	addr = efrm_buddy_free_list_pop(b, smallest);

	DEBUG_ALLOC(EFRM_NOTICE("buddy - alloc %x order %d cut from order %d",
				addr, order, smallest););
	while (smallest-- > order)
		efrm_buddy_free_list_add(b, smallest, addr + (1 << smallest));

	EFRM_DO_DEBUG(b->orders[addr] = (uint8_t) order);

	EFRM_ASSERT(addr < 1u << b->order);
	return addr;
}


int efrm_buddy_alloc_special(struct efrm_buddy_allocator *b,
			     unsigned order,
			     bool (*accept_fn)(int low, unsigned order,
					       void* arg),
			     void* arg)
{
	/* Keep allocating until we find one that satisfies [accept_fn].
	 * We put the rejected ones on a list which is freed before return.
	 * The reject list is formed using [b->links[addr].prev], which is
	 * safe because [addr] cannot be in a free list at this time.  We
	 * can't use the [next] field because that is used to detect
	 * whether or not a buddy is free.
	 */
	struct list_head *rejects = NULL;
	struct list_head *l;
	int addr;

	DEBUG_ALLOC(EFRM_NOTICE("%s(%u)", __FUNCTION__, order));
	EFRM_ASSERT(b);

	while (1) {
		addr = efrm_buddy_alloc(b, order);
		if (addr < 0 || accept_fn(addr, order, arg))
			break;
		b->links[addr].prev = rejects;
		rejects = &b->links[addr];
	}
	while ((l = rejects) != NULL) {
		rejects = l->prev;
		efrm_buddy_free(b, l - b->links, order);
	}
	return addr;
}


void
efrm_buddy_free(struct efrm_buddy_allocator *b, unsigned addr,
		unsigned order)
{
	unsigned buddy_addr;

	DEBUG_ALLOC(EFRM_NOTICE("%s(%u, %u)", __FUNCTION__, addr, order));
	EFRM_ASSERT(b);
	EFRM_ASSERT(order <= b->order);
	EFRM_ASSERT((unsigned long)addr + ((unsigned long)1 << order) <=
		    (unsigned long)1 << b->order);
	EFRM_ASSERT(!efrm_buddy_addr_in_free_list(b, addr));
	EFRM_ASSERT(b->orders[addr] == order);

	/* merge free blocks */
	while (order < b->order) {
		buddy_addr = addr ^ (1 << order);
		if (!efrm_buddy_addr_in_free_list(b, buddy_addr) ||
		    b->orders[buddy_addr] != order)
			break;
		efrm_buddy_free_list_del(b, buddy_addr);
		if (buddy_addr < addr)
			addr = buddy_addr;
		++order;
	}

	DEBUG_ALLOC(EFRM_NOTICE
		    ("buddy - free %x merged into order %d", addr, order););
	efrm_buddy_free_list_add(b, order, addr);
}
