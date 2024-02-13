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

#include <ci/efhw/buddy.h>
#include <ci/efhw/common.h>

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
efhw_buddy_free_list_add(struct efhw_buddy_allocator *b,
			 unsigned order, unsigned addr)
{
	list_add(&b->links[addr], &b->free_lists[order]);
	b->orders[addr] = (uint8_t) order;
}
static inline void
efhw_buddy_free_list_del(struct efhw_buddy_allocator *b, unsigned addr)
{
	list_del(&b->links[addr]);
	b->links[addr].next = NULL;
}
static inline int
efhw_buddy_free_list_empty(struct efhw_buddy_allocator *b, unsigned order)
{
	return list_empty(&b->free_lists[order]);
}
static inline unsigned
efhw_buddy_free_list_pop(struct efhw_buddy_allocator *b, unsigned order)
{
	struct list_head *l = list_pop(&b->free_lists[order]);
	l->next = NULL;
	return (unsigned)(l - b->links);
}
static inline int
efhw_buddy_addr_in_free_list(struct efhw_buddy_allocator *b, unsigned addr)
{
	return b->links[addr].next != NULL;
}
static inline unsigned
efhw_buddy_free_list_first(struct efhw_buddy_allocator *b, unsigned order)
{
	return (unsigned)(b->free_lists[order].next - b->links);
}


int efhw_buddy_ctor(struct efhw_buddy_allocator *b, unsigned order)
{
	unsigned o;
	unsigned size = 1 << order;

	DEBUG_ALLOC(EFHW_NOTICE("%s(%u)", __FUNCTION__, order));
	EFHW_ASSERT(b);
	EFHW_ASSERT(order <= sizeof(unsigned) * 8 - 1);

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

	efhw_buddy_free_list_add(b, b->order, 0);

	return 0;

fail3:
	vfree(b->links);
fail2:
	kfree(b->free_lists);
fail1:
	return -ENOMEM;
}


int efhw_buddy_range_ctor(struct efhw_buddy_allocator *b, int low, int high)
{
	int i, rc, log2_n;
	log2_n = fls(high - 1);
	if ((rc = efhw_buddy_ctor(b, log2_n)) < 0 )
		return rc;
	for (i = 0; i < (1 << log2_n); ++i) {
		rc = efhw_buddy_alloc(b, 0);
		EFHW_ASSERT(rc >= 0);
		EFHW_ASSERT(rc < (1 << log2_n));
	}
	for (i = low; i < high; ++i)
		efhw_buddy_free(b, i, 0);
	return 0;
}


void efhw_buddy_dtor(struct efhw_buddy_allocator *b)
{
	EFHW_ASSERT(b);

	kfree(b->free_lists);
	vfree(b->links);
	vfree(b->orders);
}


int efhw_buddy_alloc(struct efhw_buddy_allocator *b, unsigned order)
{
	unsigned smallest;
	unsigned addr;

	DEBUG_ALLOC(EFHW_NOTICE("%s(%u)", __FUNCTION__, order));
	EFHW_ASSERT(b);

	/* Find smallest chunk that is big enough.  ?? Can optimise this by
	 ** keeping array of pointers to smallest chunk for each order.
	 */
	smallest = order;
	while (smallest <= b->order &&
	       efhw_buddy_free_list_empty(b, smallest))
		++smallest;

	if (smallest > b->order) {
		DEBUG_ALLOC(EFHW_NOTICE
			    ("buddy - alloc order %d failed - max order %d",
			     order, b->order););
		return -ENOMEM;
	}

	/* Split blocks until we get one of the correct size. */
	addr = efhw_buddy_free_list_pop(b, smallest);

	DEBUG_ALLOC(EFHW_NOTICE("buddy - alloc %x order %d cut from order %d",
				addr, order, smallest););
	while (smallest-- > order)
		efhw_buddy_free_list_add(b, smallest, addr + (1 << smallest));

	EFHW_DO_DEBUG(b->orders[addr] = (uint8_t) order);

	EFHW_ASSERT(addr < 1u << b->order);
	return addr;
}


int efhw_buddy_alloc_special(struct efhw_buddy_allocator *b,
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

	DEBUG_ALLOC(EFHW_NOTICE("%s(%u)", __FUNCTION__, order));
	EFHW_ASSERT(b);

	while (1) {
		addr = efhw_buddy_alloc(b, order);
		if (addr < 0 || accept_fn(addr, order, arg))
			break;
		b->links[addr].prev = rejects;
		rejects = &b->links[addr];
	}
	while ((l = rejects) != NULL) {
		rejects = l->prev;
		efhw_buddy_free(b, l - b->links, order);
	}
	return addr;
}


void
efhw_buddy_free(struct efhw_buddy_allocator *b, unsigned addr,
		unsigned order)
{
	unsigned buddy_addr;

	DEBUG_ALLOC(EFHW_NOTICE("%s(%u, %u)", __FUNCTION__, addr, order));
	EFHW_ASSERT(b);
	EFHW_ASSERT(order <= b->order);
	EFHW_ASSERT((unsigned long)addr + ((unsigned long)1 << order) <=
		    (unsigned long)1 << b->order);
	EFHW_ASSERT(!efhw_buddy_addr_in_free_list(b, addr));
	EFHW_ASSERT(b->orders[addr] == order);

	/* merge free blocks */
	while (order < b->order) {
		buddy_addr = addr ^ (1 << order);
		if (!efhw_buddy_addr_in_free_list(b, buddy_addr) ||
		    b->orders[buddy_addr] != order)
			break;
		efhw_buddy_free_list_del(b, buddy_addr);
		if (buddy_addr < addr)
			addr = buddy_addr;
		++order;
	}

	DEBUG_ALLOC(EFHW_NOTICE
		    ("buddy - free %x merged into order %d", addr, order););
	efhw_buddy_free_list_add(b, order, addr);
}
