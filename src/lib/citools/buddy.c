/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  slp
**  \brief  Implementation of a buddy allocator.
**   \date  2002/08/07
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_citools */

#include "citools_internal.h"

/* debugging */
#define DEBUG_ALLOC(x)
#define CI_DEBUG_BUDDY_ALLOCATOR          1


#define FL(b,o)            ((b)->free_lists + (o))
#define LINK_TO_ADDR(b,l)  ((unsigned)((l) - (b)->links))
#define ADDR_TO_LINK(b,a)  ((b)->links + (a))
#define IS_BUSY(b,a)       (ci_dllink_is_free(ADDR_TO_LINK((b),(a))))
#define SET_BUSY(b,a)      ci_dllink_mark_free(ADDR_TO_LINK((b),(a)))


int  ci_buddy_ctor2(ci_buddy_allocator* b, unsigned order,
		    void* (*alloc_fn)(size_t), void (*free_fn)(void*))
{
  unsigned o;

  ci_assert(b);

  b->order = order;
  b->free_lists = (ci_dllist*) alloc_fn((order+1) * sizeof(ci_dllist));
  if( b->free_lists == 0 )  goto fail1;

  b->links = (ci_dllink*) alloc_fn(ci_pow2(order) * sizeof(ci_dllink));
  if( b->links == 0 )  goto fail2;

  b->orders = (ci_uint8*) alloc_fn(ci_pow2(order));
  if( b->orders == 0 )  goto fail3;

  CI_DEBUG(CI_ZERO_ARRAY(b->links, ci_pow2(order)));

  for( o = 0; o <= b->order; ++o )
    ci_dllist_init(b->free_lists + o);

  ci_dllist_push(FL(b, b->order), ADDR_TO_LINK(b, 0));
  ci_assert(b->order < 255);	
  b->orders[0] = (ci_uint8)b->order;

  ci_assert(!IS_BUSY(b, LINK_TO_ADDR(b, ci_dllist_head(FL(b, b->order)))));

  return 0;

 fail3:
  free_fn(b->links);
 fail2:
  free_fn(b->free_lists);
 fail1:
  return -ENOMEM;
}


void ci_buddy_dtor2(ci_buddy_allocator* b, void (*free_fn)(void*))
{
  ci_buddy_assert_valid(b);

  free_fn(b->free_lists);
  free_fn(b->links);
  free_fn(b->orders);
}


int ci_buddy_alloc(ci_buddy_allocator* b, unsigned order)
{
  unsigned smallest;
  ci_dllink* l;
  unsigned addr;

  ci_buddy_assert_valid(b);

  /* Find smallest chunk that is big enough.  ?? Can optimise this by
  ** keeping array of pointers to smallest chunk for each order.
  */
  smallest = order;
  while( smallest <= b->order && ci_dllist_is_empty(FL(b, smallest)) )
    ++smallest;

  if( smallest > b->order ) {
    DEBUG_ALLOC(ci_log("buddy - alloc order %d failed - max order %d",
                       order, b->order););
    return -ENOMEM;
  }

  /* Split blocks until we get one of the correct size. */
  l = ci_dllist_pop(FL(b, smallest));
  addr = LINK_TO_ADDR(b, l);

  DEBUG_ALLOC(ci_log("buddy - alloc %x order %d cut from order %d",
                     addr, order, smallest););
  while( smallest-- > order ) {
    l = ADDR_TO_LINK(b, addr + ci_pow2(smallest));
    ci_dllist_push(FL(b, smallest), l);
    b->orders[addr + ci_pow2(smallest)] = (ci_uint8) smallest;
  }

  SET_BUSY(b, addr);
  CI_DEBUG(b->orders[addr] = (ci_uint8) order);

  ci_assert_ge((int) addr, 0);
  ci_assert_lt(addr, 1u << b->order);
  return addr;
}


void ci_buddy_free(ci_buddy_allocator* b, unsigned addr, unsigned order)
{
  unsigned buddy_addr;
  ci_dllink* l;

  ci_buddy_assert_valid(b);
  ci_assert_le(order, b->order);
  ci_assert_le((unsigned long)addr + ci_pow2(order), ci_pow2(b->order));
  ci_assert(IS_BUSY(b, addr));
  ci_assert_equal(b->orders[addr], order);

  /* merge free blocks */
  while( order < b->order ) {
    buddy_addr = addr ^ ci_pow2(order);
    if( IS_BUSY(b, buddy_addr) || b->orders[buddy_addr] != order )  break;
    l = ADDR_TO_LINK(b, buddy_addr);
    ci_dllist_remove(l);
    if( buddy_addr < addr )  addr = buddy_addr;
    ++order;
  }

  DEBUG_ALLOC(ci_log("buddy - free %x merged into order %d", addr, order););
  ci_dllist_push(FL(b, order), ADDR_TO_LINK(b, addr));
  b->orders[addr] = (ci_uint8)order;
}


/* Attempt to reserve the given region using all available free blocks.
 * BUG: This function has no way to reverse it's working (not without
 * additional storage), so it can't gracefully return success/failure.
 * It just asserts
 */
void ci_buddy_reserve(ci_buddy_allocator *b, unsigned addr, unsigned size)
{
  ci_dllink* l, *_l;
  int next_order, order;
  unsigned block_addr, block_size;
  unsigned allocated = 0;

  ci_assert_ge(addr, 0);
  ci_assert_lt(addr, addr + size);
  ci_assert_le(addr + size, 1u << b->order);

  for( order = b->order; (order >= 0) && (allocated < size); --order ) {
    block_size = 1<<order;
    next_order = order-1;
    CI_DLLIST_FOR_EACH4(l, FL(b, order), _l) {
      block_addr = LINK_TO_ADDR(b, l);
      if( (block_addr >= addr) && (block_addr + block_size <= addr + size) ) {
	/* This block sits entirely within the region, so move from the
	 * free list onto the work list */
	ci_dllist_remove(l);
	allocated += block_size;
      } else if( (block_addr + block_size > addr) && (block_addr < addr + size) ) {
	/* This block sits over either the left hand or right hand edges.
	 * Split it into two allocations and push them both on the free list */
	ci_assert_gt(order, 0);
	ci_dllist_remove(l);
	ci_dllist_push(FL(b, next_order), l);
	l = ADDR_TO_LINK(b, block_addr + (1<<next_order));
	ci_dllist_push(FL(b, next_order), l);
      }
    }
  }

  ci_assert_equal(allocated, size);
}

#if CI_DEBUG_BUDDY_ALLOCATOR
void ci_buddy_validate(ci_buddy_allocator* b)
{
  unsigned int order, addr;
  ci_dllink* l;

  /* Check that free lists and IS_BUSY()ness match up, and that all free
  ** blocks are properly merged.
  */

  /* ?? Or is it better to iterate over free lists?  Or both ;-) */

  for( addr = 0; addr < ci_pow2(b->order); ++addr ) {
    if( IS_BUSY(b, addr) ) {
      /* ?? Search free lists to determine size of block, and ensure it
      ** is all busy...  */
    }
    else {
      /* ?? */
    }
  }
  /* iterate over the free lists */
  for(order = 0; order <= b->order; ++order) {
      CI_DLLIST_FOR_EACH(l, FL(b, order)){
	/* ?? do something useful here */
	ci_assert(!IS_BUSY(b, LINK_TO_ADDR(b, l)));
      }
  }
}
#endif


#if CI_INCLUDE_ASSERT_VALID
void ci_buddy_assert_valid(ci_buddy_allocator* b)
{
  ci_assert(b);
  ci_assert(b->free_lists);
  ci_assert(b->links);
  ci_assert_ge(b->order, 0);

# if CI_DEBUG_BUDDY_ALLOCATOR
  ci_buddy_validate(b);
# endif
}
#endif

/*! \cidoxg_end */
