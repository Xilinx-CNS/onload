/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2013-2020 Xilinx, Inc. */
/**************************************************************************\
 * *//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author
**  \brief
**   \date
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_transport_ip */

#include <ci/internal/ip.h>
#include <ci/internal/pio_buddy.h>

#if 1
#define DEBUG_ALLOC(x)
#else
#define DEBUG_ALLOC(x) x
#endif


/* Macros for accessing buddy allocator state, for buddy allocator b. */
/* Get free list for order o. */
#define FREE_LIST(ni,b,o)     oo_p_dllink_ptr(ni,(b)->free_lists + (o))
/* Get buddy block addr associated with a link l. */
#define LINK_TO_ADDR(b,l)  ((ci_uint32)((l) - (b)->links))
/* Get link for buddy block addr a. */
#define ADDR_TO_LINK(ni,b,a)  oo_p_dllink_ptr(ni,(b)->links + (a))


static inline int
ci_pio_buddy_free_list_empty(ci_netif* ni, ci_pio_buddy_allocator* b,
                             ci_uint8 order)
{
  return oo_p_dllink_is_empty(ni, FREE_LIST(ni, b, order));
}


static inline int
ci_pio_buddy_addr_in_free_list(ci_netif* ni, ci_pio_buddy_allocator* b,
                               ci_int32 addr)
{
  /* Links should always have been marked as free when not on a free list. */
  return !oo_p_dllink_is_empty(ni, ADDR_TO_LINK(ni, b, addr));
}


static inline void
ci_pio_buddy_free_list_add(ci_netif* ni, ci_pio_buddy_allocator* b,
                           ci_uint8 order, ci_uint32 addr)
{
  /* If we're putting this on a free list it shouldn't already be on one. */
  ci_assert(!ci_pio_buddy_addr_in_free_list(ni, b, addr));

  oo_p_dllink_add(ni, FREE_LIST(ni, b, order), ADDR_TO_LINK(ni, b, addr));
  b->orders[addr] = order;
}


static inline void
ci_pio_buddy_free_list_remove(ci_netif* ni, ci_pio_buddy_allocator* b,
                              ci_uint32 addr)
{
  /* If we're removing this from a free list it should be linked. */
  ci_assert(ci_pio_buddy_addr_in_free_list(ni, b, addr));

  oo_p_dllink_del_init(ni, ADDR_TO_LINK(ni, b, addr));
}


static inline ci_uint32
ci_pio_buddy_free_list_pop(ci_netif* ni, ci_pio_buddy_allocator* b,
                           ci_uint8 order)
{
  struct oo_p_dllink_state l;

  /* Should have ensured there was something on this list before now. */
  ci_assert(!ci_pio_buddy_free_list_empty(ni, b, order));

  l = oo_p_dllink_statep(ni, FREE_LIST(ni, b, order).l->next);
  oo_p_dllink_del_init(ni, l);
  return LINK_TO_ADDR(b, l.l);
}


void
ci_pio_buddy_ctor(ci_netif* ni, ci_pio_buddy_allocator* b, unsigned pio_len)
{
  ci_uint8 o;

  /* Order of the buffer size in bytes.  N.B. The buddy API takes orders of
   * buffer sizes in chunks of CI_CFG_MIN_PIO_BLOCK_ORDER, so subtract the
   * latter before passing [pio_order] to buddy-API functions. */
  unsigned pio_order = ci_log2_le(pio_len);

  /* Basic sanity */
  ci_assert(b);
  /* Orders array uses a uint8 */
  ci_assert(CI_PIO_BUDDY_MAX_ORDER < 255);
  /* Buffer size is sane and within range. */
  ci_assert(CI_IS_POW2(pio_len));
  ci_assert_ge(pio_order, CI_CFG_MIN_PIO_BLOCK_ORDER);

  /* Initialise the free list for each order. */
  for( o = 0; o <= CI_PIO_BUDDY_MAX_ORDER; ++o )
    oo_p_dllink_init(ni, FREE_LIST(ni, b, o));

  /* Initialise the links for each block. */
  for( o = 0; o < (1u << CI_PIO_BUDDY_MAX_ORDER); ++o )
    oo_p_dllink_init(ni, ADDR_TO_LINK(ni, b, o));

  /* At initialisation we have one free block containing the whole space. */
  ci_pio_buddy_free_list_add(ni, b, pio_order - CI_CFG_MIN_PIO_BLOCK_ORDER, 0);

  b->initialised = 1;
}


void
ci_pio_buddy_dtor(ci_netif* ni, ci_pio_buddy_allocator* b)
{
  b->initialised = 0;
}


ci_int32
ci_pio_buddy_alloc(ci_netif* ni, ci_pio_buddy_allocator* b, ci_uint8 order)
{
#if CI_CFG_PIO
  ci_uint8 smallest;
  ci_uint32 addr;
  if( b->initialised ) {
    order -= CI_CFG_MIN_PIO_BLOCK_ORDER;

    /* Find smallest free block that is big enough. */
    smallest = order;
    while( smallest <= CI_PIO_BUDDY_MAX_ORDER &&
           ci_pio_buddy_free_list_empty(ni, b, smallest) )
      ++smallest;

    if( smallest > CI_PIO_BUDDY_MAX_ORDER ) {
      DEBUG_ALLOC(ci_log("buddy - alloc order %d failed - max order %d",
                         order, CI_PIO_BUDDY_MAX_ORDER););
      return -ENOMEM;
    }

    /* Take a block from the free list that we've identified. */
    addr = ci_pio_buddy_free_list_pop(ni, b, smallest);

    DEBUG_ALLOC(ci_log("buddy - alloc %x order %d cut from order %d",
                       addr, order, smallest););

    /* If the block we've got is larger than the order requested then split
     * blocks.
     */
    while( smallest-- > order )
      ci_pio_buddy_free_list_add(ni, b, smallest, addr + ci_pow2(smallest));

    b->orders[addr] = (ci_uint8) order;

    /* Should never end up with an addr outside our range of blocks. */
    ci_assert_ge((ci_int32) addr, 0);
    ci_assert_lt(addr, 1u << CI_PIO_BUDDY_MAX_ORDER);

    return addr * (1u << CI_CFG_MIN_PIO_BLOCK_ORDER);
  }
#endif
  return -ENOSPC;
}


void
ci_pio_buddy_free(ci_netif* ni, ci_pio_buddy_allocator* b, ci_int32 offset,
                  ci_uint8 order)
{
  ci_uint32 buddy_addr;
  ci_uint32 addr = offset / (1u << CI_CFG_MIN_PIO_BLOCK_ORDER);
  order -= CI_CFG_MIN_PIO_BLOCK_ORDER;

  /* Order should be within valid range and addr should be for a valid block */
  ci_assert_le(order, CI_PIO_BUDDY_MAX_ORDER);
  ci_assert_le(addr + (1u << order), 1u << CI_PIO_BUDDY_MAX_ORDER);
  /* Check we're freeing something that's been allocated. */
  ci_assert(!ci_pio_buddy_addr_in_free_list(ni, b, addr));
  /* Check what we're freeing has the size we expect. */
  ci_assert_equal(b->orders[addr], order);

  /* If this block isn't of the maximum order then freeing it may allow us
   * to merge it with its buddy.
   */
  while( order < CI_PIO_BUDDY_MAX_ORDER) {
    buddy_addr = addr ^ ci_pow2(order);

    /* If this block's buddy is busy, or of a different order then we can't
     * merge.
     */
    if( !ci_pio_buddy_addr_in_free_list(ni, b, buddy_addr) ||
        b->orders[buddy_addr] != order )
      break;

    /* Merge! */
    ci_pio_buddy_free_list_remove(ni, b, buddy_addr);

    /* Continue to see if we can merge again, using the address of the first
     * of this buddy pair.
     */
    if( buddy_addr < addr )
      addr = buddy_addr;

    ++order;
  }

  DEBUG_ALLOC(ci_log("buddy - free %x merged into order %d", addr, order););

  /* Bung the block we've ended up with on the free list for the appropriate
   * order.
   */
  ci_pio_buddy_free_list_add(ni, b, order, addr);
}


/*! \cidoxg_end */
