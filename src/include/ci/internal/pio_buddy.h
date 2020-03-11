/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __CI_INTERNAL_PIO_BUDDY_H__
#define __CI_INTERNAL_PIO_BUDDY_H__


struct ci_pio_buddy_allocator;
struct ci_netif;


/*! Initialise a PIO buddy allocator. */
extern void ci_pio_buddy_ctor(ci_netif* ni, ci_pio_buddy_allocator* buddy,
                              unsigned pio_len);

/*! Destruct a PIO buddy allocator. */
extern void ci_pio_buddy_dtor(ci_netif* ni, ci_pio_buddy_allocator* buddy);

/*! Allocate a block from the PIO region.  Allocates a block of length
 * 1 << order and returns the offset into the PIO region of that block.
 * Returns less than 0 (errno) on failure.
 */
extern ci_int32 ci_pio_buddy_alloc(ci_netif* ni, ci_pio_buddy_allocator*,
                              ci_uint8 order);

/*! Free a block in the PIO region.  The provided offset should be an offset
 * into the region as returned from ci_pio_buddy_alloc.
 */
extern void ci_pio_buddy_free(ci_netif* ni, ci_pio_buddy_allocator*,
                              ci_int32 offset, ci_uint8 order);


#endif  /* __CI_INTERNAL_PIO_BUDDY_H__ */

