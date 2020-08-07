/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */
#ifndef __TOOLS_CPLANE_MASK_H__
#define __TOOLS_CPLANE_MASK_H__

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* This type is somewhat similar to fd_set, but it has arbitrary size to
 * keep all the rows for mac and fwd tables. */
typedef uint64_t* cp_row_mask_t;

#define CP_ROW_MASK_ROW2IDX(id) ((id) >> 6)
#define CP_ROW_MASK_ROW2BIT(id) ((id) & ((1 << 6) - 1))
#define CP_ROW_MASK_SIZE2ENTRIES(size) (CP_ROW_MASK_ROW2IDX((size) - 1) + 1)

#define CP_ROW_MASK_IDX2ROW(idx) ((uint64_t)(idx) << 6)

static inline size_t
cp_row_mask_sizeof(cicp_mac_rowid_t size)
{
  return CP_ROW_MASK_SIZE2ENTRIES(size) * sizeof(uint64_t);
}
static inline cp_row_mask_t
cp_row_mask_alloc(cicp_mac_rowid_t size)
{
  size_t bytes = cp_row_mask_sizeof(size);
  cp_row_mask_t mask = malloc(bytes);
  ci_assert(mask); /* malloc never fails */
  memset(mask, 0, bytes);
  return mask;
}
static inline cp_row_mask_t
cp_row_mask_realloc(cp_row_mask_t mask, cicp_mac_rowid_t oldsize,
                    cicp_mac_rowid_t newsize)
{
  size_t old = cp_row_mask_sizeof(oldsize);
  size_t new = cp_row_mask_sizeof(newsize);
  if( old == new )
    return mask;
  cp_row_mask_t new_mask = realloc(mask, new);
  if( new > old )
    memset((char*) new_mask + old, 0, new - old);
  return new_mask;
}
static inline void
cp_row_mask_init(cp_row_mask_t mask, cicp_mac_rowid_t size)
{
  int entries = CP_ROW_MASK_SIZE2ENTRIES(size);
  memset(mask, 0, entries * sizeof(mask[0]));
}
static void inline
cp_row_mask_set(cp_row_mask_t mask, cicp_mac_rowid_t id)
{
  mask[CP_ROW_MASK_ROW2IDX(id)] |= 1ULL << CP_ROW_MASK_ROW2BIT(id);
}
static void inline
cp_row_mask_unset(cp_row_mask_t mask, cicp_mac_rowid_t id)
{
  mask[CP_ROW_MASK_ROW2IDX(id)] &= ~(1ULL << CP_ROW_MASK_ROW2BIT(id));
}
static bool inline
cp_row_mask_get(cp_row_mask_t mask, cicp_mac_rowid_t id)
{
  return mask[CP_ROW_MASK_ROW2IDX(id)] & (1ULL << CP_ROW_MASK_ROW2BIT(id));
}

/* Find the first set(or unset) bit in the entry, starting with the "start"
 * bit.  This function boils down to ffsll() call; the caller must
 * decrement the result by 1 before use.  Alike to ffsll(), 0 is returned
 * if there are no more bits in the entry.
 */
static inline cicp_mac_rowid_t
cp_row_mask_find_first_bit_in_entry(uint64_t entry, cicp_mac_rowid_t start, bool set)
{
  if( ! set )
    entry = ~entry;
  entry &=~ ((1ULL << start) - 1);
  return ffsll(entry);
}

static inline cicp_mac_rowid_t
cp_row_mask_iter_set(const cp_row_mask_t mask,
                     cicp_mac_rowid_t start, cicp_mac_rowid_t size, bool set)
{
  int i = CP_ROW_MASK_ROW2IDX(start);
  cicp_mac_rowid_t bit;
  cicp_mac_rowid_t init_mask = CP_ROW_MASK_ROW2BIT(start);

  if( start >= size )
    return CICP_MAC_ROWID_BAD;

  do {
    bit = cp_row_mask_find_first_bit_in_entry(mask[i], init_mask, set);
    init_mask = 0;
    if( bit > 0 ) {
      bit += CP_ROW_MASK_IDX2ROW(i);
      return bit <= size ? bit - 1 : CICP_MAC_ROWID_BAD;
    }
  } while( CP_ROW_MASK_IDX2ROW(++i) < size );
  return CICP_MAC_ROWID_BAD;
}

/* mask1 |= ~mask2 */
static inline void
cp_row_mask_do_or_not(cp_row_mask_t mask1, cp_row_mask_t mask2,
                       cicp_mac_rowid_t size)
{
  int entries = CP_ROW_MASK_SIZE2ENTRIES(size);
  int i;

  for( i = 0; i < entries; i++ )
    mask1[i] |= ~mask2[i];
}

#endif /* __TOOLS_CPLANE_MASK_H__ */
