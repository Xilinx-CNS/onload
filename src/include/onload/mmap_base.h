/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2019 Xilinx, Inc. */
#ifndef __ONLOAD_MMAP_BASE_H__
#define __ONLOAD_MMAP_BASE_H__

/*********************************************************************
***************************** Memory maps ****************************
*********************************************************************/

/* Mmap offset is multiple of PAGE_SIZE.  Mmaps with different offsets may
 * "virtually overlap", i.e. the "offset" number can be considered as
 * opaque ID for a given memory area.
 *
 * High bits of the offset is used to define "mapping type"
 * and the rest is parsed depending on the "type".
 */

/* Mapping types.  The low OO_MMAP_TYPE_SHIFT bits are available for use by
 * each mapping type. */
#define OO_MMAP_TYPE_NETIF        0
#define OO_MMAP_TYPE_CPLANE       1
#ifdef __x86_64__
# define OO_MMAP_TYPE_DSHM        2
#endif

#define OO_MMAP_TYPE_MASK        0x3
#define OO_MMAP_TYPE_WIDTH       2
#define OO_MMAP_TYPE_SHIFT       CI_PAGE_SHIFT
#define OO_MMAP_ID_SHIFT         (OO_MMAP_TYPE_WIDTH + OO_MMAP_TYPE_SHIFT)
#define OO_MMAP_TYPE(offset) \
    (((offset) >> OO_MMAP_TYPE_SHIFT) & OO_MMAP_TYPE_MASK)

static inline uint64_t
OO_MMAP_OFFSET_TO_MAP_ID(off_t offset)
{
  return (uint64_t) offset >> OO_MMAP_ID_SHIFT;
}

static inline off_t
OO_MMAP_MAKE_OFFSET(uint8_t map_type, uint64_t map_id)
{
  off_t offset = map_id << OO_MMAP_ID_SHIFT;
  offset |= ((off_t) map_type) << OO_MMAP_TYPE_SHIFT;
  return offset;
}

#endif /* __ONLOAD_MMAP_BASE_H__ */
