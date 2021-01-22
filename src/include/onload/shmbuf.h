/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file 
** <L5_PRIVATE L5_SOURCE>
** \author  ok_sasha
**  \brief  shmbuf Linux support
**     $Id$
**   \date  2007/07
**    \cop  (c) Solaraflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver  */
 
#ifndef __CI_DRIVER_EFAB_SHMBUF_H__
#define __CI_DRIVER_EFAB_SHMBUF_H__

#include <ci/driver/internal.h>

/*--------------------------------------------------------------------
 *
 * ci_shmbuf_t: A (potentially) large buffer that is contiguous
 * in the kernel address space.  It may be mapped to userlevel, where it is
 * contiguous.  On some platforms, pages may be allocated on demand.
 *
 * On Linux, pages are allocated on-demand.
 *
 *--------------------------------------------------------------------*/

typedef struct {
  size_t        n_pages;
  struct page** pages;
  pte_t**       ptes;
  void*         addr;
} ci_shmbuf_t;


extern int
ci_shmbuf_alloc(ci_shmbuf_t* b, unsigned n_pages, unsigned n_fault_pages);
extern void ci_shmbuf_free(ci_shmbuf_t* b);

ci_inline unsigned ci_shmbuf_size(ci_shmbuf_t* b)
{ return b->n_pages << CI_PAGE_SHIFT; }

ci_inline void* __ci_shmbuf_ptr(ci_shmbuf_t* b, unsigned off) {
  return (char*)b->addr + off;
}

/* Asserts that accessing the shmbuf at the given offset (using
** __ci_shmbuf_ptr above) is safe.
*/
ci_inline void
ci_shmbuf_assert_access_okay(ci_shmbuf_t* b, unsigned off, unsigned size)
{
  unsigned end_off __attribute__((unused)) = off + size - 1;
  /*
  ci_log("checking validity of %x", off >> CI_PAGE_SHIFT);
  ci_log("off %x size %x bufsize %x",
          off, size, (b->n_pages << CI_PAGE_SHIFT));
  ci_log("valid %d %d,",
	  efhw_page_is_valid(&b->pages[off >> CI_PAGE_SHIFT]),
	  efhw_page_is_valid(&b->pages[end_off >> CI_PAGE_SHIFT])); 
  ci_log("eptr %p %p",__ci_shmbuf_ptr(b, off) + size - 1, __ci_shmbuf_ptr(b, end_off));
  */
  /* The region lies within the shmbuf. */
  ci_assert_le(off + size, b->n_pages << CI_PAGE_SHIFT);
  /* Pages have been allocated (assumes size <= CI_PAGE_SIZE). */
  ci_assert(b->pages[off >> CI_PAGE_SHIFT]);
  ci_assert(b->pages[end_off >> CI_PAGE_SHIFT]);
}

ci_inline char* ci_shmbuf_ptr(ci_shmbuf_t* b, unsigned off) {
  ci_shmbuf_assert_access_okay(b, off, 1);
  return __ci_shmbuf_ptr(b, off);
}

extern int ci_shmbuf_demand_page(ci_shmbuf_t* b, unsigned page_i);

ci_inline struct page* ci_shmbuf_page(ci_shmbuf_t* b, unsigned offset)
{
  ci_assert(CI_OFFSET(offset, CI_PAGE_SIZE) == 0);
  offset >>= CI_PAGE_SHIFT;
  ci_assert(offset < b->n_pages);
  return b->pages[offset];
}

ci_inline int ci_shmbuf_mmap(ci_shmbuf_t* b, unsigned offset,
			     unsigned long* bytes,
			     struct vm_area_struct *vma,
			     int* map_num, unsigned long* p_offset)
{
  unsigned n = ci_shmbuf_size(b) - offset;
  n = CI_MIN(n, *bytes);
  *bytes -= n;
  ++*map_num;
  *p_offset += n;
  return 0;
}

#endif /* __CI_DRIVER_EFAB_SHMBUF_H__ */

/*! \cidoxg_end */
