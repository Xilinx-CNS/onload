/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */
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
  
/*! \cidoxg_driver_linux */
 
#include <onload/debug.h>
#include <onload/shmbuf.h>


int ci_shmbuf_alloc(ci_shmbuf_t* b, unsigned n_pages, unsigned n_fault_pages)
{
  size_t i;

  ci_assert(b);
  ci_assert_le(n_fault_pages, n_pages);
  ci_assert_ge(n_fault_pages, 1);

  b->n_pages = n_pages;
  b->pages = vzalloc(n_pages * sizeof(b->pages[0]));
  if( ! b->pages )
    return -ENOMEM;
  b->ptes = vzalloc(n_pages * sizeof(b->ptes[0]));
  if( ! b->ptes ) {
    vfree(b->pages);
    return -ENOMEM;
  }

  b->vm = alloc_vm_area(n_pages << PAGE_SHIFT, b->ptes);
  if( ! b->vm ) {
    ci_shmbuf_free(b);
    return -ENOMEM;
  }

  for( i = 0; i < n_fault_pages; ++i )
    if( ci_shmbuf_demand_page(b, i) != 0 ) {
      ci_shmbuf_free(b);
      return -ENOMEM;
    }

  return 0;
}


void ci_shmbuf_free(ci_shmbuf_t* b)
{
  unsigned i;

  ci_assert(b);
  ci_assert(b->pages);

  if( b->vm )
    free_vm_area(b->vm);
  b->vm = NULL;

  for( i = 0; i < b->n_pages; ++i )
    if( b->pages[i] )
      __free_page(b->pages[i]);

  vfree(b->pages);
  b->pages = NULL;
  vfree(b->ptes);
  b->ptes = NULL;
}


int ci_shmbuf_demand_page(ci_shmbuf_t* b, unsigned page_i)
{
  ci_assert(b);
  ci_assert(b->vm);
  ci_assert(b->pages);
  ci_assert(page_i < b->n_pages);

  if( ! b->pages[page_i] ) {
    struct page* p = alloc_page(__GFP_ZERO |
                                (in_interrupt() ? GFP_ATOMIC : GFP_KERNEL));
    if( p ) {
      if( cmpxchg(&b->pages[page_i], NULL, p) == 0 )
        *b->ptes[page_i] = mk_pte(p, PAGE_KERNEL);
      else
        __free_page(p);
      return 0;
    }
    OO_DEBUG_VM(ci_log("%s: out of memory", __FUNCTION__));
    return -ENOMEM;
  }

  return 0;
}

/*! \cidoxg_end */
