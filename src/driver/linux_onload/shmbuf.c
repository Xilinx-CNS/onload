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


static int map_page(void* addr, struct page* page, pgprot_t prot)
{
  /* There's no interface for doing this, so we use ugly trickery. Might break
   * on kernel changes. */
  struct vm_struct area;
  struct page** pages = &page;
  area.addr = addr;
  /* We want one page, but map_vm_area() assumes there's a guard page too,
   * unless we specify the VM_NO_GUARD flag, which was added in Linux 4.0. */
#ifdef VM_NO_GUARD
  area.size = CI_PAGE_SIZE;
  area.flags = VM_NO_GUARD;
#else
  area.size = CI_PAGE_SIZE * 2;
  area.flags = 0;
#endif

  return map_vm_area(&area, prot,
#ifdef EFRM_MAP_VM_AREA_TAKES_PAGESTARSTAR
                     pages
#else
                     /* Kernels before 3.17 have an extra degree of indirection
                      * and will advance [pages] by the number of pages mapped.
                      */
                     &pages
#endif
                     );
}


int ci_shmbuf_alloc(ci_shmbuf_t* b, unsigned n_pages, unsigned n_fault_pages)
{
  size_t i;

  ci_assert(b);
  ci_assert_le(n_fault_pages, n_pages);
  ci_assert_ge(n_fault_pages, 1);

  b->n_pages = n_pages;
  b->base = NULL;
  b->pages = vzalloc(n_pages * sizeof(b->pages[0]));
  if( ! b->pages )
    return -ENOMEM;

  for( i = 0; i < n_fault_pages; ++i ) {
    b->pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if( ! b->pages[i] ) {
      ci_shmbuf_free(b);
      return -ENOMEM;
    }
  }

  /* vmalloc.c has no suitable interface for separate allocation of a VMA and
   * mapping of pages in to it, so we allocate-and-map the same page to get a
   * large enough VMA then unmap most of it */
  for( i = n_fault_pages; i < n_pages; ++i )
    b->pages[i] = b->pages[0];
  b->base = vmap(b->pages, n_pages, 0, PAGE_KERNEL);
  if( ! b->base ) {
    ci_shmbuf_free(b);
    return -ENOMEM;
  }
  if( n_pages > n_fault_pages ) {
    unsigned long first_dummy_page = (unsigned long) b->base +
                                     CI_PAGE_SIZE * n_fault_pages;
    unsigned long dummy_pages_len = (n_pages - n_fault_pages) * CI_PAGE_SIZE;
#ifdef EFRM_HAVE_UNMAP_KERNEL_RANGE /* exported from 3.16 */
    unmap_kernel_range(first_dummy_page, dummy_pages_len);
#else
    /* We'd like to use unmap_kernel_range() here, which deals with the
     * necessary flushing itself, but it's not exported on older kernels
     * (RHEL7) so we need to do the separate steps ourselves.
     */
    flush_cache_vunmap(first_dummy_page, first_dummy_page + dummy_pages_len);
    unmap_kernel_range_noflush(first_dummy_page, dummy_pages_len);
    /* The kernel only flushes mappings lazily, so we want to force a flush
     * here to be sure our unmap is visible everywhere.
     */
    vm_unmap_aliases();
#endif
  }

  for( i = n_fault_pages; i < n_pages; ++i )
    b->pages[i] = NULL;

  return 0;
}


void ci_shmbuf_free(ci_shmbuf_t* b)
{
  unsigned i;

  ci_assert(b);
  ci_assert(b->base);
  ci_assert(b->pages);

  for( i = 0; i < b->n_pages; ++i )
    if( b->pages[i] )
      __free_page(b->pages[i]);

  vunmap(b->base);
  vfree(b->pages);
  b->base = NULL;
  b->pages = NULL;
}


int ci_shmbuf_demand_page(ci_shmbuf_t* b, unsigned page_i,
			       ci_irqlock_t* lock)
{
  ci_assert(b);
  ci_assert(b->base);
  ci_assert(b->pages);
  ci_assert(page_i < b->n_pages);

  if( ! b->pages[page_i] ) {
    struct page* p = alloc_page(__GFP_ZERO |
                                (in_interrupt() ? GFP_ATOMIC : GFP_KERNEL));
    if( p ) {
      ci_irqlock_state_t lock_flags;
      ci_irqlock_lock(lock, &lock_flags);
      if( ! b->pages[page_i] ) {
        void* addr = (char*)b->base + page_i * CI_PAGE_SIZE;
        /* In general, map_page() can make GFP_KERNEL allocations.  However,
         * it only does this if there are holes in the page tables, and we know
         * that there aren't any because we populated the entire mapping when
         * we allocated the shmbuf. */
        if( map_page(addr, p, PAGE_KERNEL) ) {
          ci_irqlock_unlock(lock, &lock_flags);
          __free_page(p);
          OO_DEBUG_VM(ci_log("%s: map failed", __FUNCTION__));
          return -ENOMEM;
        }
        b->pages[page_i] = p;
        p = NULL;
      }
      ci_irqlock_unlock(lock, &lock_flags);
      if( p )
        __free_page(p);
      return 0;
    }
    OO_DEBUG_VM(ci_log("%s: out of memory", __FUNCTION__));
    return -ENOMEM;
  }

  return 0;
}

/*! \cidoxg_end */
