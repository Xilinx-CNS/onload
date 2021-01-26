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
#include <asm/tlbflush.h>


static int apply_pte(pte_t *pte,
/* pgtable_t parameter exists in linux<=4.19 */
#ifdef EFRM_PTE_FN_T_USES_PGTABLE
                     pgtable_t token,
#endif
                     unsigned long addr, void* data)
{
  ci_shmbuf_t* b = data;
  b->ptes[(addr - (unsigned long)b->addr) >> PAGE_SHIFT] = pte;
  return 0;
}

/* This is flush_tlb_all, not available from linux>=5.10 */
static void do_flush_tlb_all(void *info)
{
  __flush_tlb_all();
}
void ci_flush_tlb_all(void)
{
  on_each_cpu(do_flush_tlb_all, NULL, 1);
}

int ci_shmbuf_alloc(ci_shmbuf_t* b, unsigned n_pages, unsigned n_fault_pages)
{
  size_t i;
  int rc;

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

  for( i = 0; i < n_fault_pages; ++i ) {
    b->pages[i] = alloc_page(__GFP_ZERO | GFP_KERNEL);
    if( b->pages[i] == NULL ) {
      b->n_pages = i;
      ci_shmbuf_free(b);
      return -ENOMEM;
    }
  }

  for( ; i < n_pages; i++ )
    b->pages[i] = ZERO_PAGE(0);

  b->addr = vmap(b->pages, n_pages, VM_MAP, PAGE_KERNEL);
  if( ! b->addr ) {
    ci_shmbuf_free(b);
    return -ENOMEM;
  }

  /* It is unclear for me (Sasha) and Richard why it works, but it does.
   * In theory, we should use `init_mm` aka `init_task.active_mm` instead
   * of current->active_mm, see ON-12686.
   */
  rc = apply_to_page_range(current->active_mm, (unsigned long)b->addr,
                           n_pages * PAGE_SIZE, apply_pte, b);

  ci_assert_equal(rc, 0);
  if( rc != 0 ) {
    ci_shmbuf_free(b);
    return rc;
  }

  /* Reset all the other pages */
  for( i = n_fault_pages; i < n_pages; ++i )
    pte_clear(current->active_mm, (unsigned long)b->addr + i * PAGE_SIZE,
              b->ptes[i]);
  ci_flush_tlb_all();

  return 0;
}


void ci_shmbuf_free(ci_shmbuf_t* b)
{
  unsigned i;

  ci_assert(b);
  ci_assert(b->pages);

  if( b->addr )
    vunmap(b->addr);
  b->addr = NULL;

  for( i = 0; i < b->n_pages; ++i )
    if( b->pages[i] != ZERO_PAGE(0) )
      __free_page(b->pages[i]);

  vfree(b->pages);
  b->pages = NULL;
  vfree(b->ptes);
  b->ptes = NULL;
}


int ci_shmbuf_demand_page(ci_shmbuf_t* b, unsigned page_i)
{
  struct page* zero = ZERO_PAGE(0);

  ci_assert(b);
  ci_assert(b->addr);
  ci_assert(b->pages);
  ci_assert(page_i < b->n_pages);

  if( b->pages[page_i] == zero ) {
    struct page* p = alloc_page(__GFP_ZERO |
                                (in_interrupt() ? GFP_ATOMIC : GFP_KERNEL));
    if( p ) {
      if( cmpxchg(&b->pages[page_i], zero, p) == zero )
        *b->ptes[page_i] = mk_pte(p, PAGE_KERNEL);
      else
        __free_page(p);

      /* We do not need to call flush_tlb(), exploiting this bullet in
       * Intel's reference manual 4.10.4.3:
       *
       *   If a paging-structure entry is modified to change the P flag
       *   from 0 to 1, no invalidation is necessary. This is
       *   because no TLB entry or paging-structure cache entry is
       *   created with information from a paging-structure entry
       *   in which the P flag is 0.
       *
       * (as proposed by Richard Hughes).
       */
      return 0;
    }
    OO_DEBUG_VM(ci_log("%s: out of memory", __FUNCTION__));
    return -ENOMEM;
  }

  return 0;
}

/*! \cidoxg_end */
