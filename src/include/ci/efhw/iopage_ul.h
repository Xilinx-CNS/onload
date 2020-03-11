/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#ifndef __CI_EFHW_IOPAGE_UL_H__
#define __CI_EFHW_IOPAGE_UL_H__

#include <ci/compat.h>
#include <ci/tools/debug.h>
#include <ci/tools/sysdep.h>

#include <ci/efhw/common_sysdep.h> /* for dma_addr_t */

/*--------------------------------------------------------------------
 *
 * page reservation -- single address space
 *
 *--------------------------------------------------------------------*/

#define __va(phys)  (void*)(phys)
#define __pa(virt)  (ci_phys_addr_t)(virt)

struct efhw_page {
  ci_uintptr_t kva;
  ci_uintptr_t free_kva;
};

ci_inline int efhw_page_alloc(struct efhw_page* p) {
  CI_TEST((p->free_kva = (ci_uintptr_t)ci_alloc(CI_PAGE_SIZE * 2)) != 0);
  p->kva = CI_ALIGN_FWD(p->free_kva, CI_PAGE_SIZE);
  return p->kva ? 0 : -ENOMEM;
}

ci_inline int efhw_page_alloc_zeroed(struct efhw_page* p) {
  CI_TEST((p->free_kva = (ci_uintptr_t)ci_calloc(1, CI_PAGE_SIZE * 2)) != 0);
  p->kva = CI_ALIGN_FWD(p->free_kva, CI_PAGE_SIZE);
  return p->kva ? 0 : -ENOMEM;
}

ci_inline void efhw_page_free(struct efhw_page* p)
{ ci_assert(p); ci_free((void*)p->free_kva); }

ci_inline char* efhw_page_ptr(struct efhw_page* p)
{ return (char*)p->kva; }

ci_inline unsigned efhw_page_pfn(struct efhw_page* p)
{ return (unsigned)(p->kva >> CI_PAGE_SHIFT); }

ci_inline void efhw_page_mark_invalid(struct efhw_page* p)
{ p->kva = 0; }

ci_inline int efhw_page_is_valid(struct efhw_page* p)
{ return p->kva != 0; }

ci_inline void efhw_page_init_from_va(struct efhw_page* p, void* va)
{ p->kva = (ci_uintptr_t) va; }


/*--------------------------------------------------------------------
 *
 * struct efhw_iopage: A single page of memory.  Directly mapped in the
 * driver, and can be mapped to userlevel.  Can also be accessed by the
 * NIC.
 *
 *--------------------------------------------------------------------*/

struct efhw_iopage {
  struct efhw_page  p;
  dma_addr_t   dma_addr;
};


ci_inline dma_addr_t efhw_iopage_dma_addr(struct efhw_iopage* p)
{ return p->dma_addr; }

#define efhw_iopage_ptr(iop)		efhw_page_ptr(&(iop)->p)

/*--------------------------------------------------------------------
 *
 * struct efhw_iopages: A set of pages that are contiguous in physical memory.
 * Directly mapped in the driver, and can be mapped to userlevel.  Can also
 * be accessed by the NIC.
 *
 * NB. The O/S may be unwilling to allocate many, or even any of these.  So
 * only use this type where the NIC really needs a physically contiguous
 * buffer.
 *
 *--------------------------------------------------------------------*/

struct efhw_iopages {
  caddr_t	  kva;
  unsigned	  order;
  dma_addr_t   dma_addr;
};


ci_inline char* efhw_iopages_ptr(struct efhw_iopages* p)
{ return p->kva; }

ci_inline unsigned efhw_iopages_pfn(struct efhw_iopages* p, int page_i)
{ return (unsigned) (__pa(p->kva) >> CI_PAGE_SHIFT) + page_i; }

ci_inline dma_addr_t efhw_iopages_dma_addr(struct efhw_iopages* p, int page_i)
{ return p->dma_addr + (page_i << CI_PAGE_SHIFT); }

ci_inline unsigned efhw_iopages_size(struct efhw_iopages* p)
{ return 1u << (p->order + CI_PAGE_SHIFT); }


#endif /* __CI_EFHW_IOPAGE_UL_H__ */
