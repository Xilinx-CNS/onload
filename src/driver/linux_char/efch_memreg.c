/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2012-2020 Xilinx, Inc. */
#include "efch.h"
#include <ci/efrm/vi_resource.h>
#include <ci/efch/op_types.h>
#include <ci/efrm/pd.h>
#include <ci/efrm/buffer_table.h>
#include "char_internal.h"
#include <ci/efrm/sysdep.h>
#include "driver/linux_resource/kernel_compat.h"

struct efch_memreg_area_params {
  struct efrm_bt_collection           bt_alloc;
  int                                 n_addrs;
  bool                                mapped;
  dma_addr_t                         *dma_addrs;
};

struct efch_memreg {
  struct efrm_pd                     *pd;
  int                                 n_pages;
  struct page                       **pages;
  int                                 nic_order;

  struct efch_memreg_area_params      middle;

#if (PAGE_SIZE != EFHW_NIC_PAGE_SIZE)
  struct efch_memreg_area_params      head;
  struct efch_memreg_area_params      tail;
#endif
};


static void efch_memreg_free(struct efch_memreg *mr)
{
  int i;

#if (PAGE_SIZE != EFHW_NIC_PAGE_SIZE)
  if (mr->head.mapped) {
    efrm_pd_dma_unmap(mr->pd, mr->head.n_addrs, 0,
                      mr->head.dma_addrs,
                      sizeof(mr->head.dma_addrs[0]),
                      &mr->head.bt_alloc, 0);
    vfree(mr->head.dma_addrs);
  }
#endif

  if (mr->middle.mapped) {
    efrm_pd_dma_unmap(mr->pd, mr->middle.n_addrs, mr->nic_order,
                      mr->middle.dma_addrs,
                      sizeof(mr->middle.dma_addrs[0]),
                      &mr->middle.bt_alloc, 0);
    vfree(mr->middle.dma_addrs);
  }

#if (PAGE_SIZE != EFHW_NIC_PAGE_SIZE)
  if (mr->tail.mapped) {
    efrm_pd_dma_unmap(mr->pd, mr->tail.n_addrs, 0,
                      mr->tail.dma_addrs,
                      sizeof(mr->tail.dma_addrs[0]),
                      &mr->tail.bt_alloc, 0);
    vfree(mr->tail.dma_addrs);
  }
#endif

  for (i = 0; i < mr->n_pages; ++i)
    put_page(mr->pages[i]);
  if (mr->pd != NULL)
    efrm_pd_release(mr->pd);
  vfree(mr->pages);
  kfree(mr);
}


static struct efch_memreg *efch_memreg_alloc(int n_pages)
{
  struct efch_memreg *mr = NULL;
  size_t bytes;

  if ((mr = kmalloc(sizeof(*mr), GFP_KERNEL)) == NULL)
    goto fail1;
  memset(mr, 0, sizeof(*mr));
  bytes = n_pages * sizeof(mr->pages[0]);
  if ((mr->pages = vmalloc(bytes)) == NULL)
    goto fail2;
  return mr;


 fail2:
  kfree(mr);
 fail1:
  return NULL;
}

/**********************************************************************/

static void put_user_64(uint64_t v, uint64_t *p)
{
  put_user(v, p);
}

static int efch_dma_map(struct efrm_pd *pd,
                        struct efch_memreg_area_params *ar,
                        int nic_order, void **addrs,
                        void **user_addrs, int user_addrs_stride,
                        void (*user_addr_put)(uint64_t, uint64_t *))
{
  int rc;

  ar->dma_addrs = vmalloc(ar->n_addrs *
                          sizeof(ar->dma_addrs[0]));
  if (ar->dma_addrs == NULL)
    return -ENOMEM;

  rc = efrm_pd_dma_map(pd, ar->n_addrs, nic_order,
                       addrs, sizeof(addrs[0]),
                       ar->dma_addrs,
                       sizeof(ar->dma_addrs[0]),
                       *user_addrs, user_addrs_stride,
                       user_addr_put, &ar->bt_alloc, 0, NULL);
  if (rc < 0) {
    EFCH_ERR("%s: ERROR: efrm_pd_dma_map failed (%d)", __FUNCTION__, rc);
    return rc;
  }

  ar->mapped = true;
  *user_addrs = (void *)((char *)*user_addrs +
                         (ar->n_addrs << nic_order) * user_addrs_stride);

  return 0;
}


/* Returns the maximal possible order of a compound page beginning at the page
 * containing the passed address. */
static inline unsigned addr_page_align_order(uint64_t addr)
{
  return (unsigned) __ffs(addr >> PAGE_SHIFT);
}


static int
memreg_rm_alloc(ci_resource_alloc_t* alloc_,
                ci_resource_table_t* priv_opt,
                efch_resource_t* ch_rs, int intf_ver_id)
{
  struct efch_memreg_alloc *alloc = &alloc_->u.memreg;
  struct efrm_resource *vi_or_pd = NULL;
  struct efch_memreg *mr;
  struct efrm_pd *pd;
  int rc, max_pages;
  uint64_t in_mem_end;
  uint64_t first_page;
  uint64_t last_page;
  unsigned comp_order;
  int this_comp_order;
  int comp_shift;
  unsigned long comp_size;
  unsigned long comp_mask;
  uint64_t head_begin;
  uint64_t head_end;
  uint64_t tail_begin;
  uint64_t tail_end;
  void *user_addrs;
  int user_addrs_stride;
  int max_addrs;
  unsigned int i;
  void **addrs;
  struct page **cur_page;
  int page_stride;

  /* Quietly align end to a NIC page size.  This is also done in
   * ef_memreg_alloc() so in most cases is unnecessary, but by also
   * doing it here we continue to support applications built against
   * older Onload versions that do not do this alignment themselves
   */
  in_mem_end = alloc->in_mem_ptr +
    CI_ALIGN_FWD(alloc->in_mem_bytes, EFHW_NIC_PAGE_SIZE);

  if ((alloc->in_mem_bytes == 0) ||
      ((alloc->in_mem_ptr & (EFHW_NIC_PAGE_SIZE - 1)) != 0) ||
      ((in_mem_end & (EFHW_NIC_PAGE_SIZE - 1)) != 0)) {
    rc = -EINVAL;
    goto fail1;
  }

  rc = efch_lookup_rs(alloc->in_vi_or_pd_fd, alloc->in_vi_or_pd_id,
                      EFRM_RESOURCE_VI, &vi_or_pd);
  if (rc < 0)
    rc = efch_lookup_rs(alloc->in_vi_or_pd_fd, alloc->in_vi_or_pd_id,
                        EFRM_RESOURCE_PD, &vi_or_pd);
  if (rc < 0) {
    EFCH_ERR("%s: ERROR: fd=%d id="EFCH_RESOURCE_ID_FMT" (%d)",
             __FUNCTION__, alloc->in_vi_or_pd_fd,
             EFCH_RESOURCE_ID_PRI_ARG(alloc->in_vi_or_pd_id), rc);
    goto fail1;
  }

  /* For convenience we allow caller to give us a VI instead of a PD.  But
   * what we really want is the PD.
   */
  if (vi_or_pd->rs_type == EFRM_RESOURCE_VI) {
    pd = efrm_vi_get_pd(efrm_to_vi_resource(vi_or_pd));
    efrm_resource_ref(efrm_pd_to_resource(pd));
    efrm_resource_release(vi_or_pd);
  } else {
    pd = efrm_pd_from_resource(vi_or_pd);
  }

  first_page = alloc->in_mem_ptr & PAGE_MASK;
  last_page = (in_mem_end + PAGE_SIZE - 1) & PAGE_MASK;
  max_pages = (last_page - first_page) >> PAGE_SHIFT;

  if ((mr = efch_memreg_alloc(max_pages)) == NULL) {
    EFCH_ERR("%s: ERROR: out of mem (max_pages=%d)",
             __FUNCTION__, max_pages);
    rc = -ENOMEM;
    goto fail2;
  }

  down_read(&current->mm->mmap_sem);
  for (mr->n_pages = 0; mr->n_pages < max_pages; mr->n_pages += rc) {
    rc = get_user_pages(first_page + mr->n_pages * PAGE_SIZE,
                        max_pages - mr->n_pages, FOLL_WRITE,
                        mr->pages + mr->n_pages, NULL);
    if (rc <= 0) {
      EFCH_ERR("%s: ERROR: get_user_pages(%d) returned %d",
               __FUNCTION__, max_pages - mr->n_pages, rc);
      break;
    }
  }
  up_read(&current->mm->mmap_sem);
  if (mr->n_pages < max_pages) {
    if (rc == 0)
      rc = -EFAULT;
    goto fail3;
  }

  /* Compound pages of order n can be programmed to the buffer table using
   * (1 << (n - m)) entries or order m for any m <= n.  (The NIC imposes
   * restrictions on admissible values of m, but we can resolve those later.)
   * The memreg API requires that we use a constant order for all entries in
   * the allocation, so the optimal order is the minimum over all pages in the
   * allocation.  Find that minimal order: let i index pages of size PAGE_SIZE,
   * and check the order for the first page in each compound page, incrementing
   * i to skip the tail pages.
   */
  comp_order = UINT_MAX;
  for (i = 0; comp_order > 0 && i < mr->n_pages; i += 1u << this_comp_order) {
    uint64_t page_addr = (uint64_t)(ci_uintptr_t)page_address(mr->pages[i]);
    this_comp_order = CI_MIN(compound_order(compound_head(mr->pages[i])),
                             addr_page_align_order(page_addr));
    comp_order = CI_MIN(comp_order, this_comp_order);
  }
  ci_assert_lt(comp_order, UINT_MAX);

  /* The API requires that the end of the allocation be NIC-page-aligned, and
   * we checked this earlier.  There are two further complications:
   *   1. On systems where PAGE_SIZE != EFHW_NIC_PAGE_SIZE, we have no
   *      guarantee that the end of the allocation is PAGE_SIZE-aligned.  We
   *      handle this later using mr->head and mr->tail.
   *   2. On all systems, there is no guarantee that the end of the allocation
   *      is comp_order-aligned.  For example, the caller could memreg a buffer
   *      backed by a huge page that is aligned to the huge page at the start
   *      but not at the end.  This appears to us here as a compound page of
   *      huge-page order, but that doesn't imply alignment of the end of the
   *      allocation.  We fix this case up now, by clamping comp_order to the
   *      effective order induced by the final full PAGE_SIZE-sized page in the
   *      allocation.  Any misalignment beyond that point is an instance of
   *      case 1 above.
   */
  comp_order = CI_MIN(comp_order, addr_page_align_order(in_mem_end));

  comp_shift = PAGE_SHIFT + comp_order;
  comp_size = 1UL << comp_shift;
  comp_mask = ~(comp_size - 1);
  mr->nic_order = EFHW_GFP_ORDER_TO_NIC_ORDER(comp_order);

  head_begin = alloc->in_mem_ptr;
  head_end = (alloc->in_mem_ptr + comp_size - 1) & comp_mask;
  tail_begin = in_mem_end & comp_mask;
  tail_end = in_mem_end;

  user_addrs = (void *)(ci_uintptr_t)alloc->in_addrs_out_ptr;
  user_addrs_stride = alloc->in_addrs_out_stride;

  if (tail_begin < head_end) {
    head_end = tail_end;
    tail_begin = 0;
    tail_end = 0;
  }

#if (PAGE_SIZE != EFHW_NIC_PAGE_SIZE)
  if (head_begin != head_end)
    mr->head.n_addrs = (head_end - head_begin) >> EFHW_NIC_PAGE_SHIFT;
  else
    mr->head.n_addrs = 0;
#endif

  if (head_end != tail_begin)
    mr->middle.n_addrs = (tail_begin - head_end) >> comp_shift;
  else
    mr->middle.n_addrs = 0;

#if (PAGE_SIZE != EFHW_NIC_PAGE_SIZE)
  if (tail_begin != tail_end)
    mr->tail.n_addrs = (tail_end - tail_begin) >> EFHW_NIC_PAGE_SHIFT;
  else
    mr->tail.n_addrs = 0;
#endif

#if (PAGE_SIZE != EFHW_NIC_PAGE_SIZE)
  max_addrs = (mr->head.n_addrs > mr->middle.n_addrs) ?
                  mr->head.n_addrs : mr->middle.n_addrs;
  max_addrs = (mr->tail.n_addrs > max_addrs) ?
                  mr->tail.n_addrs : max_addrs;
#else
  max_addrs = mr->middle.n_addrs;
#endif

  addrs = vmalloc(max_addrs * sizeof(*addrs));
  if (addrs == NULL) {
    rc = -ENOMEM;
    goto fail3;
  }

  cur_page = mr->pages;
  page_stride = sizeof(mr->pages[0]) << comp_order;

#if (PAGE_SIZE != EFHW_NIC_PAGE_SIZE)
  if (mr->head.n_addrs != 0) {
    void *ptr;

    ptr = page_address(*cur_page) + comp_size - (head_end - head_begin);
    cur_page = (struct page **)((char *)cur_page + page_stride);

    for (i = 0; i < mr->head.n_addrs; i++) {
      addrs[i] = ptr + i * EFHW_NIC_PAGE_SIZE;
    }

    rc = efch_dma_map(pd, &mr->head, 0, addrs,
                      &user_addrs, user_addrs_stride,
                      put_user_64);
    if (rc < 0)
      goto fail4;
  }
#endif

  if (mr->middle.n_addrs != 0) {

    for (i = 0; i < mr->middle.n_addrs; i++) {
      addrs[i] = page_address(*cur_page);
      cur_page = (struct page **)((char *)cur_page + page_stride);
    }

    rc = efch_dma_map(pd, &mr->middle, mr->nic_order, addrs,
                      &user_addrs, user_addrs_stride,
                      put_user_64);
    if (rc < 0)
      goto fail4;

  }

#if (PAGE_SIZE != EFHW_NIC_PAGE_SIZE)
  if (mr->tail.n_addrs != 0) {
    void *ptr;

    ptr = page_address(*cur_page);
    cur_page = (struct page **)((char *)cur_page + page_stride);

    for (i = 0; i < mr->tail.n_addrs; i++) {
      addrs[i] = ptr + i * EFHW_NIC_PAGE_SIZE;
    }

    rc = efch_dma_map(pd, &mr->tail, 0, addrs,
                      &user_addrs, user_addrs_stride,
                      put_user_64);
    if (rc < 0)
      goto fail4;
  }
#endif

  vfree(addrs);

  mr->pd = pd;
  ch_rs->rs_base = NULL;
  ch_rs->memreg = mr;
  /* ?? todo: alloc->something = something_else; */
  return 0;


 fail4:
  vfree(addrs);

#if (PAGE_SIZE != EFHW_NIC_PAGE_SIZE)
  if (mr->head.mapped) {
    efrm_pd_dma_unmap(pd, mr->head.n_addrs, 0,
                      mr->head.dma_addrs,
                      sizeof(mr->head.dma_addrs[0]),
                      &mr->head.bt_alloc, 0);
  }
#endif

  if (mr->middle.mapped) {
    efrm_pd_dma_unmap(pd, mr->middle.n_addrs, mr->nic_order,
                      mr->middle.dma_addrs,
                      sizeof(mr->middle.dma_addrs[0]),
                      &mr->middle.bt_alloc, 0);
  }

#if (PAGE_SIZE != EFHW_NIC_PAGE_SIZE)
  if (mr->tail.mapped) {
    efrm_pd_dma_unmap(pd, mr->tail.n_addrs, 0,
                      mr->tail.dma_addrs,
                      sizeof(mr->tail.dma_addrs[0]),
                      &mr->tail.bt_alloc, 0);
  }
#endif

 fail3:
  efch_memreg_free(mr);
 fail2:
  efrm_pd_release(pd);
 fail1:
  return rc;
}


static void memreg_rm_free(efch_resource_t *rs)
{
  efch_memreg_free(rs->memreg);
}


efch_resource_ops efch_memreg_ops = {
  .rm_alloc = memreg_rm_alloc,
  .rm_free = memreg_rm_free,
  .rm_mmap = NULL,
  .rm_nopage = NULL,
  .rm_dump = NULL,
  .rm_rsops = NULL,
  .rm_mmap_bytes = NULL,
};
