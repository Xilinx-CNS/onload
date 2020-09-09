/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains non-contiguous I/O buffers support.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 * Certain parts of the driver were implemented by
 *          Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 *          OKTET Labs Ltd, Russia,
 *          http://oktetlabs.ru, <info@oktetlabs.ru>
 *          by request of Solarflare Communications
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

#include <ci/efhw/iopage.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efrm/resource.h>
#include <ci/efrm/pd.h>
#include <onload/iobufset.h>
#include <onload/debug.h>
#include <onload/tcp_driver.h>
#include "ci/driver/kernel_compat.h"


/************** IO page operations ****************/

void oo_iobufset_kfree(struct oo_buffer_pages *pages)
{

  if( (void *)(pages + 1) != (void *)pages->pages )
    kfree(pages->pages);
  kfree(pages);
}

#ifdef OO_DO_HUGE_PAGES

#define OO_SHM_KEY_BASE 0xefab
#define OO_SHM_KEY(id) (OO_SHM_KEY_BASE | (id << 16))
#define OO_SHM_KEY_ID_MASK 0xffff
#define OO_SHM_NEXT_ID(id) ((id + 1) & OO_SHM_KEY_ID_MASK)

static int oo_bufpage_huge_alloc(struct oo_buffer_pages *p, int *flags)
{
  int shmid = -1;
  long uaddr;
  static unsigned volatile last_key_id = 0;
  unsigned start_key_id;
  unsigned id;
  int rc;
  const struct cred *orig_creds = NULL;
  struct cred *creds = NULL;
  struct vm_area_struct* vma;

  ci_assert( current->mm );

  /* sys_shmget(SHM_HUGETLB) need CAP_IPC_LOCK.
   * So, we give this capability and reset it back.
   * Since we modify per-thread capabilities,
   * there are no side effects. */
  if (~current_cred()->cap_effective.cap[0] & (1 << CAP_IPC_LOCK)) {
    creds = prepare_creds();
    if( creds != NULL ) {
      creds->cap_effective.cap[0] |= 1 << CAP_IPC_LOCK;
      orig_creds = override_creds(creds);
    }
  }

  /* Simultaneous access to last_key_id is possible, but we do not care.
   * It is just a hint where we should look for free ids. */
  start_key_id = last_key_id;

  for (id = OO_SHM_NEXT_ID(start_key_id);
       id != start_key_id;
       id = OO_SHM_NEXT_ID(id)) {
    shmid = efab_linux_sys_shmget(OO_SHM_KEY(id), HPAGE_SIZE,
                                  SHM_HUGETLB | IPC_CREAT | IPC_EXCL |
                                  SHM_R | SHM_W);
    if (shmid == -EEXIST)
      continue; /* try another id */
    if (shmid < 0) {
      if (shmid == -ENOMEM && !(*flags & OO_IOBUFSET_FLAG_HUGE_PAGE_FAILED) )
        *flags |= OO_IOBUFSET_FLAG_HUGE_PAGE_FAILED;
      rc = shmid;
      goto out;
    }
    last_key_id = id;
    break;
  }
  if (shmid < 0) {
    ci_log("%s: Failed to allocate huge page: EEXIST", __func__);
    last_key_id = 0; /* reset last_key_id */
    rc = shmid;
    goto out;
  }

  /* There is a somewhat intricate dance to be performed around the allocation
   * of SHM segments and their IDs.  We need shmat() to work at user-level on
   * the SHM segments for as long as the stack is not orphaned, but we also
   * need to delete the segments from the context of the IPC namespace in which
   * they were allocated.  To do the latter reliably, we delete the segments
   * almost immediately after allocating them.  Deleted segments can still be
   * attached as long as their reference-count never hits zero, which we
   * arrange.  Everything eventually gets cleaned up when we release the last
   * reference when freeing the oo_buffer_pages structure.  */

  /* Map the SHM segment into our address space. */
  uaddr = efab_linux_sys_shmat(shmid, NULL, 0);
  if (uaddr < 0) {
    rc = (int)uaddr;
    goto fail3;
  }

  mmap_write_lock(current->mm);

  /* Pin the pages. */
  rc = get_user_pages((unsigned long)uaddr, 1, FOLL_WRITE, &(p->pages[0]),
                      NULL);
  if (rc < 0) {
    mmap_write_unlock(current->mm);
    goto fail2;
  }

  /* Before we detach the segment, take out an extra reference to it. */
  vma = find_vma(current->mm, (unsigned long) uaddr);
  if (vma == NULL) {
    mmap_write_unlock(current->mm);
    /* This shouldn't be possible: we mapped the SHM successfully, so its vma
     * had better be where we expect it to be. */
    ci_assert(0);
    rc = -ENOENT;
    goto fail1;
  }
  vma->vm_ops->open(vma);

  /* We need to use the close vm_op to release the reference when we're
   * finished with it, but it won't be directly available in the context in
   * which we'll need it, so take a note of it now. */
  p->close = vma->vm_ops->close;
  p->shm_map_file = vma->vm_file;
  get_file(p->shm_map_file);

  mmap_write_unlock(current->mm);

  /* Now that we've ensured that the kernel will not free the SHM segment and
   * we have pinned its pages, we have no further use for the UL mapping. */
  rc = efab_linux_sys_shmdt((char __user *)uaddr);
  if (rc < 0)
    goto fail1;

  /* While we're still in the right namespace, delete the segment.  Anyone who
   * knows [shmid] can continue to attach to it. */
  efab_linux_sys_shmctl(shmid, IPC_RMID, NULL);

  p->shmid = shmid;
  rc = 0;
  goto out;

fail1:
  put_page(p->pages[0]);
fail2:
  efab_linux_sys_shmdt((char __user *)uaddr);
fail3:
  efab_linux_sys_shmctl(shmid, IPC_RMID, NULL);
out:
  if (orig_creds != NULL) {
    revert_creds(orig_creds);
    put_cred(creds);
  }
  return rc;
}

static void oo_bufpage_huge_free(struct oo_buffer_pages *p)
{
  struct vm_area_struct vma;

  ci_assert(p->shmid >= 0);
  ci_assert(current);

  /* Release the reference to the SHM segment.  The only interface that we have
   * to the function that does this is via the memory mapper, so we have to
   * mock up a little bit of state.  This is pretty unpleasant.  We zero-
   * initialise the vma to make any future kernel changes that break our
   * assumptions about this interface more apparent. */
  memset(&vma, 0, sizeof(vma));
  vma.vm_file = p->shm_map_file;
  p->close(&vma);
  fput(p->shm_map_file);

  put_page(p->pages[0]);
  oo_iobufset_kfree(p);
}
#endif
 

/************** Alloc/free page set ****************/

static void oo_iobufset_free_pages(struct oo_buffer_pages *pages)
{
#ifdef OO_DO_HUGE_PAGES
  if( pages->shmid >= 0 )
    oo_bufpage_huge_free(pages);
  else
#endif
  {
    int i;

    for (i = 0; i < pages->n_bufs; ++i)
      __free_pages(pages->pages[i], compound_order(pages->pages[i]));
    oo_iobufset_kfree(pages);
  }
}


static void* alloc_array_and_header(size_t header_bytes, size_t array_bytes,
                                    int gfp_flag, int elements_ptr_offset)
{
  size_t size = header_bytes + array_bytes;
  void* hdr;
  void* elements;

  if( size < PAGE_SIZE ) {
    hdr = kmalloc(size, gfp_flag);
    if( hdr == NULL )
      return NULL;
    elements = (char *)hdr + header_bytes;
  }
  else {
    /* Avoid multi-page allocations */
    hdr = kmalloc(header_bytes, gfp_flag);
    if( hdr == NULL )
      return NULL;
    /* This can still potentially be more than one page in the case of
     * oo_iobufset_init (the user called onload_zc_register_buffers) but the
     * kernel will cope fine with that and, unlike when Onload is creating its
     * own packet buffers, we can't assume a nice neat alignment such that
     * splitting cleverly is worthwhile */
    elements = kmalloc(array_bytes, gfp_flag);
    if( elements == NULL ) {
      kfree(hdr);
      return NULL;
    }
  }
  *(void**)((char*)hdr + elements_ptr_offset) = elements;
  return hdr;
}


static int oo_bufpage_init(struct oo_buffer_pages **pages_out,
                           int n_bufs, int gfp_flag)
{
  struct oo_buffer_pages *pages;

  pages = alloc_array_and_header(sizeof(struct oo_buffer_pages),
                                 n_bufs * sizeof(struct page *), gfp_flag,
                                 offsetof(struct oo_buffer_pages, pages));
  if( ! pages )
    return -ENOMEM;
  pages->n_bufs = n_bufs;
#ifdef OO_DO_HUGE_PAGES
  pages->shmid = -1;
#endif
  oo_atomic_set(&pages->ref_count, 1);
  *pages_out = pages;
  return 0;
}


static int oo_bufpage_alloc(struct oo_buffer_pages **pages_out,
                            int user_order, int low_order, int min_nic_order,
                            int *flags, int gfp_flag)
{
  struct oo_buffer_pages *pages;
  int n_bufs = 1 << (user_order - low_order);
  int i;
  int rc;

  if( low_order < min_nic_order )
    return -EMSGSIZE;

  rc = oo_bufpage_init(&pages, n_bufs, gfp_flag);
  if( rc )
    return rc;

#ifdef OO_DO_HUGE_PAGES
  if( (*flags & (OO_IOBUFSET_FLAG_HUGE_PAGE_TRY |
                 OO_IOBUFSET_FLAG_HUGE_PAGE_FORCE)) &&
      gfp_flag == GFP_KERNEL &&
      low_order == HPAGE_SHIFT - PAGE_SHIFT ) {
    if (oo_bufpage_huge_alloc(pages, flags) == 0) {
      *pages_out = pages;
      return 0;
    }
  }
  if( *flags & OO_IOBUFSET_FLAG_HUGE_PAGE_FORCE ) {
    ci_assert_equal(low_order, HPAGE_SHIFT - PAGE_SHIFT);
    return -ENOMEM;
  }
#endif

  if( low_order > 0 ) {
    /* __GFP_COMP hint suggests that the page allocator optimistically assume
     * that these pages are going to be compound, for faster allocation
     * __GFP_NOWARN is necessary because we properly handle high-order page
     * allocation failure by allocating pages one-by-one. */
    gfp_flag |= __GFP_COMP | __GFP_NOWARN;
  }

  for( i = 0; i < n_bufs; ++i ) {
    pages->pages[i] = alloc_pages_node(numa_node_id(), gfp_flag, low_order);
    if( pages->pages[i] == NULL ) {
      OO_DEBUG_VERB(ci_log("%s: failed to allocate page (i=%u) "
                           "user_order=%d page_order=%d",
                           __FUNCTION__, i, user_order, low_order));
      pages->n_bufs = i;
      oo_iobufset_free_pages(pages);
      return -ENOMEM;
    }
    memset(page_address(pages->pages[i]), 0, PAGE_SIZE << low_order);
  }
  
  *pages_out = pages;
  return 0;
}

/************** Alloc/free oo_buffer_pages structure ****************/

void oo_iobufset_pages_release(struct oo_buffer_pages *pages)
{
  if (oo_atomic_dec_and_test(&pages->ref_count))
    oo_iobufset_free_pages(pages);
}

int
oo_iobufset_pages_alloc(int nic_order, int min_nic_order, int *flags,
                        struct oo_buffer_pages **pages_out)
{
  int rc;
  int gfp_flag = (in_atomic() || in_interrupt()) ? GFP_ATOMIC : GFP_KERNEL;
  int order = nic_order - fls(EFHW_NIC_PAGES_IN_OS_PAGE) + 1;
  int min_order = min_nic_order - fls(EFHW_NIC_PAGES_IN_OS_PAGE) + 1;

  ci_assert(pages_out);
  ci_assert_ge(order, min_order);

#if CI_CFG_PKTS_AS_HUGE_PAGES
  if( *flags & OO_IOBUFSET_FLAG_HUGE_PAGE_FORCE ) {
# ifdef OO_DO_HUGE_PAGES
    rc = oo_bufpage_alloc(pages_out, order, order, min_order, flags,
                          gfp_flag);
# else
    rc = -ENOMEM;
# endif
  } else
#endif
  {
    int low_order = order;
    if( *flags & OO_IOBUFSET_FLAG_COMPOUND_PAGE_LIMIT )
      low_order -= 3;
    else if( *flags & OO_IOBUFSET_FLAG_COMPOUND_PAGE_NONE )
      low_order = 0;
    do {
      /* It is better to allocate high-order pages for many reasons:
       * - in theory, access to continious memory is faster;
       * - with high-order pages, we get small size for dma_addrs array
       *   and it fits into one or two pages.
       *
       * So, if one-compound-page-for-all failed, we try lower order in
       * hope to keep both dma_addrs array and the packet buffers themselves
       * to use not-very-high-order allocations.
       *
       * TODO: it may be useful to go through EF10 page orders:
       * x86: 9(hugepage),8,4,0
       * ppc: 4(max,=9nic),3(=8nic),0(=5nic)
       */
      rc = oo_bufpage_alloc(pages_out, order, low_order, min_order, flags,
                            gfp_flag);
      if( rc == 0 || low_order == 0 )
        break;
      low_order -= 3;
      if( low_order < 0 )
        low_order = 0;
    } while( 1 );
  }

  if( rc == -EMSGSIZE ) {
    LOG_E(ci_log("%s: ERROR: oo_bufpage_alloc() failed (%d), requested page "
                 "size order is larger than the minimum NIC page size order",
                 __FUNCTION__, rc));
  }

  OO_DEBUG_VERB(ci_log("%s: [%p] order %d", __FUNCTION__, *pages_out, order));

  return rc;
}

int oo_iobufset_init(struct oo_buffer_pages **pages_out, int n_bufs)
{
  int rc = oo_bufpage_init(pages_out, n_bufs, GFP_KERNEL);
  if( rc < 0 )
    return rc;
  /* Users calling this function own their own pages, so bodge the refcount
   * such that we never call oo_iobufset_free_pages() */
  oo_atomic_set(&(*pages_out)->ref_count, 2);
  return 0;
}


/************** Alloc/free iobufset structure ****************/

static void oo_iobufset_free_memory(struct oo_iobufset *rs)
{
  if( (void *)rs->dma_addrs != (void *)(rs + 1) )
    kfree(rs->dma_addrs);
  kfree(rs);

}
static void
oo_iobufset_resource_free(struct oo_iobufset *rs, int reset_pending)
{
  efrm_pd_dma_unmap(rs->pd, rs->pages->n_bufs,
                    EFHW_GFP_ORDER_TO_NIC_ORDER(
                                    compound_order(rs->pages->pages[0])),
                    &rs->dma_addrs[0], sizeof(rs->dma_addrs[0]),
                    &rs->buf_tbl_alloc, reset_pending);

  if (rs->pd != NULL)
    efrm_pd_release(rs->pd);
  oo_iobufset_pages_release(rs->pages);

  oo_iobufset_free_memory(rs);
}


void
oo_iobufset_resource_release(struct oo_iobufset *iobrs, int reset_pending)
{
  if (oo_atomic_dec_and_test(&iobrs->ref_count))
    oo_iobufset_resource_free(iobrs, reset_pending);
}

static void put_user_fake(uint64_t v, uint64_t *p)
{
  *p = v;
}

int
oo_iobufset_resource_alloc(struct oo_buffer_pages * pages, struct efrm_pd *pd,
                           struct oo_iobufset **iobrs_out, uint64_t *hw_addrs,
                           int reset_pending, int *page_order)
{
  struct oo_iobufset *iobrs;
  int rc;
  int gfp_flag = (in_atomic() || in_interrupt()) ? GFP_ATOMIC : GFP_KERNEL;
  int nic_order;
  void **addrs;
  unsigned int i;

  ci_assert(iobrs_out);
  ci_assert(pd);

  iobrs = alloc_array_and_header(sizeof(struct oo_iobufset),
                                 pages->n_bufs * sizeof(dma_addr_t), gfp_flag,
                                 offsetof(struct oo_iobufset, dma_addrs));
  if( ! iobrs )
    return -ENOMEM;

  oo_atomic_set(&iobrs->ref_count, 1);
  iobrs->pd = pd;
  iobrs->pages = pages;

  nic_order = EFHW_GFP_ORDER_TO_NIC_ORDER(compound_order(pages->pages[0]));

  addrs = kmalloc(sizeof(void *) * pages->n_bufs, gfp_flag);
  if (addrs == NULL)
  {
    rc = -ENOMEM;
    goto fail;
  }

  for (i = 0; i < pages->n_bufs; i++) {
    addrs[i] = page_address(pages->pages[i]);
  }

  rc = efrm_pd_dma_map(iobrs->pd, pages->n_bufs,
		       nic_order,
		       addrs, sizeof(addrs[0]),
		       &iobrs->dma_addrs[0], sizeof(iobrs->dma_addrs[0]),
		       hw_addrs, sizeof(hw_addrs[0]),
		       put_user_fake, &iobrs->buf_tbl_alloc, reset_pending, page_order);
  kfree(addrs);

  if( rc < 0 )
    goto fail;

  OO_DEBUG_VERB(ci_log("%s: [%p] %d pages", __FUNCTION__,
                       iobrs, iobrs->pages->n_bufs));

  efrm_resource_ref(efrm_pd_to_resource(pd));
  oo_atomic_inc(&pages->ref_count);
  *iobrs_out = iobrs;
  return 0;

fail:
  oo_iobufset_free_memory(iobrs);
  return rc;
}


int oo_iobufset_resource_remap_bt(struct oo_iobufset *iobrs, uint64_t *hw_addrs)
{
  return efrm_pd_dma_remap_bt(iobrs->pd, iobrs->pages->n_bufs,
                              compound_order(iobrs->pages->pages[0]),
                              &iobrs->dma_addrs[0], sizeof(iobrs->dma_addrs[0]),
                              hw_addrs, sizeof(hw_addrs[0]),
                              put_user_fake,
                              &iobrs->buf_tbl_alloc);
}
