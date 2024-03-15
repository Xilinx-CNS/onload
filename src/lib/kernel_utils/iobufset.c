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
#include <kernel_utils/iobufset.h>
#include "ci/driver/kernel_compat.h"

/************** Alloc/free page set ****************/

void oo_iobufset_kfree(struct oo_buffer_pages *pages)
{
  if( (void *)(pages + 1) != (void *)pages->pages )
    kfree(pages->pages);
  kfree(pages);
}
EXPORT_SYMBOL(oo_iobufset_kfree);


static void oo_iobufset_free_pages(struct oo_buffer_pages *pages)
{
#ifdef OO_DO_HUGE_PAGES
  if( oo_hugetlb_page_valid(&pages->hugetlb_page) ) {
    /* We are likely called from a non-atomic context, e.g. in a work queue
     * or even on behalf of the UL process. However, play safe and check if
     * we can perform non-atomic operations. */
    bool atomic_context = in_atomic() || in_interrupt();
    oo_hugetlb_page_free(&pages->hugetlb_page, atomic_context);
  } else
#endif
  {
    int i;

    for (i = 0; i < pages->n_bufs; ++i)
      __free_pages(pages->pages[i], compound_order(pages->pages[i]));
  }

  oo_iobufset_kfree(pages);
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
  oo_hugetlb_page_reset(&pages->hugetlb_page);
#endif
  oo_atomic_set(&pages->ref_count, 1);
  *pages_out = pages;
  return 0;
}


static int oo_bufpage_alloc(struct oo_buffer_pages **pages_out,
                            int user_order, int low_order, int min_nic_order,
                            int *flags, int gfp_flag,
                            struct oo_hugetlb_allocator *hugetlb_alloc)
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

    if( hugetlb_alloc ) {
      rc = oo_hugetlb_page_alloc(hugetlb_alloc, &pages->hugetlb_page);
      if( ! rc ) {
        pages->pages[0] = pages->hugetlb_page.page;
        *pages_out = pages;
        return 0;
      }
      if( rc == -EINTR ) {
        oo_iobufset_kfree(pages);
        return rc;
      }
    }

    /* Failure path. */
    if( ! (*flags & OO_IOBUFSET_FLAG_HUGE_PAGE_FAILED) )
      *flags |= OO_IOBUFSET_FLAG_HUGE_PAGE_FAILED;
  }
  if( *flags & OO_IOBUFSET_FLAG_HUGE_PAGE_FORCE ) {
    EFRM_ASSERT(low_order == HPAGE_SHIFT - PAGE_SHIFT);
    oo_iobufset_kfree(pages);
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
      EFRM_ERR("%s: failed to allocate page (i=%u) "
                           "user_order=%d page_order=%d",
                           __FUNCTION__, i, user_order, low_order);
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
EXPORT_SYMBOL(oo_iobufset_pages_release);

int
oo_iobufset_pages_alloc(int nic_order, int min_nic_order, int *flags,
                        struct oo_buffer_pages **pages_out,
                        struct oo_hugetlb_allocator *hugetlb_alloc)
{
  int rc;
  int gfp_flag = (in_atomic() || in_interrupt()) ? GFP_ATOMIC : GFP_KERNEL;
  int order = nic_order - fls(EFHW_NIC_PAGES_IN_OS_PAGE) + 1;
  int min_order = min_nic_order - fls(EFHW_NIC_PAGES_IN_OS_PAGE) + 1;

  EFRM_ASSERT(pages_out);
  EFRM_ASSERT(order >= min_order);

#if CI_CFG_PKTS_AS_HUGE_PAGES
  if( *flags & OO_IOBUFSET_FLAG_HUGE_PAGE_FORCE ) {
# ifdef OO_DO_HUGE_PAGES
    rc = oo_bufpage_alloc(pages_out, order, order, min_order, flags,
                          gfp_flag, hugetlb_alloc);
# else
    rc = -ENOMEM;
# endif
  } else
#endif
  {
    /* It is better to allocate high-order pages for many reasons:
     * - in theory, access to continious memory is faster;
     * - with high-order pages, we get small size for dma_addrs array
     *   and it fits into one or two pages.
     *
     * However, using compound pages that are smaller than huge pages can
     * break assumptions in the kernel and cause problems, for example when
     * providing them to AF_XDP sockets. We only attempt to allocate this size,
     * and fall back to individual pages if this fails.
     */
    int low_order = order;
    if( *flags & OO_IOBUFSET_FLAG_COMPOUND_PAGE_NONE ||
        low_order < HPAGE_SHIFT - PAGE_SHIFT )
      low_order = 0;
    else
      low_order = HPAGE_SHIFT - PAGE_SHIFT;

    rc = oo_bufpage_alloc(pages_out, order, low_order, min_order, flags,
                          gfp_flag, hugetlb_alloc);

    if( rc != 0 && rc != -EINTR && low_order != 0 )
      rc = oo_bufpage_alloc(pages_out, order, 0, min_order, flags, gfp_flag,
                            hugetlb_alloc);
  }

  if( rc == -EMSGSIZE ) {
    EFRM_ERR("%s: ERROR: oo_bufpage_alloc() failed (%d), requested page "
                 "size order is larger than the minimum NIC page size order",
                 __FUNCTION__, rc);
  }

  return rc;
}
EXPORT_SYMBOL(oo_iobufset_pages_alloc);

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
EXPORT_SYMBOL(oo_iobufset_init);


/************** Alloc/free iobufset structure ****************/

static void oo_iobufset_free_memory(struct oo_iobufset *rs)
{
  if( (void *)rs->dma_addrs != (void *)(rs + 1) )
    kfree(rs->dma_addrs);
  kfree(rs);

}

void oo_iobufset_resource_release(struct oo_iobufset *rs, int reset_pending)
{
  efrm_pd_dma_unmap(rs->pd, rs->pages->n_bufs,
                    EFHW_GFP_ORDER_TO_NIC_ORDER(
                                    compound_order(rs->pages->pages[0])),
                    rs->free_addrs,
                    &rs->buf_tbl_alloc, reset_pending);

  if (rs->pd != NULL)
    efrm_pd_release(rs->pd);
  oo_iobufset_pages_release(rs->pages);

  oo_iobufset_free_memory(rs);
}
EXPORT_SYMBOL(oo_iobufset_resource_release);

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

  EFRM_ASSERT(iobrs_out);
  EFRM_ASSERT(pd);

  /* Request space for two arrays of n_bufs, then treat the first as
   * iobrs->dma_addrs and the second as iobrs->free_addrs. */
  iobrs = alloc_array_and_header(sizeof(struct oo_iobufset),
                                 2 * pages->n_bufs * sizeof(dma_addr_t),
                                 gfp_flag,
                                 offsetof(struct oo_iobufset, dma_addrs));
  if( ! iobrs )
    return -ENOMEM;
  iobrs->free_addrs = iobrs->dma_addrs + pages->n_bufs;

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
                       addrs, iobrs->dma_addrs, iobrs->free_addrs,
                       hw_addrs, sizeof(hw_addrs[0]),
                       put_user_fake, &iobrs->buf_tbl_alloc, reset_pending, page_order);
  kfree(addrs);

  if( rc < 0 )
    goto fail;

  efrm_resource_ref(efrm_pd_to_resource(pd));
  oo_atomic_inc(&pages->ref_count);
  *iobrs_out = iobrs;
  return 0;

fail:
  oo_iobufset_free_memory(iobrs);
  return rc;
}
EXPORT_SYMBOL(oo_iobufset_resource_alloc);


int oo_iobufset_resource_remap_bt(struct oo_iobufset *iobrs, uint64_t *hw_addrs)
{
  return efrm_pd_dma_remap_bt(iobrs->pd, iobrs->pages->n_bufs,
                              compound_order(iobrs->pages->pages[0]),
                              iobrs->dma_addrs, iobrs->free_addrs,
                              hw_addrs, sizeof(hw_addrs[0]),
                              put_user_fake,
                              &iobrs->buf_tbl_alloc);
}
EXPORT_SYMBOL(oo_iobufset_resource_remap_bt);
