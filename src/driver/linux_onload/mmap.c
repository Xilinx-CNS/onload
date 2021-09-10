/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file driver.c mmap file operation--for onload and sfc_char driver
** <L5_PRIVATE L5_SOURCE>
** \author  slp
**  \brief  Package - driver/linux	Linux driver support
**     $Id$
**   \date  2002/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_driver_linux */


/*--------------------------------------------------------------------
 *
 * Compile time assertions for this file
 *
 *--------------------------------------------------------------------*/

#define __ci_driver_shell__	/* implements driver to kernel interface */

/*--------------------------------------------------------------------
 *
 * CI headers
 *
 *--------------------------------------------------------------------*/

#include <onload/linux_mmap.h>
#include <onload/debug.h>
#include <onload/tcp_helper_fns.h>
#include <onload/mmap.h>
#include <onload/dshm.h>
#include <ci/driver/kernel_compat.h>
#include <onload/cplane_driver.h>
#include <ci/efch/mmap.h>
#include <ci/efrm/vi_resource_manager.h>


/****************************************************************************
 *
 * Page faulting
 *
 ****************************************************************************/

/*! map offset in shared data to physical page frame number */
static vm_fault_t
tcp_helper_rm_nopage_mem(tcp_helper_resource_t* trs,
                         struct vm_area_struct *vma, unsigned long offset)
{
  ci_netif* ni = &trs->netif;
  int rc;

  OO_DEBUG_SHM(ci_log("%s: %u", __FUNCTION__, trs->id));

  /* NB: the order in which offsets are compared against shared memory
         areas must be the same order that is used to allocate those offsets in
         allocate_netif_resources() above.  Currently there's only a single
         region.
  */

  rc = oo_shmbuf_fault(&ni->shmbuf, vma, offset);
  if( rc == 0 )
    return VM_FAULT_NOPAGE;

  OO_DEBUG_SHM(ci_log("%s: offset %lx out of range", __FUNCTION__, offset));
  return VM_FAULT_SIGBUS;
}


static struct page*
tcp_helper_rm_nopage_timesync(tcp_helper_resource_t* trs,
                              struct vm_area_struct *vma,
                              unsigned long offset)
{
  OO_DEBUG_SHM(ci_log("%s: %u", __FUNCTION__, trs->id));

  return efab_tcp_driver.timesync_page;
}


static struct page*
tcp_helper_rm_nopage_iobuf(tcp_helper_resource_t* trs, struct vm_area_struct *vma,
                           unsigned long offset)
{
  ci_netif* ni = &trs->netif;
  int intf_i;

  OO_DEBUG_SHM(ci_log("%s: %u", __FUNCTION__, trs->id));

  /* VIs (descriptor rings and event queues). */
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    struct tcp_helper_nic* trs_nic = &trs->nic[intf_i];
    int i;
    int num_vis = ci_netif_num_vis(ni);
    for( i = 0; i < num_vis; ++i ) {
      unsigned bytes = trs_nic->thn_vi_mmap_bytes[i];
      if( offset + CI_PAGE_SIZE <= bytes )
        return efab_vi_resource_nopage(trs_nic->thn_vi_rs[i], vma, offset,
                                       bytes);
      offset -= bytes;
    }
  }
  OO_DEBUG_SHM(ci_log("%s: %u offset %ld too great",
                      __FUNCTION__, trs->id, offset));
  return NULL;
}

static struct page*
tcp_helper_rm_nopage_pkts(tcp_helper_resource_t* trs, struct vm_area_struct *vma,
                          unsigned long offset)
{
  int bufset_id = offset / (CI_CFG_PKT_BUF_SIZE * PKTS_PER_SET);
  ci_netif* ni = &trs->netif;

  if( ! ni->pkt_bufs[bufset_id] ) {
    OO_DEBUG_ERR(ci_log("%s: %u BAD offset=%lx bufset_id=%d",
                        __FUNCTION__, trs->id, offset, bufset_id));
    return NULL;
  }

  offset -= bufset_id * CI_CFG_PKT_BUF_SIZE * PKTS_PER_SET;
  return pfn_to_page(oo_iobufset_pfn(ni->pkt_bufs[bufset_id], offset));
}

static vm_fault_t
tcp_helper_rm_nopage(tcp_helper_resource_t* trs, struct vm_area_struct *vma,
                     int map_id, unsigned long offset,
                     struct page** page_out)
{
  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, 0);

  OO_DEBUG_SHM(ci_log("%s: %u", __FUNCTION__, trs->id));

  switch( map_id ) {
    case CI_NETIF_MMAP_ID_STATE:
      return tcp_helper_rm_nopage_mem(trs, vma, offset);
    case CI_NETIF_MMAP_ID_TIMESYNC:
      *page_out = tcp_helper_rm_nopage_timesync(trs, vma, offset);
      return *page_out == NULL ? VM_FAULT_SIGBUS : 0;
    case CI_NETIF_MMAP_ID_IOBUFS:
      *page_out = tcp_helper_rm_nopage_iobuf(trs, vma, offset);
      return *page_out == NULL ? VM_FAULT_SIGBUS : 0;
    case CI_NETIF_MMAP_ID_IO:
    case CI_NETIF_MMAP_ID_EFCT_SHM:
#if CI_CFG_PIO
    case CI_NETIF_MMAP_ID_PIO:
#endif
#if CI_CFG_CTPIO
    case CI_NETIF_MMAP_ID_CTPIO:
#endif
      OO_DEBUG_SHM(ci_log("%s: map_id=%d. Debugger?", __FUNCTION__, map_id));
      /* These mappings are always present, and so a page fault should never
       * come down this path, but ptrace() can get us here. */
      return VM_FAULT_SIGBUS;
    default:
      ci_assert_ge(map_id, CI_NETIF_MMAP_ID_PKTS);
      *page_out = tcp_helper_rm_nopage_pkts(trs, vma,
                                       offset +
                                       (map_id - CI_NETIF_MMAP_ID_PKTS) *
                                       CI_CFG_PKT_BUF_SIZE * PKTS_PER_SET);
      return *page_out == NULL ? VM_FAULT_SIGBUS : 0;
  }

}


static vm_fault_t
__vm_op_nopage(tcp_helper_resource_t* trs, struct vm_area_struct* vma,
               unsigned long address, struct page** page_out)
{
  int map_id = OO_MMAP_OFFSET_TO_MAP_ID(VMA_OFFSET(vma));
  vm_fault_t rc = tcp_helper_rm_nopage(trs, vma, map_id,
                                       address - vma->vm_start,
                                       page_out);

  if( *page_out == NULL )
    return rc;

  get_page(*page_out);

  OO_DEBUG_TRAMP(ci_log("%s: %u vma=%p sz=%lx pageoff=%lx id=%"CI_PRIx64,
                 __FUNCTION__, trs->id, vma, vma->vm_end - vma->vm_start,
                 (address - vma->vm_start) >> CI_PAGE_SHIFT,
                 OO_MMAP_OFFSET_TO_MAP_ID(VMA_OFFSET(vma))));

  return rc;
}


static vm_fault_t vm_op_fault(
#ifdef EFRM_HAVE_OLD_FAULT
                       struct vm_area_struct *vma,
#endif
                       struct vm_fault *vmf) {
#ifndef EFRM_HAVE_OLD_FAULT
  struct vm_area_struct *vma = vmf->vma;
#endif
  tcp_helper_resource_t* trs = (tcp_helper_resource_t*) vma->vm_private_data;
  unsigned long address = VM_FAULT_ADDRESS(vmf);
  vm_fault_t rc = 0;

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, 0);

  rc = __vm_op_nopage(trs, vma, address, &vmf->page);

  if( rc == VM_FAULT_SIGBUS && ~current->flags & PF_DUMPCORE ) {
    /* We don't generally expect to fail to map, but there are legitimate
     * cases where this occurs, such as the application using
     * mlockall(MCL_FUTURE) resulting in the kernel trying to fault in pages
     * that would back not yet allocated resources.  Because of this we only
     * log failure as a debug message.
     */
    OO_DEBUG_TRAMP(ci_log("%s: %u vma=%p sz=%lx pageoff=%lx id=%"CI_PRIx64
                          " FAILED",
                          __FUNCTION__, trs->id,
                          vma, vma->vm_end - vma->vm_start,
                          (address - vma->vm_start) >> CI_PAGE_SHIFT,
                          OO_MMAP_OFFSET_TO_MAP_ID(VMA_OFFSET(vma))));
  }

  return rc;
}


static struct vm_operations_struct vm_ops = {
  .fault = vm_op_fault,
};


/****************************************************************************
 *
 * mmap: map userspace onto either pinned down memory or PCI space
 *
 ****************************************************************************/

static int tcp_helper_rm_mmap_mem(tcp_helper_resource_t* trs,
                                  unsigned long bytes,
                                  struct vm_area_struct* vma)
{
  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx", __func__, trs->id, bytes));

  /* Let's fault in the first chunk right now, and defer the socket states
   * to the fault handler.
   */
  if( bytes == oo_shmbuf_size(&trs->netif.shmbuf) )
    return oo_shmbuf_fault(&trs->netif.shmbuf, vma, 0);
  else
    return -EFAULT;
}


static int tcp_helper_rm_mmap_timesync(tcp_helper_resource_t* trs,
                                       unsigned long bytes,
                                       struct vm_area_struct* vma, int is_writable)
{
  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx", __func__, trs->id, bytes));

  if( is_writable )
    return -EPERM;

  bytes -= PAGE_SIZE;
  ci_assert_equal(bytes, 0);

  return 0;
}


static int mmap_all_vis(tcp_helper_resource_t* trs, int intf_i,
                                 unsigned long *bytes,
                                 struct vm_area_struct* vma, int *map_num,
                                 unsigned long *offset, int map_type)
{
  int vi_i;
  int n = ci_netif_num_vis(&trs->netif);
  for( vi_i = 0; vi_i < n; ++vi_i ) {
    int rc = efab_vi_resource_mmap(trs->nic[intf_i].thn_vi_rs[vi_i],
                                   bytes, vma, map_num, offset, map_type);
    if( rc < 0 )
      return rc;
  }
  return 0;
}


static int tcp_helper_rm_mmap_io(tcp_helper_resource_t* trs,
                                 unsigned long bytes,
                                 struct vm_area_struct* vma)
{
  int rc, intf_i;
  int map_num = 0;
  unsigned long offset = 0;
  ci_netif* ni;

  ni = &trs->netif;
  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx", __func__, trs->id, bytes));

  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
    rc = mmap_all_vis(trs, intf_i, &bytes, vma, &map_num, &offset,
                      EFCH_VI_MMAP_IO);
    if( rc < 0 )
      return rc;
  }
  ci_assert_equal(bytes, 0);

  return 0;
}


#if CI_CFG_PIO
static int tcp_helper_rm_mmap_pio(tcp_helper_resource_t* trs,
                                  unsigned long bytes,
                                  struct vm_area_struct* vma)
{
  int rc, intf_i;
  int map_num = 0;
  unsigned long offset = 0;

  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx", __func__, trs->id, bytes));

  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
    if( trs->nic[intf_i].thn_pio_io_mmap_bytes != 0 ) {
      rc = efab_vi_resource_mmap(tcp_helper_vi(trs, intf_i), &bytes, vma,
                                 &map_num, &offset, EFCH_VI_MMAP_PIO);
      if( rc < 0 )
        return rc;
    }
  }
  ci_assert_equal(bytes, 0);

  return 0;
}
#endif

#if CI_CFG_CTPIO
static int tcp_helper_rm_mmap_ctpio(tcp_helper_resource_t* trs,
                                    unsigned long bytes,
                                    struct vm_area_struct* vma)
{
  int rc, intf_i;
  int map_num = 0;
  unsigned long offset = 0;

  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx", __func__, trs->id, bytes));

  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
    if( trs->nic[intf_i].thn_ctpio_io_mmap_bytes != 0 ) {
      rc = efab_vi_resource_mmap(tcp_helper_vi(trs, intf_i), &bytes, vma,
                                 &map_num, &offset, EFCH_VI_MMAP_CTPIO);
      if( rc < 0 )
        return rc;
    }
  }
  ci_assert_equal(bytes, 0);

  return 0;
}
#endif


#if CI_CFG_TCP_OFFLOAD_RECYCLER
static int tcp_helper_rm_mmap_plugin(tcp_helper_resource_t* trs,
                                     unsigned long bytes,
                                     struct vm_area_struct* vma)
{
  int rc, intf_i;
  int map_num = 0;
  unsigned long offset = 0;

  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx", __func__, trs->id, bytes));

  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
    unsigned long n = PAGE_SIZE;
    if( ! trs->netif.nic_hw[intf_i].plugin )
      continue;
    if( ! trs->netif.nic_hw[intf_i].plugin_io ) {
      OO_DEBUG_ERR(ci_log("%s: mapping CSR region when plugin doesn't use it",
                          __FUNCTION__));
      return -EINVAL;
    }
    rc = efab_vi_resource_mmap(trs->nic[intf_i].thn_vi_rs[CI_Q_ID_TCP_APP], &n,
                    vma, &map_num, &offset,
                    EFCH_VI_MMAP_PLUGIN_BASE +
                    trs->nic[intf_i].thn_plugin_mapped_csr_offset / PAGE_SIZE);
    if( rc < 0 )
      return rc;
    ci_assert_equal(n, 0);
    bytes -= PAGE_SIZE;
  }
  ci_assert_equal(bytes, 0);

  return 0;
}
#endif



static int tcp_helper_rm_mmap_buf(tcp_helper_resource_t* trs,
                                  unsigned long bytes,
                                  struct vm_area_struct* vma)
{
  int intf_i, rc;
  ci_netif* ni;
  int map_num = 0;
  unsigned long offset = 0;

  ni = &trs->netif;
  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx", __func__, trs->id, bytes));

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i ) {
    rc = mmap_all_vis(trs, intf_i, &bytes, vma, &map_num, &offset,
                      EFCH_VI_MMAP_MEM);
    if( rc < 0 )
      return rc;
  }
  ci_assert_equal(bytes, 0);
  return 0;
}


static int tcp_helper_rm_mmap_efct_shm(tcp_helper_resource_t* trs,
                                       unsigned long bytes,
                                       struct vm_area_struct* vma)
{
  int intf_i;
  ci_netif* ni;
  int map_num = 0;
  unsigned long offset = 0;

  ni = &trs->netif;
  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx", __func__, trs->id, bytes));

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    mmap_all_vis(trs, intf_i, &bytes, vma, &map_num, &offset,
                 EFCH_VI_MMAP_RXQ_SHM);
  }
  ci_assert_equal(bytes, 0);
  return 0;
}


/* fixme: this handler is linux-only */
static int tcp_helper_rm_mmap_pkts(tcp_helper_resource_t* trs,
                                   unsigned long bytes,
                                   struct vm_area_struct* vma, int map_id)
{
  ci_netif* ni;
  ci_netif_state* ns;
  int bufid = map_id - CI_NETIF_MMAP_ID_PKTS;

  if( bytes != CI_CFG_PKT_BUF_SIZE * PKTS_PER_SET )
    return -EINVAL;

  ni = &trs->netif;
  ns = ni->state;
  ci_assert(ns);

  /* Reserve space for packet buffers */
  if( bufid < 0 || bufid > ni->packets->sets_max ||
      ni->pkt_bufs[bufid] == NULL ) {
    OO_DEBUG_ERR(ci_log("%s: %u BAD bufset_id=%d", __FUNCTION__,
                        trs->id, bufid));
    return -EINVAL;
  }
#ifdef OO_DO_HUGE_PAGES
  if( oo_iobufset_get_shmid(ni->pkt_bufs[bufid]) >= 0 ) {
    OO_DEBUG_ERR(ci_log("%s: [%d] WARNING mmapping huge page from bufset=%d "
                        "will split it", __func__, trs->id, bufid));
  }
#endif

  if( oo_iobufset_npages(ni->pkt_bufs[bufid]) == 1 ) {
    /* Avoid nopage handler, mmap it all at once */
    return vm_insert_page(vma, vma->vm_start, ni->pkt_bufs[bufid]->pages[0]);
  }

  return 0;
}


static int
efab_tcp_helper_rm_mmap(tcp_helper_resource_t* trs, unsigned long bytes,
                        struct vm_area_struct* vma, int map_id, int is_writable)
{
  int rc;

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, 0);
  ci_assert(bytes > 0);

  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx map_id=%x", __func__,
                     trs->id, bytes, map_id));

  switch( map_id ) {
    case CI_NETIF_MMAP_ID_TIMESYNC:
      rc = tcp_helper_rm_mmap_timesync(trs, bytes, vma, is_writable);
      break;
    case CI_NETIF_MMAP_ID_IO:
      rc = tcp_helper_rm_mmap_io(trs, bytes, vma);
      break;
#if CI_CFG_PIO
    case CI_NETIF_MMAP_ID_PIO:
      rc = tcp_helper_rm_mmap_pio(trs, bytes, vma);
      break;
#endif
#if CI_CFG_CTPIO
    case CI_NETIF_MMAP_ID_CTPIO:
      rc = tcp_helper_rm_mmap_ctpio(trs, bytes, vma);
      break;
#endif
#if CI_CFG_TCP_OFFLOAD_RECYCLER
    case CI_NETIF_MMAP_ID_PLUGIN:
      rc = tcp_helper_rm_mmap_plugin(trs, bytes, vma);
      break;
#endif
    case CI_NETIF_MMAP_ID_IOBUFS:
      rc = tcp_helper_rm_mmap_buf(trs, bytes, vma);
      break;
    case CI_NETIF_MMAP_ID_EFCT_SHM:
      rc = tcp_helper_rm_mmap_efct_shm(trs, bytes, vma);
      break;
    default:
      /* CI_NETIF_MMAP_ID_PKTS + set_id */
      rc = tcp_helper_rm_mmap_pkts(trs, bytes, vma, map_id);
  }

  if( rc == 0 )  return 0;

  OO_DEBUG_VM(ci_log("%s: failed map_id=%x rc=%d", __FUNCTION__, map_id, rc));
  return rc;
}


static int
oo_stack_mmap(ci_private_t* priv, struct vm_area_struct* vma)
{
  off_t offset = VMA_OFFSET(vma);
  unsigned long bytes = vma->vm_end - vma->vm_start;
  int map_id = OO_MMAP_OFFSET_TO_MAP_ID(offset);

  if( !priv->thr ) return -ENODEV;

  ci_assert((offset & PAGE_MASK) == offset);

  vma->vm_flags |= EFRM_VM_BASE_FLAGS;
  vma->vm_private_data = (void *) priv->thr;

  vma->vm_ops = &vm_ops;

  switch( map_id )
  {
    case CI_NETIF_MMAP_ID_STATE:
      return tcp_helper_rm_mmap_mem(priv->thr, bytes, vma);
    default:
      return efab_tcp_helper_rm_mmap(priv->thr, bytes, vma, map_id,
                                     vma->vm_flags & VM_WRITE);
  }
}


int
oo_fop_mmap(struct file* file, struct vm_area_struct* vma)
{
  ci_private_t* priv = (ci_private_t*) file->private_data;
  unsigned char map_type = OO_MMAP_TYPE(VMA_OFFSET(vma));

  if( !priv )
    return -EBADF;

  if( vma->vm_end == vma->vm_start ) {
    ci_log("%s: bytes == 0", __func__);
    return -EINVAL;
  }

  /* We never turn read-only mmaps into read-write.  Forbid it. */
  if( ! (vma->vm_flags & VM_WRITE) )
    vma->vm_flags &= ~VM_MAYWRITE;

  switch( map_type ) {
  case OO_MMAP_TYPE_NETIF:
    return oo_stack_mmap(priv, vma);
  case OO_MMAP_TYPE_CPLANE:
    return oo_cplane_mmap(file, vma);
#ifdef OO_MMAP_TYPE_DSHM
  case OO_MMAP_TYPE_DSHM:
    return oo_dshm_mmap_impl(vma);
#endif
  default:
    ci_log("%s: Invalid mapping type %d", __FUNCTION__, map_type);
    return -EINVAL;
  }
}

/* Map any virtual address in the kernel address space to the physical page
** frame number.
*/
unsigned ci_va_to_pfn(void *addr)
{
  struct page *page = NULL;

  ci_check(!in_atomic());

  page = vmalloc_to_page(addr);

  return page ? page_to_pfn(page) : -1;
}

