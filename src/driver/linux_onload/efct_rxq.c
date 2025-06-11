/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#include <onload/linux_mmap.h>
#include <onload/debug.h>
#include <onload/tcp_helper_fns.h>
#include <onload/mmap.h>
#include <ci/driver/kernel_compat.h>
#include <ci/efch/mmap.h>
#include <ci/efrm/efct_rxq.h>

static vm_fault_t
tcp_helper_rm_nopage_ubuf(tcp_helper_resource_t* trs, struct vm_area_struct *vma,
                          uint64_t map_id, unsigned long offset)
{
  unsigned long bytes = vma->vm_end - vma->vm_start;
  int intf_i = OO_MMAP_UBUF_POST_INTF_I(map_id);
  int ix = OO_MMAP_UBUF_POST_IX(map_id);
  resource_size_t io_addr;
  int rc;

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, 0);
  ci_assert(bytes > 0);
  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx map_id=0x%"PRIx64, __func__,
                     trs->id, bytes, map_id));

  io_addr = efrm_rxq_superbuf_window(trs->nic[intf_i].thn_efct_rxq[ix]);
  rc = io_remap_pfn_range(vma, vma->vm_start + offset, io_addr >> PAGE_SHIFT,
                          CI_ROUND_UP(bytes, (unsigned long)CI_PAGE_SIZE),
                          vma->vm_page_prot);
  if( rc == 0 )
    return VM_FAULT_NOPAGE;

  OO_DEBUG_VM(ci_log("%s: offset %lx out of range", __FUNCTION__, offset));
  return VM_FAULT_SIGBUS;
}


static vm_fault_t vm_op_fault_ubuf(
#ifdef EFRM_HAVE_OLD_FAULT
                       struct vm_area_struct *vma,
#endif
                       struct vm_fault *vmf) {
#ifndef EFRM_HAVE_OLD_FAULT
  struct vm_area_struct *vma = vmf->vma;
#endif
  tcp_helper_resource_t* trs = (tcp_helper_resource_t*) vma->vm_private_data;
  uint64_t map_id = OO_MMAP_OFFSET_TO_MAP_ID(VMA_OFFSET(vma));
  unsigned long address = VM_FAULT_ADDRESS(vmf);
  vm_fault_t rc = 0;

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, 0);

  rc = tcp_helper_rm_nopage_ubuf(trs, vma, map_id, address - vma->vm_start);

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


static struct vm_operations_struct vm_ops_ubuf = {
  .fault = vm_op_fault_ubuf,
};


int oo_ubuf_post_mmap(struct file *file, struct vm_area_struct *vma)
{
  ci_private_t* priv = (ci_private_t*) file->private_data;
  off_t offset = VMA_OFFSET(vma);

  if( !priv->thr )
    return -ENODEV;

  ci_assert((offset & PAGE_MASK) == offset);
  /* Avoid compiler sadness in NDEBUG builds */
  (void)offset;

  vm_flags_set(vma, EFRM_VM_IO_FLAGS);
  vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
  vma->vm_private_data = (void *) priv->thr;
  vma->vm_ops = &vm_ops_ubuf;

  /* Defer mapping until we try to fault the memory */
  return 0;
}
