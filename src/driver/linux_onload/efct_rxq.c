/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#include <onload/linux_mmap.h>
#include <onload/debug.h>
#include <onload/tcp_helper_fns.h>
#include <onload/mmap.h>
#include <ci/driver/kernel_compat.h>
#include <ci/efch/mmap.h>
#include <ci/efrm/efct_rxq.h>

int oo_ubuf_post_mmap(struct file *file, struct vm_area_struct *vma)
{
  ci_private_t* priv = (ci_private_t*) file->private_data;
  resource_size_t io_addr;
  int rc;

  unsigned long bytes = vma->vm_end - vma->vm_start;
  off_t offset = VMA_OFFSET(vma);
  uint64_t map_id = OO_MMAP_OFFSET_TO_MAP_ID(offset);
  int intf_i = OO_MMAP_UBUF_POST_INTF_I(map_id);
  int ix = OO_MMAP_UBUF_POST_IX(map_id);

  if( !priv->thr )
    return -ENODEV;

  TCP_HELPER_RESOURCE_ASSERT_VALID(priv->thr, 0);
  ci_assert((offset & PAGE_MASK) == offset);
  ci_assert(bytes > 0);

  vm_flags_set(vma, EFRM_VM_IO_FLAGS);
  vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

  io_addr = efrm_rxq_superbuf_window(priv->thr->nic[intf_i].thn_efct_rxq[ix]);

  /* This requires a write lock on current->mm->mmap_lock, which has already
   * been acquired (in order to call do_mmap) before reaching this point. */
  rc = io_remap_pfn_range(vma, vma->vm_start, io_addr >> PAGE_SHIFT,
                          CI_ROUND_UP(bytes, (unsigned long)CI_PAGE_SIZE),
                          vma->vm_page_prot);

  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx map_id=0x%" PRIx64 " rc=%d", __func__,
                     priv->thr->id, bytes, map_id, rc));


  return rc;
}
