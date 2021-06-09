/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2019 Xilinx, Inc. */
#include <ci/driver/resource/linux_efhw_nic.h>
#include <ci/driver/internal.h>
#include "linux_char_internal.h"
#include "char_internal.h"
#include <ci/driver/kernel_compat.h>


/****************************************************************************
 *
 * mmap: map userspace onto either pinned down memory or PCI space
 *
 ****************************************************************************/

int 
ci_mmap_io(struct efhw_nic* nic, resource_size_t page_addr, size_t len,
           void* opaque, int* map_num, unsigned long* offset, int set_wc)
{
  struct vm_area_struct* vma = (struct vm_area_struct*) opaque;

  if( len == 0 ) {
    EFCH_WARN("%s: ERROR: map_num=%d offset=%lx len=0",
              __FUNCTION__, *map_num, *offset);
    return 0;
  }

  ci_assert(vma);
  ci_assert((len &~ CI_PAGE_MASK) == 0);
  ci_assert((*offset &~ CI_PAGE_MASK) == 0);
  ci_assert(*map_num == 0 || *offset > 0);

  vma->vm_flags |= EFRM_VM_IO_FLAGS;

  if( set_wc )
    vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
  else
    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

  EFCH_TRACE("%s: pages=%d offset=0x%x phys=0x%llx prot=0x%lx",
             __FUNCTION__, (int) (len >> CI_PAGE_SHIFT),
             (int) (*offset >> CI_PAGE_SHIFT),
             (unsigned long long) (page_addr),
             (unsigned long) pgprot_val(vma->vm_page_prot));

  ++*map_num;
  *offset += len;

  return io_remap_pfn_range(vma, vma->vm_start + *offset - len,
			    (page_addr) >> PAGE_SHIFT, len,
			    vma->vm_page_prot);
}

