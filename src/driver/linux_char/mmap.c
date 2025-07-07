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

#include "linux_char_internal.h"
#include "efch.h"
#include <ci/efch/op_types.h>
#include <ci/tools/dllist.h>
#include "char_internal.h"
#include <ci/driver/kernel_compat.h>


#define VMA_OFFSET(vma)  ((vma)->vm_pgoff << PAGE_SHIFT)

/* The fault callback has different prototypes in different linux versions:
 * - linux<=4.10: 2 arguments (EFRM_HAVE_OLD_FAULT);
 * - 4.11<=linux<=5.0: 1 argument, returns int;
 * - 4.17<=linux<=5.1: 1 argument, returns vm_fault_t
 *                    (EFRM_HAVE_NEW_FAULT).
 * For some versions vm_fault_t is int, so the last 2 lines have some
 * common numbers.
 */
static vm_fault_t vm_op_fault(
#ifdef EFRM_HAVE_OLD_FAULT
                       struct vm_area_struct *vma, 
#endif
                       struct vm_fault *vmf) {
#ifndef EFRM_HAVE_OLD_FAULT
  struct vm_area_struct *vma = vmf->vma;
#endif
  struct efrm_resource *rs = vma->vm_private_data;
  unsigned long address = VM_FAULT_ADDRESS(vmf);
  efch_resource_ops *ops;

  ops = efch_ops_table[rs->rs_type];
  if( ops->rm_nopage ) {
    vmf->page = ops->rm_nopage(rs, vma, address - vma->vm_start,
                               vma->vm_end - vma->vm_start);
    if( vmf->page != NULL ) {
      get_page(vmf->page);

      EFCH_TRACE("%s: "EFRM_RESOURCE_FMT" vma=%p sz=%lx pageoff=%lx id=%d",
                 __FUNCTION__, EFRM_RESOURCE_PRI_ARG(rs),
                 vma, vma->vm_end - vma->vm_start,
                 (address - vma->vm_start) >> CI_PAGE_SHIFT,
                 EFAB_MMAP_OFFSET_TO_MAP_ID(VMA_OFFSET(vma)));
      return 0;
    }
  }

  /* Linux walks VMAs on core dump, suppress the message */
  if( ~current->flags & PF_DUMPCORE )
    EFCH_ERR("%s: "EFRM_RESOURCE_FMT" vma=%p sz=%lx pageoff=%lx id=%d FAILED%s",
             __FUNCTION__, EFRM_RESOURCE_PRI_ARG(rs),
             vma, vma->vm_end - vma->vm_start,
             (address - vma->vm_start) >> CI_PAGE_SHIFT,
             EFAB_MMAP_OFFSET_TO_MAP_ID(VMA_OFFSET(vma)),
             ops->rm_nopage ? "":" NO HANDLER");

  return VM_FAULT_SIGBUS;
}

static struct vm_operations_struct vm_ops = {
  .fault = vm_op_fault
};


/****************************************************************************
 *
 * mmap: map userspace onto either pinned down memory or PCI space
 *
 ****************************************************************************/

int
ci_char_fop_mmap(struct file* file, struct vm_area_struct* vma)
{
  ci_private_char_t* priv = (ci_private_char_t*) file->private_data;
  efch_resource_t* rs;
  efch_resource_id_t rsid;
  off_t offset;
  unsigned long bytes;
  int rc;

  if( !priv )  return -EBADF;

  offset = VMA_OFFSET(vma);
  bytes = vma->vm_end - vma->vm_start;

  if( bytes == 0 ) {
    ci_log("ci_char_fop_mmap: bytes == 0");
    return -EINVAL;
  }

  ci_assert((offset & PAGE_MASK) == offset);

  /* NB. Resources can never be freed from the resource_table, so no need
  ** to take a lock here to do resource lookup.
  */
  rsid = EFAB_MMAP_OFFSET_TO_RESOURCE_ID(offset);
  if( (rc = efch_resource_id_lookup(rsid, &priv->rt, &rs)) < 0 )
    return rc;

  vm_flags_set(vma, EFRM_VM_BASE_FLAGS);

  /* Hook into the VM so we can keep a proper reference count on this
  ** resource.
  */
  vma->vm_ops = &vm_ops;
  vma->vm_private_data = rs->rs_base;

  EFCH_TRACE("%s: "EFCH_RESOURCE_ID_FMT " -> " EFRM_RESOURCE_FMT 
             " %d pages offset=0x%lx vma=%p ptr=0x%lx-%lx", 
             __FUNCTION__, EFCH_RESOURCE_ID_PRI_ARG(rsid),
             EFRM_RESOURCE_PRI_ARG(rs->rs_base),
             (int) (bytes >> CI_PAGE_SHIFT), offset, 
             vma, vma->vm_start, vma->vm_end);


  rc = rs->rs_ops->rm_mmap(rs->rs_base, &bytes, vma,
                           EFAB_MMAP_OFFSET_TO_MAP_ID(offset));

  /* the call to rm_mmap should have decremented bytes according to the
     amount of memory it filled. If we've got any left, the user asked for
     too much, which is worrying */
#ifndef NDEBUG
  if( bytes && rc == 0 )
    ci_log("mmap: "EFRM_RESOURCE_FMT" %d pages unmapped (offset=%lx "
           "map_id=%d res_id="EFCH_RESOURCE_ID_FMT")",
           EFRM_RESOURCE_PRI_ARG(rs->rs_base),
           (int) (bytes>>CI_PAGE_SHIFT),
           (unsigned long) offset, (int) EFAB_MMAP_OFFSET_TO_MAP_ID(offset),
           EFCH_RESOURCE_ID_PRI_ARG(rsid));
#endif

  efch_resource_put(rs);
  return rc;
}

