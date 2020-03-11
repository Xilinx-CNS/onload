/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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
#include <onload/linux_trampoline.h>
#include <driver/linux_resource/kernel_compat.h>
#include <onload/cplane_driver.h>


/* All valid mm_hash structures have their 'magic' member set to this */
enum {MM_ENTRY_MAGIC = 0xabadf00l};

/* No. of entries in the mm hash-table.  The usual tradeoff -- bigger number
 * uses more mem but with shorter chains, so potentially better performance
 */
enum {MM_HASH_SIZE=256};

/* The hash-table is an array of lists of mm_hash structures. */
static ci_dllist mm_hash_tbl[MM_HASH_SIZE];

/* A lock to protect the hash-table.  If we really wanted to go mad we could
 * have one lock per entry in the table.  But the hash-table is infrequently
 * updated, so a single r/w lock should suffice.
 */
DEFINE_RWLOCK(oo_mm_tbl_lock);


/* Function to hash an 'mm' pointer */
static inline unsigned int
hash_mm (struct mm_struct *mm) {
  ci_uintptr_t t = (ci_uintptr_t)mm;
  ci_assert (t);
  /* The mm was allocated from a slab cache and so for normal builds is 
  * aligned to L1 cache line. No point using always zero bits in the hash. */
  return (t / (unsigned)L1_CACHE_BYTES) & (MM_HASH_SIZE-1);
}

/* Utility function to find current process's entry in the mm hash table.
 * Returns pointer to current process's mm-hash struct, or NULL if not found
 * Hash table lock must be held in read or write mode by caller.
 *
 * Lock must be held in read or write mode
 */
struct mm_hash* oo_mm_tbl_lookup(struct mm_struct *mm)
{
  struct mm_hash *p;
  int hash = hash_mm (mm);
  ci_assert (mm_hash_tbl [hash].l.next);
  ci_assert (mm_hash_tbl [hash].l.prev);
  for (p = (struct mm_hash*) ci_dllist_head (&mm_hash_tbl [hash]);
       !ci_dllist_is_anchor (&mm_hash_tbl [hash], &p->link);
       p = (struct mm_hash*) p->link.next) {
    ci_assert (p->magic == MM_ENTRY_MAGIC);
    if (p->mm == mm)
      return p;
  }

  return NULL;
}
 

/* Add a new item to the mm hash table.  At the point of calling, the
 * table must be locked in write mode, and the entry to add be not already
 * present in the hash table.  The newly added entry will have a
 * reference-count of zero.
 *
 * Returns a pointer to the newly added entry
 * Returns with the lock still held
 */
static struct mm_hash*
efab_create_mm_entry (struct mm_struct *mm) {
  struct mm_hash *p;

  ci_assert( ! oo_mm_tbl_lookup(mm));

  p = kmalloc (sizeof *p, 0);
  if (p) {
    OO_DEBUG_TRAMP(ci_log("Made mm_hash %p for mm %p", p, mm));
    p->magic = MM_ENTRY_MAGIC;
    p->mm = mm;
    p->ref = 0;               // Will be inc-ed by caller
    CI_USER_PTR_SET (p->trampoline_entry, 0); // No trampoline registered yet
    CI_USER_PTR_SET (p->signal_data.user_data, 0); // No signal info
    ci_dllist_push (&mm_hash_tbl [hash_mm (mm)], &p->link);
  }

  return p;
}


/* Incrememnts a reference count on an item in the MM hash table.  If there is
 * no record of key 'mm' in the table, one is created.  In this case it's
 * reference count is '1' when the function returns.
 *
 * Must be called with a non-NULL 'mm' pointer
 * Must be called with the table lock NOT held.
 *
 * Returns zero on success, or -ve error code on failure.
 */
static int efab_add_mm_ref (struct mm_struct *mm) {

  int rc = 0;
  struct mm_hash *p;

  ci_assert (mm);
  write_lock (&oo_mm_tbl_lock);
 
  /* Does this mm already exists in the hash table? */
  p = oo_mm_tbl_lookup(mm);
  if (!p) {
    /* Nope -- create one */
    p = efab_create_mm_entry (mm);
    if (!p) {
      rc = -ENOMEM;
      goto exit;
    }
  }

  ci_assert (p);
  p->ref++;

exit:
  write_unlock (&oo_mm_tbl_lock);
  return rc;
}

/* Decrements a reference on an item in the MM hash-table.
 * Hash table lock must be held in write mode by caller.
 * Returns with the lock still held.
 * Returns 1 if the entry was removed and should be freed.
 */
int efab_put_mm_hash_locked(struct mm_hash *p)
{
  if (!--p->ref) {
    OO_DEBUG_TRAMP(ci_log("Deleting mm_hash %p", p));
    ci_dllist_remove (&p->link);
    return 1;
  }
  return 0;
}

/* Free MM hash table entry after efab_put_mm_hash_locked have
 * returned 1.
 * No locks should be held.
 */
void efab_free_mm_hash(struct mm_hash *p)
{
  ci_assert_equal(p->ref, 0);
  if( safe_signals_and_exit )
    efab_signal_process_fini(&p->signal_data);
  kfree (p);
}

/* Decrements a reference on an item in the MM hash-table.
 * 'mm' must be in the table at the time of calling.
 * If the reference count decrements to zero, the item is removed from the
 * table (and its associated storage freed).
 * 
 * Must be called with the lock NOT held
 */
static void efab_del_mm_ref (struct mm_struct *mm) {
  struct mm_hash *p;
  int do_free = 0;

  write_lock (&oo_mm_tbl_lock);

  p = oo_mm_tbl_lookup(mm);
  if( p == NULL ) {
    /* It should happen after ENOMEM in efab_add_mm_ref only */
    ci_log("%s: ERROR: can not lookup this mm", __func__);
    write_unlock (&oo_mm_tbl_lock);
    return;
  }

  ci_assert (p->mm == mm);

  do_free = efab_put_mm_hash_locked(p);

  write_unlock (&oo_mm_tbl_lock);

  if( do_free )
    efab_free_mm_hash(p);
}


void oo_mm_tbl_init(void)
{
  int i;
  for( i = 0; i < MM_HASH_SIZE; i++ )
    ci_dllist_init(&mm_hash_tbl[i]);
}


/****************************************************************************
 *
 * mmap: need VM operations to keep track of mmaps onto resources
 *
 ****************************************************************************/

static void vm_op_open(struct vm_area_struct* vma)
{
  tcp_helper_resource_t* map;
  int rc;

  map = (tcp_helper_resource_t*) vma->vm_private_data;
  TCP_HELPER_RESOURCE_ASSERT_VALID(map, 0);

  OO_DEBUG_TRAMP(ci_log("vm_op_open: %u vma=%p rs_refs=%d",
		 map->id, vma, (int) oo_atomic_read(&map->ref_count)));

  if( OO_MMAP_OFFSET_TO_MAP_ID(VMA_OFFSET(vma)) == CI_NETIF_MMAP_ID_STATE ) {
    rc = efab_add_mm_ref (vma->vm_mm);
    if( rc != 0 )
      ci_log("%s: ERROR: failed to register mm: rc=%d", __func__, rc);
  }
}


static void vm_op_close(struct vm_area_struct* vma)
{
  tcp_helper_resource_t* map;
  map = (tcp_helper_resource_t*) vma->vm_private_data;

  OO_DEBUG_TRAMP(ci_log("vm_op_close: %u vma=%p rs_refs=%d",
		 map->id, vma, (int) oo_atomic_read(&map->ref_count)));

  if( OO_MMAP_OFFSET_TO_MAP_ID(VMA_OFFSET(vma)) == CI_NETIF_MMAP_ID_STATE )
    efab_del_mm_ref (vma->vm_mm);

  TCP_HELPER_RESOURCE_ASSERT_VALID(map, 0);
}


static struct page*
__vm_op_nopage(tcp_helper_resource_t* trs, struct vm_area_struct* vma,
               unsigned long address, int* type)
{
  struct page* pg;
  int map_id = OO_MMAP_OFFSET_TO_MAP_ID(VMA_OFFSET(vma));
  unsigned long pfn = tcp_helper_rm_nopage(trs, vma, map_id,
                                           address - vma->vm_start);

  if( pfn == (unsigned) -1 )
    return NULL;

  pg = pfn_to_page(pfn);
  get_page(pg);

  OO_DEBUG_TRAMP(ci_log("%s: %u vma=%p sz=%lx pageoff=%lx id=%"CI_PRIx64
                        " pfn=%lx",
                 __FUNCTION__, trs->id, vma, vma->vm_end - vma->vm_start,
                 (address - vma->vm_start) >> CI_PAGE_SHIFT,
                 OO_MMAP_OFFSET_TO_MAP_ID(VMA_OFFSET(vma)), pfn));

  return pg;
}


static struct page* vm_op_nopage(struct vm_area_struct* vma,
                                 unsigned long address,
				 int* type)
{
  tcp_helper_resource_t* trs = (tcp_helper_resource_t*) vma->vm_private_data;
  struct page *pg;

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, 0);

  pg = __vm_op_nopage(trs, vma, address, type);
  if( pg != NULL )
    return pg;

  /* Linux walks VMAs on core dump, suppress the message */
  if( ~current->flags & PF_DUMPCORE ) {
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

  return NOPAGE_SIGBUS;
}

static vm_fault_t vm_op_fault(
#ifdef EFRM_HAVE_OLD_FAULT
                       struct vm_area_struct *vma,
#endif
                       struct vm_fault *vmf) {
#ifndef EFRM_HAVE_OLD_FAULT
  struct vm_area_struct *vma = vmf->vma;
#endif
  struct page* page;

  page = vm_op_nopage(vma, VM_FAULT_ADDRESS(vmf), NULL);
  vmf->page = page;

  return ( page == NULL ) ? VM_FAULT_SIGBUS : 0; 
}


static struct vm_operations_struct vm_ops = {
  .open  = vm_op_open,
  .close = vm_op_close,
  .fault = vm_op_fault,
};


/****************************************************************************
 *
 * mmap: map userspace onto either pinned down memory or PCI space
 *
 ****************************************************************************/


static int
oo_stack_mmap(ci_private_t* priv, struct vm_area_struct* vma)
{
  off_t offset = VMA_OFFSET(vma);
  unsigned long bytes = vma->vm_end - vma->vm_start;
  int map_id = OO_MMAP_OFFSET_TO_MAP_ID(offset);
  int rc;

  if( !priv->thr ) return -ENODEV;

  ci_assert((offset & PAGE_MASK) == offset);

  if( map_id == CI_NETIF_MMAP_ID_STATE &&
      (rc = efab_add_mm_ref (vma->vm_mm)) < 0 )
    return rc;

  vma->vm_flags |= EFRM_VM_BASE_FLAGS;

  /* Hook into the VM so we can keep a proper reference count on this
  ** resource.
  */
  vma->vm_ops = &vm_ops;
  vma->vm_private_data = (void *) priv->thr;

  OO_DEBUG_TRAMP(ci_log("mmap:  -> %u %d pages offset=0x%lx "
                 "vma=%p ptr=0x%lx-%lx", 
		 priv->thr->id, (int) (bytes >> CI_PAGE_SHIFT), offset, 
		 vma, vma->vm_start, vma->vm_end));

  rc = efab_tcp_helper_rm_mmap(priv->thr, bytes, vma, map_id,
                               vma->vm_flags & VM_WRITE);
  if( map_id == CI_NETIF_MMAP_ID_STATE && rc < 0 )
    efab_del_mm_ref (vma->vm_mm);

  return rc;
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

