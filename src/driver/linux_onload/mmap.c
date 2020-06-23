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
#include <ci/efch/mmap.h>


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

  OO_DEBUG_TRAMP(ci_log("vm_op_open: %u vma=%p refs: "OO_THR_REF_FMT,
		 map->id, vma, OO_THR_REF_ARG(map->ref)));

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

  OO_DEBUG_TRAMP(ci_log("vm_op_close: %u vma=%p refs: "OO_THR_REF_FMT,
		 map->id, vma, OO_THR_REF_ARG(map->ref)));

  if( OO_MMAP_OFFSET_TO_MAP_ID(VMA_OFFSET(vma)) == CI_NETIF_MMAP_ID_STATE )
    efab_del_mm_ref (vma->vm_mm);

  TCP_HELPER_RESOURCE_ASSERT_VALID(map, 0);
}


/****************************************************************************
 *
 * Page faulting
 *
 ****************************************************************************/

/*! map offset in shared data to physical page frame number */
static struct page*
tcp_helper_rm_nopage_mem(tcp_helper_resource_t* trs,
                         struct vm_area_struct *vma, unsigned long offset)
{
  ci_netif* ni = &trs->netif;

  OO_DEBUG_SHM(ci_log("%s: %u", __FUNCTION__, trs->id));

  /* NB: the order in which offsets are compared against shared memory
         areas must be the same order that is used to allocate those offsets in
         allocate_netif_resources() above.  Currently there's only a single
         region.
  */

  if( offset < ci_shmbuf_size(&ni->pages_buf) )
    return ci_shmbuf_page(&ni->pages_buf, offset);

  OO_DEBUG_SHM(ci_log("%s: offset %lx out of range", __FUNCTION__, offset));
  ci_assert(0);
  return NULL;
}


static struct page*
tcp_helper_rm_nopage_timesync(tcp_helper_resource_t* trs,
                              struct vm_area_struct *vma,
                              unsigned long offset)
{
  OO_DEBUG_SHM(ci_log("%s: %u", __FUNCTION__, trs->id));

  return ci_shmbuf_page(&efab_tcp_driver.shmbuf, offset);
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

static struct page*
tcp_helper_rm_nopage(tcp_helper_resource_t* trs, struct vm_area_struct *vma,
                     int map_id, unsigned long offset)
{

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, 0);

  OO_DEBUG_SHM(ci_log("%s: %u", __FUNCTION__, trs->id));

  switch( map_id ) {
    case CI_NETIF_MMAP_ID_STATE:
      return tcp_helper_rm_nopage_mem(trs, vma, offset);
    case CI_NETIF_MMAP_ID_TIMESYNC:
      return tcp_helper_rm_nopage_timesync(trs, vma, offset);
    case CI_NETIF_MMAP_ID_IOBUFS:
      return tcp_helper_rm_nopage_iobuf(trs, vma, offset);
    case CI_NETIF_MMAP_ID_IO:
#if CI_CFG_PIO
    case CI_NETIF_MMAP_ID_PIO:
#endif
#if CI_CFG_CTPIO
    case CI_NETIF_MMAP_ID_CTPIO:
#endif
      OO_DEBUG_SHM(ci_log("%s: map_id=%d. Debugger?", __FUNCTION__, map_id));
      /* IO mappings are always present, and so a page fault should never come
       * down this path, but ptrace() can get us here. */
      return NULL;
    default:
      ci_assert_ge(map_id, CI_NETIF_MMAP_ID_PKTS);
      return tcp_helper_rm_nopage_pkts(trs, vma,
                                       offset +
                                       (map_id - CI_NETIF_MMAP_ID_PKTS) *
                                       CI_CFG_PKT_BUF_SIZE * PKTS_PER_SET);
  }

}


static struct page*
__vm_op_nopage(tcp_helper_resource_t* trs, struct vm_area_struct* vma,
               unsigned long address, int* type)
{
  int map_id = OO_MMAP_OFFSET_TO_MAP_ID(VMA_OFFSET(vma));
  struct page* pg = tcp_helper_rm_nopage(trs, vma, map_id,
                                           address - vma->vm_start);

  if( pg == NULL )
    return NULL;

  get_page(pg);

  OO_DEBUG_TRAMP(ci_log("%s: %u vma=%p sz=%lx pageoff=%lx id=%"CI_PRIx64,
                 __FUNCTION__, trs->id, vma, vma->vm_end - vma->vm_start,
                 (address - vma->vm_start) >> CI_PAGE_SHIFT,
                 OO_MMAP_OFFSET_TO_MAP_ID(VMA_OFFSET(vma))));

  return pg;
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

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, 0);

  vmf->page = __vm_op_nopage(trs, vma, address, NULL);

  if( vmf->page == NULL && ~current->flags & PF_DUMPCORE ) {
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

  return ( vmf->page == NULL ) ? VM_FAULT_SIGBUS : 0;
}


static struct vm_operations_struct vm_state_ops = {
  .open  = vm_op_open,
  .close = vm_op_close,
  .fault = vm_op_fault,
};

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
  int rc = 0;
  int map_num = 0;
  unsigned long offset = 0;

  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx", __func__, trs->id, bytes));

  /* Hook into the VM so we can keep a proper reference count on this
  ** resource.
  */
  vma->vm_ops = &vm_state_ops;
  if( efab_add_mm_ref(vma->vm_mm) )
    return -EFAULT;

  rc = ci_shmbuf_mmap(&trs->netif.pages_buf, 0, &bytes, vma,
                           &map_num, &offset);
  if( rc < 0 )  goto out;
  OO_DEBUG_MEMSIZE(ci_log("after mapping page buf have %ld", bytes));

  ci_assert_equal(bytes, 0);

 out:
  if( rc < 0 )
    efab_del_mm_ref (vma->vm_mm);
  return rc;
}


static int tcp_helper_rm_mmap_timesync(tcp_helper_resource_t* trs,
                                       unsigned long bytes,
                                       struct vm_area_struct* vma, int is_writable)
{
  int rc = 0;
  int map_num = 0;
  unsigned long offset = 0;

  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx", __func__, trs->id, bytes));

  if( is_writable )
    return -EPERM;

  rc = ci_shmbuf_mmap(&efab_tcp_driver.shmbuf, offset, &bytes, vma,
                      &map_num, &offset);
  if( rc < 0 )  return rc;
  ci_assert_equal(bytes, 0);

  return rc;
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
    if( trs->netif.nic_hw[intf_i].plugin_handle == INVALID_PLUGIN_HANDLE )
      continue;
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
    return remap_pfn_range(vma, vma->vm_start,
                           oo_iobufset_pfn(ni->pkt_bufs[bufid], 0), bytes,
                           vma->vm_page_prot);
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

  vma->vm_ops = &vm_ops;

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

