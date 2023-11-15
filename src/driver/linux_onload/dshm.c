/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2016-2020 Xilinx, Inc. */
/**
 * \file Implementation of "donation" shared memory mechanism.
 *
 * Clients firstly register user-space buffers with us, identified by a class
 * (specified by the caller) and ID (returned by us).  We take a reference to
 * the underlying pages.  Other clients can then map those buffers into their
 * own address spaces.
 */

#include <linux/errno.h>

#ifndef __KERNEL__
#include <limits.h>
#endif

#include <ci/compat.h>
#include <ci/tools.h>
#include <ci/driver/internal.h>

#include <onload/debug.h>
#include <onload/dshm.h>
#include <onload/id_pool.h>
#include <onload/mmap.h>
#include <onload/dshm.h>

/* For get_user_pages() compat. */
#include "ci/driver/kernel_compat.h"

/* Global state. */
static struct {
  /* Lists of shared buffers indexed by class. */
  ci_dllist buffers[OO_DSHM_CLASS_COUNT];

  /* Lock protecting this state. */
  ci_irqlock_t lock;

  /* Pools of IDs to assign to buffers. */
#define OO_DSHM_ID_POOL_INIT_SIZE  32
#define OO_DSHM_ID_POOL_MAX_IDS    INT_MAX
  ci_id_pool_t ids[OO_DSHM_CLASS_COUNT];
} oo_dshm_state;


/* Per-buffer state. */
struct oo_dshm_buffer {
  int buffer_id;
  struct page** pages;
  ci_uint32 num_pages;
  ci_int32 shm_class;
  ci_dllink class_link;
  ci_dllink handle_link;
  uid_t owner_euid;
  atomic_t refcount;
};


static inline int /* bool */
validate_shm_class(ci_int32 shm_class)
{
  return shm_class < OO_DSHM_CLASS_COUNT && shm_class >= 0;
}


int
oo_dshm_register_impl(ci_int32 shm_class, ci_user_ptr_t user_addr,
                      ci_uint32 length, ci_int32* buffer_id_out,
                      ci_dllist* handle_list)
{
  struct oo_dshm_buffer* buffer;
  ci_irqlock_state_t lock_flags;
  int rc;

  OO_DEBUG_SHM(ci_log("%s: shm_class=%d user_addr=%p length=%u", __FUNCTION__,
                      shm_class, CI_USER_PTR_GET(user_addr), length));

  if( ! validate_shm_class(shm_class) )
    return -EINVAL;

  /* Allocate storage for dshm-buffer metadata. */
  buffer = ci_alloc(sizeof(struct oo_dshm_buffer));
  if( buffer == NULL )
    return -ENOMEM;

  buffer->shm_class = shm_class;
  buffer->owner_euid = ci_geteuid();
  atomic_set(&buffer->refcount, 1);

  /* Allocate storage for page metadata. */
  buffer->num_pages =
    (ci_uint32) ((ci_uint64) length + PAGE_SIZE - 1) / PAGE_SIZE;
  if( buffer->num_pages == 0 ) {
    rc = -EINVAL;
    goto fail1;
  }
  buffer->pages = vmalloc(sizeof(struct page*) * buffer->num_pages);
  if( buffer->pages == NULL ) {
    rc = -ENOMEM;
    goto fail1;
  }

  /* Allocate an ID for the buffer. */
  ci_irqlock_lock(&oo_dshm_state.lock, &lock_flags);
  *buffer_id_out = ci_id_pool_alloc(&oo_dshm_state.ids[shm_class]);
  ci_irqlock_unlock(&oo_dshm_state.lock, &lock_flags);
  if( *buffer_id_out == CI_ID_POOL_ID_NONE ) {
    rc = -EBUSY;
    goto fail2;
  }
  buffer->buffer_id = *buffer_id_out;

  /* Take references to the pages from the user's buffer. */
  mmap_read_lock(current->mm);
  rc = ci_pin_user_pages((unsigned long) CI_USER_PTR_GET(user_addr),
                         buffer->num_pages, 0 /* read-only, no force */,
                         buffer->pages);
  mmap_read_unlock(current->mm);

  if( rc < (int)buffer->num_pages ) {
    /* We pinned fewer pages than we asked for.  This should never happen, so
     * treat it as fatal. */
    int i;
    for( i = 0; i < rc; ++i )
      unpin_user_page(buffer->pages[i]);
    rc = -EIO;
    goto fail3;
  }

  /* Stash the buffer in the appropriate lists so that we can find it again. */
  ci_irqlock_lock(&oo_dshm_state.lock, &lock_flags);
  ci_dllist_push(&oo_dshm_state.buffers[shm_class], &buffer->class_link);
  ci_dllist_push(handle_list, &buffer->handle_link);
  ci_irqlock_unlock(&oo_dshm_state.lock, &lock_flags);

  return 0;

 fail3:
  ci_id_pool_free(&oo_dshm_state.ids[shm_class], buffer->buffer_id,
                  &oo_dshm_state.lock);
 fail2:
  vfree(buffer->pages);
 fail1:
  ci_free(buffer);
  return rc;
}


static inline int /* bool */
can_map_dshm(const struct oo_dshm_buffer* buffer)
{
  return ci_geteuid() == buffer->owner_euid || ci_getuid() == 0;
}


int
oo_dshm_list_impl(ci_int32 shm_class, ci_user_ptr_t buffer_ids,
                  ci_uint32* count_in_out)
{
  ci_uint32 num_returned = 0;
  ci_int32* buffer_ids_local;
  struct oo_dshm_buffer* buffer;
  ci_irqlock_state_t lock_flags;
  int rc = 0;

  OO_DEBUG_SHM(ci_log("%s: shm_class=%d buffer_ids=%p count=%u", __FUNCTION__,
                      shm_class, CI_USER_PTR_GET(buffer_ids), *count_in_out));

  if( ! validate_shm_class(shm_class) )
    return -EINVAL;

  /* We create a local buffer into which to store IDs.  We write into this
   * while holding the lock, and then copy_to_user() to the real buffer after
   * dropping the lock. */
  buffer_ids_local = ci_alloc(sizeof(*buffer_ids_local) * (*count_in_out));
  if( buffer_ids_local == NULL )
    return -ENOMEM;

  /* Fill the intermediate array with the IDs of the buffers in this class that
   * the caller is allowed to map. */
  ci_irqlock_lock(&oo_dshm_state.lock, &lock_flags);
  CI_DLLIST_FOR_EACH2(struct oo_dshm_buffer, buffer, class_link,
                      &oo_dshm_state.buffers[shm_class]) {
    if( (size_t) num_returned >= *count_in_out )
      break;
    if( can_map_dshm(buffer) )
      buffer_ids_local[num_returned++] = buffer->buffer_id;
  }
  ci_irqlock_unlock(&oo_dshm_state.lock, &lock_flags);

  /* Copy to the user's array now that we've dropped the lock. */
  if( copy_to_user(CI_USER_PTR_GET(buffer_ids), buffer_ids_local,
                   num_returned * sizeof(buffer_ids_local[0])) != 0 )
    rc = -EFAULT;

  *count_in_out = num_returned;

  ci_free(buffer_ids_local);
  return rc;
}


static void dshm_release(struct oo_dshm_buffer* buffer)
{
  if( atomic_dec_and_test(&buffer->refcount) ) {
    ci_uint32 i;
    for( i = 0; i < buffer->num_pages; ++i )
      unpin_user_page(buffer->pages[i]);

    ci_id_pool_free(&oo_dshm_state.ids[buffer->shm_class], buffer->buffer_id,
                    &oo_dshm_state.lock);

    vfree(buffer->pages);
    ci_free(buffer);
  }
}


/* Frees all dshm buffers in a list for a given driver handle.  Existing
 * mappings of those segments will continue to be valid. */
int
oo_dshm_free_handle_list(ci_dllist* list)
{
  struct oo_dshm_buffer* buffer;
  struct oo_dshm_buffer* next_buffer;
  ci_irqlock_state_t lock_flags;

  OO_DEBUG_SHM(ci_log("%s:", __FUNCTION__));

  /* Write each ID into the caller's array.  We don't need the lock to traverse
   * the handle list as we're its last user.  On the other hand, we do need the
   * lock to adjust the class list and the ID pool. */
  CI_DLLIST_FOR_EACH3(struct oo_dshm_buffer, buffer, handle_link, list,
                      next_buffer) {
    OO_DEBUG_SHM(ci_log("%s: id=%d class=%d", __FUNCTION__, buffer->buffer_id,
                        buffer->shm_class));

    ci_dllist_remove(&buffer->handle_link);

    ci_irqlock_lock(&oo_dshm_state.lock, &lock_flags);
    ci_dllist_remove(&buffer->class_link);
    ci_irqlock_unlock(&oo_dshm_state.lock, &lock_flags);

    dshm_release(buffer);
  }

  return 0;
}



#ifdef OO_MMAP_TYPE_DSHM
/* Maps a dshm segment into a process's address space. */
int
oo_dshm_mmap_impl(struct vm_area_struct* vma)
{
  ci_uint64 map_id = OO_MMAP_OFFSET_TO_MAP_ID(VMA_OFFSET(vma));
  ci_int32 buffer_id = OO_MMAP_DSHM_BUFFER_ID(map_id);
  ci_int32 shm_class = OO_MMAP_DSHM_SHM_CLASS(map_id);
  struct oo_dshm_buffer* buffer = NULL;
  ci_irqlock_state_t lock_flags;
  unsigned long map_length = vma->vm_end - vma->vm_start;

  /* Return -EINVAL if anything goes wrong. */
  int rc = -EINVAL;

  OO_DEBUG_SHM(ci_log("%s: vma=%p", __FUNCTION__, vma));

  /* We must be in process context. */
  ci_assert(current);

  ci_irqlock_lock(&oo_dshm_state.lock, &lock_flags);

  /* Do a linear search for the requested buffer. */
  CI_DLLIST_FOR_EACH2(struct oo_dshm_buffer, buffer, class_link,
                      &oo_dshm_state.buffers[shm_class]) {
    if( buffer->buffer_id == buffer_id ) {
      atomic_inc(&buffer->refcount);
      break;
    }
  }

  /* We've finished traversing the list, so we can drop the lock, which is
   * necessary before calling remap_pfn_range(). */
  ci_irqlock_unlock(&oo_dshm_state.lock, &lock_flags);

  /* If we found a matching buffer, try to map it. */
  if( buffer != NULL ) {
    if( can_map_dshm(buffer) ) {
      /* We've found the buffer.  Map as many of its pages as we can into our
       * address space.  If we fail to map any of the pages, give up; the
       * kernel will then tidy up begind us.
       */
      ci_uint32 num_pages = CI_MIN((unsigned long)buffer->num_pages,
                                   map_length >> PAGE_SHIFT);
      ci_uint32 i;
      for( i = 0, rc = 0; i < num_pages && rc == 0; ++i ) {
        /* vm_insert_page() would have been simpler (and allow core dumps to
         * capture these pages), but it fails with anonymous pages */
        rc = remap_pfn_range(vma,
                             vma->vm_start + (unsigned long) i * PAGE_SIZE,
                             page_to_pfn(buffer->pages[i]),
                             PAGE_SIZE, vma->vm_page_prot);
      }
    }
    else {
      OO_DEBUG_SHM(ci_log("%s: can't map buffer owned by %u", __FUNCTION__,
                          buffer->owner_euid));
      rc = -EACCES;
    }
    dshm_release(buffer);
  }

  return rc;
}
#endif /* defined(OO_MMAP_TYPE_DSHM) */


void
oo_dshm_init(void)
{
  int i;

  ci_irqlock_ctor(&oo_dshm_state.lock);

  for( i = 0; i < OO_DSHM_CLASS_COUNT; ++i ) {
    ci_dllist_init(&oo_dshm_state.buffers[i]);
    ci_id_pool_ctor(&oo_dshm_state.ids[i], OO_DSHM_ID_POOL_MAX_IDS,
                    OO_DSHM_ID_POOL_INIT_SIZE);
  }
}


void
oo_dshm_fini(void)
{
  int i;

  for( i = 0; i < OO_DSHM_CLASS_COUNT; ++i )
    ci_id_pool_dtor(&oo_dshm_state.ids[i]);

  ci_irqlock_dtor(&oo_dshm_state.lock);
}
