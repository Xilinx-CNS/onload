/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: Copyright (C) 2024, Advanced Micro Devices, Inc. */

#include <ci/efhw/stack_vi_allocator.h>
#include <ci/efhw/efhw_types.h>

int efhw_stack_vi_allocator_ctor(struct efhw_stack_vi_allocator *alloc,
              unsigned vi_min, unsigned vi_lim)
{
  unsigned i;
  EFHW_ASSERT(vi_min < vi_lim);
  alloc->capacity = vi_lim - vi_min;
  alloc->head = 0;
  alloc->vi_nos = vmalloc(sizeof(alloc->vi_nos[0]) * alloc->capacity);
  if(!alloc->vi_nos) {
    return -ENOMEM;
  }
  for(i = 0; i < alloc->capacity; i++) {
    alloc->vi_nos[i] = vi_min + i;
  }
  return 0;
}

void efhw_stack_vi_allocator_dtor(struct efhw_stack_vi_allocator *alloc)
{
  EFHW_ASSERT(alloc->vi_nos);
  vfree(alloc->vi_nos);
  alloc->vi_nos = NULL;
}

/* Find a vi that satisfies accept_fn in LIFO order. Swap the vi
 * pointed to by alloc->head with the one we just alloced so we
 * maintain a set of unallocated vis. */
int efhw_stack_vi_alloc(struct efhw_stack_vi_allocator *alloc,
          bool (*accept_fn)(int instance, void *arg), void *arg)
{
  unsigned i;
  for(i = alloc->head; i < alloc->capacity; i++) {
    if(accept_fn(alloc->vi_nos[i], arg)) {
      int vi_no = alloc->vi_nos[i];
      alloc->vi_nos[i] = alloc->vi_nos[alloc->head];
      alloc->head++;
      return vi_no;
    }
  }
  return -ENOMEM;
}

void efhw_stack_vi_free(struct efhw_stack_vi_allocator *alloc, int vi_no)
{
  EFHW_ASSERT(alloc->head != 0);  
  alloc->vi_nos[--alloc->head] = vi_no;
}
