/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: Copyright (c) 2024-2025 Advanced Micro Devices, Inc. */

#include <ci/efhw/efhw_stack_allocator.h>
#include <ci/efhw/efhw_types.h>

int efhw_stack_allocator_ctor(struct efhw_stack_allocator *alloc,
                              int *values, uint32_t capacity)
{
  EFHW_ASSERT(capacity > 0);
  alloc->capacity = capacity;
  alloc->head = 0;
  alloc->values = values;
  return 0;
}

int efhw_stack_vi_allocator_ctor(struct efhw_stack_allocator *alloc,
                                 unsigned vi_min, unsigned vi_lim)
{
  unsigned i, capacity;
  int *values;
  EFHW_ASSERT(vi_min < vi_lim);
  capacity = vi_lim - vi_min;
  values = kmalloc(sizeof(values[0]) * capacity, GFP_KERNEL);
  if(!values)
    return -ENOMEM;

  for(i = 0; i < capacity; i++)
    values[i] = vi_min + i;
  return efhw_stack_allocator_ctor(alloc, values, capacity);
}

void efhw_stack_allocator_dtor(struct efhw_stack_allocator *alloc)
{
  EFHW_ASSERT(alloc->values);
  kfree(alloc->values);
  alloc->values = NULL;
}

/* Find a value that satisfies accept_fn in LIFO order. Swap the value pointed
 * to by alloc->head with the one we just allocated so we maintain a set of
 * unallocated values. */
int efhw_stack_alloc(struct efhw_stack_allocator *alloc,
                     bool (*accept_fn)(int instance, void *arg), void *arg)
{
  unsigned i;
  for(i = alloc->head; i < alloc->capacity; i++) {
    if(accept_fn(alloc->values[i], arg)) {
      int value = alloc->values[i];
      alloc->values[i] = alloc->values[alloc->head];
      alloc->head++;
      return value;
    }
  }
  return -ENOMEM;
}

void efhw_stack_free(struct efhw_stack_allocator *alloc, int value)
{
  EFHW_ASSERT(alloc->head != 0);  
  alloc->values[--alloc->head] = value;
}
