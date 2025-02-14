/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: Copyright (c) 2024-2025 Advanced Micro Devices, Inc. */

/* Allocator to produce integer values in LIFO order */

#ifndef __CI_EFHW_STACK_ALLOCATOR_H__
#define __CI_EFHW_STACK_ALLOCATOR_H__

#include <ci/efhw/common.h>

/* Stack allocates downwards. Therefore, when full, head == 0 */
struct efhw_stack_allocator {
  uint32_t  head;
  uint32_t capacity;
  int *values; /* Array of size capacity */
};

/* Constructor for the stack allocator, takes in a pointer to a pre-filled
 * buffer of values to allocate from. The memory for this buffer is freed in
 * efhw_stack_allocator_dtor */
extern int efhw_stack_allocator_ctor(struct efhw_stack_allocator *alloc,
                                     int *values, uint32_t capacity);

/* Specialisation of efhw_stack_allocator_ctor for range of vis with min and lim
 */
extern int efhw_stack_vi_allocator_ctor(struct efhw_stack_allocator *alloc,
                                        unsigned vi_min, unsigned vi_lim);

void efhw_stack_allocator_dtor(struct efhw_stack_allocator *alloc);

int efhw_stack_alloc(struct efhw_stack_allocator *alloc,
                     bool (*accept_fn)(int instance, void *arg), void *arg);

void efhw_stack_free(struct efhw_stack_allocator *alloc, int value);

#endif /* __CI_EFHW_STACK_ALLOCATOR_H__ */
