/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: Copyright (C) 2024, Advanced Micro Devices, Inc. */

/* Allocator to produce vi numbers in LIFO order */

#ifndef __CI_EFHW_STACK_VI_ALLOCATOR_H__
#define __CI_EFHW_STACK_VI_ALLOCATOR_H__

#include <ci/efhw/efhw_types.h>

/* Stack allocates downwards. Therefore, when full, head == 0 */
struct efhw_stack_vi_allocator {
  uint32_t  head;
  uint32_t capacity;
  int *vi_nos; /* Array of size vi_lim - vi_min */
};

extern int efhw_stack_vi_allocator_ctor(struct efhw_stack_vi_allocator *alloc,
              unsigned vi_min, unsigned vi_lim);

void efhw_stack_vi_allocator_dtor(struct efhw_stack_vi_allocator *alloc);

int efhw_stack_vi_alloc(struct efhw_stack_vi_allocator *alloc,
          bool (*accept_fn)(int instance, void *arg), void *arg);

void efhw_stack_vi_free(struct efhw_stack_vi_allocator *alloc, int vi_no);

#endif /* __CI_EFHW_STACK_VI_ALLOCATOR_H__ */
