/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

/* Dependencies */
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* Functions under test */
#include "shrub_pool.h"

/* Test infrastructure */
#include "unit_test.h"

static void test_alloc_buffer_empty_pool(void) {
  size_t n_buffers = 16;
  struct ef_shrub_buffer_pool *pool;
  ef_shrub_init_pool(n_buffers, &pool);

  ef_shrub_buffer_id next = ef_shrub_alloc_buffer(pool);
  CHECK(next, ==, EF_SHRUB_INVALID_BUFFER);

  ef_shrub_fini_pool(pool);
}

static void test_alloc_buffer_normal(void) {
  size_t n_buffers = 16;
  struct ef_shrub_buffer_pool *pool;
  ef_shrub_init_pool(n_buffers, &pool);
  ef_shrub_buffer_id expected = 1;

  ef_shrub_free_buffer(pool, expected);

  ef_shrub_buffer_id next = ef_shrub_alloc_buffer(pool);
  CHECK(next, ==, expected);

  ef_shrub_fini_pool(pool);
}

static void test_filling_buffer(void) {
  int i;
  size_t n_buffers = 16;
  struct ef_shrub_buffer_pool *pool;
  ef_shrub_init_pool(n_buffers, &pool);

  /* There should be no issues when filling the buffer */
  for(i = 0; i < n_buffers; i++) {
    ef_shrub_buffer_id buffer = i;
    ef_shrub_free_buffer(pool, buffer);
  }

  /* The pool should return the buffer_ids in the reverse order to which they
   * were inserted. */
  for(i = 0; i < n_buffers; i++) {
    ef_shrub_buffer_id expected = n_buffers - 1 - i;
    CHECK(ef_shrub_alloc_buffer(pool), ==, expected);
  }

  /* The pool should now be empty, so trying to retrieve from it should fail */
  CHECK(ef_shrub_alloc_buffer(pool), ==, EF_SHRUB_INVALID_BUFFER);

  ef_shrub_fini_pool(pool);
}

int main(void) {
  TEST_RUN(test_alloc_buffer_empty_pool);
  TEST_RUN(test_alloc_buffer_normal);
  TEST_RUN(test_filling_buffer);
  TEST_END();
}
