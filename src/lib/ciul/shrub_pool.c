/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

#include <stddef.h>
#include "ef_vi_internal.h"
#include "shrub_pool.h"

struct ef_shrub_buffer_pool {
  size_t next;
  size_t n_buffers;
  /* Flexible array member */
  ef_shrub_buffer_id buffers[];
};

int ef_shrub_init_pool(size_t n_buffers, struct ef_shrub_buffer_pool **pool_out)
{
  struct ef_shrub_buffer_pool *pool;
  size_t i;

  pool = malloc(sizeof(*pool) + n_buffers * sizeof(pool->buffers[0]));
  if( pool == NULL )
    return -ENOMEM;

  pool->n_buffers = n_buffers;
  pool->next = 0;
  for( i = 0; i < n_buffers; i++ )
    pool->buffers[i] = EF_SHRUB_INVALID_BUFFER;

  *pool_out = pool;
  return 0;
}

void ef_shrub_fini_pool(struct ef_shrub_buffer_pool *pool)
{
  free(pool);
}

ef_shrub_buffer_id ef_shrub_alloc_buffer(struct ef_shrub_buffer_pool *pool)
{
  ef_shrub_buffer_id buffer;

  EF_VI_ASSERT(pool->next <= pool->n_buffers);
  if( pool->next == 0 )
    return EF_SHRUB_INVALID_BUFFER;

  pool->next--;
  buffer = pool->buffers[pool->next];
  EF_VI_DEBUG(pool->buffers[pool->next] = EF_SHRUB_INVALID_BUFFER);

  return buffer;
}

void ef_shrub_free_buffer(struct ef_shrub_buffer_pool *pool,
                         const ef_shrub_buffer_id buffer)
{
  EF_VI_ASSERT(pool->next < pool->n_buffers);

  EF_VI_ASSERT(pool->buffers[pool->next] == EF_SHRUB_INVALID_BUFFER);
  pool->buffers[pool->next++] = buffer;
}
