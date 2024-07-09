/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

#ifndef __CI_CIUL_SHRUB_POOL_H__
#define __CI_CIUL_SHRUB_POOL_H__

#include <etherfabric/shrub_shared.h>

struct ef_shrub_buffer_pool;

/* Allocates and initialises a buffer pool.
 * Returns 0 on success, negative error code on failure */
int ef_shrub_init_pool(size_t n_buffers,
                       struct ef_shrub_buffer_pool **pool_out);

/* Frees the buffer pool. */
void ef_shrub_fini_pool(struct ef_shrub_buffer_pool *pool);

/* Allocates a buffer from the pool.
 * Returns the id of the buffer, or EF_SHRUB_INVALID_BUFFER on failure */
ef_shrub_buffer_id ef_shrub_alloc_buffer(struct ef_shrub_buffer_pool *pool);

/* Adds a buffer into the pool. */
void ef_shrub_free_buffer(struct ef_shrub_buffer_pool *pool,
                          const ef_shrub_buffer_id buffer);

#endif /* __CI_CIUL_SHRUB_POOL_H__ */
