/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

/* Queue management for shrub server */

#include <etherfabric/shrub_shared.h>

struct ef_shrub_queue {
  int shared_fds[EF_SHRUB_FD_COUNT];

  size_t buffer_bytes, buffer_count;
  int fifo_index;
  int fifo_size;
  int connection_count;
  int ix;

  ef_shrub_buffer_id* fifo;
  unsigned* buffer_refs;
  int* buffer_fifo_indices;

  struct ef_shrub_connection* connections;
  struct ef_shrub_connection* closed_connections;
};

static inline int ef_shrub_fifo_bytes(struct ef_shrub_queue* queue)
{
  return queue->fifo_size * sizeof(ef_shrub_buffer_id);
}

int ef_shrub_queue_open(struct ef_shrub_queue** queue_out,
                        struct ef_vi* vi,
                        size_t buffer_bytes,
                        size_t buffer_count,
                        int qid);

void ef_shrub_queue_close(struct ef_shrub_queue* queue);

void ef_shrub_queue_release_buffer(struct ef_shrub_queue* queue,
                                   struct ef_vi* vi,
                                   ef_shrub_buffer_id buffer);

void ef_shrub_queue_poll(struct ef_shrub_queue* queue, struct ef_vi* vi);

