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
  uint64_t qid;

  struct ef_vi* vi;
  ef_shrub_buffer_id* fifo;
  unsigned* buffer_refs;
  int* buffer_fifo_indices;

  struct ef_shrub_connection* connections;
};

int ef_shrub_queue_open(struct ef_shrub_queue* queue,
                        struct ef_vi* vi,
                        size_t buffer_bytes,
                        size_t buffer_count,
                        size_t fifo_size,
                        int client_fifo_fd,
                        int qid);

void ef_shrub_queue_close(struct ef_shrub_queue* queue);

void ef_shrub_queue_release_buffer(struct ef_shrub_queue* queue,
                                   ef_shrub_buffer_id buffer);

void ef_shrub_queue_poll(struct ef_shrub_queue* queue);

