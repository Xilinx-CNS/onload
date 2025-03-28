/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

/* Connection management for shrub server */

#ifndef __CI_CIUL_SHRUB_CONNECTION_H__
#define __CI_CIUL_SHRUB_CONNECTION_H__

#include <stdint.h>
#include <stddef.h>
#include <etherfabric/shrub_shared.h>

struct ef_shrub_queue;

struct ef_shrub_connection {
  struct ef_shrub_connection* next;
  struct ef_shrub_queue* queue;

  int socket;
  size_t fifo_index;
  size_t fifo_size;
  size_t fifo_mmap_offset;

  ef_shrub_buffer_id* fifo;
};

struct ef_shrub_connection*
ef_shrub_connection_alloc(int fifo_fd, size_t* fifo_offset, size_t fifo_size);
int ef_shrub_connection_send_metrics(struct ef_shrub_connection* connection);

void ef_shrub_connection_attached(struct ef_shrub_connection* connection,
                                  struct ef_shrub_queue* queue);
void ef_shrub_connection_detached(struct ef_shrub_connection* connection,
                                  struct ef_shrub_queue* queue);

#endif
