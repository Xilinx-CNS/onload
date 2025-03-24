/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

/* Connection management for shrub server */

#include <etherfabric/shrub_shared.h>

struct ef_shrub_queue;

struct ef_shrub_connection {
  struct ef_shrub_connection* next;
  struct ef_shrub_queue* queue;

  int socket;
  int fifo_index;
  size_t fifo_mmap_offset;

  ef_shrub_buffer_id* fifo;
};

struct ef_shrub_connection*
ef_shrub_connection_alloc(struct ef_shrub_queue* queue);

void ef_shrub_connection_attach(struct ef_shrub_connection* connection,
                                struct ef_shrub_queue* queue);
void ef_shrub_connection_detach(struct ef_shrub_connection* connection,
                                struct ef_vi* vi);

int ef_shrub_connection_send_metrics(struct ef_shrub_connection* connection);

