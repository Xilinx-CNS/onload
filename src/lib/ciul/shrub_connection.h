/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

/* Connection management for shrub server */

#ifndef __CI_CIUL_SHRUB_CONNECTION_H__
#define __CI_CIUL_SHRUB_CONNECTION_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <etherfabric/internal/shrub_shared.h>

struct ef_shrub_queue;

struct ef_shrub_connection {
  struct ef_shrub_connection* next;
  struct ef_shrub_queue* queue;

  int socket;
  size_t fifo_size;
  size_t client_fifo_index;
  size_t client_fifo_mmap_offset;

  /* If buffer_refs[buffer_idx] is true, then this client has taken a reference
   * to the buffer at queue->buffers[buffer_idx] and has not returned it. */
  bool *buffer_refs;

  ef_shrub_buffer_id* client_fifo;
};

int
ef_shrub_connection_alloc(struct ef_shrub_connection** connection_out,
                          int client_fifo_fd, size_t* client_fifo_offset,
                          size_t fifo_size);

int ef_shrub_connection_send_metrics(struct ef_shrub_connection* connection);

int ef_shrub_connection_send_token(struct ef_shrub_connection* connection,
                                   unsigned token);

struct ef_shrub_client_state*
ef_shrub_connection_client_state(struct ef_shrub_connection* connection);

void ef_shrub_connection_dump_to_fd(struct ef_shrub_connection* connection,
                                    int fd, char* buf, size_t buflen);

int ef_shrub_connection_attach_queue(struct ef_shrub_connection* connection,
                                     struct ef_shrub_queue* queue);

#endif
