/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

/* Queue management for shrub server */

#ifndef __CI_CIUL_SHRUB_QUEUE_H__
#define __CI_CIUL_SHRUB_QUEUE_H__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <etherfabric/internal/shrub_shared.h>

struct ef_shrub_queue {
  int shared_fds[EF_SHRUB_FD_COUNT];

  size_t buffer_bytes, buffer_count;
  size_t fifo_index;
  size_t fifo_size;
  int connection_count;
  int ix;
  uint64_t qid;

  struct ef_vi* vi;
  ef_shrub_buffer_id* fifo;
  struct ef_shrub_queue_buffer* buffers;
  struct ef_shrub_connection* connections;
};

int ef_shrub_queue_open(struct ef_shrub_queue* queue,
                        struct ef_vi* vi,
                        size_t buffer_bytes,
                        size_t buffer_count,
                        size_t fifo_size,
                        int client_fifo_fd,
                        int server_fifo_fd,
                        int qid,
                        bool use_interrupts);

void ef_shrub_queue_close(struct ef_shrub_queue* queue);
void ef_shrub_queue_poll(struct ef_shrub_queue* queue);

void ef_shrub_queue_attached(struct ef_shrub_queue* queue,
                             struct ef_shrub_connection* connection);
void ef_shrub_queue_detached(struct ef_shrub_queue* queue,
                             struct ef_shrub_connection* connection);

void ef_shrub_queue_dump_to_fd(struct ef_shrub_queue* queue, int fd,
                               char* buf, size_t buflen);

int ef_shrub_queue_buffer_get_ref_count(struct ef_shrub_queue* queue,
                                        int buffer_index);

#endif
