/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

/* Enable memfd_create */
#define _GNU_SOURCE

#include "ef_vi_internal.h"
#include "shrub_queue.h"
#include "shrub_connection.h"
#include "bitfield.h"

#include <etherfabric/internal/efct_uk_api.h> // for CI_HUGEPAGE_SIZE

static ef_shrub_buffer_id set_buffer_id(ef_shrub_buffer_id id, bool sentinel)
{
  ci_dword_t buffer_id;
  CI_POPULATE_DWORD_2(
    buffer_id,
    EF_SHRUB_BUFFER_ID, id,
    EF_SHRUB_SENTINEL, sentinel
  );
  return buffer_id.u32[0];
}

static bool fifo_has_space(struct ef_shrub_queue* queue)
{
  return queue->fifo_size > 0 &&
         queue->fifo[queue->fifo_index] == EF_SHRUB_INVALID_BUFFER;
}

static size_t fifo_bytes(struct ef_shrub_queue* queue)
{
  return queue->fifo_size * sizeof(ef_shrub_buffer_id);
}

static size_t buffer_total_bytes(struct ef_shrub_queue* queue)
{
  return EF_VI_ROUND_UP(queue->buffer_count * queue->buffer_bytes,
                        CI_HUGEPAGE_SIZE);
}

static int queue_map_fifo(struct ef_shrub_queue* queue)
{
  int i;
  queue->fifo = mmap(NULL, fifo_bytes(queue), PROT_WRITE,
                     MAP_SHARED | MAP_POPULATE,
                     queue->shared_fds[EF_SHRUB_FD_SERVER_FIFO], 0);
  if( queue->fifo == MAP_FAILED )
    return -errno;

  for( i = 0; i < queue->fifo_size; ++i )
    queue->fifo[i] = EF_SHRUB_INVALID_BUFFER;

  return 0;
}

static int queue_alloc_refs(struct ef_shrub_queue* queue)
{
  queue->buffer_refs = calloc(queue->buffer_count, sizeof(ef_shrub_buffer_id));
  if( queue->buffer_refs == NULL )
    return -ENOMEM;

  return 0;
}

static int queue_alloc_buffer_fifo_indices(struct ef_shrub_queue* queue)
{
  int i;
  queue->buffer_fifo_indices = malloc(queue->buffer_count * sizeof(int));
  if ( queue->buffer_fifo_indices == NULL )
    return -ENOMEM;

  for (i = 0; i < queue->buffer_count; i++)
    queue->buffer_fifo_indices[i] = -1;
  return 0;
}

static int queue_alloc_shared(struct ef_shrub_queue* queue)
{
  int fd, rc;

  queue->shared_fds[EF_SHRUB_FD_BUFFERS] = -1;
  queue->shared_fds[EF_SHRUB_FD_SERVER_FIFO] = -1;

  fd = memfd_create("ef_shrub_buffer", MFD_HUGETLB);
  if( fd < 0 )
    return -errno;
  queue->shared_fds[EF_SHRUB_FD_BUFFERS] = fd;

  rc = ftruncate(fd, buffer_total_bytes(queue));
  if( rc < 0 )
    return -errno;

  fd = memfd_create("ef_shrub_server_fifo", 0);
  if( fd < 0 )
    return -errno;
  queue->shared_fds[EF_SHRUB_FD_SERVER_FIFO] = fd;

  rc = ftruncate(fd, fifo_bytes(queue));
  if( rc < 0 )
    return -errno;

  rc = fcntl(fd, F_SETFL, O_RDONLY);
  if( rc < 0 )
    return -errno;

  return 0;
}

static void poll_fifo(struct ef_vi* vi, struct ef_shrub_queue* queue,
                      struct ef_shrub_connection* connection)
{
  int i = connection->fifo_index;

  ef_shrub_buffer_id buffer = connection->fifo[i];

  if( buffer == EF_SHRUB_INVALID_BUFFER )
    return;

  connection->fifo[i] = EF_SHRUB_INVALID_BUFFER;
  connection->fifo_index = i == queue->fifo_size - 1 ? 0 : i + 1;
  ef_shrub_queue_release_buffer(queue, vi, buffer);
}

static void poll_fifos(struct ef_vi* vi, struct ef_shrub_queue* queue)
{
  struct ef_shrub_connection* c;
  for( c = queue->connections; c != NULL; c = c->next )
    poll_fifo(vi, queue, c);
}

int ef_shrub_queue_open(struct ef_shrub_queue* queue,
                        struct ef_vi* vi,
                        size_t buffer_bytes,
                        size_t buffer_count,
                        size_t fifo_size,
                        int client_fifo_fd,
                        int qid)
{
  int rc;

  queue->shared_fds[EF_SHRUB_FD_CLIENT_FIFO] = client_fifo_fd;
  queue->buffer_bytes = buffer_bytes;
  queue->buffer_count = buffer_count;
  queue->fifo_size = fifo_size;
  queue->qid = qid;

  rc = queue_alloc_refs(queue);
  if( rc < 0 )
    return rc;

  rc = queue_alloc_buffer_fifo_indices(queue);
  if ( rc < 0 )
    goto fail_indices;

  rc = queue_alloc_shared(queue);
  if( rc < 0 )
    goto fail_shared;

  rc = queue_map_fifo(queue);
  if( rc < 0 )
    goto fail_fifo;

  rc = vi->efct_rxqs.ops->attach(vi,
                                 qid,
                                 queue->shared_fds[EF_SHRUB_FD_BUFFERS],
                                 queue->buffer_count,
                                 false);
  if (rc < 0)
    goto fail_queue_attach;
  
  queue->ix = rc;
  return 0;

fail_queue_attach:
  munmap(queue->fifo, fifo_bytes(queue));
fail_fifo:
  close(queue->shared_fds[EF_SHRUB_FD_BUFFERS]);
  close(queue->shared_fds[EF_SHRUB_FD_SERVER_FIFO]);
fail_shared:
  free(queue->buffer_fifo_indices);
fail_indices:
  free(queue->buffer_refs);
  return rc;
}

void ef_shrub_queue_close(struct ef_shrub_queue* queue)
{
  /* TODO close connections */
  munmap(queue->fifo, fifo_bytes(queue));
  close(queue->shared_fds[EF_SHRUB_FD_BUFFERS]);
  close(queue->shared_fds[EF_SHRUB_FD_SERVER_FIFO]);
  free(queue->buffer_fifo_indices);
  free(queue->buffer_refs);
}

void ef_shrub_queue_poll(struct ef_shrub_queue* queue, struct ef_vi* vi)
{
  bool sentinel;
  unsigned sbseq;
  ef_vi_efct_rxq_ops* ops;
  ops = vi->efct_rxqs.ops;

  poll_fifos(vi, queue);
  while( fifo_has_space(queue) ) {
    int next_buffer = ops->next(vi, queue->ix, &sentinel, &sbseq);
    if ( next_buffer < 0 ) {
      break;
    }
    int i = queue->fifo_index;
    queue->fifo[i] = set_buffer_id(next_buffer, sentinel);
    assert(queue->buffer_refs[next_buffer] == 0);
    queue->buffer_refs[next_buffer] = queue->connection_count;
    queue->buffer_fifo_indices[next_buffer] = i;
    queue->fifo_index = i == queue->fifo_size - 1 ? 0 : i + 1;
  }
}

void ef_shrub_queue_release_buffer(struct ef_shrub_queue* queue,
                                   struct ef_vi* vi,
                                   ef_shrub_buffer_id buffer)
{
  assert(buffer != EF_SHRUB_INVALID_BUFFER);
  if ( --queue->buffer_refs[buffer] == 0 ) {
    int buffer_fifo_index = queue->buffer_fifo_indices[buffer];
    queue->fifo[buffer_fifo_index] = EF_SHRUB_INVALID_BUFFER;
    queue->buffer_fifo_indices[buffer] = -1;
    vi->efct_rxqs.ops->free(vi, queue->ix, buffer);
  }
}

