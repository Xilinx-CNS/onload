/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

#include "ef_vi_internal.h"
#include "shrub_queue.h"
#include "shrub_connection.h"
#include "shrub_server_sockets.h"
#include "bitfield.h"

#include <etherfabric/internal/efct_uk_api.h> // for CI_HUGEPAGE_SIZE

/* Per-buffer state indicating its location in the queue's outgoing fifo */
struct ef_shrub_queue_buffer
{
  int ref_count;  /* Number of clients that have yet to release it */
  int fifo_index; /* Valid if ref_count is non-zero */
};

/* Make a munged id value suitable for writing into the outgoing fifo */
static ef_shrub_buffer_id set_buffer_id(int index, bool sentinel)
{
  ci_dword_t buffer_id;
  CI_POPULATE_DWORD_2(
    buffer_id,
    EF_SHRUB_BUFFER_ID, index,
    EF_SHRUB_SENTINEL, sentinel
  );
  return buffer_id.u32[0];
}

/* Extract the buffer index from a munged id value */
static uint32_t get_buffer_index(ef_shrub_buffer_id id)
{
  ci_dword_t id2;
  id2.u32[0] = id;
  return CI_DWORD_FIELD(id2, EF_SHRUB_BUFFER_ID);
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

static int next_fifo_index(struct ef_shrub_queue* queue, int index)
{
  return index == queue->fifo_size - 1 ? 0 : index + 1;
}

static int prev_fifo_index(struct ef_shrub_queue* queue, int index)
{
  return index == 0 ? queue->fifo_size - 1 : index - 1;
}

static size_t buffer_total_bytes(struct ef_shrub_queue* queue)
{
  return EF_VI_ROUND_UP(queue->buffer_count * queue->buffer_bytes,
                        CI_HUGEPAGE_SIZE);
}

static int queue_map_fifo(struct ef_shrub_queue* queue)
{
  int i, rc;
  void* map;
  rc = ef_shrub_server_mmap(&map, fifo_bytes(queue), PROT_WRITE,
                            MAP_SHARED | MAP_POPULATE,
                            queue->shared_fds[EF_SHRUB_FD_SERVER_FIFO], 0);
  if( rc < 0 )
    return rc;
  queue->fifo = map;

  for( i = 0; i < queue->fifo_size; ++i )
    queue->fifo[i] = EF_SHRUB_INVALID_BUFFER;

  return 0;
}

static int queue_alloc_buffers(struct ef_shrub_queue* queue)
{
  queue->buffers = calloc(queue->buffer_count, sizeof(queue->buffers[0]));
  if( queue->buffers == NULL )
    return -ENOMEM;

  return 0;
}

static int queue_alloc_shared(struct ef_shrub_queue* queue)
{
  int fd;

  queue->shared_fds[EF_SHRUB_FD_BUFFERS] = -1;
  queue->shared_fds[EF_SHRUB_FD_SERVER_FIFO] = -1;

  fd = ef_shrub_server_memfd_create("ef_shrub_buffer",
                                    buffer_total_bytes(queue), true);
  if( fd < 0 )
    return fd;
  queue->shared_fds[EF_SHRUB_FD_BUFFERS] = fd;

  fd = ef_shrub_server_memfd_create("ef_shrub_server_fifo",
                                    fifo_bytes(queue), false);
  if( fd < 0 )
    return fd;
  queue->shared_fds[EF_SHRUB_FD_SERVER_FIFO] = fd;

  return 0;
}

static void release_buffer(struct ef_shrub_queue* queue, int buffer_index)
{
  struct ef_shrub_queue_buffer* buffer = &queue->buffers[buffer_index];
  if( --buffer->ref_count == 0 ) {
    /* Remove all FIFO entries older than the buffer being freed. All
     * clients must have taken these (or they wouldn't be releasing a later
     * buffer), and we don't want a client holding on to a buffer to prevent
     * the FIFO from refilling. */
    if( buffer->fifo_index >= 0 ) {
      int remove_fifo_index = buffer->fifo_index;
      while( remove_fifo_index != queue->fifo_index ) {
        ef_shrub_buffer_id id = queue->fifo[remove_fifo_index];
        if( id != EF_SHRUB_INVALID_BUFFER ) {
          int remove_buffer_index = get_buffer_index(id);
          queue->buffers[remove_buffer_index].fifo_index = -1;
          queue->fifo[remove_fifo_index] = EF_SHRUB_INVALID_BUFFER;
        }
        remove_fifo_index = prev_fifo_index(queue, remove_fifo_index);
      }
    }

    queue->vi->efct_rxqs.ops->free(queue->vi, queue->ix, buffer_index);
  }
}

static void poll_connection(struct ef_shrub_queue* queue,
                            struct ef_shrub_connection* connection)
{
  int fifo_index = connection->fifo_index;

  /* The client doesn't post the sentinel value, just the buffer index,
   * so there's no need to call get_buffer_index */
  ef_shrub_buffer_id buffer_index = connection->fifo[fifo_index];

  if( buffer_index == EF_SHRUB_INVALID_BUFFER )
    return;

  connection->fifo[fifo_index] = EF_SHRUB_INVALID_BUFFER;
  connection->fifo_index = next_fifo_index(queue, fifo_index);

  if( buffer_index >= queue->buffer_count )
    return; /* TBD: the client is misbehaving, should we disconnect? */

  release_buffer(queue, buffer_index);
}

static void poll_connections(struct ef_shrub_queue* queue)
{
  struct ef_shrub_connection* c;
  for( c = queue->connections; c != NULL; c = c->next )
    poll_connection(queue, c);
}

static void poll_fifo(struct ef_shrub_queue* queue)
{
  while( fifo_has_space(queue) ) {
    bool sentinel;
    unsigned sbseq;
    int buffer_index =
      queue->vi->efct_rxqs.ops->next(queue->vi, queue->ix, &sentinel, &sbseq);
    if ( buffer_index < 0 )
      break;

    int fifo_index = queue->fifo_index;
    assert(queue->fifo[fifo_index] == EF_SHRUB_INVALID_BUFFER);
    queue->fifo[fifo_index] = set_buffer_id(buffer_index, sentinel);

    struct ef_shrub_queue_buffer* buffer = &queue->buffers[buffer_index];
    assert(buffer->ref_count == 0);
    buffer->ref_count = queue->connection_count;
    buffer->fifo_index = fifo_index;

    queue->fifo_index = next_fifo_index(queue, fifo_index);
  }
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

  memset(queue, 0, sizeof(*queue));
  queue->shared_fds[EF_SHRUB_FD_CLIENT_FIFO] = client_fifo_fd;
  queue->buffer_bytes = buffer_bytes;
  queue->buffer_count = buffer_count;
  queue->fifo_size = fifo_size;
  queue->qid = qid;
  queue->vi = vi;

  rc = queue_alloc_buffers(queue);
  if( rc < 0 )
    return rc;

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
  free(queue->buffers);
  return rc;
}

void ef_shrub_queue_close(struct ef_shrub_queue* queue)
{
  /* TODO ON-16708 close connections */
  munmap(queue->fifo, fifo_bytes(queue));
  close(queue->shared_fds[EF_SHRUB_FD_BUFFERS]);
  close(queue->shared_fds[EF_SHRUB_FD_SERVER_FIFO]);
  free(queue->buffers);
}

void ef_shrub_queue_poll(struct ef_shrub_queue* queue)
{
  poll_connections(queue);
  poll_fifo(queue);
}

void ef_shrub_queue_attached(struct ef_shrub_queue* queue,
                             struct ef_shrub_client_state* client)
{
  int fifo_index = queue->fifo_index;
  int prev_index = prev_fifo_index(queue, fifo_index);

  /* Scan backwards over valid buffers to find the most recent empty slot in
   * the fifo. The synchronisation point must be after that point, so we
   * provide the earliest valid buffer we find to the client. The client will
   * scan forwards from there to find the synchronisation point. */
  while( queue->fifo[prev_index] != EF_SHRUB_INVALID_BUFFER ) {
    fifo_index = prev_index;

    /* Take a reference to this buffer */
    ef_shrub_buffer_id buffer_id = queue->fifo[fifo_index];
    assert(buffer_id != EF_SHRUB_INVALID_BUFFER);
    queue->buffers[get_buffer_index(buffer_id)].ref_count++;

    /* This should never happen since the FIFO should never be completely full,
     * but we shouldn't loop forever if it does happen somehow. */
    assert(fifo_index != queue->fifo_index);
    if( fifo_index == queue->fifo_index )
      break; /* The queue is full and we've reached the oldest buffer */

    prev_index = prev_fifo_index(queue, fifo_index);
  }

  queue->connection_count++;
  client->server_fifo_index = fifo_index;
}

void ef_shrub_queue_detached(struct ef_shrub_queue* queue,
                             struct ef_shrub_client_state* client)
{
  int fifo_index = client->server_fifo_index;
  while( fifo_index != queue->fifo_index ) {
    ef_shrub_buffer_id buffer_id = queue->fifo[fifo_index];
    assert(buffer_id != EF_SHRUB_INVALID_BUFFER);
    release_buffer(queue, get_buffer_index(buffer_id));
    fifo_index = next_fifo_index(queue, fifo_index);
  }

  queue->connection_count--;
}
