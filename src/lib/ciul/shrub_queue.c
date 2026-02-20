/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

#include "ef_vi_internal.h"
#include "shrub_queue.h"
#include "shrub_connection.h"
#include "shrub_server_sockets.h"
#include <ci/internal/seq.h>

#include <etherfabric/internal/efct_uk_api.h> // for CI_HUGEPAGE_SIZE

/* Per-buffer state indicating its location in the queue's outgoing fifo */
struct ef_shrub_queue_buffer
{
  int ref_count;  /* Number of clients that have yet to release it */
  int fifo_index; /* Valid if ref_count is non-zero */
};

/* Make a munged id value suitable for writing into the outgoing fifo
 * Format: [sbseq:32][sentinel:1][index:31]
 */
static ef_shrub_buffer_id make_buffer_id(int index, bool sentinel,
                                         uint32_t sbseq)
{
  EF_VI_ASSERT(index >= 0);
  return ((uint64_t)sbseq << 32) | ((uint64_t)sentinel << 31) | (uint64_t)index;
}

static bool fifo_has_space(ef_shrub_buffer_id* fifo, int fifo_size,
                           int fifo_index)
{
  return fifo_size > 0 && fifo[fifo_index] == EF_SHRUB_INVALID_BUFFER;
}

static int next_fifo_index(int index, int fifo_size)
{
  return index == fifo_size - 1 ? 0 : index + 1;
}

static int prev_fifo_index(int index, int fifo_size)
{
  return index == 0 ? fifo_size - 1 : index - 1;
}

static size_t buffer_total_bytes(struct ef_shrub_queue* queue)
{
  return EF_VI_ROUND_UP(queue->buffer_count * queue->buffer_bytes,
                        CI_HUGEPAGE_SIZE);
}

static int queue_alloc_fifo(struct ef_shrub_queue* queue)
{
  int i;

  queue->fifo = calloc(queue->fifo_size, sizeof(queue->fifo[0]));
  if( queue->fifo == NULL )
    return -ENOMEM;

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

  fd = ef_shrub_server_memfd_create("ef_shrub_buffer",
                                    buffer_total_bytes(queue), true);
  if( fd < 0 )
    return fd;
  queue->shared_fds[EF_SHRUB_FD_BUFFERS] = fd;

  return 0;
}

static void release_buffer(struct ef_shrub_queue* queue,
                           struct ef_shrub_connection* connection,
                           int buffer_index, bool full_free)
{
  struct ef_shrub_queue_buffer* buffer = &queue->buffers[buffer_index];
  int fifo_index;

  EF_VI_ASSERT(buffer_index != EF_SHRUB_INVALID_BUFFER);

  if( ! connection->buffer_refs[buffer_index] )
    return;

  /* Find this buffer in the server fifo */
  for( fifo_index = prev_fifo_index(connection->server_fifo_index,
                                    connection->fifo_size);
       connection->server_fifo[fifo_index] != EF_SHRUB_INVALID_BUFFER;
       fifo_index = prev_fifo_index(fifo_index, connection->fifo_size) )
    if( ef_shrub_buffer_index(connection->server_fifo[fifo_index]) == buffer_index)
      break;

  /* Clear the buffers before and including this one in the server fifo */
  for( ;
       fifo_index != connection->server_fifo_index;
       fifo_index = prev_fifo_index(fifo_index, connection->fifo_size) )
    connection->server_fifo[fifo_index] = EF_SHRUB_INVALID_BUFFER;

  connection->buffer_refs[buffer_index] = false;
  connection->referenced_buffer_count--;

  if( --buffer->ref_count == 0 && full_free ) {
    struct ef_shrub_connection* conn;

#ifndef NDEBUG
    for( conn = queue->connections; conn; conn = conn->next )
      EF_VI_ASSERT(!conn->buffer_refs[buffer_index]);
#endif

    /* Remove all FIFO entries older than the buffer being freed. All
     * clients must have taken these (or they wouldn't be releasing a later
     * buffer), and we don't want a client holding on to a buffer to prevent
     * the FIFO from refilling. */
    if( buffer->fifo_index >= 0 ) {
      int remove_fifo_index = buffer->fifo_index;
      size_t next_valid_fifo_index = next_fifo_index(buffer->fifo_index,
                                                     queue->fifo_size);

      /* Update connections to avoid referencing cleared regions of the
       * queue fifo. */
      for( conn = queue->connections; conn != NULL; conn = conn->next ) {
        /* If queue->fifo_index < conn->queue_fifo_index <= buffer->fifo_index
         * then this connection points to data that we're about to destroy, so
         * we should update it to point to the first bit of valid data. This
         * action will drop buffers from the perspective of this connection. */
        if( ! SEQ_BTW((size_t)conn->queue_fifo_index,
                      (size_t)next_valid_fifo_index,
                      (size_t)queue->fifo_index) ) {
          /* We need to offset the amount here by the fifo size to account
           * for fifo sizes that aren't powers of two. */
          int n_dropped =
            (next_valid_fifo_index + queue->fifo_size - conn->queue_fifo_index)
              % queue->fifo_size;
          conn->stats.dropped_buffers += n_dropped;
          conn->queue_fifo_index = next_valid_fifo_index;
        }
        /* Either this connection is looking at a valid buffer, or it's waiting
         * for the next valid buffer from the queue fifo */
        EF_VI_ASSERT(conn->queue_fifo_index == queue->fifo_index ||
                     queue->fifo[conn->queue_fifo_index] !=
                     EF_SHRUB_INVALID_BUFFER);
      }

      /* Empty out the fifo entries */
      while( remove_fifo_index != queue->fifo_index ) {
        ef_shrub_buffer_id id = queue->fifo[remove_fifo_index];
        if( id != EF_SHRUB_INVALID_BUFFER ) {
          int remove_buffer_index = ef_shrub_buffer_index(id);
          queue->buffers[remove_buffer_index].fifo_index = -1;
          queue->fifo[remove_fifo_index] = EF_SHRUB_INVALID_BUFFER;
        }
        remove_fifo_index = prev_fifo_index(remove_fifo_index, queue->fifo_size);
      }
    }

    queue->vi->efct_rxqs.ops->free(queue->vi, queue->ix, buffer_index);
  }
}

static void poll_client_fifo(struct ef_shrub_queue* queue,
                             struct ef_shrub_connection* connection)
{
  int fifo_index = connection->client_fifo_index;

  /* The client doesn't post the sentinel value, just the buffer index,
   * so there's no need to call get_buffer_index */
  ef_shrub_buffer_id buffer_index = connection->client_fifo[fifo_index];

  if( buffer_index == EF_SHRUB_INVALID_BUFFER )
    return;

  connection->client_fifo[fifo_index] = EF_SHRUB_INVALID_BUFFER;
  connection->client_fifo_index = next_fifo_index(fifo_index,
                                                  queue->fifo_size);

  if( buffer_index >= queue->buffer_count )
    return; /* TBD: the client is misbehaving, should we disconnect? */

  release_buffer(queue, connection, buffer_index, true);
}

static void poll_client_fifos(struct ef_shrub_queue* queue)
{
  struct ef_shrub_connection* c;
  for( c = queue->connections; c != NULL; c = c->next )
    poll_client_fifo(queue, c);
}

static void poll_queue_fifo(struct ef_shrub_queue* queue)
{
  while( fifo_has_space(queue->fifo, queue->fifo_size, queue->fifo_index) ) {
    struct ef_shrub_queue_buffer* buffer = NULL;
    int buffer_index;
    unsigned sbseq;
    bool sentinel;

    /* Having space in our fifo doesn't necessarily mean we have any buffers to
     * add to it, even though we size our fifo to support posting all of our
     * buffers an no more. It is possible that buffer A is not freed but a
     * later buffer B is freed, in which case we remove buffer A from the fifo
     * to make space for other buffers. In this case, we will be left with a
     * gap until buffer A is released and so may get -EAGAIN below. */
    buffer_index = queue->vi->efct_rxqs.ops->next(queue->vi, queue->ix,
                                                  &sentinel, &sbseq);
    if( buffer_index < 0 )
      return;

    EF_VI_ASSERT(buffer_index < queue->buffer_count);
    buffer = &queue->buffers[buffer_index];
    EF_VI_ASSERT(buffer->ref_count == 0);

    EF_VI_ASSERT(queue->fifo[queue->fifo_index] == EF_SHRUB_INVALID_BUFFER);
    queue->fifo[queue->fifo_index] = make_buffer_id(buffer_index, sentinel,
                                                    sbseq);
    buffer->fifo_index = queue->fifo_index;
    queue->fifo_index = next_fifo_index(queue->fifo_index, queue->fifo_size);
  }
}

static bool connection_can_have_buffer(struct ef_shrub_queue* queue,
                                       struct ef_shrub_connection* conn)
{
  /* If the connection's fifo is full, then it can't have any more buffers */
  if( ! fifo_has_space(conn->server_fifo, conn->fifo_size,
                       conn->server_fifo_index) )
    return false;

  /* If the connection has been given its maximum number of buffers, then it
   * must free some before we give it any more. */
  if( conn->referenced_buffer_count >= conn->max_referenced_buffers )
    return false;

  return true;
}

static void poll_server_fifo(struct ef_shrub_queue* queue,
                             struct ef_shrub_connection* conn)
{
  while( connection_can_have_buffer(queue, conn) ) {
    struct ef_shrub_queue_buffer* buffer;
    ef_shrub_buffer_id buffer_id;
    int buffer_index;

    buffer_id = queue->fifo[conn->queue_fifo_index];
    if( buffer_id == EF_SHRUB_INVALID_BUFFER )
      break;
    conn->queue_fifo_index = next_fifo_index(conn->queue_fifo_index,
                                             queue->fifo_size);
    buffer_index = ef_shrub_buffer_index(buffer_id);
    EF_VI_ASSERT(buffer_index < queue->buffer_count);
    buffer = &queue->buffers[buffer_index];

    EF_VI_ASSERT(!conn->buffer_refs[buffer_index]);
    conn->buffer_refs[buffer_index] = true;
    conn->referenced_buffer_count++;
    buffer->ref_count++;

    EF_VI_ASSERT(conn->server_fifo[conn->server_fifo_index] ==
                 EF_SHRUB_INVALID_BUFFER);
    conn->server_fifo[conn->server_fifo_index] = buffer_id;
    conn->server_fifo_index = next_fifo_index(conn->server_fifo_index,
                                              conn->fifo_size);
  }
}

static void poll_server_fifos(struct ef_shrub_queue* queue)
{
  struct ef_shrub_connection* c;
  for( c = queue->connections; c != NULL; c = c->next )
    poll_server_fifo(queue, c);
}

int ef_shrub_queue_open(struct ef_shrub_queue* queue,
                        struct ef_vi* vi,
                        size_t buffer_bytes,
                        size_t buffer_count,
                        size_t fifo_size,
                        int client_fifo_fd,
                        int server_fifo_fd,
                        int qid,
                        bool use_interrupts)
{
  int rc;

  memset(queue, 0, sizeof(*queue));
  queue->shared_fds[EF_SHRUB_FD_CLIENT_FIFO] = client_fifo_fd;
  queue->shared_fds[EF_SHRUB_FD_SERVER_FIFO] = server_fifo_fd;
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

  rc = queue_alloc_fifo(queue);
  if( rc < 0 )
    goto fail_alloc_fifo;

  rc = vi->efct_rxqs.ops->attach(vi,
                                 qid,
                                 queue->shared_fds[EF_SHRUB_FD_BUFFERS],
                                 queue->buffer_count,
                                 false, use_interrupts);
  if (rc < 0)
    goto fail_queue_attach;

  queue->ix = rc;
  return 0;

fail_queue_attach:
  free(queue->fifo);
fail_alloc_fifo:
  close(queue->shared_fds[EF_SHRUB_FD_BUFFERS]);
fail_shared:
  free(queue->buffers);
  queue->fifo_size = 0;
  return rc;
}

void ef_shrub_queue_close(struct ef_shrub_queue* queue)
{
  /* TODO ON-16708 close connections */
  queue->vi->efct_rxqs.ops->detach(queue->vi, queue->ix);
  free(queue->fifo);
  close(queue->shared_fds[EF_SHRUB_FD_BUFFERS]);
  free(queue->buffers);
  queue->fifo_size = 0;
}

void ef_shrub_queue_poll(struct ef_shrub_queue* queue)
{
  /* Handle client requests to free buffers */
  poll_client_fifos(queue);

  /* Update our own fifo with any newly postable buffers */
  poll_queue_fifo(queue);

  /* Post any new buffers to clients that can accept them */
  poll_server_fifos(queue);
}

void ef_shrub_queue_attached(struct ef_shrub_queue* queue,
                             struct ef_shrub_connection* connection)
{
  int fifo_index = queue->fifo_index;
  int prev_index = prev_fifo_index(fifo_index, queue->fifo_size);

  /* Scan backwards over valid buffers to find the most recent empty slot in
   * the fifo. The synchronisation point must be after that point, so we
   * provide the earliest valid buffer we find to the client. The client will
   * scan forwards from there to find the synchronisation point. */
  while( queue->fifo[prev_index] != EF_SHRUB_INVALID_BUFFER ) {
    fifo_index = prev_index;

    /* This should never happen since the FIFO should never be completely full,
     * but we shouldn't loop forever if it does happen somehow. */
    assert(fifo_index != queue->fifo_index);
    if( fifo_index == queue->fifo_index )
      break; /* The queue is full and we've reached the oldest buffer */

    prev_index = prev_fifo_index(fifo_index, queue->fifo_size);
  }

  queue->connection_count++;
  connection->queue_fifo_index = fifo_index;

  /* After finding the last valid buffer in the queue fifo, post the available
   * buffers to the client as we would in a normal poll. */
  poll_server_fifo(queue, connection);
}

void ef_shrub_queue_detached(struct ef_shrub_queue* queue,
                             struct ef_shrub_connection* connection)
{
  struct ef_shrub_connection* conn;
  int max_queue_fifo_index;
  int buffer_index;

  /* Find the connection which has consumed the most of the queue's fifo that
   * isn't us. The first valid slot will be the queue's fifo index + 1, but
   * we account for the later subtraction by incrementing twice here. */
  max_queue_fifo_index =
    next_fifo_index(next_fifo_index(queue->fifo_index, queue->fifo_size),
                    queue->fifo_size);
  for( conn = queue->connections; conn; conn = conn->next )
    if( conn != connection &&
        SEQ_BTW(conn->queue_fifo_index,
                max_queue_fifo_index,
                queue->fifo_index) )
        max_queue_fifo_index = conn->queue_fifo_index;

  /* We want to store one less than the max queue fifo index as we're only
   * interested in buffers that are in use, rather than the buffer that a
   * connection would get next. */
  max_queue_fifo_index = prev_fifo_index(max_queue_fifo_index,
                                         queue->fifo_size);

  for( buffer_index = 0; buffer_index < queue->buffer_count; buffer_index++ ) {
    struct ef_shrub_queue_buffer* buffer = &queue->buffers[buffer_index];
    bool full_free;

    if( ! connection->buffer_refs[buffer_index] )
      continue;

    /* If we are the only connection to consume this buffer from the queue fifo
     * then we shouldn't do a full free. */
    full_free = buffer->fifo_index == -1 ||
                SEQ_BTW((size_t)max_queue_fifo_index,
                        (size_t)buffer->fifo_index,
                        (size_t)queue->fifo_index);

    release_buffer(queue, connection, buffer_index, full_free);
  }

  EF_VI_ASSERT(connection->referenced_buffer_count == 0);
  queue->reserved_buffer_count -= connection->max_referenced_buffers;

  if( --queue->connection_count == 0 )
    ef_shrub_queue_close(queue);
}

void ef_shrub_queue_dump_to_fd(struct ef_shrub_queue* queue, int fd,
                               char* buf, size_t buflen)
{
  struct ef_shrub_connection *connection;
  ef_vi_efct_rxq_state *rxq_state =
    &queue->vi->ep_state->rxq.efct_state[queue->ix];
#ifndef NDEBUG
  int fifo_index, buffer_index;
  int idx, iter;
#endif

  shrub_log_to_fd(fd, buf, buflen, "  rxq[%d]: hw: %d\n",
                  queue->ix, rxq_state->qid);
  shrub_log_to_fd(fd, buf, buflen, "    sbseq: %d free_head: %d "
                  "fifo_head: %d\n", rxq_state->sbseq,
                  rxq_state->free_head, rxq_state->fifo_head);
  shrub_log_to_fd(fd, buf, buflen, "    tail_hw: %d tail_sw: %d "
                  "count_hw: %d count_sw: %d\n", rxq_state->fifo_tail_hw,
                  rxq_state->fifo_tail_sw, rxq_state->fifo_count_hw,
                  rxq_state->fifo_count_sw);

#ifndef NDEBUG
  shrub_log_to_fd(fd, buf, buflen, "    free_list: ");
  for( idx = 0, iter = rxq_state->free_head;
       idx < queue->buffer_count && iter != -1;
       idx++, iter = efct_rx_desc_for_sb(queue->vi, queue->ix, iter)->sbid_next ) {
    shrub_log_to_fd(fd, buf, buflen, "%s%d", idx == 0 ? "" : " -> ", iter);
  }
  shrub_log_to_fd(fd, buf, buflen, "\n");

  shrub_log_to_fd(fd, buf, buflen, "    hw_list: ");
  for( idx = 0, iter = rxq_state->fifo_tail_hw;
       idx < rxq_state->fifo_count_hw && iter != -1;
       idx++, iter = efct_rx_desc_for_sb(queue->vi, queue->ix, iter)->sbid_next ) {
    shrub_log_to_fd(fd, buf, buflen, "%s%d", idx == 0 ? "" : " -> ", iter);
  }
  shrub_log_to_fd(fd, buf, buflen, "\n");

  shrub_log_to_fd(fd, buf, buflen, "    sw_list: ");
  for( idx = 0, iter = rxq_state->fifo_tail_sw;
       idx < rxq_state->fifo_count_sw && iter != -1;
       idx++, iter = efct_rx_desc_for_sb(queue->vi, queue->ix, iter)->sbid_next ) {
    shrub_log_to_fd(fd, buf, buflen, "%s%d", idx == 0 ? "" : " -> ", iter);
  }
  shrub_log_to_fd(fd, buf, buflen, "\n");
#endif

  shrub_log_to_fd(fd, buf, buflen, "    fifo_size: %d\n", queue->fifo_size);
#ifndef NDEBUG
  for( fifo_index = prev_fifo_index(queue->fifo_index, queue->fifo_size);
       queue->fifo[fifo_index] != EF_SHRUB_INVALID_BUFFER;
       fifo_index = prev_fifo_index(fifo_index, queue->fifo_size) ) {
    ef_shrub_buffer_id buffer_id = queue->fifo[fifo_index];
    shrub_log_to_fd(fd, buf, buflen, "    fifo[%d]: buffer_id: %#llx "
                    "buffer_index: %d\n", fifo_index, buffer_id,
                    ef_shrub_buffer_index(buffer_id));
    shrub_log_to_fd(fd, buf, buflen, "             buffer_sentinel: %d "
                    "buffer_sbseq: %d\n", ef_shrub_buffer_sentinel(buffer_id),
                    ef_shrub_buffer_sbseq(buffer_id));
  }
#endif

  shrub_log_to_fd(fd, buf, buflen,
                  "    buffer_count: %zu reserved_buffer_count: %zu\n",
                  queue->buffer_count, queue->reserved_buffer_count);
#ifndef NDEBUG
  for( buffer_index = 0; buffer_index < queue->buffer_count; buffer_index++ ) {
    struct ef_shrub_queue_buffer* buffer = &queue->buffers[buffer_index];
    if( buffer->ref_count != 0 ) {
      shrub_log_to_fd(fd, buf, buflen, "    buffer[%d]: ref_count: %d "
                      "fifo_index: %d\n", buffer_index, buffer->ref_count,
                      buffer->fifo_index);
    }
  }
#endif

  shrub_log_to_fd(fd, buf, buflen, "    connection_count: %llu\n",
                  queue->connection_count);
  for( connection = queue->connections;
       connection != NULL;
       connection = connection->next )
    ef_shrub_connection_dump_to_fd(connection, fd, buf, buflen);
}

int ef_shrub_queue_buffer_get_ref_count(struct ef_shrub_queue* queue,
                                        int buffer_index)
{
  if( buffer_index < 0 || buffer_index >= queue->buffer_count )
    return 0;

  return queue->buffers[buffer_index].ref_count;
}
