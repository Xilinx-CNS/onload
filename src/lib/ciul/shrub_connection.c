/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

#include "ef_vi_internal.h"
#include "shrub_queue.h"
#include "shrub_connection.h"
#include "shrub_server_sockets.h"

#include <unistd.h>
#include <sys/mman.h>

static struct ef_shrub_client_state*
get_client_state(struct ef_shrub_connection* connection)
{
  return (void*)((char*)connection->fifo +
                 connection->fifo_size * sizeof(ef_shrub_buffer_id));
}

struct ef_shrub_connection*
ef_shrub_connection_alloc(int fifo_fd, size_t* fifo_offset, size_t fifo_size)
{
  int i, rc;
  struct ef_shrub_connection* connection;
  void* map;
  size_t fifo_bytes = fifo_size * sizeof(ef_shrub_buffer_id);
  size_t total_bytes = fifo_bytes +
    EF_VI_ROUND_UP(sizeof(struct ef_shrub_client_state), PAGE_SIZE);

  connection = calloc(1, sizeof(struct ef_shrub_connection));
  if( connection == NULL )
    return NULL;

  rc = ftruncate(fifo_fd, *fifo_offset + total_bytes);
  if( rc < 0 )
    goto fail_fifo;

  map = mmap(NULL, total_bytes, PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_POPULATE, fifo_fd, *fifo_offset);
  if( map == MAP_FAILED )
    goto fail_fifo;

  connection->fifo = map;
  connection->fifo_size = fifo_size;
  connection->fifo_mmap_offset = *fifo_offset;
  *fifo_offset += total_bytes;

  for( i = 0; i < fifo_size; ++i )
    connection->fifo[i] = EF_SHRUB_INVALID_BUFFER;

  return connection;

fail_fifo:
  free(connection);
  return NULL;
}

void ef_shrub_connection_attached(struct ef_shrub_connection* connection,
                                  struct ef_shrub_queue* queue)
{
  ef_shrub_queue_attached(queue, get_client_state(connection)->server_fifo_index);
}

void ef_shrub_connection_detached(struct ef_shrub_connection* connection,
                                  struct ef_shrub_queue* queue)
{
  ef_shrub_queue_detached(queue, get_client_state(connection)->server_fifo_index);
}

int ef_shrub_connection_send_metrics(struct ef_shrub_connection* connection)
{
  int rc;
  struct ef_shrub_client_state* state = get_client_state(connection);
  struct ef_shrub_queue* queue = connection->queue;

  //TODO: re-evaluate this if-check startup state case on completion of ON-16190
  if ( queue->connection_count > 0 ) {
    /* Function to scan backwards in the FIFO until it finds the first invalid buffer.
     * The index afterwards is the first valid buffer that we wish to sync upon. */
    int queue_index = queue->fifo_index == 0 ? queue->fifo_size - 1 : queue->fifo_index - 1;
    assert(queue->fifo[queue_index] != EF_SHRUB_INVALID_BUFFER);
    while ( queue->fifo[queue_index] != EF_SHRUB_INVALID_BUFFER ) {
      queue_index--;
      if ( queue_index < 0 )
        queue_index = queue->fifo_size - 1;
    }
    state->server_fifo_index = ( queue_index == queue->fifo_size - 1 ? 0 : queue_index + 1 );
  }

  struct ef_shrub_shared_metrics* metrics = &state->metrics;
  struct iovec iov = {
    .iov_base = metrics,
    .iov_len = sizeof(*metrics)
  };
  char cmsg_buf[CMSG_SPACE(sizeof(queue->shared_fds))];
  struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsg_buf,
    .msg_controllen = sizeof(cmsg_buf)
  };
  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  if( cmsg == NULL )
    return -EPROTO;

  metrics->server_version = EF_SHRUB_VERSION;
  metrics->buffer_bytes = queue->buffer_bytes;
  metrics->buffer_count = queue->buffer_count;
  metrics->server_fifo_size = queue->fifo_size;
  metrics->client_fifo_offset = connection->fifo_mmap_offset;
  metrics->client_fifo_size = queue->fifo_size;

  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(queue->shared_fds));
  memcpy(CMSG_DATA(cmsg), queue->shared_fds, sizeof(queue->shared_fds));

  rc = ef_shrub_server_sendmsg(connection->socket, &msg);
  if( rc < 0 )
    return -errno;

  return 0;
}

