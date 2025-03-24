/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

#include "ef_vi_internal.h"
#include "shrub_queue.h"
#include "shrub_connection.h"
#include "shrub_server_sockets.h"

#include <unistd.h>
#include <sys/mman.h>

static int client_total_bytes(struct ef_shrub_queue* queue)
{
  return ef_shrub_fifo_bytes(queue) +
    EF_VI_ROUND_UP(sizeof(struct ef_shrub_client_state), PAGE_SIZE);
}

static struct ef_shrub_client_state*
get_client_state(struct ef_shrub_connection* connection)
{
  return (void*)((char*)connection->fifo +
                 ef_shrub_fifo_bytes(connection->queue));
}

static uint32_t get_buffer_id(ef_shrub_buffer_id id)
{
  ci_dword_t id2;
  id2.u32[0] = id;
  return CI_DWORD_FIELD(id2, EF_SHRUB_BUFFER_ID);
}

struct ef_shrub_connection*
ef_shrub_connection_alloc(struct ef_shrub_queue* queue)
{
  int i, fd, rc;
  struct ef_shrub_connection* connection;
  void* map;
  size_t offset;

  if( queue->closed_connections ) {
    connection = queue->closed_connections;
    queue->closed_connections = connection->next;
    return connection;
  }

  connection = calloc(1, sizeof(struct ef_shrub_connection));
  if( connection == NULL )
    return NULL;

  fd = queue->shared_fds[EF_SHRUB_FD_CLIENT_FIFO];

  offset = queue->connection_count * client_total_bytes(queue);
  rc = ftruncate(fd, offset + client_total_bytes(queue));
  if( rc < 0 )
    goto fail_fifo;

  map = mmap(NULL, client_total_bytes(queue),
             PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_POPULATE, fd, offset);
  if( map == MAP_FAILED )
    goto fail_fifo;

  connection->fifo_mmap_offset = offset;
  connection->fifo = map;

  for( i = 0; i < queue->fifo_size; ++i )
    connection->fifo[i] = EF_SHRUB_INVALID_BUFFER;

  return connection;

fail_fifo:
  free(connection);
  return NULL;
}

void ef_shrub_connection_attach(struct ef_shrub_connection* connection,
                                struct ef_shrub_queue* queue)
{
  struct ef_shrub_client_state* state;
  int i;

  assert(connection->queue == NULL);
  connection->queue = queue;

  connection->next = queue->connections;
  queue->connections = connection;

  if ( queue->connection_count > 0 ) {
    state = (void*)((char*)connection->fifo + ef_shrub_fifo_bytes(queue));
    i = state->server_fifo_index;
    while ( i != queue->fifo_index ) {
      ef_shrub_buffer_id buffer = queue->fifo[i];
      assert(buffer != EF_SHRUB_INVALID_BUFFER);
      queue->buffer_refs[get_buffer_id(buffer)]++; 
      i = (i == queue->fifo_size - 1 ? 0: i + 1);
    } 
  }

  queue->connection_count++;
}

void ef_shrub_connection_detach(struct ef_shrub_connection* connection,
                                struct ef_vi* vi)
{
  struct ef_shrub_client_state* state = get_client_state(connection);
  struct ef_shrub_queue* queue = connection->queue;
  int i;

  /* TBD would a doubly linked list or something be better? */
  if( connection == queue->connections ) {
    queue->connections = connection->next;
  }
  else {
    struct ef_shrub_connection* c;
    for( c = queue->connections; c != NULL; c = c->next ) {
      if( c->next == connection ) {
        c->next = connection->next;
        break;
      }
    }
  }

  connection->queue = NULL;
  connection->next = queue->closed_connections;
  queue->closed_connections = connection;

  i = state->server_fifo_index;
  while ( i != queue->fifo_index ) {
    ef_shrub_buffer_id buffer = queue->fifo[i];
    assert(buffer != EF_SHRUB_INVALID_BUFFER);
    ef_shrub_queue_release_buffer(queue, vi, get_buffer_id(buffer));
    i = (i == queue->fifo_size - 1 ? 0: i + 1);
  }

  queue->connection_count--;
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

