/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

#include "ef_vi_internal.h"
#include "shrub_queue.h"
#include "shrub_connection.h"
#include "shrub_server_sockets.h"

#include <stdio.h>

struct ef_shrub_client_state*
ef_shrub_connection_client_state(struct ef_shrub_connection* connection)
{
  return (void*)((char*)connection->client_fifo +
                 connection->fifo_size * sizeof(ef_shrub_buffer_id));
}

static int map_shared_state(void** map, int fd, size_t offset, size_t bytes)
{
  int rc;

  rc = ef_shrub_server_memfd_resize(fd, offset + bytes);
  if( rc < 0 )
    return rc;

  rc = ef_shrub_server_mmap(map, bytes, PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_POPULATE, fd, offset);
  if( rc < 0 )
    return rc;

  return 0;
}

int
ef_shrub_connection_alloc(struct ef_shrub_connection** connection_out,
                          int client_fifo_fd, size_t* client_fifo_offset,
                          int server_fifo_fd, size_t* server_fifo_offset,
                          size_t fifo_size)
{
  int i, rc;
  struct ef_shrub_connection* connection;
  size_t fifo_bytes = fifo_size * sizeof(ef_shrub_buffer_id);
  size_t total_client_bytes = fifo_bytes +
    EF_VI_ROUND_UP(sizeof(struct ef_shrub_client_state), PAGE_SIZE);

  connection = calloc(1, sizeof(struct ef_shrub_connection));
  if( connection == NULL )
    return -ENOMEM;

  rc = map_shared_state((void**)&connection->client_fifo, client_fifo_fd,
                        *client_fifo_offset, total_client_bytes);
  if( rc < 0 )
    goto fail_client_map;

  rc = map_shared_state((void**)&connection->server_fifo, server_fifo_fd,
                        *server_fifo_offset, fifo_bytes);
  if( rc < 0 )
    goto fail_server_map;

  connection->client_fifo_mmap_offset = *client_fifo_offset;
  *client_fifo_offset += total_client_bytes;
  connection->server_fifo_mmap_offset = *server_fifo_offset;
  *server_fifo_offset += fifo_bytes;

  connection->fifo_size = fifo_size;
  for( i = 0; i < fifo_size; ++i )
    connection->client_fifo[i] = EF_SHRUB_INVALID_BUFFER;
  for( i = 0; i < fifo_size; ++i )
    connection->server_fifo[i] = EF_SHRUB_INVALID_BUFFER;

  *connection_out = connection;
  return 0;

fail_server_map:
  munmap(connection->client_fifo, total_client_bytes);
fail_client_map:
  free(connection);
  return rc;
}

int ef_shrub_connection_send_token(struct ef_shrub_connection* connection,
                                   unsigned token)
{
  struct ef_shrub_token_response response = {0};
  int rc;

  response.shared_rxq_token = token;
  rc = ef_shrub_server_send(connection->socket, &response, sizeof(response));
  if( rc < 0 )
    return rc;
  if( rc < sizeof(response) )
    return -EIO;

  return 0;
}

int ef_shrub_connection_send_metrics(struct ef_shrub_connection* connection)
{
  int rc;
  struct ef_shrub_queue* queue = connection->queue;
  struct ef_shrub_shared_metrics* metrics =
    &ef_shrub_connection_client_state(connection)->metrics;
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
  metrics->server_fifo_offset = connection->server_fifo_mmap_offset;
  metrics->server_fifo_size = connection->fifo_size;
  metrics->client_fifo_offset = connection->client_fifo_mmap_offset;
  metrics->client_fifo_size = connection->fifo_size;

  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(queue->shared_fds));
  memcpy(CMSG_DATA(cmsg), queue->shared_fds, sizeof(queue->shared_fds));

  rc = ef_shrub_server_sendmsg(connection->socket, &msg);
  if( rc < 0 )
    return -errno;

  return 0;
}

int ef_shrub_connection_attach_queue(struct ef_shrub_connection* connection,
                                     struct ef_shrub_queue* queue)
{
  struct ef_shrub_client_state* client_state =
    ef_shrub_connection_client_state(connection);
  size_t new_reserved_bufs;
  size_t buffer_refs_bytes;
  void* buffer_refs;
  size_t ref_size;
  int i;

  if( ! connection || ! queue )
    return -EINVAL;

  new_reserved_bufs = queue->reserved_buffer_count +
                      connection->max_referenced_buffers;
  if( connection->max_referenced_buffers < EF_SHRUB_CLIENT_BUFFER_COUNT_MIN ||
      new_reserved_bufs > queue->buffer_count )
    return -ENOBUFS;

  connection->queue = queue;

  connection->client_fifo_index = client_state->client_fifo_index = 0;
  connection->server_fifo_index = client_state->server_fifo_index = 0;

  memset(&connection->stats, 0, sizeof(connection->stats));

  /* If our calculation has overflowed, then we can't do much about it except
   * complain that we can't satisfy the memory allocation request. */
  ref_size = sizeof(connection->buffer_refs[0]);
  buffer_refs_bytes = queue->buffer_count * ref_size;
  if( buffer_refs_bytes / ref_size != queue->buffer_count )
    return -ENOMEM;

  buffer_refs = realloc(connection->buffer_refs, buffer_refs_bytes);
  if( buffer_refs == NULL )
    return -ENOMEM;

  connection->buffer_refs = buffer_refs;
  for( i = 0; i < queue->buffer_count; ++i )
    connection->buffer_refs[i] = false;

  for( i = 0; i < connection->fifo_size; i++ ) {
    connection->client_fifo[i] = EF_SHRUB_INVALID_BUFFER;
    connection->server_fifo[i] = EF_SHRUB_INVALID_BUFFER;
  }

  /* We must not fail after setting this, or we should reduce the amount if
   * we do fail. */
  queue->reserved_buffer_count = new_reserved_bufs;

  return 0;
}

#ifndef NDEBUG
static int prev_fifo_index(int index, int fifo_size)
{
  return index == 0 ? fifo_size - 1 : index - 1;
}
#endif

void ef_shrub_connection_dump_to_fd(struct ef_shrub_connection* connection,
                                    int fd, char* buf, size_t buflen)
{
  struct ef_shrub_client_state* client_state =
    ef_shrub_connection_client_state(connection);
  bool print_comma = false;
  int printed_chars = 0;
  int buffer_index;
#ifndef NDEBUG
  int fifo_index;
#endif

  shrub_log_to_fd(fd, buf, buflen, "    connection[fd %d]: "
                  "queue_fifo_index: %llu\n", connection->socket,
                  connection->queue_fifo_index);

  shrub_log_to_fd(fd, buf, buflen,
                  "      server_fifo_index_write: %llu "
                  "server_fifo_index_read: %llu\n"
                  "      server_fifo_size: %llu\n",
                  connection->server_fifo_index,
                  client_state->server_fifo_index,
                  client_state->metrics.server_fifo_size);
#ifndef NDEBUG
  for( fifo_index = prev_fifo_index(connection->server_fifo_index,
                                    client_state->metrics.server_fifo_size);
       connection->server_fifo[fifo_index] != EF_SHRUB_INVALID_BUFFER;
       fifo_index = prev_fifo_index(fifo_index,
                                    client_state->metrics.server_fifo_size) ) {
    ef_shrub_buffer_id buffer_id = connection->server_fifo[fifo_index];
    shrub_log_to_fd(fd, buf, buflen,
                    "      server_fifo[%d]: buffer_id: %#llx "
                    "buffer_index: %d\n", fifo_index, buffer_id,
                    ef_shrub_buffer_index(buffer_id));
    shrub_log_to_fd(fd, buf, buflen,
                    "                      buffer_sentinel: %d "
                    "buffer_sbseq: %d\n", ef_shrub_buffer_sentinel(buffer_id),
                    ef_shrub_buffer_sbseq(buffer_id));
  }
#endif

  shrub_log_to_fd(fd, buf, buflen,
                  "      client_fifo_index_write: %llu "
                  "client_fifo_index_read: %llu \n"
                  "      client_fifo_size: %llu\n",
                  client_state->client_fifo_index,
                  connection->client_fifo_index,
                  client_state->metrics.client_fifo_size);
#ifndef NDEBUG
  for( fifo_index = prev_fifo_index(client_state->client_fifo_index,
                                    client_state->metrics.client_fifo_size);
       connection->client_fifo[fifo_index] != EF_SHRUB_INVALID_BUFFER;
       fifo_index = prev_fifo_index(fifo_index,
                                    client_state->metrics.client_fifo_size) ) {
    ef_shrub_buffer_id buffer_id = connection->client_fifo[fifo_index];
    shrub_log_to_fd(fd, buf, buflen,
                    "      client_fifo[%d]: buffer_id: %#llx "
                    "buffer_index: %d\n", fifo_index, buffer_id,
                    ef_shrub_buffer_index(buffer_id));
    shrub_log_to_fd(fd, buf, buflen,
                    "                      buffer_sentinel: %d "
                    "buffer_sbseq: %d\n", ef_shrub_buffer_sentinel(buffer_id),
                    ef_shrub_buffer_sbseq(buffer_id));
  }
#endif

  shrub_log_to_fd(fd, buf, buflen, "      referenced_buffer_count: %zu "
                  "max_referenced_buffers: %zu\n",
                  connection->referenced_buffer_count,
                  connection->max_referenced_buffers);
#define SHRUB_DUMP_CONN_BUF_REFS_LINE "      buffer_refs: {"
  shrub_log_to_fd(fd, buf, buflen, SHRUB_DUMP_CONN_BUF_REFS_LINE);
  for( buffer_index = 0;
       buffer_index < connection->queue->buffer_count;
       buffer_index++ ) {
    if( connection->buffer_refs[buffer_index] ) {
      const int line_chars = sizeof(SHRUB_DUMP_SECTION_SEPARATOR) -
                             sizeof(SHRUB_DUMP_CONN_BUF_REFS_LINE);
      bool new_line = false;
      int print_len;

      print_len = snprintf(NULL, 0, "%s%d",
                           print_comma ? ", ": "",
                           buffer_index);
      /* If we can't figure out how long the string would be for whatever
       * reason, lets just assume some arbitrary value that will still keep
       * the numbers tightly grouped over multiple lines. */
      if( print_len <= 0 )
        print_len = 5;

      if( printed_chars + print_len > line_chars ) {
        new_line = true;
        printed_chars = 0;
      }

      printed_chars += print_len;

      shrub_log_to_fd(fd, buf, buflen, "%s%s%d",
                      print_comma ? ", ": "",
                      new_line ? "\n                    " : "",
                      buffer_index);

      print_comma = true;
    }
  }
  shrub_log_to_fd(fd, buf, buflen, "}\n");

  shrub_log_to_fd(fd, buf, buflen, "      dropped_buffers: %llu\n",
                  connection->stats.dropped_buffers);
}
