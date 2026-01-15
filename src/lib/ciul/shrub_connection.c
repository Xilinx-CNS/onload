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
  return (void*)((char*)connection->fifo +
                 connection->fifo_size * sizeof(ef_shrub_buffer_id));
}

int
ef_shrub_connection_alloc(struct ef_shrub_connection** connection_out,
                          int fifo_fd, size_t* fifo_offset, size_t fifo_size)
{
  int i, rc;
  struct ef_shrub_connection* connection;
  void* map;
  size_t fifo_bytes = fifo_size * sizeof(ef_shrub_buffer_id);
  size_t total_bytes = fifo_bytes +
    EF_VI_ROUND_UP(sizeof(struct ef_shrub_client_state), PAGE_SIZE);

  connection = calloc(1, sizeof(struct ef_shrub_connection));
  if( connection == NULL )
    return -ENOMEM;

  rc = ef_shrub_server_memfd_resize(fifo_fd, *fifo_offset + total_bytes);
  if( rc < 0 )
    goto fail_fifo;

  rc = ef_shrub_server_mmap(&map, total_bytes, PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_POPULATE, fifo_fd, *fifo_offset);
  if( rc < 0 )
    goto fail_fifo;

  connection->fifo = map;
  connection->fifo_size = fifo_size;
  connection->fifo_mmap_offset = *fifo_offset;
  *fifo_offset += total_bytes;

  for( i = 0; i < fifo_size; ++i )
    connection->fifo[i] = EF_SHRUB_INVALID_BUFFER;

  *connection_out = connection;
  return 0;

fail_fifo:
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
  metrics->server_fifo_size = queue->fifo_size;
  metrics->client_fifo_offset = connection->fifo_mmap_offset;
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
  void* buffer_refs;
  int i;

  if( ! connection || ! queue )
    return -EINVAL;

  connection->queue = queue;

  buffer_refs = reallocarray(connection->buffer_refs,
                             queue->buffer_count,
                             sizeof(connection->buffer_refs[0]));
  if( buffer_refs == NULL )
    return -ENOMEM;

  connection->buffer_refs = buffer_refs;
  for( i = 0; i < queue->buffer_count; ++i )
    connection->buffer_refs[i] = false;

  return 0;
}

void ef_shrub_connection_dump_to_fd(struct ef_shrub_connection* connection,
                                    int fd, char* buf, size_t buflen)
{
  struct ef_shrub_client_state* client_state =
    ef_shrub_connection_client_state(connection);
  bool print_comma = false;
  int printed_chars = 0;
  int buffer_index;

  shrub_log_to_fd(fd, buf, buflen, "    connection[fd %d]: "
                  "server_fifo_index: %llu server_fifo_size: %llu\n",
                  connection->socket, client_state->server_fifo_index,
                  client_state->metrics.server_fifo_size);
  shrub_log_to_fd(fd, buf, buflen, "      client_fifo_index: %llu "
                  "client_fifo_size: %llu\n", client_state->client_fifo_index,
                  client_state->metrics.client_fifo_size);

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
}
