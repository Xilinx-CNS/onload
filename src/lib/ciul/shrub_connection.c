/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

#include "ef_vi_internal.h"
#include "shrub_queue.h"
#include "shrub_connection.h"
#include "shrub_server_sockets.h"

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

