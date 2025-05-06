/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

#include "ef_vi_internal.h"

#include <etherfabric/shrub_server.h>
#include <etherfabric/shrub_shared.h>

#include "shrub_server_sockets.h"
#include "shrub_connection.h"
#include "shrub_queue.h"
#include "logging.h"
#include "driver_access.h"

struct ef_shrub_server {
  struct ef_shrub_server_sockets sockets;
  ef_vi* vi;
  size_t buffer_bytes;
  size_t buffer_count;
  size_t client_fifo_offset;
  int client_fifo_fd;
  unsigned pd_excl_rxq_tok;
  char socket_path[EF_SHRUB_SERVER_SOCKET_LEN];
  struct ef_shrub_connection* closed_connections;
  struct ef_shrub_connection* pending_connections;
  struct ef_shrub_queue queues[EF_VI_MAX_EFCT_RXQS];
};

static size_t fifo_size(struct ef_shrub_server* server)
{
  size_t bytes = (server->buffer_count + 1) * sizeof(ef_shrub_buffer_id);
  size_t pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
  return pages * (PAGE_SIZE / sizeof(ef_shrub_buffer_id));
}

/* Unix server operations */
static int server_connection_opened(struct ef_shrub_server* server);
static int server_request_received(struct ef_shrub_server* server,
                                   struct ef_shrub_connection* connection);
static int server_connection_closed(struct ef_shrub_server* server,
                                    struct ef_shrub_connection* connection);

static int unix_server_poll(struct ef_shrub_server* server)
{
  int rc;
  struct epoll_event event;
  rc = ef_shrub_server_epoll_wait(&server->sockets, &event);
  if( rc > 0 ) {
    if( event.events & EPOLLHUP )
      rc = server_connection_closed(server, event.data.ptr);
    else if( event.data.ptr == NULL )
      rc = server_connection_opened(server);
    else if( event.events & EPOLLIN )
      rc = server_request_received(server, event.data.ptr);
  }
  return rc;
}

static void remove_connection(struct ef_shrub_connection** list,
                              struct ef_shrub_connection* connection)
{
  if( *list == connection ) {
    *list = connection->next;
  }
  else {
    struct ef_shrub_connection* c;
    for( c = *list; c != NULL; c = c->next ) {
      if( c->next == connection ) {
        c->next = connection->next;
        break;
      }
    }
  }
}

static struct ef_shrub_queue*
find_queue(struct ef_shrub_server* server, uint64_t qid)
{
  int i;
  struct ef_shrub_queue* unused = NULL;
  for( i = 0; i < EF_VI_MAX_EFCT_RXQS; ++i ) {
    struct ef_shrub_queue* queue = &server->queues[i];
    if( queue->connections == NULL )
      unused = queue;
    else if( queue->qid == qid )
      return queue;
  }

  return unused;
}

static int server_request_queue(struct ef_shrub_server* server,
                                struct ef_shrub_connection* connection,
                                int qid)
{
  struct ef_shrub_queue* queue;
  int rc;

  if( connection->socket < 0 )
    return -ENOTCONN;

  if( connection->queue != NULL )
    return -EALREADY;

  remove_connection(&server->pending_connections, connection);

  queue = find_queue(server, qid);
  if( queue == NULL )
    return -ENOSPC;

  if( queue->connections == NULL ) {
    rc = ef_shrub_queue_open(queue, server->vi,
                             server->buffer_bytes, server->buffer_count,
                             fifo_size(server), server->client_fifo_fd,
                             qid);
    if( rc < 0 )
      return rc;
  }

  connection->queue = queue;
  rc = ef_shrub_connection_send_metrics(connection);
  if( rc < 0 )
    return rc;

  connection->next = queue->connections;
  queue->connections = connection;
  ef_shrub_queue_attached(queue, ef_shrub_connection_client_state(connection));

  return 0;
}

static int server_connection_opened(struct ef_shrub_server* server)
{
  int rc = 0;
  struct ef_shrub_connection* connection;
  int socket = ef_shrub_server_accept(&server->sockets);
  epoll_data_t epoll_data;

  if( socket < 0 )
    return socket;

  connection = server->closed_connections;
  if( connection == NULL ) {
    rc = ef_shrub_connection_alloc(&connection,
                                   server->client_fifo_fd,
                                   &server->client_fifo_offset,
                                   fifo_size(server));
    if( rc < 0 )
      return rc;
  }
  else {
    server->closed_connections = connection->next;
  }

  connection->socket = socket;
  connection->next = server->pending_connections;
  server->pending_connections = connection;

  epoll_data.ptr = connection;
  rc = ef_shrub_server_epoll_add(&server->sockets, socket, epoll_data);
  if( rc < 0 )
    server_connection_closed(server, connection);

  return rc;
}

static int server_init_pd_excl_rxq_tok(struct ef_shrub_server *server)
{
  ci_resource_op_t op = {};
  int rc = 0;
  op.op = CI_RSOP_PD_EXCL_RXQ_TOKEN_GET;
  op.id = efch_make_resource_id(server->vi->vi_resource_id);
  rc = ef_shrub_server_resource_op(server->vi->dh, &op);
  server->pd_excl_rxq_tok = op.u.pd_excl_rxq_tok_get.token;
  return rc;
}

static int server_request_token(struct ef_shrub_server *server, int socket)
{
  struct ef_shrub_token_response response = {0};
  int rc;

  response.shared_rxq_token = server->pd_excl_rxq_tok;
  rc = ef_shrub_server_send(socket, &response, sizeof(response));
  if( rc < 0 )
    return -errno;
  if( rc < sizeof(response) )
    return -EIO;
  return 0;
}

static int server_request_received(struct ef_shrub_server* server,
                                   struct ef_shrub_connection* connection)
{
  struct ef_shrub_request request;
  int rc;

  rc = ef_shrub_server_recv(connection->socket, &request, sizeof(request));
  if( rc < sizeof(request)) {
    if(rc < 0)
      rc = -errno;
    else
      rc = -EPROTO;

    goto out_close;
  }

  if( request.server_version != EF_SHRUB_VERSION ) {
    rc = -EPROTO;
    goto out_close;
  }

  switch( request.type ) {
  case EF_SHRUB_REQUEST_TOKEN:
    rc = server_request_token(server, connection->socket);
    /* Client will connect again once it has an rxq to attach to. Remove it from
     * the epoll set */
    goto out_close;
  case EF_SHRUB_REQUEST_QUEUE:
    rc = server_request_queue(server, connection, request.requests.queue.qid);
    if( rc < 0 )
      goto out_close;

    break;
  default:
    rc = -EOPNOTSUPP;
    goto out_close;
  }

  return 0;

out_close:
  server_connection_closed(server, connection);
  return rc;
}

static int server_connection_closed(struct ef_shrub_server* server,
                                    struct ef_shrub_connection* connection)
{
  struct ef_shrub_queue* queue = connection->queue;

  if( queue == NULL ) {
    remove_connection(&server->pending_connections, connection);
  }
  else {
    connection->queue = NULL;
    remove_connection(&queue->connections, connection);
    ef_shrub_queue_detached(queue, ef_shrub_connection_client_state(connection));
  }

  if( connection->socket >= 0 ) {
    ef_shrub_server_close_fd(connection->socket);
    connection->socket = -1;
  }

  connection->next = server->closed_connections;
  server->closed_connections = connection;

  return 0;
}

int ef_shrub_server_open(struct ef_vi* vi,
                         struct ef_shrub_server** server_out,
                         const char* server_addr,
                         size_t buffer_bytes,
                         size_t buffer_count)
{
  struct ef_shrub_server *server;
  int rc;

  ef_shrub_server_remove(server_addr);

  server = calloc(1, sizeof(*server));
  if( server == NULL)
    return -ENOMEM;

  rc = ef_shrub_server_sockets_open(&server->sockets, server_addr);
  if( rc < 0 )
    goto fail_sockets;

  rc = ef_shrub_server_memfd_create("ef_shrub_client_fifo", 0, false);
  if( rc < 0 )
    goto fail_memfd;

  server->client_fifo_fd = rc;
  server->vi = vi;
  strncpy(server->socket_path, server_addr, sizeof(server->socket_path));

  rc = server_init_pd_excl_rxq_tok(server);
  if( rc )
    goto fail_init_pd_token;

  server->buffer_count = buffer_count;
  server->buffer_bytes = buffer_bytes;

  *server_out = server;
  return 0;

fail_init_pd_token:
  ef_shrub_server_close_fd(server->client_fifo_fd);
fail_memfd:
  ef_shrub_server_sockets_close(&server->sockets);
fail_sockets:
  free(server);
  return rc;
}

void ef_shrub_server_poll(struct ef_shrub_server* server)
{
  int i;

  unix_server_poll(server);
  for( i = 0; i < EF_VI_MAX_EFCT_RXQS; ++i )
    ef_shrub_queue_poll(&server->queues[i]);
}

void ef_shrub_server_close(struct ef_shrub_server* server)
{
  int i;

  for( i = 0; i < EF_VI_MAX_EFCT_RXQS; ++i )
    ef_shrub_queue_close(&server->queues[i]);

  ef_shrub_server_close_fd(server->client_fifo_fd);
  ef_shrub_server_sockets_close(&server->sockets);
  if ( server->socket_path[0] != '\0' )
    ef_shrub_server_remove(server->socket_path);
  free(server);
}
