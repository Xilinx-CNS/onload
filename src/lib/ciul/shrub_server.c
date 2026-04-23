/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

#include "ef_vi_internal.h"

#include <etherfabric/internal/shrub_server.h>
#include <etherfabric/internal/shrub_shared.h>

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
  size_t server_fifo_offset;
  int server_fifo_fd;
  unsigned pd_excl_rxq_tok;
  bool use_interrupts;
  struct timespec last_disconnection;
  const int* controller_wakeup_fd;
  size_t n_wakeup_registered;
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

static int ef_shrub_server_wakeup_set_add(struct ef_shrub_server* server,
                                          struct ef_shrub_connection* conn)
{
  epoll_data_t epoll_data = {0};
  int rc;

  if( conn->requested_wakeups )
    return -EALREADY;

  if( ! server->use_interrupts )
    return 0;

  if( ! server->controller_wakeup_fd )
    return -EINVAL;

  if( server->n_wakeup_registered > 0 ) {
    server->n_wakeup_registered++;
    conn->requested_wakeups = true;
    return 0;
  }

  rc = ef_shrub_server_epoll_add(*server->controller_wakeup_fd, server->vi->dh,
                                 epoll_data);
  if( rc < 0 ) {
    ef_log("Error: failed to add server VI to wakeup set: %d (%s)",
           rc, strerror(-rc));
    return rc;
  }

  server->n_wakeup_registered++;
  conn->requested_wakeups = true;

  return 0;
}

static void ef_shrub_server_wakeup_set_del(struct ef_shrub_server* server,
                                           struct ef_shrub_connection* conn)
{
  int rc;

  if( ! server->use_interrupts || ! server->controller_wakeup_fd ||
      ! conn->requested_wakeups || server->n_wakeup_registered == 0 )
    return;

  conn->requested_wakeups = false;
  if( --server->n_wakeup_registered > 0 )
    return;

  rc = ef_shrub_server_epoll_del(*server->controller_wakeup_fd, server->vi->dh);
  if( rc < 0 )
    ef_log("Warning: failed to remove server VI from wakeup set: %d (%s)",
           rc, strerror(-rc));
}

static int unix_server_poll(struct ef_shrub_server* server)
{
  int rc;
  struct epoll_event event;
  int n_events = 0;
  rc = ef_shrub_server_epoll_wait(&server->sockets, &event);
  if( rc > 0 ) {
    n_events = rc;
    if( event.events & EPOLLHUP )
      rc = server_connection_closed(server, event.data.ptr);
    else if( event.data.ptr == NULL )
      rc = server_connection_opened(server);
    else if( event.events & EPOLLIN )
      rc = server_request_received(server, event.data.ptr);
  }
  return (rc < 0) ? rc : n_events;
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

bool ef_shrub_server_has_clients(struct ef_shrub_server* server)
{
  int i;

  for( i = 0; i < sizeof(server->queues) / sizeof(server->queues[0]); i++ )
    if( server->queues[i].connections )
      return true;

  return false;
}

struct timespec
ef_shrub_server_get_last_disconnection_time(struct ef_shrub_server* server)
{
  return server->last_disconnection;
}

static struct ef_shrub_queue*
find_queue(struct ef_shrub_server* server, int qid)
{
  int i;
  struct ef_shrub_queue* unused = NULL;
  for( i = 0; i < EF_VI_MAX_EFCT_RXQS; ++i ) {
    struct ef_shrub_queue* queue = &server->queues[i];
    if( queue->connections == NULL )
      unused = queue;
    else if( qid < 0 || queue->qid == qid )
      return queue;
  }

  return unused;
}

static int server_request_queue(struct ef_shrub_server* server,
                                struct ef_shrub_connection* connection,
                                int qid, size_t max_connection_buffers)
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
                             server->server_fifo_fd, qid,
                             server->use_interrupts);
    if( rc < 0 )
      return rc;
  }

  connection->max_referenced_buffers = max_connection_buffers;

  rc = ef_shrub_connection_attach_queue(connection, queue);
  if( rc < 0 )
    return rc;

  rc = ef_shrub_connection_send_metrics(connection);
  if( rc < 0 )
    return rc;

  connection->next = queue->connections;
  queue->connections = connection;
  ef_shrub_queue_attached(queue, connection);

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
                                   server->server_fifo_fd,
                                   &server->server_fifo_offset,
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

  rc = ef_shrub_server_wakeup_set_add(server, connection);
  if( rc < 0 )
    goto fail_out;

  epoll_data.ptr = connection;
  rc = ef_shrub_server_epoll_add(server->sockets.epoll, socket, epoll_data);
  if( rc < 0 )
    goto fail_out;

  return rc;

fail_out:
  /* Closing the connection will remove this server from the wakeup set if
   * it needs to */
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

static int server_request_filter_info(struct ef_shrub_server* server,
                                      struct ef_shrub_connection* connection)
{
  return ef_shrub_connection_send_filter_info(connection,
                                              server->pd_excl_rxq_tok,
                                              server->use_interrupts);
}

static int server_request_received(struct ef_shrub_server* server,
                                   struct ef_shrub_connection* connection)
{
  struct ef_shrub_request request;
  int rc;
  int qid;

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
  case EF_SHRUB_REQUEST_FILTER_INFO:
    rc = server_request_filter_info(server, connection);
    /* Client will connect again once it has an rxq to attach to. Remove it from
     * the epoll set */
    goto out_close;
  case EF_SHRUB_REQUEST_QUEUE:
    qid = request.queue.qid == EF_SHRUB_QUEUE_ANY ? -1 : request.queue.qid;
    rc = server_request_queue(server, connection, qid,
                              request.queue.max_connection_buffers);
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
    ef_shrub_queue_detached(queue, connection);
  }

  if( connection->socket >= 0 ) {
    ef_shrub_server_close_fd(connection->socket);
    connection->socket = -1;
  }

  ef_shrub_server_wakeup_set_del(server, connection);

  connection->next = server->closed_connections;
  server->closed_connections = connection;

  clock_gettime(CLOCK_MONOTONIC, &server->last_disconnection);

  return 0;
}

int ef_shrub_server_open(struct ef_vi* vi,
                         struct ef_shrub_server** server_out,
                         const char* server_addr,
                         size_t buffer_bytes,
                         size_t buffer_count,
                         bool use_irqs,
                         const int* controller_wakeup_fd)
{
  struct ef_shrub_server *server;
  epoll_data_t epoll_data = {0};
  int rc;

  ef_shrub_server_remove(server_addr);

  if( ! controller_wakeup_fd )
    return -EINVAL;

  server = calloc(1, sizeof(*server));
  if( server == NULL)
    return -ENOMEM;

  rc = ef_shrub_server_sockets_open(&server->sockets, server_addr);
  if( rc < 0 )
    goto fail_sockets;

  server->controller_wakeup_fd = controller_wakeup_fd;
  server->use_interrupts = use_irqs;
  if( use_irqs ) {
    rc = ef_shrub_server_epoll_add(*server->controller_wakeup_fd,
                                   server->sockets.epoll, epoll_data);
    if( rc < 0 )
      goto fail_add_to_wakeup;
  }

  rc = ef_shrub_server_memfd_create("ef_shrub_client_fifo", 0, false);
  if( rc < 0 )
    goto fail_memfd_client;

  server->client_fifo_fd = rc;

  rc = ef_shrub_server_memfd_create("ef_shrub_server_fifo", 0, false);
  if( rc < 0 )
    goto fail_memfd_server;

  server->server_fifo_fd = rc;

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
  ef_shrub_server_close_fd(server->server_fifo_fd);
fail_memfd_server:
  ef_shrub_server_close_fd(server->client_fifo_fd);
fail_memfd_client:
  if( use_irqs )
    ef_shrub_server_epoll_del(*server->controller_wakeup_fd,
                              server->sockets.epoll);
fail_add_to_wakeup:
  ef_shrub_server_sockets_close(&server->sockets);
fail_sockets:
  free(server);
  return rc;
}

int ef_shrub_server_poll(struct ef_shrub_server* server)
{
  int n_events = 0;
  int rc;
  int i;

  rc = unix_server_poll(server);
  n_events += (rc > 0) ? rc : 0;

  for( i = 0; i < EF_VI_MAX_EFCT_RXQS; ++i )
    n_events += ef_shrub_queue_poll(&server->queues[i]);

  return n_events;
}

void ef_shrub_server_close(struct ef_shrub_server* server)
{
  int i;

  for( i = 0; i < EF_VI_MAX_EFCT_RXQS; ++i )
    if( server->queues[i].connection_count != 0 )
      ef_shrub_queue_close(&server->queues[i]);

  /* We're closing, so lets bypass any referencing checking here and just
   * remove ourselves from the wakeup set to be safe. */
  if( server->n_wakeup_registered > 0 ) {
    server->n_wakeup_registered = 0;
    ef_shrub_server_epoll_del(*server->controller_wakeup_fd, server->vi->dh);
  }

  ef_shrub_server_close_fd(server->server_fifo_fd);
  ef_shrub_server_close_fd(server->client_fifo_fd);
  ef_shrub_server_sockets_close(&server->sockets);
  if ( server->socket_path[0] != '\0' )
    ef_shrub_server_remove(server->socket_path);
  free(server);
}

void ef_shrub_server_dump_to_fd(struct ef_shrub_server* server, int fd,
                                char* buf, size_t buflen)
{
  int i;

  shrub_log_to_fd(fd, buf, buflen, "  pd token: %u buffer count: %llu "
                                   "interrupt mode: %s\n",
                  server->pd_excl_rxq_tok, server->buffer_count,
                  server->use_interrupts ? "enabled" : "disabled");
  shrub_log_to_fd(fd, buf, buflen, "  Registered wakeup count: %lu\n",
                  server->n_wakeup_registered);

  for( i = 0; i < sizeof(server->queues) / sizeof(server->queues[0]); i++ )
    if( server->queues[i].fifo_size )
      ef_shrub_queue_dump_to_fd(&server->queues[i], fd, buf, buflen);
}
