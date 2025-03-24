/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

#include "ef_vi_internal.h"

#include <etherfabric/shrub_server.h>
#include <etherfabric/shrub_shared.h>
#include <ci/tools/sysdep.h>

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
  /* Array of size res->vi.efct_rxqs.max_qs. */
  struct ef_shrub_queue** shrub_queues;
  unsigned pd_excl_rxq_tok;
  char socket_path[EF_SHRUB_SERVER_SOCKET_LEN];
};

static int server_connection_opened(struct ef_shrub_server* server);
static int server_request_received(struct ef_shrub_server* server, int socket);
static int server_connection_closed(struct ef_shrub_server* server, void *data);

static int unix_server_poll(struct ef_shrub_server* server)
{
  int rc;
  struct epoll_event event;
  rc = ef_shrub_server_epoll_wait(&server->sockets, &event);
  if( rc > 0 ) {
    if( event.events & EPOLLHUP )
      // FIXME event.data.ptr is invalid if we haven't received a request
      rc = server_connection_closed(server, event.data.ptr);
    else if( event.data.ptr == NULL )
      rc = server_connection_opened(server);
    else if( event.events & EPOLLIN )
      rc = server_request_received(server, event.data.fd);
  }
  return rc;
}

static int server_alloc_queue_elems(struct ef_shrub_server *server,
                                    int max_qs)
{
  /* TODO: This is not the max value for HW queues - I suspect we should assign
   * to design params instead. */
  server->shrub_queues = calloc(max_qs, sizeof(server->shrub_queues[0]));
  if( server->shrub_queues == NULL ) {
    return -ENOMEM;
  }
  return 0;
}

static int server_request_queue(struct ef_shrub_server* server, int socket,
                                int qid)
{
  struct ef_shrub_connection* connection;
  struct ef_shrub_queue* queue;
  epoll_data_t epoll_data;
  int rc;

  queue = server->shrub_queues[qid];
  if( queue == NULL ) {
    rc = ef_shrub_queue_open(&queue, server->vi,
                             server->buffer_bytes, server->buffer_count,
                             qid);
    if( rc < 0 )
      return rc;
    server->shrub_queues[qid] = queue;
  }

  connection = ef_shrub_connection_alloc(queue);
  if( connection == NULL ) {
    rc = -1; /* TODO propogate connection_alloc's rc */
    goto fail;
  }

  connection->socket = socket;

  rc = ef_shrub_connection_send_metrics(connection);
  if( rc < 0 )
    goto fail;

  epoll_data.ptr = connection;
  rc = ef_shrub_server_epoll_mod(&server->sockets, socket, epoll_data);
  if( rc < 0 )
    goto fail;

  ef_shrub_connection_attach(connection, queue);
  return 0;

fail:
  connection->next = queue->closed_connections;
  queue->closed_connections = connection;
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
  /* Client will connect again once it has an rxq to attach to. Remove it from
   * the epoll set */
  ef_shrub_server_close_socket(socket);
  return 0;
}

static int server_request_received(struct ef_shrub_server* server, int socket)
{
  struct ef_shrub_request request;
  int rc;

  rc = ef_shrub_server_recv(socket, &request, sizeof(request));
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
    rc = server_request_token(server, socket);
    goto out_close;
  case EF_SHRUB_REQUEST_QUEUE:
    rc = server_request_queue(server, socket, request.requests.queue.qid);
    if( rc < 0 )
      goto out_close;

    break;
  default:
    rc = -EOPNOTSUPP;
    goto out_close;
  }

  return 0;

out_close:
  ef_shrub_server_close_socket(socket);
  return rc;
}

static int server_connection_opened(struct ef_shrub_server* server)
{
  int rc = 0;
  int socket = ef_shrub_server_accept(&server->sockets);
  epoll_data_t epoll_data;

  if( socket < 0 )
    return socket;

  epoll_data.fd = socket;
  rc = ef_shrub_server_epoll_add(&server->sockets, socket, epoll_data);
  if( rc < 0 )
    ef_shrub_server_close_socket(socket);

  return rc;
}

static int server_connection_closed(struct ef_shrub_server* server, void *data)
{
  struct ef_shrub_connection* connection = data;
  ef_shrub_server_close_socket(connection->socket);
  ef_shrub_connection_detach(connection, server->vi);
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

  server->vi = vi;
  strncpy(server->socket_path, server_addr, sizeof(server->socket_path));

  /* TBD Do this and the above as a single allocation. */
  rc = server_alloc_queue_elems(server, vi->efct_rxqs.max_qs);
  if(rc < 0)
    goto fail_queues_alloc;

  rc = server_init_pd_excl_rxq_tok(server);
  if( rc )
    goto fail_init_pd_token;

  server->buffer_count = buffer_count;
  server->buffer_bytes = buffer_bytes;

  *server_out = server;
  return 0;

fail_init_pd_token:
  free(server->shrub_queues);
fail_queues_alloc:
  ef_shrub_server_sockets_close(&server->sockets);
fail_sockets:
  free(server);
  return rc;
}

void ef_shrub_server_poll(struct ef_shrub_server* server)
{
  int ix;

  unix_server_poll(server);
  ci_bit_for_each_set(ix, (const ci_bits*)server->vi->efct_rxqs.active_qs,
                      server->vi->efct_rxqs.max_qs) {
    int qid = efct_get_rxq_state(server->vi, ix)->qid;

    ef_shrub_queue_poll(server->shrub_queues[qid], server->vi);
  }
}

void ef_shrub_server_close(struct ef_shrub_server* server)
{
  int ix;

  ci_bit_for_each_set(ix, (const ci_bits*)server->vi->efct_rxqs.active_qs,
                      server->vi->efct_rxqs.max_qs) {
    int qid = efct_get_rxq_state(server->vi, ix)->qid;

    ef_shrub_queue_close(server->shrub_queues[qid]);
  }

  free(server->shrub_queues);
  server->vi->efct_rxqs.ops->cleanup(server->vi);
  ef_shrub_server_sockets_close(&server->sockets);
  if ( server->socket_path[0] != '\0' )
    ef_shrub_server_remove(server->socket_path);
  free(server);
}
