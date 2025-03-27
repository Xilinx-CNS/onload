/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: Copyright (C) 2025, Advanced Micro Devices, Inc. */

/* Functions under test */
#include <etherfabric/shrub_server.h>

/* Test infrastructure */
#include "unit_test.h"

/* Dependencies */
#include <stdint.h>
#include <string.h>
#include <etherfabric/shrub_shared.h>
#include <etherfabric/ef_vi.h>
#include "shrub_queue.h"
#include "shrub_connection.h"
#include "shrub_server_sockets.h"

static const char server_addr[] = "path/to/server/socket";
static const size_t buffer_bytes = 64;
static const size_t buffer_count = 32;

static struct epoll_event* epoll_event;
static int last_accept_fd = 42; /* arbitrary */
static uint64_t last_qid = 413732132; /* arbitrary */
static epoll_data_t last_epoll_data;

static struct ef_vi* vi;
static struct ef_shrub_server* server;
static struct call_state
{
  /* Counting function calls */
  int sockets_open;
  int sockets_close;
  int epoll_add;
  int accept;
  int remove;
  int close;
  int attach;
  int detach;
  int send;
  int cleanup;

  /* Function arguments */
  int fd;
  struct ef_shrub_queue* queue;
  struct ef_shrub_connection* connection;
} *calls;

int ef_shrub_server_sockets_open(struct ef_shrub_server_sockets* sockets,
                                 const char* path)
{
  calls->sockets_open++;
  CHECK(strcmp(path, server_addr), ==, 0);
  return 0;
}

void ef_shrub_server_sockets_close(struct ef_shrub_server_sockets* sockets)
{
  calls->sockets_close++;
}

int ef_shrub_server_epoll_add(struct ef_shrub_server_sockets* sockets,
                              int fd, epoll_data_t data)
{
  calls->epoll_add++;
  calls->fd = fd;
  last_epoll_data = data;
  return 0;
}

int ef_shrub_server_epoll_wait(struct ef_shrub_server_sockets* sockets,
                               struct epoll_event* event)
{
  if( epoll_event == NULL )
    return 0;

  *event = *epoll_event;
  return 1;
}

int ef_shrub_server_remove(const char* path)
{
  calls->remove++;
  CHECK(calls->sockets_open, ==, 0);
  CHECK(strcmp(path, server_addr), ==, 0);
  return 0;
}

int ef_shrub_server_accept(struct ef_shrub_server_sockets* sockets)
{
  calls->accept++;
  return ++last_accept_fd;
}

void ef_shrub_server_close_socket(int fd)
{
  calls->close++;
  calls->fd = fd;
}

static uint64_t client_shrub_version = EF_SHRUB_VERSION;
int ef_shrub_server_recv(int fd, void* data, size_t bytes)
{
  struct ef_shrub_request* req = data;
  CHECK(bytes, ==, sizeof(*req));
  req->server_version = client_shrub_version;
  req->type = EF_SHRUB_REQUEST_QUEUE;
  req->requests.queue.qid = ++last_qid;
  return bytes;
}

int ef_shrub_server_resource_op(int fd, struct ci_resource_op_s* op)
{
  // TODO should check how this is called
  return 0;
}

int ef_shrub_queue_open(struct ef_shrub_queue* queue,
                        struct ef_vi* vi_,
                        size_t buffer_bytes_,
                        size_t buffer_count_,
                        size_t fifo_size,
                        int client_fifo_fd,
                        int qid)
{
  CHECK(vi_, ==, vi);
  CHECK(buffer_bytes_, ==, buffer_bytes);
  CHECK(buffer_count_, ==, buffer_count);
  CHECK(fifo_size, >=, buffer_count);
  CHECK(qid, ==, last_qid);

  queue->buffer_bytes = buffer_bytes;
  queue->buffer_count = buffer_count;
  queue->fifo_size = fifo_size;
  queue->qid = qid;

  return 0;
}

void ef_shrub_queue_close(struct ef_shrub_queue* queue)
{
  // Probably should check when this is called
}

void ef_shrub_queue_poll(struct ef_shrub_queue* queue)
{
  // Probably should check when this is called
}

struct ef_shrub_connection*
ef_shrub_connection_alloc(int fifo_fd, size_t* fifo_offset, size_t fifo_size)
{
  struct ef_shrub_connection* connection;
  connection = calloc(1, sizeof(struct ef_shrub_connection));
  return connection;
}

static struct ef_shrub_connection*
find_connection(struct ef_shrub_connection* target, struct ef_shrub_queue* queue)
{
  struct ef_shrub_connection* c;
  for( c = queue->connections; c != NULL && c != target; c = c->next );
  return c;
}

void ef_shrub_connection_attached(struct ef_shrub_connection* connection,
                                  struct ef_shrub_queue* queue)
{
  CHECK(connection->queue, ==, queue);
  CHECK(find_connection(connection, queue), ==, connection);
  calls->attach++;
  calls->connection = connection;
  calls->queue = queue;
}

void ef_shrub_connection_detached(struct ef_shrub_connection* connection,
                                  struct ef_shrub_queue* queue)
{
  CHECK(connection->queue, ==, NULL);
  CHECK(find_connection(connection, queue), ==, NULL);
  calls->detach++;
  calls->connection = connection;
  calls->queue = queue;
}

int ef_shrub_connection_send_metrics(struct ef_shrub_connection* connection)
{
  calls->send++;
  return 0;
}

static void mock_cleanup(ef_vi* vi)
{
  calls->cleanup++;
}

ef_vi_efct_rxq_ops mock_ops = {
  .cleanup = mock_cleanup,
};

/* Test setup */
static void init_test(void)
{
  STATE_ALLOC(struct ef_vi, vi_);
  STATE_ALLOC(struct call_state, calls_);

  vi = vi_;
  calls = calls_;

  vi->efct_rxqs.ops = &mock_ops;
  STATE_STASH(vi);
}

static void open_server(void)
{
  ef_shrub_server_open(vi, &server, server_addr, buffer_bytes, buffer_count);
  STATE_REVERT(calls);
}

#define POLL_CHECK_NOTHING \
  ef_shrub_server_poll(server); \
  STATE_CHECK_UNCHANGED(calls); \

#define POLL_CHECK_ACCEPTED \
  ef_shrub_server_poll(server); \
  STATE_CHECK(calls, accept, 1); \
  STATE_CHECK(calls, epoll_add, 1); \
  STATE_CHECK(calls, fd, last_accept_fd); \
  STATE_CHECK_UNCHANGED(calls); \

#define POLL_CHECK_ATTACHED \
  ef_shrub_server_poll(server); \
  STATE_CHECK(calls, attach, 1); \
  STATE_CHECK(calls, send, 1); \
  STATE_ACCEPT(calls, connection); \
  STATE_ACCEPT(calls, queue); \
  STATE_CHECK_UNCHANGED(calls); \

#define POLL_CHECK_DETACHED \
  ef_shrub_server_poll(server); \
  STATE_CHECK(calls, close, 1); \
  STATE_CHECK(calls, detach, 1); \
  STATE_ACCEPT(calls, fd); \
  STATE_ACCEPT(calls, connection); \
  STATE_ACCEPT(calls, queue); \
  STATE_CHECK_UNCHANGED(calls); \

#define POLL_CHECK_CLOSED \
  ef_shrub_server_poll(server); \
  STATE_CHECK(calls, close, 1); \
  STATE_CHECK(calls, fd, last_accept_fd); \
  STATE_CHECK_UNCHANGED(calls); \

static void do_connect(void)
{
  struct epoll_event event;
  epoll_event = &event;

  event.events = EPOLLIN;
  event.data.ptr = NULL;
  POLL_CHECK_ACCEPTED

  event.data = last_epoll_data;
  POLL_CHECK_ATTACHED

  epoll_event = NULL;
}

static void disconnect(struct ef_shrub_connection* connection)
{
  struct epoll_event event;
  epoll_event = &event;

  event.events = EPOLLIN | EPOLLHUP;
  event.data.ptr = connection;
  POLL_CHECK_DETACHED

  epoll_event = NULL;
}

/* Tests */

/* Opening and closing the server */
static void test_shrub_server_open(void)
{
  int rc;

  init_test();

  rc = ef_shrub_server_open(vi, &server, server_addr, buffer_bytes, buffer_count);
  CHECK(rc, ==, 0);
  STATE_CHECK(calls, sockets_open, 1);
  STATE_CHECK(calls, remove, 1);
  STATE_CHECK_UNCHANGED(calls);

  ef_shrub_server_close(server);
  STATE_CHECK(calls, sockets_close, 1);
  STATE_CHECK(calls, cleanup, 1);
  STATE_CHECK(calls, remove, 1);
  STATE_CHECK(calls, close, 1);
  STATE_ACCEPT(calls, fd); /* maybe should check it's client_fifo_fd */
  STATE_CHECK_UNCHANGED(calls);

  STATE_FREE(calls);
  STATE_FREE(vi);
}

/* Stepping through the connection process */
static void test_shrub_server_connect(void)
{
  struct epoll_event event;

  init_test();
  open_server();

  POLL_CHECK_NOTHING

  epoll_event = &event;
  event.events = EPOLLIN;
  event.data.ptr = NULL;
  POLL_CHECK_ACCEPTED

  event.data = last_epoll_data;
  POLL_CHECK_ATTACHED

  event.data = last_epoll_data;
  event.events = EPOLLIN | EPOLLHUP;
  POLL_CHECK_DETACHED

  STATE_FREE(calls);
  STATE_FREE(vi);
}

/* Multiple connections to separate queues */
static void test_shrub_server_multi(void)
{
  int i, j, n = EF_VI_MAX_EFCT_RXQS, repeat;
  struct ef_shrub_queue* queue[EF_VI_MAX_EFCT_RXQS];

  init_test();
  open_server();

  for( repeat = 0; repeat < 3; ++repeat ) {
    for( i = 0; i < n; ++i ) {
      do_connect();

      queue[i] = calls->queue;
      CHECK(queue[i], !=, NULL);
      for( j = 0; j < i; ++j )
        CHECK(queue[i], !=, queue[j]);

      CHECK(queue[i]->connections, ==, calls->connection);
      CHECK(calls->connection->next, ==, NULL);
    }

    for( i = 0; i < n; ++i ) {
      disconnect(queue[i]->connections);

      CHECK(queue[i], ==, calls->queue);
      CHECK(queue[i]->connections, ==, NULL);
    }
  }

  STATE_FREE(calls);
  STATE_FREE(vi);
}

/* Multiple connections sharing a queue */
static void test_shrub_server_share(void)
{
  int i, j, repeat;
  int n = 2 * EF_VI_MAX_EFCT_RXQS; /* no constraint on number of connections */
  struct ef_shrub_queue* queue;
  struct ef_shrub_connection* connection[2 * EF_VI_MAX_EFCT_RXQS];

  init_test();
  open_server();

  for( repeat = 0; repeat < 3; ++repeat ) {
    for( i = 0; i < n; ++i ) {
      do_connect();

      if( i == 0 )
        queue = calls->queue;
      else
        CHECK(calls->queue, ==, queue);
      CHECK(queue, !=, NULL);
      CHECK(queue->qid, ==, last_qid);

      connection[i] = calls->connection;
      CHECK(connection[i]->socket, ==, last_accept_fd);
      CHECK(connection[i], !=, NULL);
      CHECK(connection[i]->queue, ==, queue);

      /* Another connection to a different queue */
      do_connect();
      CHECK(calls->queue, !=, queue);
      last_qid -= 2;

      CHECK(queue->connections, ==, connection[i]);
      for( j = 0; j < i; ++j ) {
        CHECK(connection[j]->queue, ==, queue);
        CHECK(connection[j+1]->next, ==, connection[j]);
      }
    }

    for( i = 0; i < n; ++i ) {
      int socket = connection[i]->socket;
      disconnect(connection[i]);
      CHECK(calls->fd, ==, socket);
      CHECK(connection[i]->socket, <, 0);
      CHECK(calls->queue, ==, queue);
      CHECK(calls->connection, ==, connection[i]);
      CHECK(connection[i]->queue, ==, NULL);

      if( i != n - 1 )
        CHECK(connection[i+1]->next, ==, NULL);
      for( j = i + 1; j < n - 1; ++j )
        CHECK(connection[j+1]->next, ==, connection[j]);
      for( j = i + 1; j < n; ++j )
        CHECK(connection[j]->queue, ==, queue);
    }
    CHECK(queue->connections, ==, NULL);
  }

  STATE_FREE(calls);
  STATE_FREE(vi);
}

/* Various protocol violations */
static void test_shrub_server_bad_proto(void)
{
  int i;
  struct epoll_event event;

  init_test();
  open_server();

  epoll_event = &event;

  /* Disconnect before sending request */
  event.events = EPOLLIN;
  event.data.ptr = NULL;
  POLL_CHECK_ACCEPTED
  event.data = last_epoll_data;
  event.events = EPOLLIN | EPOLLHUP;
  POLL_CHECK_CLOSED

  /* New connection works */
  event.events = EPOLLIN;
  event.data.ptr = NULL;
  POLL_CHECK_ACCEPTED
  event.data = last_epoll_data;
  POLL_CHECK_ATTACHED

  /* Request for second queue is a protocol error */
  POLL_CHECK_DETACHED

  /* Request invalid protocol version */
  event.data.ptr = NULL;
  POLL_CHECK_ACCEPTED
  event.data = last_epoll_data;
  ++client_shrub_version;
  POLL_CHECK_CLOSED
  --client_shrub_version;

  /* New connections work up to maximum queue count */
  for( i = 0; i < EF_VI_MAX_EFCT_RXQS; ++i ) {
    event.data.ptr = NULL;
    POLL_CHECK_ACCEPTED
    event.data = last_epoll_data;
    POLL_CHECK_ATTACHED
  }

  /* Request for too many queues fails */
  event.data.ptr = NULL;
  POLL_CHECK_ACCEPTED
  event.data = last_epoll_data;
  POLL_CHECK_CLOSED

  STATE_FREE(calls);
  STATE_FREE(vi);
}

int main(void) {
  TEST_RUN(test_shrub_server_open);
  TEST_RUN(test_shrub_server_connect);
  TEST_RUN(test_shrub_server_multi);
  TEST_RUN(test_shrub_server_share);
  TEST_RUN(test_shrub_server_bad_proto);
  TEST_END();
}
