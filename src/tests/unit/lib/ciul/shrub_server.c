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

static uint64_t active_qs;
static struct epoll_event* epoll_event;
static int last_accept_fd = 42;
static epoll_data_t last_epoll_data;

static struct ef_vi* vi;
static struct ef_shrub_server* server;
static struct call_state
{
  /* Counting function calls */
  int sockets_open;
  int sockets_close;
  int epoll_add;
  int epoll_mod;
  int accept;
  int remove;
  int close;
  int attach;
  int detach;
  int send;
  int cleanup;

  /* Function arguments */
  int fd;
} *calls;

int ef_shrub_server_sockets_open(struct ef_shrub_server_sockets* sockets,
                                 const char* path)
{
  calls->sockets_open++;
  CHECK(calls->remove, ==, 1);
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

int ef_shrub_server_epoll_mod(struct ef_shrub_server_sockets* sockets,
                              int fd, epoll_data_t data)
{
  calls->epoll_mod++;
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

int ef_shrub_server_recv(int fd, void* data, size_t bytes)
{
  struct ef_shrub_request* req = data;
  CHECK(bytes, ==, sizeof(*req));
  req->server_version = EF_SHRUB_VERSION;
  req->type = EF_SHRUB_REQUEST_QUEUE;
  req->requests.queue.qid = 0; // TODO arbitrary value fails due to bogus use as array index
  return bytes;
}

int ef_shrub_server_resource_op(int fd, struct ci_resource_op_s* op)
{
  // TODO should check how this is called
  return 0;
}

int ef_shrub_queue_open(struct ef_shrub_queue** queue_out,
                        struct ef_vi* vi_,
                        size_t buffer_bytes_,
                        size_t buffer_count_,
                        int qid)
{
  struct ef_shrub_queue* queue;

  CHECK(vi_, ==, vi);
  CHECK(buffer_bytes_, ==, buffer_bytes);
  CHECK(buffer_count_, ==, buffer_count);

  queue = calloc(1, sizeof(*queue));
  queue->buffer_bytes = buffer_bytes;
  queue->buffer_count = buffer_count;

  *queue_out = queue;
  return 0;
}

struct ef_shrub_connection*
ef_shrub_connection_alloc(struct ef_shrub_queue* queue)
{
  struct ef_shrub_connection* connection;
  connection = calloc(1, sizeof(struct ef_shrub_connection));
  return connection;
}

void ef_shrub_connection_attach(struct ef_shrub_connection* connection,
                                struct ef_shrub_queue* queue)
{
  calls->attach++;
}

void ef_shrub_connection_detach(struct ef_shrub_connection* connection,
                                struct ef_shrub_queue* queue,
                                struct ef_vi* vi_)
{
  CHECK(vi_, ==, vi);
  calls->detach++;
}

int ef_shrub_connection_send_metrics(struct ef_shrub_connection* connection,
                                     struct ef_shrub_queue* queue)
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

/* Tests */
static void init_test(void)
{
  STATE_ALLOC(struct ef_vi, vi_);
  STATE_ALLOC(struct call_state, calls_);

  vi = vi_;
  calls = calls_;

  vi->efct_rxqs.active_qs = &active_qs;
  vi->efct_rxqs.ops = &mock_ops;
  STATE_STASH(vi);
}

static void open_server(void)
{
  ef_shrub_server_open(vi, &server, server_addr, buffer_bytes, buffer_count);
  STATE_REVERT(calls);
}

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
  STATE_CHECK_UNCHANGED(calls);

  STATE_FREE(calls);
  STATE_FREE(vi);
}

static void test_shrub_server_connect(void)
{
  struct epoll_event event;

  init_test();
  open_server();

  ef_shrub_server_poll(server);
  STATE_CHECK_UNCHANGED(calls);

  epoll_event = &event;
  event.events = EPOLLIN;
  event.data.ptr = NULL;
  ef_shrub_server_poll(server);
  STATE_CHECK(calls, accept, 1);
  STATE_CHECK(calls, epoll_add, 1);
  STATE_CHECK(calls, fd, last_accept_fd);
  STATE_CHECK_UNCHANGED(calls);

  event.data = last_epoll_data;
  ef_shrub_server_poll(server);
  STATE_CHECK(calls, epoll_mod, 1);
  STATE_CHECK(calls, fd, last_accept_fd);
  STATE_CHECK(calls, attach, 1);
  STATE_CHECK(calls, send, 1);
  STATE_CHECK_UNCHANGED(calls);

  event.data = last_epoll_data;
  event.events = EPOLLIN | EPOLLHUP;
  ef_shrub_server_poll(server);
  STATE_CHECK(calls, close, 1);
  STATE_CHECK(calls, fd, last_accept_fd);
  STATE_CHECK(calls, detach, 1);
  STATE_CHECK_UNCHANGED(calls);

  STATE_FREE(calls);
  STATE_FREE(vi);
}

int main(void) {
  TEST_RUN(test_shrub_server_open);
  TEST_RUN(test_shrub_server_connect);
  TEST_END();
}
