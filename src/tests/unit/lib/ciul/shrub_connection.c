/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: Copyright (C) 2025, Advanced Micro Devices, Inc. */

/* Functions under test */
#include "shrub_connection.h"

/* Test infrastructure */
#include "unit_test.h"

/* Dependencies */
#include <sys/socket.h>
#include "shrub_queue.h"
#include "shrub_server_sockets.h"

static const int buffer_fd = 15;
static const int server_fifo_fd = 16;
static const int client_fifo_fd = 17;
static const int socket_fd = 18;

static const size_t fifo_offset = 65536;
static const size_t fifo_size = 4096;
static const size_t fifo_bytes = fifo_size * sizeof(ef_shrub_buffer_id);
static const size_t total_bytes = fifo_bytes + sizeof(struct ef_shrub_client_state);

struct ef_shrub_queue queue = {
  .shared_fds = {buffer_fd, server_fifo_fd, client_fifo_fd},
  .buffer_bytes = 12345,
  .buffer_count = 75,
  .fifo_size = 123,
};

static size_t new_offset;
static void* mmap_addr;

int ef_shrub_server_memfd_resize(int fd, size_t size)
{
  CHECK(fd, ==, client_fifo_fd);
  CHECK(size, >=, fifo_offset + total_bytes);

  new_offset = size;
  return 0;
}

int ef_shrub_server_mmap(void** addr_out, size_t size,
                         int prot, int flags, int fd, size_t offset)
{
  CHECK(size, >=, total_bytes);
  CHECK(size, <=, new_offset - fifo_offset);
  CHECK(prot, ==, PROT_READ | PROT_WRITE);
  CHECK(flags, ==, MAP_SHARED | MAP_POPULATE);
  CHECK(fd, ==, client_fifo_fd);
  CHECK(offset, ==, fifo_offset);

  *addr_out = mmap_addr = calloc(1, size);
  return 0;
}

int ef_shrub_server_sendmsg(int fd, struct msghdr* msg)
{
  struct ef_shrub_shared_metrics* metrics;
  struct cmsghdr* cmsg;

  CHECK(fd, ==, socket_fd);
  CHECK(msg->msg_iovlen, ==, 1);
  CHECK(msg->msg_iov->iov_len, ==, sizeof(*metrics));

  metrics = msg->msg_iov->iov_base;
  CHECK(metrics->server_version, ==, EF_SHRUB_VERSION);
  CHECK(metrics->buffer_bytes, ==, queue.buffer_bytes);
  CHECK(metrics->buffer_count, ==, queue.buffer_count);
  CHECK(metrics->server_fifo_size, ==, queue.fifo_size);
  CHECK(metrics->client_fifo_offset, ==, fifo_offset);
  CHECK(metrics->client_fifo_size, ==, fifo_size);

  cmsg = CMSG_FIRSTHDR(msg);
  CHECK(cmsg->cmsg_level, ==, SOL_SOCKET);
  CHECK(cmsg->cmsg_level, ==, SCM_RIGHTS);
  CHECK(cmsg->cmsg_len, ==, CMSG_LEN(3 * sizeof(int)));

  int* fds = (int*)CMSG_DATA(cmsg);
  CHECK(fds[EF_SHRUB_FD_BUFFERS], ==, buffer_fd);
  CHECK(fds[EF_SHRUB_FD_SERVER_FIFO], ==, server_fifo_fd);
  CHECK(fds[EF_SHRUB_FD_CLIENT_FIFO], ==, client_fifo_fd);

  return 0;
}

/* Tests */
void test_shrub_connection(void)
{
  int rc;
  size_t offset = fifo_offset;
  struct ef_shrub_connection* connection;
  rc = ef_shrub_connection_alloc(&connection, client_fifo_fd, &offset, fifo_size);
  CHECK(rc, ==, 0);
  CHECK(offset, ==, new_offset);
  CHECK(connection, !=, NULL);
  CHECK(connection->next, ==, NULL);
  CHECK(connection->queue, ==, NULL);
  CHECK(connection->client_fifo, ==, mmap_addr);
  CHECK(connection->client_fifo_index, ==, 0);
  CHECK(connection->fifo_size, ==, fifo_size);
  CHECK(connection->client_fifo_mmap_offset, ==, fifo_offset);

  connection->queue = &queue;
  connection->socket = socket_fd;
  ef_shrub_connection_send_metrics(connection);

  struct ef_shrub_client_state* state = ef_shrub_connection_client_state(connection);
  CHECK(state->server_fifo_index, ==, 0);
  CHECK(state->client_fifo_index, ==, 0);

  struct ef_shrub_shared_metrics* metrics = &state->metrics;
  CHECK(metrics->server_version, ==, EF_SHRUB_VERSION);
  CHECK(metrics->buffer_bytes, ==, queue.buffer_bytes);
  CHECK(metrics->buffer_count, ==, queue.buffer_count);
  CHECK(metrics->server_fifo_size, ==, queue.fifo_size);
  CHECK(metrics->client_fifo_offset, ==, fifo_offset);
  CHECK(metrics->client_fifo_size, ==, fifo_size);
}

int main(void)
{
  TEST_RUN(test_shrub_connection);
  TEST_END();
}
