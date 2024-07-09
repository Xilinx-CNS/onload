/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

/* Enable memfd_create. TBD is there a better way to share memory? */
#define _GNU_SOURCE

#include "ef_vi_internal.h"

#include <etherfabric/unix_server.h>
#include <etherfabric/shrub_server.h>
#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <etherfabric/efct_vi.h>
#include <etherfabric/internal/efct_uk_api.h> // for CI_HUGEPAGE_SIZE

#include "shrub_pool.h"
#include "shrub_shared.h"
#include "logging.h"
#include "bitfield.h"


#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/epoll.h>

static ef_shrub_buffer_id set_buffer_id(ef_shrub_buffer_id id, bool sentinel) {
  ci_dword_t buffer_id;
  CI_POPULATE_DWORD_2(
    buffer_id,
    EF_SHRUB_BUFFER_ID, id,
    EF_SHRUB_SENTINEL, sentinel
  );
  return buffer_id.u32[0];
}

struct ef_shrub_connection {
  struct ef_shrub_connection* next;

  int socket;
  int fifo_index;
  size_t fifo_mmap_offset;

  ef_shrub_buffer_id* fifo;
};

struct ef_shrub_server {
  struct unix_server connection_server;
  int shared_fds[EF_SHRUB_FD_COUNT];

  size_t buffer_bytes, buffer_count;
  int fifo_index;
  int fifo_size;
  int connection_count;

  ef_shrub_buffer_id* fifo;
  unsigned* buffer_refs;

  struct ef_shrub_connection* connections;
  struct ef_shrub_connection* closed_connections;
};


static bool fifo_has_space(struct ef_shrub_server* server) {
  return server->fifo_size > 0 && server->fifo[server->fifo_index] == EF_SHRUB_INVALID_BUFFER;
}

static void set_fifo_size(struct ef_shrub_server* server)
{
  int bytes = (server->buffer_count + 1) * sizeof(ef_shrub_buffer_id);
  int pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
  server->fifo_size = pages * (PAGE_SIZE / sizeof(ef_shrub_buffer_id));
}

static int fifo_bytes(struct ef_shrub_server* server)
{
  return server->fifo_size * sizeof(ef_shrub_buffer_id);
}

static size_t buffer_total_bytes(struct ef_shrub_server* server)
{
  return EF_VI_ROUND_UP(server->buffer_count * server->buffer_bytes,
                        CI_HUGEPAGE_SIZE);
}

static void init_fifo(struct ef_shrub_server* server, ef_shrub_buffer_id* fifo)
{
  int i;
  for( i = 0; i < server->fifo_size; ++i )
    fifo[i] = EF_SHRUB_INVALID_BUFFER;
}

static int server_alloc_refs(struct ef_shrub_server* server)
{
  server->buffer_refs = calloc(server->buffer_count, sizeof(ef_shrub_buffer_id));
  if( server->buffer_refs == NULL )
    return -ENOMEM;

  return 0;
}


static int server_alloc_shared(struct ef_shrub_server* server)
{
  int fd, rc, i;

  for( i = 0; i < EF_SHRUB_FD_COUNT; ++i )
    server->shared_fds[i] = -1;

  fd = memfd_create("ef_shrub_buffer", MFD_HUGETLB);
  if( fd < 0 )
    return -errno;
  server->shared_fds[EF_SHRUB_FD_BUFFERS] = fd;

  rc = ftruncate(fd, buffer_total_bytes(server));
  if( rc < 0 )
    return -errno;

  fd = memfd_create("ef_shrub_server_fifo", 0);
  if( fd < 0 )
    return -errno;
  server->shared_fds[EF_SHRUB_FD_SERVER_FIFO] = fd;

  rc = ftruncate(fd, fifo_bytes(server));
  if( rc < 0 )
    return -errno;

  rc = fcntl(fd, F_SETFL, O_RDONLY);
  if( rc < 0 )
    return -errno;

  fd = memfd_create("ef_shrub_client_fifo", 0);
  if( fd < 0 )
    return -errno;
  server->shared_fds[EF_SHRUB_FD_CLIENT_FIFO] = fd;

  return 0;
}

static int server_map_fifo(struct ef_shrub_server* server)
{
  server->fifo = mmap(NULL, fifo_bytes(server), PROT_WRITE,
                      MAP_SHARED | MAP_POPULATE,
                      server->shared_fds[EF_SHRUB_FD_SERVER_FIFO], 0);
  if( server->fifo == MAP_FAILED )
    return -errno;

  init_fifo(server, server->fifo);
  return 0;
}

static void poll_fifo(struct ef_vi* vi, struct ef_shrub_server* server,
                      struct ef_shrub_connection* connection, int qid)
{
  int i = connection->fifo_index;

  ef_shrub_buffer_id buffer = connection->fifo[i];

  if( buffer == EF_SHRUB_INVALID_BUFFER )
    return;

  connection->fifo[i] = EF_SHRUB_INVALID_BUFFER;
  connection->fifo_index = i == server->fifo_size - 1 ? 0 : i + 1;
  if( --server->buffer_refs[buffer] == 0 )
    vi->efct_rxqs.ops->free(vi, qid, buffer);
}

static void poll_fifos(struct ef_vi* vi, struct ef_shrub_server* server,
                       int qid)
{
  struct ef_shrub_connection* c;
  for( c = server->connections; c != NULL; c = c->next )
    poll_fifo(vi, server, c, qid);
}

static struct ef_shrub_connection*
connection_alloc(struct ef_shrub_server* server)
{
  int fd, rc;
  struct ef_shrub_connection* connection;
  void* map;
  size_t offset;

  if( server->closed_connections ) {
    connection = server->closed_connections;
    server->closed_connections = connection->next;
    return connection;
  }

  connection = calloc(1, sizeof(struct ef_shrub_connection));
  if( connection == NULL )
    return NULL;

  fd = server->shared_fds[EF_SHRUB_FD_CLIENT_FIFO];

  offset = server->connection_count * fifo_bytes(server);
  rc = ftruncate(fd, offset + fifo_bytes(server));
  if( rc < 0 )
    goto fail_fifo;

  map = mmap(NULL, fifo_bytes(server), PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_POPULATE, fd, offset);
  if( map == MAP_FAILED )
    goto fail_fifo;

  connection->fifo_mmap_offset = offset;
  connection->fifo = map;
  init_fifo(server, connection->fifo);

  return connection;

fail_fifo:
  free(connection);
  return NULL;
}

static int connection_send_metrics(struct ef_shrub_server* server,
                                   struct ef_shrub_connection* connection)
{
  int rc;
  struct ef_shrub_shared_metrics metrics = {
    .server_version = EF_SHRUB_VERSION,
    .buffer_bytes = server->buffer_bytes,
    .buffer_count = server->buffer_count,
    .server_fifo_size = fifo_bytes(server),
    .client_fifo_offset = connection->fifo_mmap_offset,
    .client_fifo_size = fifo_bytes(server)
  };
  struct iovec iov = {
    .iov_base = &metrics,
    .iov_len = sizeof(metrics)
  };
  char cmsg_buf[CMSG_SPACE(sizeof(server->shared_fds))];
  struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsg_buf,
    .msg_controllen = sizeof(cmsg_buf)
  };
  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  if( cmsg == NULL )
    return -EPROTO;

  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(server->shared_fds));
  memcpy(CMSG_DATA(cmsg), server->shared_fds, sizeof(server->shared_fds));

  rc = sendmsg(connection->socket, &msg, 0);
  if( rc < 0 )
    return -errno;

  return 0;
}

static int server_connection_opened(struct unix_server* unix_server)
{
  int rc, socket;
  struct ef_shrub_connection* connection;
  struct ef_shrub_server* server = CI_CONTAINER(struct ef_shrub_server,
                                                connection_server, unix_server);
  socket = accept(server->connection_server.listen, NULL, NULL);
  if( socket < 0 )
    return socket;

  connection = connection_alloc(server);
  if( connection == NULL ) {
    rc = -1; /* TODO propagate connection_alloc's rc */
    goto fail_alloc;
  }

  connection->socket = socket;
  rc = connection_send_metrics(server, connection);
  if( rc < 0 )
    goto fail_send;

  rc = unix_server_epoll_add(&server->connection_server, connection->socket,
                             connection);
  if( rc < 0 )
    goto fail_epoll;

  /* TODO synchronise */
  connection->next = server->connections;
  server->connections = connection;
  server->connection_count++;
  return 0;

fail_epoll:
fail_send:
  connection->next = server->closed_connections;
  server->closed_connections = connection;
fail_alloc:
  close(socket);
  return rc;
}

static int server_connection_closed(struct unix_server* unix_server,
                             void *data)
{
  struct ef_shrub_server* server = CI_CONTAINER(struct ef_shrub_server,
                                                connection_server, unix_server);
  struct ef_shrub_connection* connection = data;
  /* TODO release buffers owned by this connection */
  close(connection->socket);

  /* TBD would a doubly linked list or something be better? */
  if( connection == server->connections ) {
    server->connections = connection->next;
  }
  else {
    struct ef_shrub_connection* c;
    for( c = server->connections; c != NULL; c = c->next ) {
      if( c->next == connection ) {
        c->next = connection->next;
        break;
      }
    }
  }

  connection->next = server->closed_connections;
  server->closed_connections = connection;
  server->connection_count--;
  return 0;
}

static void poll_sockets(struct ef_shrub_server* server)
{
  while( true )
    unix_server_poll(&server->connection_server);
}

int ef_shrub_server_open(struct ef_vi* vi,
                         struct ef_shrub_server** server_out,
                         const char* server_addr,
                         size_t buffer_bytes,
                         size_t buffer_count,
                         int qid)
{
  struct ef_shrub_server* server;
  int rc, i;

  server = calloc(1, sizeof(*server));
  if( server == NULL )
    return -ENOMEM;

  server->buffer_bytes = buffer_bytes;
  server->buffer_count = buffer_count;
  set_fifo_size(server);

  rc = server_alloc_refs(server);
  if( rc < 0 )
    goto fail_refs;

  rc = server_alloc_shared(server);
  if( rc < 0 )
    goto fail_shared;

  rc = server_map_fifo(server);
  if( rc < 0 )
    goto fail_fifo;

  rc = unix_server_init(&server->connection_server, server_addr);
  if( rc < 0 )
    goto fail_unix_server_init;
  server->connection_server.ops.connection_opened = server_connection_opened;
  server->connection_server.ops.connection_closed = server_connection_closed;

  rc = vi->efct_rxqs.ops->attach(vi,
                                 qid,
                                 server->shared_fds[EF_SHRUB_FD_BUFFERS],
                                 server->buffer_count,
                                 false);
  if (rc < 0)
    goto fail_server_attach;

  *server_out = server;
  return 0;

fail_server_attach:
  unix_server_fini(&server->connection_server);
fail_unix_server_init:
  munmap(server->fifo, fifo_bytes(server));
fail_fifo:
fail_shared:
  for( i = 0; i < EF_SHRUB_FD_COUNT; ++i )
    close(server->shared_fds[i]);
  free(server->buffer_refs);
fail_refs:
  free(server);
  return rc;
}

void ef_shrub_server_close(struct ef_shrub_server* server)
{
  int i;

  /* TODO close connections */
  unix_server_fini(&server->connection_server);
  munmap(server->fifo, fifo_bytes(server));
  for( i = 0; i < EF_SHRUB_FD_COUNT; ++i )
    close(server->shared_fds[i]);
  free(server->buffer_refs);
  free(server);
}

void ef_shrub_server_poll(struct ef_vi* vi, struct ef_shrub_server* server, int qid)
{
  bool sentinel;
  unsigned sbseq;
  ef_vi_efct_rxq_ops* ops;
  ops = vi->efct_rxqs.ops;

  poll_fifos(vi, server, qid);
  while( fifo_has_space(server) ) {
    int next_buffer = ops->next(vi, qid, &sentinel, &sbseq);
    if ( next_buffer < 0 ) {
      break;
    }
    int i = server->fifo_index;
    server->fifo[i] = set_buffer_id(next_buffer, sentinel);
    assert(server->buffer_refs[next_buffer] == 0);
    server->buffer_refs[next_buffer] = server->connection_count;
    server->fifo_index = i == server->fifo_size - 1 ? 0 : i + 1;
  }

  /* TBD: should this be a separate operation?
   * Perhaps exposing an fd for higher level polling? */
  poll_sockets(server);
}

