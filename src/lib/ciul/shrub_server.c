/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

/* Enable memfd_create. TBD is there a better way to share memory? */
#define _GNU_SOURCE

#include "ef_vi_internal.h"

#include <etherfabric/unix_server.h>
#include <etherfabric/shrub_server.h>
#include <etherfabric/shrub_shared.h>
#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <etherfabric/efct_vi.h>
#include <etherfabric/internal/efct_uk_api.h> // for CI_HUGEPAGE_SIZE

#include "shrub_pool.h"
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
  int qid;

  int socket;
  int fifo_index;
  size_t fifo_mmap_offset;

  ef_shrub_buffer_id* fifo;
};

struct ef_shrub_queue {
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

struct shrub_queue_elem {
  struct ef_shrub_queue *queue;
  int prev;
  int next;
};

struct ef_shrub_server {
  struct unix_server unix_server;
  ef_vi* vi;
  size_t buffer_bytes;
  size_t buffer_count;
  /* Array of size res->vi.efct_rxqs.max_qs. A doubly linked list is formed
   * using the prev and next indices in each elem. */
  struct shrub_queue_elem *shrub_queues;
  int shrub_queue_head;
};

static bool fifo_has_space(struct ef_shrub_queue* queue) {
  return queue->fifo_size > 0 && queue->fifo[queue->fifo_index] == EF_SHRUB_INVALID_BUFFER;
}

static void set_fifo_size(struct ef_shrub_queue* queue)
{
  int bytes = (queue->buffer_count + 1) * sizeof(ef_shrub_buffer_id);
  int pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
  queue->fifo_size = pages * (PAGE_SIZE / sizeof(ef_shrub_buffer_id));
}

static int fifo_bytes(struct ef_shrub_queue* queue)
{
  return queue->fifo_size * sizeof(ef_shrub_buffer_id);
}

static size_t buffer_total_bytes(struct ef_shrub_queue* queue)
{
  return EF_VI_ROUND_UP(queue->buffer_count * queue->buffer_bytes,
                        CI_HUGEPAGE_SIZE);
}

static void init_fifo(struct ef_shrub_queue* queue, ef_shrub_buffer_id* fifo)
{
  int i;
  for( i = 0; i < queue->fifo_size; ++i )
    fifo[i] = EF_SHRUB_INVALID_BUFFER;
}

static int queue_alloc_refs(struct ef_shrub_queue* queue)
{
  queue->buffer_refs = calloc(queue->buffer_count, sizeof(ef_shrub_buffer_id));
  if( queue->buffer_refs == NULL )
    return -ENOMEM;

  return 0;
}


static int queue_alloc_shared(struct ef_shrub_queue* queue)
{
  int fd, rc, i;

  for( i = 0; i < EF_SHRUB_FD_COUNT; ++i )
    queue->shared_fds[i] = -1;

  fd = memfd_create("ef_shrub_buffer", MFD_HUGETLB);
  if( fd < 0 )
    return -errno;
  queue->shared_fds[EF_SHRUB_FD_BUFFERS] = fd;

  rc = ftruncate(fd, buffer_total_bytes(queue));
  if( rc < 0 )
    return -errno;

  fd = memfd_create("ef_shrub_queue_fifo", 0);
  if( fd < 0 )
    return -errno;
  queue->shared_fds[EF_SHRUB_FD_SERVER_FIFO] = fd;

  rc = ftruncate(fd, fifo_bytes(queue));
  if( rc < 0 )
    return -errno;

  rc = fcntl(fd, F_SETFL, O_RDONLY);
  if( rc < 0 )
    return -errno;

  fd = memfd_create("ef_shrub_client_fifo", 0);
  if( fd < 0 )
    return -errno;
  queue->shared_fds[EF_SHRUB_FD_CLIENT_FIFO] = fd;

  return 0;
}

static int queue_map_fifo(struct ef_shrub_queue* queue)
{
  queue->fifo = mmap(NULL, fifo_bytes(queue), PROT_WRITE,
                      MAP_SHARED | MAP_POPULATE,
                      queue->shared_fds[EF_SHRUB_FD_SERVER_FIFO], 0);
  if( queue->fifo == MAP_FAILED )
    return -errno;

  init_fifo(queue, queue->fifo);
  return 0;
}

static void poll_fifo(struct ef_vi* vi, struct ef_shrub_queue* queue,
                      struct ef_shrub_connection* connection, int qid)
{
  int i = connection->fifo_index;

  ef_shrub_buffer_id buffer = connection->fifo[i];

  if( buffer == EF_SHRUB_INVALID_BUFFER )
    return;

  connection->fifo[i] = EF_SHRUB_INVALID_BUFFER;
  connection->fifo_index = i == queue->fifo_size - 1 ? 0 : i + 1;
  if( --queue->buffer_refs[buffer] == 0 )
    vi->efct_rxqs.ops->free(vi, qid, buffer);
}

static void poll_fifos(struct ef_vi* vi, struct ef_shrub_queue* queue, int qid)
{
  struct ef_shrub_connection* c;
  for( c = queue->connections; c != NULL; c = c->next )
    poll_fifo(vi, queue, c, qid);
}

static struct ef_shrub_connection*
connection_alloc(struct ef_shrub_queue* queue)
{
  int fd, rc;
  struct ef_shrub_connection* connection;
  void* map;
  size_t offset;

  if( queue->closed_connections ) {
    connection = queue->closed_connections;
    queue->closed_connections = connection->next;
    return connection;
  }

  connection = calloc(1, sizeof(struct ef_shrub_connection));
  if( connection == NULL )
    return NULL;

  fd = queue->shared_fds[EF_SHRUB_FD_CLIENT_FIFO];

  offset = queue->connection_count * fifo_bytes(queue);
  rc = ftruncate(fd, offset + fifo_bytes(queue));
  if( rc < 0 )
    goto fail_fifo;

  map = mmap(NULL, fifo_bytes(queue), PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_POPULATE, fd, offset);
  if( map == MAP_FAILED )
    goto fail_fifo;

  connection->fifo_mmap_offset = offset;
  connection->fifo = map;
  init_fifo(queue, connection->fifo);

  return connection;

fail_fifo:
  free(connection);
  return NULL;
}

static int connection_send_metrics(struct ef_shrub_queue* queue,
                                   struct ef_shrub_connection* connection)
{
  int rc;
  struct ef_shrub_shared_metrics metrics = {
    .server_version = EF_SHRUB_VERSION,
    .buffer_bytes = queue->buffer_bytes,
    .buffer_count = queue->buffer_count,
    .queue_fifo_size = fifo_bytes(queue),
    .client_fifo_offset = connection->fifo_mmap_offset,
    .client_fifo_size = fifo_bytes(queue)
  };
  struct iovec iov = {
    .iov_base = &metrics,
    .iov_len = sizeof(metrics)
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

  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(queue->shared_fds));
  memcpy(CMSG_DATA(cmsg), queue->shared_fds, sizeof(queue->shared_fds));

  rc = sendmsg(connection->socket, &msg, 0);
  if( rc < 0 )
    return -errno;

  return 0;
}

static int ef_shrub_queue_open(struct ef_vi* vi,
                         struct ef_shrub_queue** queue_out,
                         size_t buffer_bytes,
                         size_t buffer_count,
                         int qid)
{
  struct ef_shrub_queue* queue;
  int rc, i;

  queue = calloc(1, sizeof(*queue));
  if( queue == NULL )
    return -ENOMEM;

  queue->buffer_bytes = buffer_bytes;
  queue->buffer_count = buffer_count;
  set_fifo_size(queue);

  rc = queue_alloc_refs(queue);
  if( rc < 0 )
    goto fail_refs;

  rc = queue_alloc_shared(queue);
  if( rc < 0 )
    goto fail_shared;

  rc = queue_map_fifo(queue);
  if( rc < 0 )
    goto fail_fifo;

  rc = vi->efct_rxqs.ops->attach(vi,
                                 qid,
                                 queue->shared_fds[EF_SHRUB_FD_BUFFERS],
                                 queue->buffer_count,
                                 false);
  if (rc < 0)
    goto fail_queue_attach;

  *queue_out = queue;
  return 0;

fail_queue_attach:
  munmap(queue->fifo, fifo_bytes(queue));
fail_fifo:
  for( i = 0; i < EF_SHRUB_FD_COUNT; ++i )
    close(queue->shared_fds[i]);
fail_shared:
  free(queue->buffer_refs);
fail_refs:
  free(queue);
  return rc;
}

static void ef_shrub_queue_close(struct ef_shrub_queue* queue)
{
  int i;

  /* TODO close connections */
  munmap(queue->fifo, fifo_bytes(queue));
  for( i = 0; i < EF_SHRUB_FD_COUNT; ++i )
    close(queue->shared_fds[i]);
  free(queue->buffer_refs);
  free(queue);
}

static void ef_shrub_queue_poll(struct ef_vi* vi, struct ef_shrub_queue* queue, int qid)
{
  bool sentinel;
  unsigned sbseq;
  ef_vi_efct_rxq_ops* ops;
  ops = vi->efct_rxqs.ops;

  poll_fifos(vi, queue, qid);
  while( fifo_has_space(queue) ) {
    int next_buffer = ops->next(vi, qid, &sentinel, &sbseq);
    if ( next_buffer < 0 ) {
      break;
    }
    int i = queue->fifo_index;
    queue->fifo[i] = set_buffer_id(next_buffer, sentinel);
    assert(queue->buffer_refs[next_buffer] == 0);
    queue->buffer_refs[next_buffer] = queue->connection_count;
    queue->fifo_index = i == queue->fifo_size - 1 ? 0 : i + 1;
  }
}


static int server_alloc_queue_elems(struct ef_shrub_server *server,
                                    int max_qs)
{
  /* TODO: This is not the max value for HW queues - I suspect we should assign
   * to design params instead. */
  int i;
  server->shrub_queues = calloc(max_qs, sizeof(server->shrub_queues[0]));
  if( server->shrub_queues == NULL ) {
    return -ENOMEM;
  }
  for(i = 0; i < max_qs; i++) {
    server->shrub_queues[i].next = -1;
    server->shrub_queues[i].prev = -1;
  }
  server->shrub_queue_head = -1;
  return 0;
}

static int server_connection_opened(struct unix_server* unix_server) {
  struct ef_shrub_server* server = CI_CONTAINER(struct ef_shrub_server,
                                                unix_server, unix_server);
  struct ef_shrub_connection* connection;
  struct ef_shrub_queue_request req;
  struct shrub_queue_elem* q_elem;
  int rc;
  int socket = accept(unix_server->listen, NULL, NULL);

  if( socket < 0 )
    return socket;

  rc = recv(socket, &req, sizeof(req), 0);
  if( rc < 0 ) {
    rc = -errno;
    goto fail;
  }

  if( req.server_version != EF_SHRUB_VERSION ) {
    rc = -EPROTO;
    goto fail;
  }

  q_elem = &server->shrub_queues[req.qid];

  if( q_elem->queue == NULL ) {
    rc = ef_shrub_queue_open(server->vi, &q_elem->queue,
                             server->buffer_bytes, server->buffer_count,
                             req.qid);
    if(rc < 0)
      goto fail;

    q_elem->next = server->shrub_queue_head;
    if(server->shrub_queue_head != -1)
      server->shrub_queues[server->shrub_queue_head].prev = req.qid;
    server->shrub_queue_head = req.qid;
  }

  connection = connection_alloc(q_elem->queue);
  if( connection == NULL ) {
    rc = -1; /* TODO propogate connection_alloc's rc */
    goto fail;
  }

  connection->socket = socket;
  rc = connection_send_metrics(q_elem->queue, connection);
  if( rc < 0 )
    goto fail_send;

  rc = unix_server_epoll_add(&server->unix_server, connection->socket,
                             connection);
  if( rc < 0 )
    goto fail_epoll;

  /* TODO synchronise */
  connection->next = q_elem->queue->connections;
  connection->qid = req.qid;
  q_elem->queue->connections = connection;
  q_elem->queue->connection_count++;

  return 0;
fail_epoll:
fail_send:
  connection->next = q_elem->queue->closed_connections;
  q_elem->queue->closed_connections = connection;
fail:
  close(socket);
  return rc;
}

static int server_connection_closed(struct unix_server* unix_server, void *data)
{
  struct ef_shrub_server* server = CI_CONTAINER(struct ef_shrub_server,
                                                unix_server, unix_server);
  struct ef_shrub_connection* connection = data;
  struct ef_shrub_queue* queue = server->shrub_queues[connection->qid].queue;
  /* TODO release buffers owned by this connection */
  close(connection->socket);

  /* TBD would a doubly linked list or something be better? */
  if( connection == queue->connections ) {
    queue->connections = connection->next;
  }
  else {
    struct ef_shrub_connection* c;
    for( c = queue->connections; c != NULL; c = c->next ) {
      if( c->next == connection ) {
        c->next = connection->next;
        break;
      }
    }
  }

  connection->next = queue->closed_connections;
  queue->closed_connections = connection;
  server->shrub_queues[connection->qid].queue->connection_count--;
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

  server = calloc(1, sizeof(*server));
  if( server == NULL)
    return -ENOMEM;

  remove(EF_SHRUB_CONTROLLER_PATH);
  rc = unix_server_init(&server->unix_server, EF_SHRUB_CONTROLLER_PATH);
  if( rc < 0 )
    goto fail_unix_server_init;
  server->unix_server.ops.connection_opened = server_connection_opened;
  server->unix_server.ops.connection_closed = server_connection_closed;

  server->vi = vi;
  /* TBD Do this and the above as a single allocation. */
  rc = server_alloc_queue_elems(server, vi->efct_rxqs.max_qs);
  if(rc < 0)
    goto fail_queues_alloc;

  server->buffer_count = buffer_count;
  server->buffer_bytes = buffer_bytes;

  *server_out = server;
  return 0;

fail_queues_alloc:
  unix_server_fini(&server->unix_server);
fail_unix_server_init:
  free(server);
  return rc;
}

void ef_shrub_server_poll(struct ef_shrub_server* server)
{
  /* First poll the server's unix server to detect any client connections
   * and allocate any necessary shrub queues.
   * Then poll all active shrub queues using the fact that there is one rxq
   * per hw queue.
   */
  uint64_t qs = *server->vi->efct_rxqs.active_qs;
  unix_server_poll(&server->unix_server);
  for ( ; ; ) {
    int i = __builtin_ffsll(qs);
    int qid;
    if (i == 0)
      break;
    --i;
    qs &= ~(1ull << i);
    qid = server->vi->efct_rxqs.q[i].qid;
    ef_shrub_queue_poll(server->vi,
                        server->shrub_queues[qid].queue, i);
  }
}

void ef_shrub_server_close(struct ef_shrub_server* server)
{
  int qid;
  for(qid = server->shrub_queue_head;
      qid != -1;
      qid = server->shrub_queues[qid].next) {
    ef_shrub_queue_close(server->shrub_queues[qid].queue);
  }
  server->vi->efct_rxqs.ops->cleanup(server->vi);
  unix_server_fini(&server->unix_server);
  free(server);
}
