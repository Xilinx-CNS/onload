/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

/* Enable memfd_create. TBD is there a better way to share memory? */
#define _GNU_SOURCE

#include "ef_vi_internal.h"

#include <etherfabric/shrub_server.h>
#include <etherfabric/shrub_shared.h>
#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <etherfabric/efct_vi.h>
#include <etherfabric/internal/efct_uk_api.h> // for CI_HUGEPAGE_SIZE
#include <ci/tools/sysdep.h>

#include "shrub_pool.h"
#include "logging.h"
#include "bitfield.h"
#include "driver_access.h"

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

static uint32_t get_buffer_id(ef_shrub_buffer_id id) {
  ci_dword_t id2;
  id2.u32[0] = id;
  return CI_DWORD_FIELD(id2, EF_SHRUB_BUFFER_ID);
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
  int ix;

  ef_shrub_buffer_id* fifo;
  unsigned* buffer_refs;
  int* buffer_fifo_indices;

  struct ef_shrub_connection* connections;
  struct ef_shrub_connection* closed_connections;
};

struct ef_shrub_server {
  struct {
    int listen;
    int epoll;
  } unix_server;
  ef_vi* vi;
  size_t buffer_bytes;
  size_t buffer_count;
  /* Array of size res->vi.efct_rxqs.max_qs. */
  struct ef_shrub_queue** shrub_queues;
  unsigned pd_excl_rxq_tok;
  char socket_path[EF_SHRUB_SERVER_SOCKET_LEN];
};

/* Unix server operations */

static int unix_server_epoll_create(struct ef_shrub_server* server)
{
  int rc = epoll_create(1);
  if( rc < 0 )
    return -errno;

  server->unix_server.epoll = rc;
  return 0;
}

static int unix_server_socket(struct ef_shrub_server* server)
{
  int rc = socket(AF_UNIX, SOCK_STREAM, 0);
  if( rc < 0 )
    return -errno;

  server->unix_server.listen = rc;
  return 0;
}

static int unix_server_listen(struct ef_shrub_server* server, const char *server_addr)
{
  int rc;
  struct sockaddr_un addr;
  size_t path_len = strlen(server_addr);

  rc = unix_server_socket(server);
  if( rc < 0 )
    return rc;

  if( path_len >= sizeof(addr.sun_path) ) {
    rc = -EINVAL;
    goto fail;
  }

  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, server_addr);

  rc = bind(server->unix_server.listen, (struct sockaddr*)&addr,
            offsetof(struct sockaddr_un, sun_path) + path_len + 1);
  if( rc < 0 )
    goto fail;

  rc = chmod(server_addr, 0666);
  if( rc < 0 )
    goto fail;

  strncpy(server->socket_path, server_addr, sizeof(server->socket_path));
  return listen(server->unix_server.listen, 32);

fail:
  close(server->unix_server.listen);
  return rc;
}


static int unix_server_epoll_ctl(struct ef_shrub_server* server, int op, int fd,
                                 epoll_data_t data)
{
  int rc;
  struct epoll_event event;

  event.events = EPOLLIN;
  event.data = data;

  rc = epoll_ctl(server->unix_server.epoll, op, fd, &event);
  if( rc < 0 )
    return -errno;

  return 0;
}

static int unix_server_epoll_add(struct ef_shrub_server* server, int fd, epoll_data_t data)
{
  return unix_server_epoll_ctl(server, EPOLL_CTL_ADD, fd, data);
}

static int unix_server_epoll_mod(struct ef_shrub_server* server, int fd, epoll_data_t data)
{
  return unix_server_epoll_ctl(server, EPOLL_CTL_MOD, fd, data);
}

static int unix_server_init(struct ef_shrub_server* server, const char* server_addr)
{
  int rc;
  epoll_data_t epoll_data;

  remove(server_addr);

  rc = unix_server_epoll_create(server);
  if( rc < 0 )
    return rc;

  rc = unix_server_listen(server, server_addr);
  if( rc < 0 )
    goto fail_server_listen;

  epoll_data.ptr = NULL;
  rc = unix_server_epoll_add(server, server->unix_server.listen, epoll_data);
  if( rc < 0 )
    goto fail_epoll_add;

  return 0;
fail_epoll_add:
  close(server->unix_server.listen);
fail_server_listen:
  close(server->unix_server.epoll);
  return rc;
}

static void unix_server_fini(struct ef_shrub_server* server)
{
  close(server->unix_server.listen);
  close(server->unix_server.epoll);
  if ( server->socket_path )
    unlink(server->socket_path);
}

static int server_connection_opened(struct ef_shrub_server* server);
static int server_request_received(struct ef_shrub_server* server, int socket);
static int server_connection_closed(struct ef_shrub_server* server, void *data);
static void server_buffer_cleanup(struct ef_vi* vi,
                                  struct ef_shrub_queue* queue,
                                  ef_shrub_buffer_id buffer);

static int unix_server_poll(struct ef_shrub_server* server)
{
  int rc;
  struct epoll_event event;
  rc = epoll_wait(server->unix_server.epoll, &event, 1, 0);
  if( rc > 0 ) {
    if( event.data.ptr == NULL )
      rc = server_connection_opened(server);
    else if( event.events & EPOLLIN )
      rc = server_request_received(server, event.data.fd);

    if( event.events & EPOLLHUP )
      rc = server_connection_closed(server, event.data.ptr);
  }
  return rc;
}

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

static int client_total_bytes(struct ef_shrub_queue* queue)
{
  return fifo_bytes(queue) +
    EF_VI_ROUND_UP(sizeof(struct ef_shrub_client_state), PAGE_SIZE);
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

static int queue_alloc_buffer_fifo_indices(struct ef_shrub_queue* queue)
{
  int i;
  queue->buffer_fifo_indices = malloc(queue->buffer_count * sizeof(int));
  if ( queue->buffer_fifo_indices == NULL )
    return -ENOMEM;

  for (i = 0; i < queue->buffer_count; i++)
    queue->buffer_fifo_indices[i] = -1;
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

  fd = memfd_create("ef_shrub_server_fifo", 0);
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
                      struct ef_shrub_connection* connection)
{
  int i = connection->fifo_index;

  ef_shrub_buffer_id buffer = connection->fifo[i];

  if( buffer == EF_SHRUB_INVALID_BUFFER )
    return;

  connection->fifo[i] = EF_SHRUB_INVALID_BUFFER;
  connection->fifo_index = i == queue->fifo_size - 1 ? 0 : i + 1;
  server_buffer_cleanup(vi, queue, buffer);
}

static void poll_fifos(struct ef_vi* vi, struct ef_shrub_queue* queue)
{
  struct ef_shrub_connection* c;
  for( c = queue->connections; c != NULL; c = c->next )
    poll_fifo(vi, queue, c);
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

  offset = queue->connection_count * client_total_bytes(queue);
  rc = ftruncate(fd, offset + client_total_bytes(queue));
  if( rc < 0 )
    goto fail_fifo;

  map = mmap(NULL, client_total_bytes(queue),
             PROT_READ | PROT_WRITE,
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

static struct ef_shrub_client_state* get_client_state(struct ef_shrub_queue* queue,
                                                      struct ef_shrub_connection* connection)
{
  return (void*)((char*)connection->fifo + fifo_bytes(queue));
}

static int connection_send_metrics(struct ef_shrub_queue* queue,
                                   struct ef_shrub_connection* connection)
{
  int rc;
  struct ef_shrub_client_state* state = get_client_state(queue, connection);

  //TODO: re-evaluate this if-check startup state case on completion of ON-16190
  if ( queue->connection_count > 0 ) {
    /* Function to scan backwards in the FIFO until it finds the first invalid buffer.
     * The index afterwards is the first valid buffer that we wish to sync upon. */
    int queue_index = queue->fifo_index == 0 ? queue->fifo_size - 1 : queue->fifo_index - 1;
    assert(queue->fifo[queue_index] != EF_SHRUB_INVALID_BUFFER);
    while ( queue->fifo[queue_index] != EF_SHRUB_INVALID_BUFFER ) {
      queue_index--;
      if ( queue_index < 0 )
        queue_index = queue->fifo_size - 1;
    }
    state->server_fifo_index = ( queue_index == queue->fifo_size - 1 ? 0 : queue_index + 1 );
  }

  struct ef_shrub_shared_metrics* metrics = &state->metrics;
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
  metrics->client_fifo_size = queue->fifo_size;

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

  rc = queue_alloc_buffer_fifo_indices(queue);
  if ( rc < 0 )
    goto fail_indices;

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
  
  queue->ix = rc;
  *queue_out = queue;
  return 0;

fail_queue_attach:
  munmap(queue->fifo, fifo_bytes(queue));
fail_fifo:
  for( i = 0; i < EF_SHRUB_FD_COUNT; ++i )
    close(queue->shared_fds[i]);
fail_shared:
  free(queue->buffer_fifo_indices);
fail_indices:
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
  free(queue->buffer_fifo_indices);
  free(queue->buffer_refs);
  free(queue);
}

static void ef_shrub_queue_poll(struct ef_vi* vi, struct ef_shrub_queue* queue)
{
  bool sentinel;
  unsigned sbseq;
  ef_vi_efct_rxq_ops* ops;
  ops = vi->efct_rxqs.ops;

  poll_fifos(vi, queue);
  while( fifo_has_space(queue) ) {
    int next_buffer = ops->next(vi, queue->ix, &sentinel, &sbseq);
    if ( next_buffer < 0 ) {
      break;
    }
    int i = queue->fifo_index;
    queue->fifo[i] = set_buffer_id(next_buffer, sentinel);
    assert(queue->buffer_refs[next_buffer] == 0);
    queue->buffer_refs[next_buffer] = queue->connection_count;
    queue->buffer_fifo_indices[next_buffer] = i;
    queue->fifo_index = i == queue->fifo_size - 1 ? 0 : i + 1;
  }
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
  struct ef_shrub_client_state* state;
  epoll_data_t epoll_data;
  int rc;

  queue = server->shrub_queues[qid];
  if( queue == NULL ) {
    rc = ef_shrub_queue_open(server->vi, &queue,
                             server->buffer_bytes, server->buffer_count,
                             qid);
    if( rc < 0 )
      return rc;
    server->shrub_queues[qid] = queue;
  }

  connection = connection_alloc(queue);
  if( connection == NULL )
    return -1; /* TODO propogate connection_alloc's rc */

  connection->socket = socket;
  rc = connection_send_metrics(queue, connection);
  if( rc < 0 )
    goto fail;

  epoll_data.ptr = connection;
  rc = unix_server_epoll_mod(server, socket, epoll_data);
  if( rc < 0 )
    goto fail;

  connection->next = queue->connections;
  connection->qid = qid;
  queue->connections = connection;

  if ( queue->connection_count > 0 ) {
    int i;
    state = (void*)((char*)connection->fifo + fifo_bytes(queue));
    i = state->server_fifo_index;
    while ( i != queue->fifo_index ) {
      ef_shrub_buffer_id buffer = queue->fifo[i];
      assert(buffer != EF_SHRUB_INVALID_BUFFER);
      queue->buffer_refs[get_buffer_id(buffer)]++; 
      i = (i == queue->fifo_size - 1 ? 0: i + 1);
    } 
  }

  queue->connection_count++;
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
  rc = ci_resource_op(server->vi->dh, &op);
  server->pd_excl_rxq_tok = op.u.pd_excl_rxq_tok_get.token;
  return rc;
}

static int server_request_token(struct ef_shrub_server *server, int socket)
{
  struct ef_shrub_token_response response = {0};
  int rc;

  response.shared_rxq_token = server->pd_excl_rxq_tok;
  rc = send(socket, &response, sizeof(response), 0);
  if( rc < 0 )
    return -errno;
  if( rc < sizeof(response) )
    return -EIO;
  /* Client will connect again once it has an rxq to attach to. Remove it from
   * the epoll set */
  rc = close(socket);
  if( rc < 0 )
    return -errno;

  return 0;
}

static int server_request_received(struct ef_shrub_server* server, int socket)
{
  struct ef_shrub_request request;
  int rc;

  rc = recv(socket, &request, sizeof(request), 0);
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
  close(socket);
  return rc;
}

static int server_connection_opened(struct ef_shrub_server* server)
{
  int rc = 0;
  int socket = accept(server->unix_server.listen, NULL, NULL);
  epoll_data_t epoll_data;

  if( socket < 0 )
    return socket;

  epoll_data.fd = socket;
  rc = unix_server_epoll_add(server, socket, epoll_data);
  if( rc < 0 )
    close(socket);

  return rc;
}

static void server_buffer_cleanup(struct ef_vi* vi,
                                  struct ef_shrub_queue* queue,
                                  ef_shrub_buffer_id buffer) {
  assert(buffer != EF_SHRUB_INVALID_BUFFER);
  if ( --queue->buffer_refs[buffer] == 0 ) {
    int buffer_fifo_index = queue->buffer_fifo_indices[buffer];
    queue->fifo[buffer_fifo_index] = EF_SHRUB_INVALID_BUFFER;
    queue->buffer_fifo_indices[buffer] = -1;
    vi->efct_rxqs.ops->free(vi, queue->ix, buffer);
  }
}

static int server_connection_closed(struct ef_shrub_server* server, void *data)
{
  int i;
  struct ef_shrub_client_state* state;
  struct ef_shrub_connection* connection = data;
  struct ef_shrub_queue* queue = server->shrub_queues[connection->qid];
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
  state = get_client_state(queue, connection);

  i = state->server_fifo_index;
  while ( i != queue->fifo_index ) {
    ef_shrub_buffer_id buffer = queue->fifo[i];
    assert(buffer != EF_SHRUB_INVALID_BUFFER);
    server_buffer_cleanup(server->vi, queue, get_buffer_id(buffer));
    i = (i == queue->fifo_size - 1 ? 0: i + 1);
  }

  queue->connection_count--;
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

  rc = unix_server_init(server, server_addr);
  if( rc < 0 )
    goto fail_unix_server_init;

  server->vi = vi;
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
  unix_server_fini(server);
fail_unix_server_init:
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

    ef_shrub_queue_poll(server->vi,
                        server->shrub_queues[qid]);
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
  unix_server_fini(server);
  free(server);
}
