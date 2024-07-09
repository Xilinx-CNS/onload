/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */
#include "shrub_client.h"


#include "ci/driver/efab/hardware/byteswap.h"
#include "ci/driver/efab/hardware/bitfield.h"

#include <etherfabric/shrub_shared.h>

#include <stdio.h>
#include <stdbool.h>

#include <stddef.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>


struct ef_shrub_client {
  int socket;

  int server_fifo_index;
  int client_fifo_index;

  struct ef_shrub_shared_metrics metrics;
  char* buffers;
  ef_shrub_buffer_id* server_fifo;
  ef_shrub_buffer_id* client_fifo;
};

static int client_socket(void)
{
  int rc = socket(AF_UNIX, SOCK_STREAM, 0);
  return rc >= 0 ? rc : -errno;
}

static int client_connect(int client, const char* server_addr)
{
  struct sockaddr_un addr;
  int path_len = strlen(server_addr);

  if( path_len >= sizeof(addr.sun_path) )
    return -EINVAL;

  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, server_addr);
  /* TBD: do we want a non-blocking option (for this and recv)? */
  return connect(client, (struct sockaddr*)&addr,
                 offsetof(struct sockaddr_un, sun_path) + path_len + 1);
}

static size_t buffer_mmap_bytes(struct ef_shrub_client* client)
{
  return client->metrics.buffer_bytes * client->metrics.buffer_count;
}

static size_t server_mmap_bytes(struct ef_shrub_client* client)
{
  return client->metrics.queue_fifo_size * sizeof(ef_shrub_buffer_id);
}

static size_t client_mmap_bytes(struct ef_shrub_client* client)
{
  return client->metrics.client_fifo_size * sizeof(ef_shrub_buffer_id);
}

static int client_mmap(struct ef_shrub_client* client,
                       void* buffer_addresses,
                       int shared_fds[EF_SHRUB_FD_COUNT])
{
  void* map;
  int flags = MAP_SHARED | MAP_POPULATE;

  map = mmap(buffer_addresses, client->metrics.buffer_count * client->metrics.buffer_bytes, PROT_READ, flags | MAP_HUGETLB | MAP_FIXED,
             shared_fds[EF_SHRUB_FD_BUFFERS], 0);
  if( map == MAP_FAILED )
    return -errno;
  client->buffers = map;

  map = mmap(NULL, server_mmap_bytes(client), PROT_READ, flags,
             shared_fds[EF_SHRUB_FD_SERVER_FIFO], 0);
  if( map == MAP_FAILED )
    return -errno;
  client->server_fifo = map;

  map = mmap(NULL, client_mmap_bytes(client), PROT_WRITE, flags,
             shared_fds[EF_SHRUB_FD_CLIENT_FIFO],
             client->metrics.client_fifo_offset);
  if( map == MAP_FAILED )
    return -errno;
  client->client_fifo = map;

  return 0;
}

static int client_request_q(struct ef_shrub_client *client,
                            const char* server_addr, int qid)
{
  int rc = 0;
  struct ef_shrub_queue_request req;

  rc = client_connect(client->socket, server_addr);
  if( rc < 0 )
    return rc;

  req.server_version = EF_SHRUB_VERSION;
  req.qid = qid;
  rc = send(client->socket, &req, sizeof(req), 0);
  if( rc < 0 )
    rc = -errno;

  return rc;
}

static int client_recv_metrics(struct ef_shrub_client* client, void* buffer_addresses)
{
  int rc, i;
  struct iovec iov = {
    .iov_base = &client->metrics,
    .iov_len = sizeof(client->metrics)
  };
  int shared_fds[EF_SHRUB_FD_COUNT];
  char cmsg_buf[CMSG_SPACE(sizeof(shared_fds))];
  struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsg_buf,
    .msg_controllen = sizeof(cmsg_buf)
  };
  struct cmsghdr* cmsg;

  rc = recvmsg(client->socket, &msg, 0);
  if( rc < 0 )
    return -errno;
  if( rc != sizeof(client->metrics) ||
      client->metrics.server_version != EF_SHRUB_VERSION)
    return -EPROTO;

  cmsg = CMSG_FIRSTHDR(&msg);
  if( cmsg == NULL ||
      cmsg->cmsg_level != SOL_SOCKET ||
      cmsg->cmsg_type != SCM_RIGHTS ||
      cmsg->cmsg_len != CMSG_LEN(sizeof(shared_fds)) )
    return -EPROTO;

  memcpy(shared_fds, CMSG_DATA(cmsg), sizeof(shared_fds));
  rc = client_mmap(client, buffer_addresses, shared_fds);
  for( i = 0; i < EF_SHRUB_FD_COUNT; ++i )
    close(shared_fds[i]);
  if( rc < 0 )
    return rc;

  /* TODO synchronise with server */
  return 0;
}

int ef_shrub_client_open(struct ef_shrub_client** client_out,
                         void* buffer_addresses, const char* server_addr,
                         int qid)
{
  struct ef_shrub_client* client;
  int rc;

  client = calloc(1, sizeof(*client));
  if( client == NULL )
    return -ENOMEM;

  rc = client_socket();
  if( rc < 0 )
    goto fail_socket;
  client->socket = rc;

  rc = client_request_q(client, server_addr, qid);
  if( rc < 0 )
    goto fail_request_q;

  rc = client_recv_metrics(client, buffer_addresses);
  if( rc < 0 )
    goto fail_recv;

  *client_out = client;
  return 0;

fail_recv:
  if( client->buffers )
    munmap(client->buffers, buffer_mmap_bytes(client));
  if( client->server_fifo )
    munmap(client->server_fifo, server_mmap_bytes(client));
  if( client->client_fifo )
    munmap(client->client_fifo, client_mmap_bytes(client));
fail_request_q:
  close(client->socket);
fail_socket:
  free(client);
  return rc;
}

void ef_shrub_client_close(struct ef_shrub_client* client)
{
  munmap(client->buffers, buffer_mmap_bytes(client));
  munmap(client->server_fifo, server_mmap_bytes(client));
  munmap(client->client_fifo, client_mmap_bytes(client));
  close(client->socket);
  free(client);
}

int ef_shrub_client_acquire_buffer(struct ef_shrub_client* client,
                                   uint32_t* buffer_id ,
                                   bool* sentinel)
{

  ci_dword_t id2;
  int i = client->server_fifo_index;
  ef_shrub_buffer_id id = client->server_fifo[i];
  if( id == EF_SHRUB_INVALID_BUFFER )
    return -EAGAIN;

  client->server_fifo_index =
    i == client->metrics.queue_fifo_size - 1 ? 0 : i + 1;

  id2.u32[0] = id;
  *buffer_id = CI_DWORD_FIELD(id2, EF_SHRUB_BUFFER_ID);
  *sentinel = CI_DWORD_FIELD(id2, EF_SHRUB_SENTINEL) == 1;
  return 0;
}

void ef_shrub_client_release_buffer(struct ef_shrub_client* client,
                                    uint32_t buffer_id)
{
  int i = client->client_fifo_index;

  client->client_fifo[i] = buffer_id;
  client->client_fifo_index = i == client->metrics.client_fifo_size - 1 ? 0 : i + 1;
}

size_t ef_shrub_client_buffer_bytes(const struct ef_shrub_client* client)
{
  return client->metrics.buffer_bytes;
}

size_t ef_shrub_client_buffer_count(const struct ef_shrub_client* client)
{
  return client->metrics.buffer_count;
}

bool ef_shrub_client_buffer_available(const struct ef_shrub_client* client)
{
  int i = client->server_fifo_index;
  ef_shrub_buffer_id id = client->server_fifo[i];
  return id != EF_SHRUB_INVALID_BUFFER;
}
