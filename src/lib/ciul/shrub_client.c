/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

#include "ef_vi_internal.h"
#include "shrub_client.h"
#include "shrub_socket.h"

/* Accessors for mapped memory */
static const ef_shrub_buffer_id*
get_server_fifo(const struct ef_shrub_client* client)
{
  return (void*)client->mappings[EF_SHRUB_FD_SERVER_FIFO];
}

static ef_shrub_buffer_id*
get_client_fifo(struct ef_shrub_client* client)
{
  return (void*)client->mappings[EF_SHRUB_FD_CLIENT_FIFO];
}

static struct ef_shrub_client_state* get_state(struct ef_shrub_client* client)
{
  return (void*)(client->mappings[EF_SHRUB_FD_COUNT]);
}

static size_t map_size(const struct ef_shrub_shared_metrics* metrics, int type)
{
  switch( type ) {
  case EF_SHRUB_FD_BUFFERS:
    return metrics->buffer_bytes * metrics->buffer_count;
  case EF_SHRUB_FD_SERVER_FIFO:
    return metrics->server_fifo_size * sizeof(ef_shrub_buffer_id);
  case EF_SHRUB_FD_CLIENT_FIFO:
    return metrics->client_fifo_size * sizeof(ef_shrub_buffer_id) +
           sizeof(struct ef_shrub_client_state);
  default:
    return 0;
  }
}

static int client_mmap(uint64_t* mappings, uintptr_t* files,
                       const struct ef_shrub_shared_metrics* metrics,
                       void* buffers)
{
  int i;
  for( i = 0; i < EF_SHRUB_FD_COUNT; ++i ) {
    int rc;
    void* addr = i == EF_SHRUB_FD_BUFFERS ? buffers : NULL;
    size_t offset = i == EF_SHRUB_FD_CLIENT_FIFO ? metrics->client_fifo_offset : 0;

    rc = ef_shrub_socket_mmap(&mappings[i], addr, map_size(metrics, i),
                              files[i], offset, i);
    if( rc < 0 )
      return rc;
  }

  mappings[EF_SHRUB_FD_COUNT] =
    mappings[EF_SHRUB_FD_CLIENT_FIFO] +
      map_size(metrics, EF_SHRUB_FD_CLIENT_FIFO) -
        sizeof(struct ef_shrub_client_state);

  return 0;
}

static int client_mmap_user(uint64_t* user_mappings, const uintptr_t* files,
                            const struct ef_shrub_shared_metrics* metrics,
                            uint64_t user_buffers)
{
  int i;
  for( i = 0; i < EF_SHRUB_FD_COUNT; ++i ) {
    int rc;
    uint64_t user_addr = i == EF_SHRUB_FD_BUFFERS ? user_buffers : 0;
    size_t offset = i == EF_SHRUB_FD_CLIENT_FIFO ? metrics->client_fifo_offset : 0;

    rc = ef_shrub_socket_mmap_user(&user_mappings[i], user_addr,
                                   map_size(metrics, i), files[i], offset, i);
    if( rc < 0 )
      return rc;
  }

  return 0;
}

void client_munmap(uint64_t* mappings, uintptr_t* files,
                   const struct ef_shrub_shared_metrics* metrics)
{
  int i;
  for( i = 0; i < EF_SHRUB_FD_COUNT; ++i ) {
    if( mappings[i] != 0 )
      ef_shrub_socket_munmap(mappings[i], map_size(metrics, i), i);
    ef_shrub_socket_close_file(files[i]);
  }
}

int ef_shrub_client_request_token(const char *server_addr,
                                  struct ef_shrub_token_response *response)
{
  struct ef_shrub_request request = {};
  uintptr_t sock;
  int rc;

  rc = ef_shrub_socket_open(&sock);
  if( rc < 0 )
    return rc;

  rc = ef_shrub_socket_connect(sock, server_addr);
  if( rc < 0 )
    goto out;

  request.server_version = EF_SHRUB_VERSION;
  request.type = EF_SHRUB_REQUEST_TOKEN;
  rc = ef_shrub_socket_send(sock, &request, sizeof(request));
  if( rc < 0 )
    goto out;

  rc = ef_shrub_socket_recv(sock, response, sizeof(*response));

out:
  ef_shrub_socket_close_socket(sock);
  return rc;
}

int ef_shrub_client_open(struct ef_shrub_client* client,
                         void* buffers,
                         const char* server_addr,
                         int qid)
{
  int rc;
  struct ef_shrub_shared_metrics metrics;
  struct ef_shrub_request request = {};
  memset(client, 0, sizeof(*client));

  rc = ef_shrub_socket_open(&client->socket);
  if( rc < 0 )
    return rc;

  rc = ef_shrub_socket_connect(client->socket, server_addr);
  if( rc < 0 )
    goto fail_request;

  request.server_version = EF_SHRUB_VERSION;
  request.type = EF_SHRUB_REQUEST_QUEUE;
  request.requests.queue.qid = qid;
  rc = ef_shrub_socket_send(client->socket, &request, sizeof(request));
  if( rc < 0 )
    goto fail_request;

  rc = ef_shrub_socket_recv_metrics(&metrics, client->files, client->socket);
  if( rc < 0 )
    goto fail_request;

  rc = client_mmap(client->mappings, client->files, &metrics, buffers);
  if( rc < 0 )
    goto fail_mmap;

  return 0;

fail_mmap:
  client_munmap(client->mappings, client->files, &metrics);
fail_request:
  ef_shrub_socket_close_socket(client->socket);
  return rc;
}

void ef_shrub_client_close(struct ef_shrub_client* client)
{
  client_munmap(client->mappings, client->files, &get_state(client)->metrics);
  ef_shrub_socket_close_socket(client->socket);
}

int ef_shrub_client_refresh_mappings(const struct ef_shrub_client* client,
                                     uint64_t user_buffers,
                                     uint64_t* user_mappings)
{
  const struct ef_shrub_client_state* state = ef_shrub_client_get_state(client);

  if( state == NULL )
    return -EOPNOTSUPP;

  return client_mmap_user(user_mappings, client->files,
                          &state->metrics, user_buffers);
}

int ef_shrub_client_acquire_buffer(struct ef_shrub_client* client,
                                   uint32_t* buffer_id,
                                   bool* sentinel)
{

  ci_dword_t id2;
  struct ef_shrub_client_state* state = get_state(client);
  int i = state->server_fifo_index;
  ef_shrub_buffer_id id = get_server_fifo(client)[i];
  if( id == EF_SHRUB_INVALID_BUFFER )
    return -EAGAIN;

  state->server_fifo_index =
    i == state->metrics.server_fifo_size - 1 ? 0 : i + 1;

  id2.u32[0] = id;
  *buffer_id = CI_DWORD_FIELD(id2, EF_SHRUB_BUFFER_ID);
  *sentinel = CI_DWORD_FIELD(id2, EF_SHRUB_SENTINEL) == 1;
  return 0;
}

void ef_shrub_client_release_buffer(struct ef_shrub_client* client,
                                    uint32_t buffer_id)
{
  struct ef_shrub_client_state* state = get_state(client);
  int i = state->client_fifo_index;

  get_client_fifo(client)[i] = buffer_id;
  state->client_fifo_index =
    i == state->metrics.client_fifo_size - 1 ? 0 : i + 1;
}

bool ef_shrub_client_buffer_available(const struct ef_shrub_client* client)
{
  int i = ef_shrub_client_get_state(client)->server_fifo_index;
  ef_shrub_buffer_id id = get_server_fifo(client)[i];
  return id != EF_SHRUB_INVALID_BUFFER;
}
