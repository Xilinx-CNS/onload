/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <etherfabric/internal/shrub_adapter.h>
#include <etherfabric/internal/shrub_shared.h>
#include <etherfabric/internal/shrub_socket.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

int ef_shrub_adapter_send_request(int controller_id,
                                  struct ef_shrub_controller_request *request)
{
  int rc;
  int received_bytes = 0;
  uintptr_t client_fd = 0;
  char socket_path[EF_SHRUB_NEGOTIATION_SOCKET_LEN];

  rc = snprintf(socket_path, sizeof(socket_path), EF_SHRUB_CONTROLLER_PATH_FORMAT
                "%s", EF_SHRUB_SOCK_DIR_PATH, controller_id,
                EF_SHRUB_NEGOTIATION_SOCKET);
  if ( rc < 0 || rc >= sizeof(socket_path) )
    return -EINVAL;

  rc = ef_shrub_socket_open(&client_fd);
  if ( rc < 0 )
    goto clean_exit;

  rc = ef_shrub_socket_connect(client_fd, socket_path);
  if ( rc < 0 )
    goto clean_exit;

  rc = ef_shrub_socket_send(client_fd, request, sizeof(*request));
  if ( rc < 0 )
    goto clean_exit;

  rc = ef_shrub_socket_recv(client_fd, &received_bytes, sizeof(int));
  if ( rc < 0 )
    goto clean_exit;

  rc = received_bytes;

clean_exit:
  if ( client_fd != 0 )
    ef_shrub_socket_close_socket(client_fd);
  return rc;
}

int ef_shrub_adapter_send_ifindex(ef_shrub_request_sender send_request_func,
                                  int controller_id, int ifindex,
                                  uint32_t buffers)
{
  struct ef_shrub_controller_request request = {0};
  request.controller_version = EF_SHRUB_VERSION;
  request.command = EF_SHRUB_CONTROLLER_CREATE_IFINDEX;
  request.create_ifindex.buffer_count = buffers;
  request.create_ifindex.ifindex = ifindex;
  return send_request_func(controller_id, &request);
}

int ef_shrub_adapter_send_hwport(ef_shrub_request_sender send_request_func,
                                 int controller_id, ci_hwport_id_t hw_port,
                                 uint32_t buffers)
{
  /*
   * This path needs to wait for the shrub controller to spawn and setup the
   * unix sockets.
   */
  struct ef_shrub_controller_request request = {0};

  CI_BUILD_ASSERT(sizeof(request.create_hwport.hw_port) >= sizeof(hw_port));

  request.controller_version = EF_SHRUB_VERSION;
  request.command = EF_SHRUB_CONTROLLER_CREATE_HWPORT;
  request.create_hwport.buffer_count = buffers;
  request.create_hwport.hw_port = hw_port;
  return send_request_func(controller_id, &request);
}

int ef_shrub_adapter_send_ifname(ef_shrub_request_sender send_request_func,
                                int controller_id, const char *ifname,
                                uint32_t buffers)
{
  unsigned int ifindex = if_nametoindex(ifname);
  if ( ifindex == 0 )
    return -errno;
  return ef_shrub_adapter_send_ifindex(send_request_func, controller_id,
                                       ifindex, buffers);
}

int ef_shrub_adapter_send_dump(ef_shrub_request_sender send_request_func,
                               int controller_id, const char *filename)
{
  struct ef_shrub_controller_request request = {0};
  request.controller_version = EF_SHRUB_VERSION;
  request.command = EF_SHRUB_CONTROLLER_DUMP_TO_FILE;
  strncpy(request.dump.file_name, filename, EF_SHRUB_DUMP_LOG_SIZE - 1);
  request.dump.file_name[EF_SHRUB_DUMP_LOG_SIZE - 1] = '\0';
  return send_request_func(controller_id, &request);
}

int ef_shrub_adapter_stop_server(ef_shrub_request_sender send_request_func,
                                 int controller_id, int shrub_token)
{
  struct ef_shrub_controller_request request = {0};
  request.controller_version = EF_SHRUB_VERSION;
  request.command = EF_SHRUB_CONTROLLER_DESTROY;
  request.destroy.shrub_token_id = shrub_token;
  return send_request_func(controller_id, &request);
}
