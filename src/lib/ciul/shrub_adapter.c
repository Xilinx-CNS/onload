/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#include <assert.h>
#include <errno.h>
#include <etherfabric/shrub_adapter.h>
#include <etherfabric/shrub_shared.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static int shrub_adapter_detect_shrub_controller(int controller_id) {
  char controller_path[EF_SHRUB_SOCKET_DIR_LEN];
  char shrub_socket[EF_SHRUB_NEGOTIATION_SOCKET_LEN];
  struct stat path_stat;
  struct stat socket_stat;
  int ret;
  assert(controller_id >= 0);

  ret = snprintf(controller_path, sizeof(controller_path), EF_SHRUB_CONTROLLER_PATH_FORMAT 
                , EF_SHRUB_SOCK_DIR_PATH, controller_id);
  if ( ret < 0 || ret >= sizeof(controller_path) )
    return -EINVAL;

  ret = snprintf(shrub_socket, sizeof(shrub_socket), "%s%s", controller_path,
                 EF_SHRUB_NEGOTIATION_SOCKET);
  if ( ret < 0 || ret >= sizeof(shrub_socket) )
    return -EINVAL;

  return stat(controller_path, &path_stat) == 0 &&
                  S_ISDIR(path_stat.st_mode) &&
                  stat(shrub_socket, &socket_stat) == 0 &&
                  S_ISSOCK(socket_stat.st_mode);
}

static int attempt_to_wait_for_controller(int controller_id) {
  int attempts = 0;
  int MAX_ATTEMPTS = 100;
  while ( shrub_adapter_detect_shrub_controller(controller_id) <= 0 ) {
    if ( attempts > MAX_ATTEMPTS )
      return -ENOENT;
    attempts += 1;
    usleep(10);
  }
  return 0;
}

int shrub_adapter_send_request(int controller_id,
                               shrub_controller_request_t *request) {
  int rc;
  ssize_t received_bytes;
  int client_fd;
  struct sockaddr_un addr;

  char socket_path[EF_SHRUB_NEGOTIATION_SOCKET_LEN];
  rc = snprintf(socket_path, sizeof(socket_path), EF_SHRUB_CONTROLLER_PATH_FORMAT
                "%s", EF_SHRUB_SOCK_DIR_PATH, controller_id,
                EF_SHRUB_NEGOTIATION_SOCKET);
  if ( rc < 0 || rc >= sizeof(socket_path) )
    return -EINVAL;

  client_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if ( client_fd == -1 )
    return -errno;

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
  addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

  rc = connect(client_fd, (struct sockaddr *)&addr, sizeof(addr));
  if ( rc < 0 ) {
    rc = -errno;
    goto clean_exit;
  }

  rc = send(client_fd, request, sizeof(*request), 0);
  if ( rc == -1 ) {
    rc = -errno;
    goto clean_exit;
  }

  received_bytes = recv(client_fd, &rc, sizeof(int), 0);
  if ( received_bytes == -1 ) {
    rc = -errno;
    goto clean_exit;
  } else if ( received_bytes != sizeof(int) ) {
    rc = -ENOMEM;
    goto clean_exit;
  }

clean_exit:
  close(client_fd);
  return rc;
}

int shrub_adapter_send_ifindex(shrub_request_sender_t send_request_func,
                               int controller_id, int ifindex, uint32_t buffers) {
  int rc;
  shrub_controller_request_t request = {0};
  request.controller_version = EF_SHRUB_VERSION;
  request.command = EF_SHRUB_CONTROLLER_CREATE_IFINDEX;
  request.create_ifindex.buffer_count = buffers;
  request.create_ifindex.ifindex = ifindex;
  rc = attempt_to_wait_for_controller(controller_id);
  if ( rc < 0 )
    return rc;
  return send_request_func(controller_id, &request);
}

int shrub_adapter_send_hwport(shrub_request_sender_t send_request_func,
  int controller_id, cicp_hwport_mask_t hw_port,
  uint32_t buffers) {
    /*
    * This path needs to wait for the shrub controller to spawn and setup the
    * unix sockets.
   */
  int rc;
  shrub_controller_request_t request = {0};
  request.controller_version = EF_SHRUB_VERSION;
  request.command = EF_SHRUB_CONTROLLER_CREATE_HWPORT;
  request.create_hwport.buffer_count = buffers;
  request.create_hwport.hw_port = hw_port;
  rc = attempt_to_wait_for_controller(controller_id);
  if ( rc < 0 )
    return rc;
  return send_request_func(controller_id, &request);
}

int shrub_adapter_send_ifname(shrub_request_sender_t send_request_func,
                              int controller_id, const char *ifname,
                              uint32_t buffers) {
                                unsigned int ifindex = if_nametoindex(ifname);
  if ( ifindex == 0 )
    return -errno;
  return shrub_adapter_send_ifindex(send_request_func, controller_id, ifindex,
                                    buffers);
}

int shrub_adapter_send_dump(shrub_request_sender_t send_request_func,
                            int controller_id, const char *filename) {
  int rc;
  shrub_controller_request_t request = {0};
  request.controller_version = EF_SHRUB_VERSION;
  request.command = EF_SHRUB_CONTROLLER_DUMP;
  strncpy(request.dump.file_name, filename, EF_SHRUB_DUMP_LOG_SIZE - 1);
  request.dump.file_name[EF_SHRUB_DUMP_LOG_SIZE - 1] = '\0';
  rc = attempt_to_wait_for_controller(controller_id);
  if ( rc < 0 )
    return rc;
  return send_request_func(controller_id, &request);
}

int shrub_adapter_stop_server(shrub_request_sender_t send_request_func,
                              int controller_id, int shrub_token) {
  int rc;
  shrub_controller_request_t request = {0};
  request.controller_version = EF_SHRUB_VERSION;
  request.command = EF_SHRUB_CONTROLLER_DESTROY;
  request.destroy.shrub_token_id = shrub_token;
  rc = attempt_to_wait_for_controller(controller_id);
  if ( rc < 0 )
    return rc;
  return send_request_func(controller_id, &request);
}
