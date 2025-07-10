/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

#include "cp_intf_ver.h"

#include <assert.h>
#include <ci/compat.h>
#include <ci/tools/log.h>
#include <cplane/cplane.h>
#include <cplane/create.h>
#include <cplane/mib.h>
#include <ctype.h>
#include <errno.h>
#include <etherfabric/efct_vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/shrub_server.h>
#include <etherfabric/shrub_shared.h>
#include <etherfabric/vi.h>
#include <fcntl.h>
#include <ftw.h>
#include <getopt.h>
#include <net/if.h>
#include <onload/driveraccess.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

int (*ci_sys_ioctl)(int, long unsigned int, ...) =
    ioctl; /* taken from cplane/private.h (example code from cplane/client.c) */

struct shrub_controller_vi;
static volatile sig_atomic_t is_running = 1;
static volatile sig_atomic_t call_shrub_dump = 0;

#define DEFAULT_BUFFER_SIZE 1024 * 1024

#define EF_SHRUB_CONFIG_SOCKET_LOCK EF_SHRUB_NEGOTIATION_SOCKET "_lock"
#define EF_SHRUB_CONFIG_SOCKET_LOCK_LEN (EF_SHRUB_SOCKET_DIR_LEN + \
                                         sizeof(EF_SHRUB_CONFIG_SOCKET_LOCK))

struct shrub_controller_vi
{
  ef_vi vi;
  int n_ev;
  int i;
  ef_pd pd;
  ef_driver_handle dh;
};

typedef struct shrub_if_config_s
{
  int ifindex;
  cicp_hwport_mask_t hw_ports;
  int token_id;
  int buffer_count;
  struct shrub_controller_vi res;
  struct ef_shrub_server *shrub_server;
  int client_fd;
  int ref_count;
  struct shrub_if_config_s *next;
  bool server_started;
} shrub_if_config_t;

typedef struct
{
  int interface_token;
  int config_socket_fd;
  int epoll_fd;
  int controller_id;
  int config_socket_lock_fd;
  shrub_if_config_t *server_config_head;
  struct oo_cplane_handle *cp;
  int oo_fd_handle;
  bool debug_mode;
  char controller_dir[EF_SHRUB_SOCKET_DIR_LEN];
  char log_dir[EF_SHRUB_LOG_LEN];
  char config_socket[EF_SHRUB_NEGOTIATION_SOCKET_LEN];
  char config_socket_lock[EF_SHRUB_CONFIG_SOCKET_LOCK_LEN];
} shrub_controller_config;

static void usage(void)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  shrub_controller <flags> "
                  "[<interface>[/<buffer_count>]]...\n");
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -d       Enable debug mode\n");
  fprintf(stderr, "  -c       Set controller_id\n");
}

static int search_for_existing_server(shrub_controller_config *config,
                                      cicp_hwport_mask_t new_hw_ports)
{
  shrub_if_config_t *current_interface = config->server_config_head;
  while ( current_interface != NULL ) {
    if ( current_interface->hw_ports == new_hw_ports ) {
      if ( config->debug_mode )
        ci_log("Info: shrub_controller found duplicate shrub_server "
               "with hw_port %d", new_hw_ports);
      current_interface->ref_count++;
      return current_interface->token_id;
    }
    current_interface = current_interface->next;
  }
  return 0;
}

static cicp_hwport_mask_t
convert_ifindex_to_hwport(shrub_controller_config *config, int ifindex)
{
  cicp_hwport_mask_t hwport_mask = 0;
  oo_cp_find_llap(config->cp, ifindex, NULL, NULL, &hwport_mask, NULL, NULL);
  return hwport_mask;
}

static int convert_hwport_to_ifindex(shrub_controller_config *config,
                                     cicp_hwport_mask_t hw_port)
{
  ci_ifid_t ifindex;
  struct cp_mibs *mib;
  cp_version_t version;

  ci_assert(config->cp);
  CP_VERLOCK_START(version, mib, config->cp)
  ifindex = cp_get_hwport_ifindex(config->cp->mib, hw_port);
  CP_VERLOCK_STOP(version, mib)
  return ifindex;
}

static int add_server_config(shrub_controller_config *config,
                             cicp_hwport_mask_t hw_port, int ifindex,
                             uint32_t buffer_count)
{

  shrub_if_config_t *new_shrub_config;

  if ( buffer_count == 0 ) {
    ci_log("Error: shrub_controller was unable to add interface "
           "with buffer size of 0");
    return -EINVAL;
  }

  new_shrub_config = (shrub_if_config_t *)malloc(sizeof(shrub_if_config_t));
  if ( new_shrub_config == NULL ) {
    ci_log("Error: shrub_controller failed to allocate memory "
           "for new interface configuration.!");
    return -ENOMEM;
  }

  new_shrub_config->ifindex = ifindex;
  new_shrub_config->hw_ports = hw_port;
  new_shrub_config->ref_count = 0;
  new_shrub_config->buffer_count = buffer_count;
  new_shrub_config->next = config->server_config_head;
  new_shrub_config->token_id = config->interface_token;
  new_shrub_config->client_fd = -1;
  new_shrub_config->server_started = false;
  config->interface_token++;
  config->server_config_head = new_shrub_config;
  return 0;
}

static void shrub_server_fini(shrub_if_config_t *config)
{
  if ( config->server_started ) {
    ef_shrub_server_close(config->shrub_server);
    ef_vi_free(&config->res.vi, config->res.dh);
    ef_pd_free(&config->res.pd, config->res.dh);
    ef_driver_close(config->res.dh);
  }
}

static void remove_and_stop_interface(shrub_controller_config *config,
                                      int intf_token)
{
  shrub_if_config_t *prev_interface = NULL;
  shrub_if_config_t *current_interface = config->server_config_head;

  while ( current_interface != NULL ) {
    if ( current_interface->token_id == intf_token ) {
      current_interface->ref_count--;
      if ( current_interface->ref_count <= 0 ) {
        shrub_server_fini(current_interface);

        if ( prev_interface != NULL )
          prev_interface->next = current_interface->next;
        else
          config->server_config_head = current_interface->next;

        free(current_interface);
      }
      break;
    }

    prev_interface = current_interface;
    current_interface = current_interface->next;
  }
}

static int shrub_server_init(shrub_controller_config *config,
                             shrub_if_config_t *interface_config)
{
  int rc;
  unsigned vi_flags = EF_VI_FLAGS_DEFAULT;
  unsigned pd_flags = EF_PD_DEFAULT | EF_PD_EXPRESS;
  struct shrub_controller_vi *res = &interface_config->res;

  char server_path[EF_SHRUB_SERVER_SOCKET_LEN];
  rc = snprintf(server_path, sizeof(server_path), "%s" EF_SHRUB_SHRUB_FORMAT,
                config->controller_dir, interface_config->token_id);
  if ( rc < 0 || rc >= sizeof(server_path) ) {
    ci_log("Error: shrub_controller failed to set server path");
    return -EINVAL;
  }

  rc = ef_driver_open(&res->dh);
  if ( rc != 0 ) {
    ci_log("Error: shrub_controller failed to open driver handle");
    return rc;
  }

  rc = ef_pd_alloc(&res->pd, res->dh, interface_config->ifindex, pd_flags);
  if ( rc != 0 ) {
    ci_log("Error: shrub_controller failed to alloc pd for %d",
      interface_config->ifindex);
    goto fail_pd_alloc;
  }

  rc = ef_vi_alloc_from_pd(&res->vi, res->dh, &res->pd, res->dh, -1, -1, 0,
                           NULL, -1, vi_flags);
  if ( rc != 0 ) {
    ci_log("Error: shrub_controller failed to allocate a vi");
    goto fail_vi_alloc;
  }

  rc = ef_shrub_server_open(&res->vi, &interface_config->shrub_server,
                            server_path, DEFAULT_BUFFER_SIZE,
                            interface_config->buffer_count);
  if ( rc != 0 ) {
    ci_log("Error: shrub_controller failed to call server open");
    goto fail_server_alloc;
  }

  interface_config->ref_count++;
  interface_config->server_started = true;

  return 0;
fail_server_alloc:
  ef_vi_free(&res->vi, res->dh);
fail_vi_alloc:
  ef_pd_free(&res->pd, res->dh);
fail_pd_alloc:
  ef_driver_close(res->dh);
  return rc;
}

static int directory_exists(const char *path)
{
  struct stat path_stat;
  return (stat(path, &path_stat) == 0 && S_ISDIR(path_stat.st_mode) ? 1 : 0);
}

static int create_directory(const char *path)
{
  int rc = 0;
  if ( mkdir(path, 0755) == 0 || errno == EEXIST )
    return rc;
  rc = -errno;
  ci_log("Error: shrub_controller failed to create the directory '%s'", path);
  return rc;
}

static int shrub_dump(shrub_controller_config *config, const char *file_name)
{
  char file_path[EF_SHRUB_LOG_LEN];
  int rc = 0;
  shrub_if_config_t *server_config;
  FILE *file;

  rc = snprintf(file_path, sizeof(file_path), "%s/%s", config->log_dir,
                file_name);
  if ( rc < 0 || rc >= sizeof(file_path) ) {
    ci_log("Error: shrub_controller was unable "
           "to set an appropriate log path!");
    return -EINVAL;
  }

  if ( !directory_exists(config->log_dir) )
    create_directory(config->log_dir);

  file = fopen(file_path, "w");
  if ( file == NULL ) {
    rc = -errno;
    ci_log("Error: shrub_controller was unable "
           "to open a file for shrub dump!");
    return rc;
  }

  fprintf(file, "Shrub Controller State:\n");
  fprintf(file, "  - Controller Name: controller-%d\n", config->controller_id);
  fprintf(file, "  - Debug Mode: %s\n", config->debug_mode ? "true" : "false");
  fprintf(file, "  - Controller Dir: %s\n", config->controller_dir);
  fprintf(file, "  - Config Socket: %s\n", config->config_socket);

  server_config = config->server_config_head;
  while ( server_config != NULL ) {
    fprintf(file, "\nShrub If Config Details:\n");
    fprintf(file, "  - Token ID: %d\n", server_config->token_id);
    fprintf(file, "  - Buffer Count: %d\n", server_config->buffer_count);
    fprintf(file, "  - Ifindex: %d\n", server_config->ifindex);
    fprintf(file, "  - Hwports: %u\n", server_config->hw_ports);
    fprintf(file, "  - Clients %d\n", server_config->ref_count);
    server_config = server_config->next;
  }

  fclose(file);
  return rc;
}

static int create_onload_config_socket(const char *socket_path, int epoll_fd)
{
  int rc = 0;
  int config_socket_fd = 0;
  struct sockaddr_un addr = {0};
  struct epoll_event event;

  unlink(socket_path);

  config_socket_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if ( config_socket_fd == -1 ) {
    rc = -errno;
    ci_log("Error: shrub_controller onload handshake socket config failed");
    return rc;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
  addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

  if ( (bind(config_socket_fd,
             (struct sockaddr *)&addr,
             sizeof(addr)) == -1) ) {
    rc = -errno;
    ci_log("Error: shrub_controller onload socket bind failed");
    goto cleanup_socket;
  }

  if ( listen(config_socket_fd, 5) == -1 ) {
    rc = -errno;
    ci_log("Error: shrub_controller onload failed to listen on onload socket");
    goto cleanup_socket;
  }

  /* Add config_socket_fd to the epoll instance */
  event.data.fd = config_socket_fd;
  event.events = EPOLLIN;
  if ( epoll_ctl(epoll_fd, EPOLL_CTL_ADD, config_socket_fd, &event) == -1 ) {
    rc = -errno;
    ci_log("Error: shrub_controller epoll_ctl failed to add config_socket_fd");
    goto cleanup_socket;
  }

  return config_socket_fd;

cleanup_socket:
  close(config_socket_fd);
  return rc;
}

static int process_create_command(shrub_controller_config *config,
                                  cicp_hwport_mask_t hw_port, int ifindex,
                                  uint32_t buffer_count, int client_fd)
{
  int rc = search_for_existing_server(config, hw_port);

  /* Either rc is -1 and the cplane can't recognise the intf or we have a
     pre-existing shrub_token/server */
  if ( rc != 0 )
    return rc;

  rc = add_server_config(config, hw_port, ifindex, buffer_count);
  if ( rc != 0 ) {
    if ( config->debug_mode ) {
      ci_log("Error: shrub_controller failed to create a server listening on "
             "ifindex %d with requested buffer_count %d",
             ifindex, buffer_count);
    }
    return rc;
  }

  rc = shrub_server_init(config, config->server_config_head);
  if ( rc != 0 ) {
    if ( config->debug_mode ) {
      ci_log("Error: shrub_controller failed to initialise server on "
             "interface %d with requested buffer_count %d",
             config->server_config_head->ifindex,
             config->server_config_head->buffer_count);
    }
    remove_and_stop_interface(config, config->server_config_head->token_id);
    return rc;
  }
  config->server_config_head->client_fd = client_fd;

  if ( config->debug_mode ) {
    ci_log("Info: shrub_controller created a new server on interface with "
           "ifindex %d buffer_count %d hwport %d",
           config->server_config_head->ifindex,
           config->server_config_head->buffer_count,
           config->server_config_head->hw_ports);
  }
  return config->server_config_head->token_id;
}

static int poll_socket(shrub_controller_config *config)
{
  int rc = 0;
  ssize_t recevied_bytes = 0;
  const int max_events = 1;
  uint32_t buffer_count = EF_SHRUB_DEFAULT_BUFFER_COUNT;
  cicp_hwport_mask_t hwport_mask = 0xffffffff;
  shrub_controller_request_t request;
  int ifindex = -1;
  struct epoll_event events[max_events];
  int response_status = 0;
  int client_fd = -1;
  int i;
  int num_events = epoll_wait(config->epoll_fd, events, max_events, 0);

  for (i = 0; i < num_events; ++i) {
    if ( events[i].data.fd == config->config_socket_fd ) {
      client_fd = accept(config->config_socket_fd, NULL, NULL);
      if ( client_fd == -1 ) {
        rc = -errno;
        if ( config->debug_mode )
          ci_log("Error: shrub_controller calling accept on "
                 "the config socket failed");
        return rc;
      }

      response_status = 0;
      recevied_bytes = recv(client_fd, &request, sizeof(request), 0);
      if ( recevied_bytes == -1 ) {
        response_status = -errno;
      } else if ( recevied_bytes != sizeof(request) ) {
        response_status = -ENOMEM;
      } else if ( request.controller_version != EF_SHRUB_VERSION ) {
          if ( config->debug_mode ) {
            ci_log("Error: shrub_controller being called from an "
                   "incompatible client! request version %d, "
                   "expected version %d ",
                   request.controller_version, EF_SHRUB_VERSION);
          }
        response_status = SHRUB_ERR_INCOMPATIBLE_VERSION;
      } else {
        buffer_count = EF_SHRUB_DEFAULT_BUFFER_COUNT;
        hwport_mask = 0xffffffff;
        ifindex = -1;

        switch (request.command)
        {
        case EF_SHRUB_CONTROLLER_DESTROY:
          remove_and_stop_interface(config, request.destroy.shrub_token_id);
          response_status = 0;
          break;
        case EF_SHRUB_CONTROLLER_CREATE_IFINDEX:
          ifindex = request.create_ifindex.ifindex;
          hwport_mask = convert_ifindex_to_hwport(config, ifindex);
          buffer_count = request.create_ifindex.buffer_count;
          response_status = process_create_command(
            config, hwport_mask, ifindex, buffer_count, client_fd
          );
          break;
        case EF_SHRUB_CONTROLLER_CREATE_HWPORT:
          hwport_mask = request.create_hwport.hw_port;
          ifindex = convert_hwport_to_ifindex(config, hwport_mask);
          buffer_count = request.create_hwport.buffer_count;
          response_status = process_create_command(
            config, hwport_mask, ifindex, buffer_count, client_fd
          );
          break;
        case EF_SHRUB_CONTROLLER_DUMP:
          shrub_dump(config, request.dump.file_name);
          response_status = 0;
          break;
        default:
          if ( config->debug_mode ) {
            ci_log("Info: shrub_controller: An unknown command was passed via "
                   "the config socket, command %d", request.command);
          }
          response_status = -1;
          break;
        }
      }

      rc = send(client_fd, &response_status, sizeof(int), 0);
      if ( rc == -1 ) {
        rc = -errno;
        if ( config->debug_mode ) {
          ci_log("Error: shrub_controller: Failed to send "
                 "response_status (%d) to the client",
                 response_status);
        }
        close(client_fd);
        return rc;
      }
      close(client_fd);
    }
  }
  return rc;
}

static void cleanup_config_socket(shrub_controller_config *config)
{
  close(config->epoll_fd);
  if ( config->config_socket_fd != -1 ) {
    close(config->config_socket_fd);
    unlink(config->config_socket);
    if ( config->debug_mode )
      ci_log("Info: shrub_controller socket closed and cleaning up! ");
  }
}

static int create_config_socket(shrub_controller_config *config)
{
  int rc = 0;
  config->epoll_fd = epoll_create1(0);
  if ( config->epoll_fd == -1 ) {
    rc = -errno;
    ci_log("Error: shrub_controller failed to create epoll instance "
           "for config socket");
    return rc;
  }

  config->config_socket_fd =
      create_onload_config_socket(config->config_socket, config->epoll_fd);
  if ( config->config_socket_fd < 0 ) {
    close(config->epoll_fd);
    return config->config_socket_fd;
  }

  chmod(config->config_socket, 0666);
  return 0;
}

static int reactor_loop(shrub_controller_config *config)
{
  while ( is_running ) {
    shrub_if_config_t *current_interface = config->server_config_head;
    while ( current_interface != NULL ) {
      ef_shrub_server_poll(current_interface->shrub_server);
      current_interface = current_interface->next;
    }
    poll_socket(config);
    if ( call_shrub_dump == 1 ) {
      shrub_dump(config, "controller-signal.dump");
      call_shrub_dump = 0;
    }
  }
  return 0;
}

int parse_interface(const char *arg, shrub_controller_config *config) {
  char *buffer_pos = strchr(arg, '/');
  char iface[IFNAMSIZ] = {0};
  int buffer_count;
  unsigned int ifindex;
  cicp_hwport_mask_t hwport;
  size_t iface_len;
  char *buffer_str;

  if ( buffer_pos ) {
    iface_len = buffer_pos - arg;
    if ( iface_len == 0 || iface_len >= IFNAMSIZ ) {
      ci_log("Error: shrub_controller invalid interface name "
             "passed as input '%s'.", arg);
      return -EINVAL;
    }

    strncpy(iface, arg, iface_len);
    iface[iface_len] = '\0';

    buffer_str = buffer_pos + 1;
    if ( !isdigit(*buffer_str) ) {
      ci_log("Error: shrub_controller invalid buffer count "
             "passed as input '%s'. ", arg);
      return -EINVAL;
    }

    buffer_count = atoi(buffer_str);
    if ( buffer_count < EF_SHRUB_DEFAULT_BUFFER_COUNT ) {
      ci_log("Error: shrub_controller invalid buffer count "
        "must be at least %d.", EF_SHRUB_DEFAULT_BUFFER_COUNT);
      return -EINVAL;
    }
  } else {
    if (strnlen(arg, IFNAMSIZ) >= IFNAMSIZ) {
      ci_log("Error: shrub_controller invalid interface name passed as input. "
             "Input is too long '%s'.", arg);
      return -EINVAL;
    }

    strcpy(iface, arg);
    buffer_count = EF_SHRUB_DEFAULT_BUFFER_COUNT;
  }

  ifindex = if_nametoindex(iface);
  if ( ifindex == 0 )
    return -errno;

  hwport = convert_ifindex_to_hwport(config, ifindex);
  return add_server_config(config, hwport, ifindex, buffer_count);
}

static void tear_down_servers(shrub_controller_config *config)
{
  shrub_if_config_t *current_interface = config->server_config_head;
  shrub_if_config_t *next_interface;
  while ( current_interface != NULL ) {
    next_interface = current_interface->next;

    if ( current_interface->client_fd >= 0 )
      close(current_interface->client_fd);

    if ( current_interface->server_started )
      shrub_server_fini(current_interface);

    free(current_interface);
    current_interface = next_interface;
  }
  config->server_config_head = NULL;
}

static int controller_servers_init(shrub_controller_config *config,
                                   char **intfs, int n_intfs)
{
  int rc;
  int i;

  config->server_config_head = NULL;
  for (i = 0; i < n_intfs; i++) {
    if ( (rc = parse_interface(intfs[i], config)) < 0 ||
        (rc = shrub_server_init(config, config->server_config_head)) < 0) {
      tear_down_servers(config);
      usage();
      return  rc;
    }
  }
  return 0;
}

void controller_signal_handler(int signal, siginfo_t* info, void* context)
{
  if ( signal == SIGUSR1 )
    call_shrub_dump = 1;
  else if ( signal == SIGTERM || signal == SIGINT || signal == SIGQUIT )
    is_running = 0;
}

static void controller_init_signals(void)
{
  struct sigaction act = {0};
  int rc;

  act.sa_flags = SA_SIGINFO;
  act.sa_sigaction = controller_signal_handler;

  rc = sigaction(SIGINT, &act, NULL);
  if ( rc < 0 )
    ci_log("Error: shrub_controller sigaction(SIGINT) failed: %s",
           strerror(errno));

  rc = sigaction(SIGTERM, &act, NULL);
  if ( rc < 0 )
    ci_log("Error: shrub_controller sigaction(SIGTERM) failed: %s",
           strerror(errno));

  rc = sigaction(SIGUSR1, &act, NULL);
  if ( rc < 0 )
    ci_log("Error: shrub_controller sigaction(SIGUSR1) failed: %s",
           strerror(errno));

  rc = sigaction(SIGQUIT, &act, NULL);
  if ( rc < 0 )
    ci_log("Error: shrub_controller sigaction(SIGQUIT) failed: %s",
           strerror(errno));
}

static int controller_init_paths(shrub_controller_config *config)
{
  int rc;

  rc = snprintf(config->log_dir, sizeof(config->log_dir),
                EF_SHRUB_CONTROLLER_PATH_FORMAT, "/var/log/",
                config->controller_id);
  if ( rc < 0 || rc >= sizeof(config->log_dir) )
    return -EINVAL;

  rc = snprintf(config->controller_dir, sizeof(config->controller_dir),
                EF_SHRUB_CONTROLLER_PATH_FORMAT, EF_SHRUB_SOCK_DIR_PATH,
                config->controller_id);
  if ( rc < 0 || rc >= sizeof(config->controller_dir) )
    return -EINVAL;

  rc = snprintf(config->config_socket, sizeof(config->config_socket), "%s%s",
                config->controller_dir, EF_SHRUB_NEGOTIATION_SOCKET);
  if ( rc < 0 || rc >= sizeof(config->config_socket) )
    return -EINVAL;

  return 0;
}

static int
controller_config_socket_lock_create(shrub_controller_config *config)
{
  int rc;
  int fd;
  char pid[16];
  struct flock file_lock = {
    .l_type = F_WRLCK,
    .l_start = 0,
    .l_whence = SEEK_SET,
    .l_len = 0
  };

  config->config_socket_lock_fd = -1;
  rc = snprintf(config->config_socket_lock, sizeof(config->config_socket_lock),
                "%s%s", config->controller_dir, EF_SHRUB_CONFIG_SOCKET_LOCK);
  if ( rc < 0 || rc >= sizeof(config->config_socket_lock) )
    return -EINVAL;

  fd = open(config->config_socket_lock, O_CREAT | O_RDWR,
            S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if ( fd < 0 ) {
    ci_log("Error: shrub_controller Failed to open config socket lock %s: %s",
           config->config_socket_lock, strerror(errno));
    return -errno;
  }

  if ( fcntl(fd, F_SETLK, &file_lock) < 0 ) {
    if( errno == EACCES || errno == EAGAIN ) {
      ci_log("Error: shrub_controller %s is already locked. "
             "Is another shrub controller running?",
             config->config_socket_lock);
    } else {
      ci_log("Error: shrub_controller failed to acquire config "
             "socket lock %s: %s", config->config_socket_lock,
             strerror(errno));
    }
    close(fd);
    return -errno;
  }

  /* Truncating the file does not set the file offset so if the file
   * already existed then the file offset will not be zero. Explicitly set the
   * seek position back to the start of the file. Ignore unlikely errors at
   * this stage. */
  if ( -1 == ftruncate(fd, 0) ||
       -1 == lseek(fd, 0, SEEK_SET) ||
       -1 == sprintf(pid, "%ld\n", (long)getpid()) ||
       -1 == write(fd, pid, strlen(pid)+1) ) {
    ci_log("Error: shrub_controller failed to write to lock file: %s",
           strerror(errno));
    close(fd);
    return -errno;
  }

  config->config_socket_lock_fd = fd;
  return 0;
}

static void
controller_config_socket_lock_destroy(shrub_controller_config *config)
{
  if (config->config_socket_lock_fd != -1) {
    close(config->config_socket_lock_fd);
    unlink(config->config_socket_lock);
  }
}

static int controller_create_directories(shrub_controller_config *config)
{
  int rc;

  if ( (rc = create_directory(EF_SHRUB_SOCK_DIR_PATH)) < 0 )
    return rc;

  if ( (rc = create_directory(config->controller_dir)) < 0 )
    return rc;

  return 0;
}

static int controller_cplane_connect(shrub_controller_config *config)
{
  int rc;

  rc = oo_fd_open(&config->oo_fd_handle);
  if ( rc ) {
    ci_log("Error: shrub_controller cannot open main cplane fd: %s. ",
           strerror(errno));
    return rc;
  }

  config->cp = malloc(sizeof(*config->cp));
  if ( !config->cp ) {
    rc = -ENOMEM;
    goto fail_alloc;
  }

  rc = oo_cp_create(config->oo_fd_handle, config->cp, CP_SYNC_LIGHT, 0);
  if ( rc )
    goto fail_cp_create;

  return rc;

fail_cp_create:
  free(config->cp);
fail_alloc:
  oo_fd_close(config->oo_fd_handle);
  return rc;
}

static void controller_cplane_disconnect(shrub_controller_config *config)
{
  oo_cp_destroy(config->cp);
  free(config->cp);
  oo_fd_close(config->oo_fd_handle);
}

int main(int argc, char *argv[])
{
  int rc = 0;
  int option;
  shrub_controller_config config = {0};
  config.interface_token = 1;
  config.controller_id = 0;

  while ( (option = getopt(argc, argv, "dc:")) != -1 ) {
    switch (option)
    {
    case 'd':
      config.debug_mode = true;
      ci_log("Info: shrub_controller Debug Mode Enabled!");
      break;
    case 'c':
      config.controller_id = atoi(optarg);
      break;
    default:
      usage();
      return EXIT_FAILURE;
    }
  }

  controller_init_signals();
  rc = controller_init_paths(&config);
  if ( rc )
    return rc;

  rc = controller_create_directories(&config);
  if ( rc )
    return rc;

  rc = controller_config_socket_lock_create(&config);
  if ( rc )
    goto fail_socket_lock_create;

  rc = create_config_socket(&config);
  if ( rc )
    goto fail_create_config_socket;

  rc = controller_cplane_connect(&config);
  if ( rc )
    goto fail_cplane_connect;

  rc = controller_servers_init(&config, &argv[optind], argc - optind);
  if ( rc )
    goto fail_servers_init;

  reactor_loop(&config);

  tear_down_servers(&config);
fail_servers_init:
  controller_cplane_disconnect(&config);
fail_cplane_connect:
  cleanup_config_socket(&config);
fail_create_config_socket:
  controller_config_socket_lock_destroy(&config);
fail_socket_lock_create:
  rmdir(config.controller_dir);

  return rc;
}
