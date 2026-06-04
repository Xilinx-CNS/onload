/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

#include "cp_intf_ver.h"

#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <ci/compat.h>
#include <ci/tools/log.h>
#include <ci/tools/onload_server.h>
#include <cplane/cplane.h>
#include <cplane/create.h>
#include <cplane/mib.h>
#include <ctype.h>
#include <errno.h>
#include <etherfabric/efct_vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/internal/shrub_socket.h>
#include <etherfabric/internal/shrub_server.h>
#include <etherfabric/internal/shrub_shared.h>
#include <etherfabric/internal/efct_uk_api.h>
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
#include <sys/timerfd.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <ci/efhw/common.h>


int (*ci_sys_ioctl)(int, long unsigned int, ...) =
    ioctl; /* taken from cplane/private.h (example code from cplane/client.c) */

struct shrub_controller_vi;
static volatile sig_atomic_t is_running = 1;
static volatile sig_atomic_t call_shrub_dump = 0;

#define DEFAULT_BUFFER_SIZE 1024 * 1024

#define INVALID_SOCKET_FD ((uintptr_t)-1)

#define DEV_KMSG "/dev/kmsg"
#define SERVER_BIN "shrub_controller"
#define SERVER_NAME "Onload Shrub Server"

#define AUTO_CLOSE_DELAY_NEVER -1

#define MS_TO_NS (1000 * 1000)
#define SEC_TO_NS (1000 * MS_TO_NS)
#define PERIODIC_POLL_TIMEOUT_DEFAULT (5ll * MS_TO_NS)
#define PERIODIC_POLL_TIMEOUT_MIN 1ll

static char* shrub_log_prefix;

struct shrub_controller_stats
{
  uint64_t controller_accept_failures;
  uint64_t controller_response_failures;
  uint64_t controller_incompatible_clients;
  uint64_t controller_failed_to_neg_client;
  uint64_t epoll_failures;
  uint64_t timerfd_settime_failures;
};

struct shrub_controller_vi
{
  ef_vi vi;
  ef_pd pd;
  ef_driver_handle dh;
};

typedef struct shrub_if_config_s
{
  int ifindex;
  ci_hwport_id_t hw_port;
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
  uintptr_t config_socket_fd;
  int epoll_fd;
  int controller_id;
  int config_socket_lock_fd;
  shrub_if_config_t *server_config_head;
  struct oo_cplane_handle *cp;
  int oo_fd_handle;
  bool debug_mode;
  bool use_interrupts;
  char controller_dir[EF_SHRUB_SOCKET_DIR_LEN];
  char log_dir[EF_SHRUB_LOG_LEN];
  char config_socket[EF_SHRUB_NEGOTIATION_SOCKET_LEN];
  char config_socket_lock[EF_SHRUB_CONFIG_SOCKET_LOCK_LEN];
  struct shrub_controller_stats controller_stats;
  int auto_close_delay;
  bool had_any_clients;
  uint64_t sum_server_buffers;
  int wakeup_epoll_fd;
  int wakeup_timer_fd;
  long long periodic_poll_timeout_ns;
} shrub_controller_config;

static void usage(void)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  shrub_controller <flags> "
                  "[<interface>[/<buffer_count>]]...\n");
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -d       Enable debug mode\n");
  fprintf(stderr, "  -i       Enable interrupts\n");
  fprintf(stderr, "  -c <id>  Set controller_id (valid values 0 - %d)\n",
          EF_SHRUB_MAX_CONTROLLER);
  fprintf(stderr, "  -D       Daemonise on startup\n");
  fprintf(stderr, "  -K       Log to kmsg\n");
  fprintf(stderr, "  -C <ms>  Close after <ms> if all clients disconnect\n");
  fprintf(stderr, "  -p <ns>  Ensure a poll happens every <ns> in interrupt-driven mode\n");
}

static bool is_hwport_llct(shrub_controller_config *config, ci_hwport_id_t hwport)
{
  struct cp_mibs *mib;
  cp_version_t version;
  bool is_llct = false;

  if ( hwport == CI_HWPORT_ID_BAD )
    return false;
  
  CP_VERLOCK_START(version, mib, config->cp)
  
  if ( hwport < mib->dim->hwport_max && !cicp_hwport_row_is_free(&mib->hwport[hwport]) ) {
    cp_nic_flags_t nic_flags = mib->hwport[hwport].nic_flags;
    is_llct = (nic_flags & NIC_FLAG_LLCT) != 0;
  }
  CP_VERLOCK_STOP(version, mib)

  if ( config->debug_mode )
    ci_log("Debug: hwport %d, is_llct=%d", hwport, is_llct);
  
  return is_llct;
}

// Based on the implementation of oo_get_llct_hwports found in tcp_helper_resource.c
static ci_hwport_id_t get_first_llct_hwport(shrub_controller_config *config,
                                            cicp_hwport_mask_t hwport_mask)
{
  for( ; hwport_mask != 0; hwport_mask &= (hwport_mask - 1) ) {
    ci_hwport_id_t hw_port = cp_hwport_mask_first(hwport_mask);
    if( is_hwport_llct(config, hw_port) )
      return hw_port;
  }
  return CI_HWPORT_ID_BAD;
}

static int search_for_existing_server(shrub_controller_config *config,
                                      ci_hwport_id_t new_hw_port)
{
  shrub_if_config_t *current_interface = config->server_config_head;
  if ( config->debug_mode )
    ci_log("Debug: search_for_existing_server: new_hw_port=%d", new_hw_port);

  if ( new_hw_port == CI_HWPORT_ID_BAD )
    return -EINVAL;

  while ( current_interface != NULL ) {
    if ( current_interface->hw_port == new_hw_port ) {
      if ( config->debug_mode )
        ci_log("Info: shrub_controller found duplicate shrub_server "
               "with hw_port %d", current_interface->hw_port);
      current_interface->ref_count++;
      return current_interface->token_id;
    }
    current_interface = current_interface->next;
  }
  return 0;
}

static ci_hwport_id_t
convert_ifindex_to_hwport(shrub_controller_config *config, int ifindex)
{
  cicp_hwport_mask_t hwport_mask = 0;
  ci_hwport_id_t result;

  oo_cp_find_llap(config->cp, ifindex, NULL, NULL, &hwport_mask, NULL, NULL);

  if ( config->debug_mode )
    ci_log("Debug: ifindex=%d, original hwport_mask=0x%x (%u)",
          ifindex, hwport_mask, hwport_mask);

  if ( hwport_mask == 0 )
    return CI_HWPORT_ID_BAD;

  result = get_first_llct_hwport(config, hwport_mask);

  if ( result != CI_HWPORT_ID_BAD && config->debug_mode )
    ci_log("Debug: Found LLCT hw_port=%u", result);

  return result;
}

static int convert_hwport_to_ifindex(shrub_controller_config *config,
                                     ci_hwport_id_t hw_port)
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
                             ci_hwport_id_t hw_port, int ifindex,
                             uint32_t buffer_count)
{

  shrub_if_config_t *new_shrub_config;

  if( buffer_count == 0 || buffer_count > EF_SHRUB_MAX_BUFFER_COUNT ) {
    ci_log("Error: shrub_controller was unable to add interface with buffer size of %d, valid range is 1-%d",
           buffer_count, EF_SHRUB_MAX_BUFFER_COUNT);
    return -EINVAL;
  }

  new_shrub_config = (shrub_if_config_t *)malloc(sizeof(shrub_if_config_t));
  if ( new_shrub_config == NULL ) {
    ci_log("Error: shrub_controller failed to allocate memory "
           "for new interface configuration.!");
    return -ENOMEM;
  }

  new_shrub_config->ifindex = ifindex;
  new_shrub_config->hw_port = hw_port;
  new_shrub_config->ref_count = 0;
  new_shrub_config->buffer_count = buffer_count;
  new_shrub_config->next = config->server_config_head;
  new_shrub_config->token_id = config->interface_token;
  new_shrub_config->client_fd = -1;
  new_shrub_config->server_started = false;
  config->interface_token++;
  config->server_config_head = new_shrub_config;
  config->sum_server_buffers += buffer_count;
  return 0;
}

static void shrub_server_fini(shrub_controller_config* controller_config,
                              shrub_if_config_t *config)
{
  controller_config->sum_server_buffers -= config->buffer_count;
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
        shrub_server_fini(config, current_interface);

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
  enum ef_vi_flags vi_flags = EF_VI_FLAGS_DEFAULT;
  enum ef_pd_flags pd_flags = EF_PD_DEFAULT | EF_PD_EXPRESS;
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
                            interface_config->buffer_count,
                            config->use_interrupts,
                            &config->wakeup_epoll_fd);
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

static void shrub_dump_summary_to_fd(int fd, shrub_controller_config *config,
                                     char *buf, size_t buflen)
{
  shrub_log_to_fd(fd, buf, buflen, SHRUB_DUMP_SECTION_SEPARATOR);
  shrub_log_to_fd(fd, buf, buflen, "\nshrub controller\n");
  shrub_log_to_fd(fd, buf, buflen, "  name: "EF_SHRUB_CONTROLLER_PREFIX"%d%s\n",
                  config->controller_id, config->debug_mode ? " (debug)" : "");
  shrub_log_to_fd(fd, buf, buflen, "  dir: %s\n", config->controller_dir);
  shrub_log_to_fd(fd, buf, buflen, "  interrupt mode: %s\n",
                  config->use_interrupts ? "enabled" : "disabled");
  shrub_log_to_fd(fd, buf, buflen, "  config socket: %s\n",
                  config->config_socket);
}

static void shrub_dump_stats_to_fd(int fd, shrub_controller_config *config,
                                   char *buf, size_t buflen)
{
  shrub_log_to_fd(fd, buf, buflen, SHRUB_DUMP_SECTION_SEPARATOR);
  shrub_log_to_fd(fd, buf, buflen, "\ncontroller statistics:\n");
  shrub_log_to_fd(fd, buf, buflen, "  client negotiation failures: %lu\n",
                  config->controller_stats.controller_failed_to_neg_client);
  shrub_log_to_fd(fd, buf, buflen, "  accept failures: %lu\n",
                  config->controller_stats.controller_accept_failures);
  shrub_log_to_fd(fd, buf, buflen, "  response send failures: %lu\n",
                  config->controller_stats.controller_response_failures);
  shrub_log_to_fd(fd, buf, buflen, "  incompatible clients detected: %lu\n",
                  config->controller_stats.controller_incompatible_clients);
  shrub_log_to_fd(fd, buf, buflen, "  epoll failures: %lu\n",
                  config->controller_stats.epoll_failures);
  shrub_log_to_fd(fd, buf, buflen, "  timerfd set time failures: %lu\n",
                  config->controller_stats.timerfd_settime_failures);
}

static void shrub_dump_server_to_fd(int fd, shrub_if_config_t *server_config,
                                    char *buf, size_t buflen)
{
  struct shrub_controller_vi *svi = &server_config->res;
  ef_vi *vi = &svi->vi;
  ef_vi_efct_rxqs *rxqs = &vi->efct_rxqs;
  char ifname[IFNAMSIZ];

  memset(ifname, 0, sizeof(ifname));
  if ( if_indextoname(server_config->ifindex, ifname) == NULL )
    snprintf(ifname, sizeof(ifname), "unknown");

  shrub_log_to_fd(fd, buf, buflen, SHRUB_DUMP_SECTION_SEPARATOR);
  shrub_log_to_fd(fd, buf, buflen, "\nshrub server\n");
  shrub_log_to_fd(fd, buf, buflen, "ifname: %.*s ifindex: %d hw_port: %x\n",
                  IFNAMSIZ - 1, ifname, server_config->ifindex,
                  server_config->hw_port);
  shrub_log_to_fd(fd, buf, buflen, "  buffer count: %d client count: %d "
                  "token: %x\n", server_config->buffer_count,
                  server_config->ref_count, server_config->token_id);
  shrub_log_to_fd(fd, buf, buflen, "  vi: %d active_qs: %x\n",
                  vi->vi_i, rxqs->active_qs ? *rxqs->active_qs : 0);

  ef_shrub_server_dump_to_fd(server_config->shrub_server, fd, buf, buflen);
}

static void shrub_dump_servers_to_fd(int fd, shrub_controller_config *config,
                                     char *buf, size_t buflen)
{
  shrub_if_config_t *server_config = config->server_config_head;
  while ( server_config != NULL ) {
    shrub_dump_server_to_fd(fd, server_config, buf, buflen);
    server_config = server_config->next;
  }
}

static void shrub_dump_to_fd(int fd, shrub_controller_config *config,
                             char *buf, size_t buflen)
{
  shrub_dump_summary_to_fd(fd, config, buf, buflen);
  shrub_dump_servers_to_fd(fd, config, buf, buflen);
  shrub_dump_stats_to_fd(fd, config, buf, buflen);
}

#define LOGBUF_SIZE 256
static int shrub_dump_to_file(shrub_controller_config *config,
                              const char *file_name)
{
  char file_path[EF_SHRUB_LOG_LEN];
  char logbuf[LOGBUF_SIZE];
  int rc = 0;
  int fd;

  rc = snprintf(file_path, sizeof(file_path), "%s/%s", config->log_dir,
                file_name);
  if ( rc < 0 || rc >= sizeof(file_path) ) {
    ci_log("Error: shrub_controller was unable "
           "to set an appropriate log path!");
    return -EINVAL;
  }

  if ( !directory_exists(config->log_dir) )
    create_directory(config->log_dir);

  fd = open(file_path, O_WRONLY | O_CREAT, S_IRUSR | S_IRGRP);
  if ( fd < 0 ) {
    rc = -errno;
    ci_log("Error: shrub_controller was unable "
           "to open a file for shrub dump!");
    return rc;
  }

  shrub_dump_to_fd(fd, config, logbuf, LOGBUF_SIZE);

  close(fd);
  return rc;
}

static int shrub_dump(shrub_controller_config *config, int fd, size_t bufsize)
{
  char *buf = malloc(bufsize);
  if( !buf )
    return -ENOMEM;

  shrub_dump_to_fd(fd, config, buf, bufsize);
  free(buf);
  return 0;
}

static int create_onload_config_socket(const char *socket_path, uintptr_t* config_socket_fd, int epoll_fd)
{
  int rc = 0;
  struct epoll_event event;

  unlink(socket_path);

  rc = ef_shrub_socket_open(config_socket_fd);
  if ( rc < 0 ) {
    ci_log("Error: shrub_controller onload handshake socket config failed");
    return rc;
  }

  rc = ef_shrub_socket_bind(*config_socket_fd, socket_path);
  if ( rc < 0 ) {
    ci_log("Error: shrub_controller onload socket bind failed");
    goto cleanup_socket;
  }

  /* We have a connection per-interface per-client. Onload clients will use
   * all interfaces by default, and it's reasonable that many apps are starting
   * up at once, so we need a generous backlog. */
  rc = ef_shrub_socket_listen(*config_socket_fd, 2048);
  if ( rc < 0 ) {
    ci_log("Error: shrub_controller onload socket listen failed");
    goto cleanup_socket;
  }

  /* Add config_socket_fd to the epoll instance */
  event.data.fd = *config_socket_fd;
  event.events = EPOLLIN;
  if ( epoll_ctl(epoll_fd, EPOLL_CTL_ADD, *config_socket_fd, &event) == -1 ) {
    rc = -errno;
    ci_log("Error: shrub_controller epoll_ctl failed to add config_socket_fd");
    goto cleanup_socket;
  }

  return rc;

cleanup_socket:
  ef_shrub_socket_close_socket(*config_socket_fd);
  return rc;
}

static int process_create_command(shrub_controller_config *config,
                                  ci_hwport_id_t hw_port, int ifindex,
                                  uint32_t buffer_count, uintptr_t client_fd)
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
           "ifindex %d buffer_count %d hw_port %d",
           config->server_config_head->ifindex,
           config->server_config_head->buffer_count,
           config->server_config_head->hw_port);
  }
  return config->server_config_head->token_id;
}

static int poll_socket(shrub_controller_config *config)
{
  int rc = 0;
  const int max_events = 1;
  uint32_t buffer_count = EF_SHRUB_DEFAULT_BUFFER_COUNT;
  ci_hwport_id_t hw_port = CI_HWPORT_ID_BAD;
  struct ef_shrub_controller_request request;
  int ifindex = -1;
  struct epoll_event events[max_events];
  int response_status = 0;
  uintptr_t client_fd = 0;
  int i;
  int num_events = epoll_wait(config->epoll_fd, events, max_events, 0);

  for (i = 0; i < num_events; ++i) {
    if ( events[i].data.fd == config->config_socket_fd ) {
      rc = ef_shrub_socket_accept(config->config_socket_fd, &client_fd);
      if ( rc < 0 ) {
        config->controller_stats.controller_accept_failures++;
        if ( config->debug_mode )
          ci_log("Error: shrub_controller calling accept on "
                 "the config socket failed");
        continue;
      }

      response_status = ef_shrub_socket_recv(client_fd, &request, sizeof(request));

      if ( response_status == 0 ) {
        if ( request.controller_version != EF_SHRUB_VERSION ) {
          if ( config->debug_mode ) {
            ci_log("Error: shrub_controller being called from an "
                   "incompatible client! request version %" PRIu64
                   ", expected version %d ",
                   request.controller_version, EF_SHRUB_VERSION);
          }
          response_status = SHRUB_ERR_INCOMPATIBLE_VERSION;
          config->controller_stats.controller_incompatible_clients++;
        } else {
          buffer_count = EF_SHRUB_DEFAULT_BUFFER_COUNT;
          hw_port = CI_HWPORT_ID_BAD;
          ifindex = -1;

          switch (request.command)
          {
          case EF_SHRUB_CONTROLLER_DESTROY:
            remove_and_stop_interface(config, request.destroy.shrub_token_id);
            break;
          case EF_SHRUB_CONTROLLER_CREATE_IFINDEX:
            ifindex = request.create_ifindex.ifindex;
            hw_port = convert_ifindex_to_hwport(config, ifindex);

            if ( hw_port == CI_HWPORT_ID_BAD ) {
              if ( config->debug_mode ) {
                ci_log("Error: shrub_controller was unable to convert "
                       "ifindex %d to a valid hw_port", ifindex);
              }
              response_status = -EINVAL;
              break;
            }

            buffer_count = request.create_ifindex.buffer_count;
            response_status = process_create_command(
              config, hw_port, ifindex, buffer_count, client_fd
            );
            break;
          case EF_SHRUB_CONTROLLER_CREATE_HWPORT:
            hw_port = request.create_hwport.hw_port;
            ifindex = convert_hwport_to_ifindex(config, hw_port);
            buffer_count = request.create_hwport.buffer_count;
            response_status = process_create_command(
              config, hw_port, ifindex, buffer_count, client_fd
            );
            break;
          case EF_SHRUB_CONTROLLER_DUMP_TO_FILE:
            shrub_dump_to_file(config, request.dump.file_name);
            break;
          case EF_SHRUB_CONTROLLER_SHRUB_DUMP:
            shrub_dump(config, client_fd, request.shrub_dump.logbuf_size);
            break;
          default:
            if ( config->debug_mode ) {
              ci_log("Info: shrub_controller: An unknown command was passed via "
                    "the config socket, command %" PRIu64, request.command);
            }
            response_status = -1;
            break;
          }
        }
      }

      if ( response_status < 0 ) {
        config->controller_stats.controller_failed_to_neg_client++;
        if ( config->debug_mode ) {
          ci_log("Error: shrub_controller failed to process an event"
                 " from the client, response_status %d", response_status);
        }
      }

      rc = ef_shrub_socket_send(client_fd, &response_status, sizeof(int));
      if ( rc < 0 ) {
        config->controller_stats.controller_response_failures++;
        if ( config->debug_mode ) {
          ci_log("Error: shrub_controller: Failed to send "
                 "response_status (%d) to the client",
                 response_status);
        }
      }
      ef_shrub_socket_close_socket(client_fd);
    }
  }
  return (rc == 0) ? num_events : rc;
}

static void cleanup_config_socket(shrub_controller_config *config)
{
  close(config->epoll_fd);
  if ( config->config_socket_fd != INVALID_SOCKET_FD ) {
    ef_shrub_socket_close_socket(config->config_socket_fd);
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

  rc = create_onload_config_socket(
        config->config_socket,
        &config->config_socket_fd,
        config->epoll_fd);
  if ( rc < 0 ) {
    close(config->epoll_fd);
    ci_log("Error: shrub_controller failed to create config socket");
    return rc;
  }

  chmod(config->config_socket, 0666);
  return 0;
}

static void cleanup_interrupt_state(shrub_controller_config *config)
{
  if ( ! config->use_interrupts )
    return;

  close(config->wakeup_timer_fd);
  close(config->wakeup_epoll_fd);
}

static int create_interrupt_state(shrub_controller_config *config)
{
  struct epoll_event ev = { 0 };
  int rc;

  if ( ! config->use_interrupts )
    return 0;

  rc = epoll_create1(0);
  if ( rc == -1 ) {
    rc = -errno;
    ci_log("Error: failed to create epoll fd for interrupt state: %d (%s)",
           rc, strerror(-rc));
    goto fail_out;
  }
  config->wakeup_epoll_fd = rc;

  ev.events = EPOLLIN;
  rc = epoll_ctl(config->wakeup_epoll_fd, EPOLL_CTL_ADD, config->epoll_fd, &ev);
  if ( rc == -1 ) {
    rc = -errno;
    ci_log("Error: failed to add config epoll fd to wakeup epoll set: %d (%s)",
           rc, strerror(-rc));
    goto cleanup_socket_out;
  }

  rc = timerfd_create(CLOCK_MONOTONIC, 0);
  if ( rc == -1 ) {
    rc = -errno;
    ci_log("Error: failed to create timerfd for wakeup timeout: %d (%s)",
           rc, strerror(-rc));
    goto cleanup_socket_out;
  }
  config->wakeup_timer_fd = rc;

  ev.data.fd = config->wakeup_timer_fd;
  rc = epoll_ctl(config->wakeup_epoll_fd, EPOLL_CTL_ADD,
                 config->wakeup_timer_fd, &ev);
  if ( rc == -1 ) {
    rc = -errno;
    ci_log("Error: failed to add timerfd to wakeup epoll set: %d (%s)",
           rc, strerror(-rc));
    goto cleanup_timer_out;
  }

  return 0;

cleanup_timer_out:
  close(config->wakeup_timer_fd);
cleanup_socket_out:
  close(config->wakeup_epoll_fd);
fail_out:
  return rc;
}

static void prime_server_vis(shrub_controller_config *config)
{
  shrub_if_config_t *intf;
  for( intf = config->server_config_head; intf != NULL; intf = intf->next )
    ef_shrub_server_prime(intf->shrub_server);
}

static int poll_shrub_servers(shrub_controller_config *config)
{
  shrub_if_config_t *current_interface = config->server_config_head;
  int n_events = 0;

  while ( current_interface != NULL ) {
    n_events += ef_shrub_server_poll(current_interface->shrub_server);
    current_interface = current_interface->next;
  }

  return n_events;
}

static void handle_controller_dump_requests(shrub_controller_config *config)
{
  if ( call_shrub_dump == 1 ) {
    shrub_dump_to_file(config, "controller-signal.dump");
    call_shrub_dump = 0;
  }
}

static int timespec_difference_ms(struct timespec lhs, struct timespec rhs)
{
  const int ms_per_sec = 1000;
  const int ns_per_ms = 1000000;
  return (lhs.tv_sec - rhs.tv_sec) * ms_per_sec +
         (lhs.tv_nsec - rhs.tv_nsec) / ns_per_ms;
}

static void handle_controller_auto_close(shrub_controller_config *config)
{
  bool any_server_has_clients = false;
  shrub_if_config_t *intf;
  struct timespec now;

  if( config->auto_close_delay == AUTO_CLOSE_DELAY_NEVER )
    return;

  for( intf = config->server_config_head;
       intf && ! any_server_has_clients;
       intf = intf->next )
    any_server_has_clients |= ef_shrub_server_has_clients(intf->shrub_server);

  /* If we have never had clients and still don't, or had clients and still do,
   * then we aren't interested in updating any state. */
  if( any_server_has_clients == config->had_any_clients )
    return;

  /* This is the first time we've seen clients, so update our state. */
  if( any_server_has_clients ) {
    config->had_any_clients = any_server_has_clients;
    return;
  }

  /* At this point, we have had clients in the past, but don't anymore. Lets
   * check how long we haven't had clients for to see if we should exit. */
  clock_gettime(CLOCK_MONOTONIC, &now);
  for( intf = config->server_config_head; intf; intf = intf->next ) {
    struct timespec disconnection_time =
      ef_shrub_server_get_last_disconnection_time(intf->shrub_server);
    int time_since_last_disconnect =
      timespec_difference_ms(now, disconnection_time);

    if( time_since_last_disconnect < config->auto_close_delay )
      return;
  }

  /* If we reach this point, we must have already had connections that are all
   * now closed at least `config->auto_close_delay` milliseconds ago, so exit. */
  is_running = false;
}

static bool reactor_loop_step(shrub_controller_config *config)
{
  int n_events = 0;
  int rc;

  rc = poll_shrub_servers(config);
  n_events += (rc > 0) ? rc : 0;

  rc = poll_socket(config);
  n_events += (rc > 0) ? rc : 0;

  /* We aren't too bothered by if any work was done by non-polling functions */
  handle_controller_dump_requests(config);
  handle_controller_auto_close(config);

  return n_events > 0;
}

static bool wait_for_wakeup_events(shrub_controller_config *config,
                                   int timeout)
{
  struct epoll_event ev;
  int rc;
  rc = epoll_wait(config->wakeup_epoll_fd, &ev, 1, timeout);
  if ( rc < 0 && errno != EINTR )
    config->controller_stats.epoll_failures++;
  return rc > 0 && ev.data.fd != config->wakeup_timer_fd;
}

static long long get_interrupt_timeout(shrub_controller_config *config)
{
  long long timeout = config->periodic_poll_timeout_ns;

  /* If an auto-close delay is set, then to ensure we respect that value we
   * must reduce our waiting timeout to at most this value. Otherwise the
   * shrub controller may remain open for longer than requested. */
  if ( config->auto_close_delay != AUTO_CLOSE_DELAY_NEVER ) {
    long long auto_close_delay = config->auto_close_delay * MS_TO_NS;
    timeout = (auto_close_delay < timeout) ? auto_close_delay : timeout;
  }

  timeout = (timeout < PERIODIC_POLL_TIMEOUT_MIN)
          ? PERIODIC_POLL_TIMEOUT_MIN : timeout;

  return timeout;
}

static void reactor_loop_interrupt(shrub_controller_config *config)
{
  long long timeout_ns = get_interrupt_timeout(config);
  int timeout_ms = (timeout_ns + MS_TO_NS - 1) / MS_TO_NS;
  struct itimerspec timeout_spec = {0};

  /* This should always be true, as the calculation above rounds up to the next
   * whole millisecond and the number of nanoseconds are guaranteed to be at
   * least 1. */
  ci_assert(timeout_ms > 0);

  timeout_spec.it_value.tv_sec = timeout_ns / SEC_TO_NS;
  timeout_spec.it_value.tv_nsec = timeout_ns -
                                  (timeout_spec.it_value.tv_sec * SEC_TO_NS);

  prime_server_vis(config);

  while ( is_running ) {
    /* If we have no servers, then make sure we can actually do some work for
     * an arbitrary number of steps. */
    const int max_reactor_steps_per_wakeup =
      (config->sum_server_buffers > 0) ? config->sum_server_buffers : 16;
    int reactor_steps_per_wakeup = max_reactor_steps_per_wakeup;
    bool did_work = true;
    bool events_ready;
    int rc;

    rc = timerfd_settime(config->wakeup_timer_fd, 0, &timeout_spec, NULL);
    if ( rc != 0 )
      config->controller_stats.timerfd_settime_failures++;

    /* Wait until any of our FDs report that there's something interesting to
     * do, then try completing work for a bounded number of iterations or
     * until we run out of work. */
    events_ready = wait_for_wakeup_events(config, timeout_ms);
    while ( reactor_steps_per_wakeup-- > 0 && did_work && is_running )
      did_work = reactor_loop_step(config);

    prime_server_vis(config);

    /* We currently don't get woken up when clients write to their FIFO when
     * freeing a buffer. This is especially problematic where one client is
     * slightly behind on freeing buffers as the above loop would only bring
     * them up-to-date after roughly (timeout * client_bufs / remaining_bufs)ms
     * which is rather punishing.
     * To work around this, we try to see if we've done any work after being
     * woken due to timing out, then spin for a short while (~1ms) to do our
     * best to let such a client catch up. If at any point we think "normal
     * service" might resume (i.e., buffers are being filled and other clients
     * are doing work) then we break back out into our usual workflow. */
    if ( reactor_steps_per_wakeup < max_reactor_steps_per_wakeup - 1 &&
         ! events_ready && ! wait_for_wakeup_events(config, 0) &&
         is_running ) {
      struct timespec start, now;

      clock_gettime(CLOCK_MONOTONIC, &start);
      now = start;

      while ( timespec_difference_ms(now, start) < 1 &&
              ! wait_for_wakeup_events(config, 0) &&
              reactor_steps_per_wakeup > 0 &&
              is_running ) {
        /* We need to give the client some time to see their new buffer(s),
         * process them, and be ready to free them. It's also slightly
         * friendlier to deschedule ourselves briefly. */
        usleep(1);
        did_work = reactor_loop_step(config);
        reactor_steps_per_wakeup -= (int)did_work;
        clock_gettime(CLOCK_MONOTONIC, &now);
      }
    }
  }
}

static void reactor_loop_spin(shrub_controller_config *config)
{
  while ( is_running )
    reactor_loop_step(config);
}

int parse_interface(const char *arg, shrub_controller_config *config) {
  const char *buffer_pos = strchr(arg, '/');
  char iface[IFNAMSIZ] = {0};
  int buffer_count;
  unsigned int ifindex;
  ci_hwport_id_t hw_port;
  size_t iface_len;
  const char *buffer_str;

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

  hw_port = convert_ifindex_to_hwport(config, ifindex);
  if ( hw_port == CI_HWPORT_ID_BAD ) {
    ci_log("Error: shrub_controller was unable to convert "
           "ifindex %d to a valid hw_port", ifindex);
    return -EINVAL;
  }

  return add_server_config(config, hw_port, ifindex, buffer_count);
}

static void tear_down_servers(shrub_controller_config *config)
{
  shrub_if_config_t *current_interface = config->server_config_head;
  shrub_if_config_t *next_interface;
  while ( current_interface != NULL ) {
    next_interface = current_interface->next;

    if ( current_interface->client_fd >= 0 )
      ef_shrub_socket_close_socket(current_interface->client_fd);

    if ( current_interface->server_started )
      shrub_server_fini(config, current_interface);

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
  bool daemonise = false;
  bool log_to_kern = false;
  struct stat stat;
  int option;
  shrub_controller_config config = {0};
  config.config_socket_fd = INVALID_SOCKET_FD;
  config.interface_token = 1;
  config.controller_id = 0;
  config.auto_close_delay = AUTO_CLOSE_DELAY_NEVER;
  config.periodic_poll_timeout_ns = PERIODIC_POLL_TIMEOUT_DEFAULT;

  /* Set sutable prefix */
  ci_server_set_log_prefix(&shrub_log_prefix, SERVER_BIN);

  /* Ensure that early errors are not lost */
  if( fstat(STDOUT_FILENO, &stat) != 0 ) {
    int fd = open(DEV_KMSG, O_WRONLY);
    if( fd != STDERR_FILENO ) {
      dup2(fd, STDERR_FILENO);
      /* Do not check the return code from dup2, as cannot log errors anyway.
       * Maybe daemonise() will have more luck, let it check for problems. */
    }
  }

  while ( (option = getopt(argc, argv, "dic:DKC:p:")) != -1 ) {
    switch (option)
    {
    case 'd':
      config.debug_mode = true;
      ci_log("Info: shrub_controller Debug Mode Enabled!");
      break;
    case 'i':
      config.use_interrupts = true;
      break;
    case 'c':
      config.controller_id = atoi(optarg);
      if( config.controller_id < 0 ||
          config.controller_id > EF_SHRUB_MAX_CONTROLLER ) {
        ci_log("Error: shrub_controller id should be between 0 and %d",
               EF_SHRUB_MAX_CONTROLLER);
        usage();
        return EXIT_FAILURE;
      }
      break;
    case 'D':
      daemonise = true;
      break;
    case 'K':
      log_to_kern = true;
      break;
    case 'C':
      config.auto_close_delay = atoi(optarg);
      break;
    case 'p':
      config.periodic_poll_timeout_ns = atoll(optarg);
      if( config.periodic_poll_timeout_ns < PERIODIC_POLL_TIMEOUT_MIN ) {
        ci_log("Error: periodic poll timeout must be at least %lldns",
               PERIODIC_POLL_TIMEOUT_MIN);
        usage();
        return EXIT_FAILURE;
      }
      break;
    default:
      usage();
      return EXIT_FAILURE;
    }
  }

  if( daemonise )
    ci_server_daemonise(&shrub_log_prefix,
                        SERVER_NAME, SERVER_BIN,
                        CI_DAEMON_CHDIR_ROOT | CI_DAEMON_CLOSE_FDS |
                        (log_to_kern ? CI_DAEMON_LOG_TO_KERN : 0));

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

  rc = create_interrupt_state(&config);
  if( rc )
    goto fail_create_interrupt_state;

  rc = controller_cplane_connect(&config);
  if ( rc )
    goto fail_cplane_connect;

  rc = controller_servers_init(&config, &argv[optind], argc - optind);
  if ( rc )
    goto fail_servers_init;

  if( config.use_interrupts )
    reactor_loop_interrupt(&config);
  else
    reactor_loop_spin(&config);

  tear_down_servers(&config);
fail_servers_init:
  controller_cplane_disconnect(&config);
fail_cplane_connect:
  cleanup_interrupt_state(&config);
fail_create_interrupt_state:
  cleanup_config_socket(&config);
fail_create_config_socket:
  controller_config_socket_lock_destroy(&config);
fail_socket_lock_create:
  rmdir(config.controller_dir);

  return rc;
}
