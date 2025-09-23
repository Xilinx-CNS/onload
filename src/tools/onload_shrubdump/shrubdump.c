/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#include <sys/socket.h>
#include <sys/un.h>

#include <ci/tools/log.h>
#include <ci/tools/utils.h>
#include <ci/app/testapp.h>
#include <onload/version.h>

#include <etherfabric/internal/shrub_shared.h>


static int cfg_id = -1;

static ci_cfg_desc cfg_opts[] = {
  { 'i', "id",  CI_CFG_INT, &cfg_id,
    "Dump the shrub controller with the specified id" },
};
#define N_CFG_OPTS (sizeof(cfg_opts) / sizeof(cfg_opts[0]))

#define LOGBUF_SIZE 1024
static int dump_named_controller(int id)
{
  int rc;
  ssize_t received_bytes;
  int client_fd;
  struct sockaddr_un addr;
  char socket_path[EF_SHRUB_NEGOTIATION_SOCKET_LEN];
  char logbuf[LOGBUF_SIZE];
  socklen_t addr_len;
  struct ef_shrub_controller_request request = {
    .controller_version = EF_SHRUB_VERSION,
    .command = EF_SHRUB_CONTROLLER_SHRUB_DUMP,
    .shrub_dump.logbuf_size = LOGBUF_SIZE,
  };

  if( id < 0 )
    return -EINVAL;

  rc = snprintf(socket_path, sizeof(socket_path),
                EF_SHRUB_CONTROLLER_PATH_FORMAT "%s", EF_SHRUB_SOCK_DIR_PATH,
                id, EF_SHRUB_NEGOTIATION_SOCKET);
  if ( rc < 0 || rc >= sizeof(socket_path) )
    return -EINVAL;

  rc = ci_init_unix_addr(socket_path, &addr, &addr_len);
  if( rc < 0 )
    return rc;

  client_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if ( client_fd == -1 )
    return -errno;

  rc = connect(client_fd, (struct sockaddr *)&addr, addr_len);
  if ( rc < 0 ) {
    rc = -errno;
    goto clean_exit;
  }

  rc = send(client_fd, &request, sizeof(request), 0);
  if ( rc == -1 ) {
    rc = -errno;
    goto clean_exit;
  }

  while( (received_bytes = recv(client_fd, logbuf, LOGBUF_SIZE, 0)) > 0 )
    ci_log("%s", logbuf);
  rc = received_bytes == 0 ? 0 : -errno;

clean_exit:
  close(client_fd);
  return rc;
}


static void usage(const char* msg)
{
  ci_log_fn = ci_log_stderr;
  ci_app_usage_default(msg);
}

int main(int argc, char** argv)
{
  int rc;
  ci_app_standard_opts = 0;
  ci_app_usage = usage;

  ci_set_log_prefix("");
  ci_log_fn = ci_log_stdout_nonl;
  ci_app_getopt("", &argc, argv, cfg_opts, N_CFG_OPTS);

  /* TODO support all option to find all controllers and dump each one */
  if( cfg_id >= 0 ) {
    rc = dump_named_controller(cfg_id);
    if( rc < 0 ) {
      ci_log("Failed to dump controller %d, rc %d\n", cfg_id, rc);
      exit(1);
    }
  }
  else {
    usage("Must select which controllers to dump");
  }

  return 0;
}
