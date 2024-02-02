/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <etherfabric/efct_vi.h>
#include <etherfabric/shrub_server.h>

#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#define SOCK_DIR_PATH "/run/onload/"
#define SOCK_NAME_LEN 20

struct shrub_controller_vi;

static int cfg_queue = 0;
static int cfg_buffer_count = 1024;
static int cfg_buffer_size = 1024 * 1024;

struct shrub_controller_vi {
  ef_vi     vi;
  int       n_ev;
  int       i;
  ef_pd     pd;
  ef_memreg memreg; /* TODO will we want this? */
  ef_driver_handle dh;
};

int init(struct ef_shrub_server** server_out,
         const char* server_addr) {
    return ef_shrub_server_open(
      server_out,
      server_addr,
      cfg_buffer_size,
      cfg_buffer_count
    );
}

int reactor_loop(struct shrub_controller_vi* res, struct ef_shrub_server* server) {
  assert(server != NULL);
  while ( true ) {
    ef_shrub_server_poll(&res->vi, server);
  }
}

static __attribute__ ((__noreturn__)) void usage(void)
{
  fprintf(stderr, "usage:\n");
  fprintf(stderr, " shrub_controller [options] <interface> \n");
  fprintf(stderr, "\n");
  fprintf(stderr, "options:\n");
  fprintf(stderr, "  -b       Total amount of superbuf buffers the controller manages.\n");
  fprintf(stderr, "  -q       RXQ and socket that the shrub controller should manage.\n");
  fprintf(stderr, "  -s       Size of each superbuf buffer.\n");
  // TODO fill out the rest of this
  exit(1);
}

int main(int argc, char* argv[]) {
  int rc;
  const char* interface;
  struct shrub_controller_vi* res;
  struct ef_shrub_server* server;
  char sock_fd_path[SOCK_NAME_LEN];
  struct stat st = {0};
  int c;
  char* queue = NULL;

  while( (c = getopt (argc, argv, "b:q:s:")) != -1 )
    switch( c ) {
      case 'b':
         cfg_buffer_count = atoi(optarg);
         break;
      case 'q':
         queue = optarg;
         cfg_queue = atoi(queue);
         break;
      case 's':
         cfg_buffer_size = atoi(optarg);
         break;
      case '?':
        usage();
    }

  argc -= optind;
  argv += optind;
  if( argc != 1 )
    usage();

  interface = argv[0];

  res = calloc(1, sizeof(*res));
  if ( res == NULL )
  {
    fprintf(stderr, "failed to allocate memory\n");
    exit(1);
  }

  rc = ef_driver_open(&res->dh);
  if ( rc != 0 ) {
    fprintf(stderr, "failed to open driver handle\n");
    exit(1);
  }

  rc = ef_pd_alloc_by_name(&res->pd, res->dh, interface, 0);
  if ( rc != 0 ) {
    fprintf(stderr, "failed to alloc pd for %s\n", interface);
    exit(1);
  }

  rc = ef_vi_alloc_from_pd(&res->vi, res->dh, &res->pd, res->dh,
                           -1, 0, 0, NULL, -1, 0);
  if ( rc != 0 ) {
    fprintf(stderr, "failed to allocate vi\n");
    exit(1);
  }

 // Create the /run/onload directory
  if (stat(SOCK_DIR_PATH, &st) == -1) {
    rc = mkdir(SOCK_DIR_PATH, 0700);
    if( rc != 0 ) {
      fprintf(stderr, "failed to create '%s'\n", SOCK_DIR_PATH);
      exit(1);
    }
  }

  memset(sock_fd_path, 0, sizeof(sock_fd_path));
  strncpy(sock_fd_path, SOCK_DIR_PATH, SOCK_NAME_LEN - 1);
  strncat(sock_fd_path, "sock", SOCK_NAME_LEN - strlen(sock_fd_path) - 1); // For now a fixed one TODO later adjust

  if (queue != NULL)
    strncat(sock_fd_path, queue, SOCK_NAME_LEN - strlen(sock_fd_path) - 1);

  //For initial development cleanup the existing socket.
  //This could be a wrong move in production where we
  // want to error instead as the socket is in control by another user.
  remove(sock_fd_path);

  rc = init(&server, sock_fd_path);
  if ( rc != 0 ) {
    //TODO: Put a handler to destruct the socket on all interrupts.
    remove(sock_fd_path);
    fprintf(stderr, "failed to initialise server\n");
    exit(1);
  }

  reactor_loop(res, server);
}

