/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

#include <ci/compat.h>
#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <etherfabric/efct_vi.h>
#include <etherfabric/shrub_server.h>
#include <etherfabric/shrub_shared.h>

#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>

struct shrub_controller_vi;

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

struct shrub_controller {
  struct shrub_controller_vi res;
  struct ef_shrub_server *shrub_server;
};

static int reactor_loop(struct shrub_controller* controller) {
  assert(controller != NULL);
  while ( true ) {
    ef_shrub_server_poll(controller->shrub_server);
  }
  return 0;
}

static int controller_init(struct shrub_controller* controller,
                           const char* interface)
{
  int rc;
  unsigned vi_flags = EF_VI_FLAGS_DEFAULT;
  unsigned pd_flags = EF_PD_DEFAULT;
  struct shrub_controller_vi* res = &controller->res;

  rc = ef_driver_open(&res->dh);
  if ( rc != 0 ) {
    fprintf(stderr, "failed to open driver handle\n");
    return rc;
  }

  rc = ef_pd_alloc_by_name(&res->pd, res->dh, interface, pd_flags);
  if ( rc != 0 ) {
    fprintf(stderr, "failed to alloc pd for %s\n", interface);
    goto fail_pd_alloc;
  }

  rc = ef_vi_alloc_from_pd(&res->vi, res->dh, &res->pd, res->dh,
                           -1, -1, 0, NULL, -1, vi_flags);
  if ( rc != 0 ) {
    fprintf(stderr, "failed to allocate vi\n");
    goto fail_vi_alloc;
  }

  rc = ef_shrub_server_open(&res->vi, &controller->shrub_server,
                            EF_SHRUB_CONTROLLER_PATH, cfg_buffer_size,
                            cfg_buffer_count);
  if (rc != 0)
    goto fail_server_alloc;

  return 0;
fail_server_alloc:
  ef_vi_free(&res->vi, res->dh);
fail_vi_alloc:
  ef_pd_free(&res->pd, res->dh);
fail_pd_alloc:
  ef_driver_close(res->dh);
  return rc;
}

static void controller_fini(struct shrub_controller* controller)
{
  ef_shrub_server_close(controller->shrub_server);
  ef_vi_free(&controller->res.vi, controller->res.dh);
  ef_pd_free(&controller->res.pd, controller->res.dh);
  ef_driver_close(controller->res.dh);
}

static __attribute__ ((__noreturn__)) void usage(void)
{
  fprintf(stderr, "usage:\n");
  fprintf(stderr, " shrub_controller [options] <interface> \n");
  fprintf(stderr, "\n");
  fprintf(stderr, "options:\n");
  fprintf(stderr, "  -b       Total amount of superbuf buffers the controller manages.\n");
  // TODO fill out the rest of this
  exit(1);
}

int main(int argc, char* argv[]) {
  int rc;
  const char* interface;
  struct shrub_controller controller;
  struct stat st = {0};
  int c;

  while( (c = getopt (argc, argv, "b:")) != -1 )
    switch( c ) {
      case 'b':
         cfg_buffer_count = atoi(optarg);
         break;
      case '?':
        usage();
    }

  argc -= optind;
  argv += optind;
  if( argc != 1 )
    usage();

  interface = argv[0];

   // Create the /run/onload directory
  if (stat(EF_SHRUB_SOCK_DIR_PATH, &st) == -1) {
    rc = mkdir(EF_SHRUB_SOCK_DIR_PATH, 0755);
    if( rc != 0 ) {
      fprintf(stderr, "failed to create '%s'\n", EF_SHRUB_SOCK_DIR_PATH);
      exit(1);
    }
  }

  rc = controller_init(&controller, interface);
  if( rc < 0 ) {
    fprintf(stderr, "Failed to initialise controller. rc=%d (%s)\n", rc, strerror(-rc));
    return -1;
  }

  reactor_loop(&controller);
  controller_fini(&controller);
  return 0;
}

