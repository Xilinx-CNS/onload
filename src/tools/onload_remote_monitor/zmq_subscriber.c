/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */
/*
 * Example ZMQ subscriber to receive stats from orm_zmq_publisher
 *
 * Additional build dependencies are czmq-devel and zeromq-devel
 */

#include <ci/internal/ip.h>
#include <ci/app/testapp.h>

#include <czmq.h>

static char* cfg_endpoint = "tcp://localhost:5556";

static ci_cfg_desc cfg_opts[] = {
  { 'h', "help", CI_CFG_USAGE, 0, "this message" },
  { 0, "endpoint",  CI_CFG_STR,  &cfg_endpoint,
    "ZMQ endpoint to subscribe to stats (default tcp://localhost:5556)" },
};
#define N_CFG_OPTS (sizeof(cfg_opts) / sizeof(cfg_opts[0]))


int main (int argc, char *argv [])
{
  ci_app_standard_opts = 0;
  ci_app_getopt("", &argc, argv, cfg_opts, N_CFG_OPTS);
  ++argv;  --argc;

  unsigned int update_n = 0;
  char* buffer = NULL;

  // allow ^C etc to stop the app
  zsys_catch_interrupts();

  fprintf(stderr, "Subscribing to ZMQ endpoint: %s\n", cfg_endpoint);
  zsock_t* subscriber = zsock_new_sub(cfg_endpoint, "");

  fprintf(stderr, "Waiting for update from publisher...\n");

  while( 1 ) {
    buffer = zstr_recv(subscriber);
    if( zsys_interrupted )
      break;
    ++update_n;
    fprintf(stderr, "Received update #%u :\n", update_n);
    printf("%s\n", buffer);
    zstr_free(&buffer);
  }

  zsock_destroy(&subscriber);
  return 0;
}
