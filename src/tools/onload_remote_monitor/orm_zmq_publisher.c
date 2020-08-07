/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */
/*
 * Example ZMQ publisher for stats
 *
 * Additional build dependencies are czmq-devel and zeromq-devel
 */

#include <ci/internal/ip.h>
#include <ci/app/testapp.h>
#include <czmq.h>

#include "orm_json_lib.h"


static struct orm_cfg cfg;
static int cfg_interval = 10;
static char* cfg_endpoint = "tcp://*:5556";

static ci_cfg_desc cfg_opts[] = {
  { 'h', "help", CI_CFG_USAGE, 0, "this message" },
  { 0, "name",  CI_CFG_STR,  &cfg.stackname, "select a single stack name" },
  { 0, "filter",  CI_CFG_STR,  &cfg.filter,
    "dump only sockets matching pcap filter" },
  { 0, "sum-all",  CI_CFG_FLAG,  &cfg.sum,
    "present sum of all the stacks's stats" },
  { 0, "metadata", CI_CFG_FLAG, &cfg.meta,
    "dump metadata describing statistics" },
  { 0, "flat", CI_CFG_FLAG,     &cfg.flat,
    "dump flatter json structure" },
  { 0, "endpoint",  CI_CFG_STR,  &cfg_endpoint,
    "ZMQ endpoint to publish stats (default tcp://*:5556)" },
  { 0, "interval",  CI_CFG_INT,  &cfg_interval,
    "Interval between stats in seconds (default 10s)" },
};
#define N_CFG_OPTS (sizeof(cfg_opts) / sizeof(cfg_opts[0]))


int main(int argc, char** argv)
{
  ci_app_standard_opts = 0;
  ci_app_getopt(
    "[stats] [more_stats] [tcp_stats] [stack] [stack_state] [vis] [opts] "
    "[lots] [extra] [all]",
    &argc, argv, cfg_opts, N_CFG_OPTS);
  ++argv;  --argc;

  int output_flags = orm_parse_output_flags(argc, (const char * const*)argv);
  if( output_flags < 0 ) {
    printf("Invalid option specified\n");
    return EXIT_FAILURE;
  }
  unsigned int n = 0;

  printf("Publishing stats to ZMQ endpoint: %s\n", cfg_endpoint);
  zsock_t* publisher = zsock_new_pub(cfg_endpoint);
  // allow ^C etc to stop the app
  zsys_catch_interrupts();

  while( 1 ) {
    if( zsys_interrupted )
      break;

    char* data = NULL;
    size_t datalen = 0;
    FILE* output_stream = open_memstream(&data, &datalen);

    int rc = orm_do_dump(&cfg, output_flags, output_stream);
    fclose(output_stream);

    if( rc == 0 ) {
      // data generated OK
      zstr_send(publisher, data);
      printf("Stats published #%u\n", ++n);
    }
    else {
      printf("Not able to generate JSON rc=%d\n", rc);
    }

    fflush(stdout);
    free(data);

    sleep(cfg_interval);
  }

  // clean up
  zsock_destroy(&publisher);
  return 0;
}
