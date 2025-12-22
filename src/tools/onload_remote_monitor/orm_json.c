/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2014-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  as
**  \brief  Dump state of all Onload stacks in json format to stdout.
**   \date  2014/12/01
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/* XXX: We are not handling the following types of stats from
 * 'onload_stackdump lots' yet.
 *
 * dump_stats(tcp_stats_fields, N_TCP_STATS_FIELDS, &t_stats, 0);
 * dump_stats(tcp_ext_stats_fields, N_TCP_EXT_STATS_FIELDS, &te_stats, 0);
 * dump_stats(udp_stats_fields, N_UDP_STATS_FIELDS, &u_stats, 0);
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

#include <ci/internal/ip.h>
#include <ci/app/testapp.h>

#include "orm_json_lib.h"

static struct orm_cfg cfg;
static bool cfg_double_buffer;
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
  { 0, "dblbuf",  CI_CFG_FLAG,  &cfg_double_buffer,
                                  "guarantee no output in case of error" },
};
#define N_CFG_OPTS (sizeof(cfg_opts) / sizeof(cfg_opts[0]))


int main(int argc, char** argv)
{
  char* buf = NULL;
  size_t buflen = 0;
  FILE* output_stream;

  ci_app_standard_opts = 0;
  ci_app_getopt(
    "[stats] [more_stats] [tcp_stats] [stack] [stack_state] [pids] [vis] "
    "[opts] [lots] [extra] [all]",
    &argc, argv, cfg_opts, N_CFG_OPTS);
  ++argv;  --argc;

  int output_flags = orm_parse_output_flags(argc, (const char * const*)argv);
  if( output_flags < 0 ) {
    fprintf(stderr, "Invalid option specified\n");
    return EXIT_FAILURE;
  }

  if( cfg_double_buffer )
    output_stream = open_memstream(&buf, &buflen);
  else
    output_stream = stdout;

  int rc = orm_do_dump(&cfg, output_flags, output_stream);

  if( cfg_double_buffer ) {
    fclose(output_stream);
    if( ! rc )
      fwrite(buf, 1, buflen, stdout);
  }

  return rc ? EXIT_FAILURE : 0;
}
