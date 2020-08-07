/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2016-2020 Xilinx, Inc. */
#define _GNU_SOURCE
#include "rtt.h"
#include <ci/app.h>

#include <sys/time.h>
#include <stdarg.h>
#include <assert.h>
#include <time.h>


static void usage_msg(FILE* f)
{
  fprintf(f, "usage:\n");
  fprintf(f, "  rtt [OPTIONS] ping|pong TX [RX]\n");
  fprintf(f, "\n");
  fprintf(f, "options:\n");
  fprintf(f, "  -i ITERATIONS           - num iterations\n");
  fprintf(f, "  -w WARMUPS              - num warm-up iterations\n");
  fprintf(f, "  -f FRAME_LEN            - frame length (bytes)\n");
  fprintf(f, "  -g GAP_NANOS            - pause between iterations (nanos)\n");
}


static __attribute__ ((__noreturn__)) void usage_err(void)
{
  usage_msg(stderr);
  exit(1);
}


int rtt_err(const char* fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
  return -1;
}


struct endpoint_type {
  const char* name;
  rtt_constructor_fn* constructor;
};


static const struct endpoint_type ep_types[] = {
  { "tcp", rtt_tcp_build_endpoint },
  { "udp", rtt_udp_build_endpoint },
  { "efvi", rtt_efvi_build_endpoint },
};

static int ep_types_n = sizeof(ep_types) / sizeof(ep_types[0]);


static const struct endpoint_type* endpoint_type_lookup(const char* name)
{
  int i;
  for( i = 0; i < ep_types_n; ++i )
    if( ! strcmp(name, ep_types[i].name) )
      return &(ep_types[i]);
  return NULL;
}


static int spec_to_endpoint(struct rtt_endpoint** ep_out,
                            const struct rtt_options* opts,
                            unsigned dirs, const char* ep_spec)
{
  char* ep_type_s = strdupa(ep_spec);
  char* args_s = strchr(ep_type_s, ':');
  if( args_s == NULL )
    return rtt_err("ERROR: bad TX or RX spec: %s\n", ep_spec);
  *(args_s++) = '\0';

  const struct endpoint_type* ep_type = endpoint_type_lookup(ep_type_s);
  if( ep_type == NULL )
    return rtt_err("ERROR: unknown endpoint type: %s\n", ep_type_s);

  const char* args[10];
  int n_args = 0;
  char *saveptr = NULL, *arg;
  while( (arg = strtok_r(args_s, ",", &saveptr)) != NULL ) {
    args_s = NULL;
    args[n_args++] = arg;
  }

  return ep_type->constructor(ep_out, opts, dirs, args, n_args);
}


static inline int64_t timespec_diff_ns(struct timespec a, struct timespec b)
{
  assert( a.tv_nsec >= 0 && a.tv_nsec < 1000000000 );
  assert( b.tv_nsec >= 0 && b.tv_nsec < 1000000000 );
  return (a.tv_sec - b.tv_sec) * (int64_t) 1000000000
    + (a.tv_nsec - b.tv_nsec);
}


static void dummy_ping(struct rtt_endpoint* ep)
{
}

static void dummy_pong(struct rtt_endpoint* ep)
{
}

struct rtt_endpoint rtt_dummy_ep = {
  .ping = dummy_ping,
  .pong = dummy_pong,
};


static int do_measure_overhead(const struct rtt_options* opts,
                               struct rtt_endpoint* tx_ep,
                               struct rtt_endpoint* rx_ep)
{
  int n_iters = opts->n_iters;
  struct timespec a, b;
  int i;

  int* results;
  RTT_TEST( results = malloc(n_iters * sizeof(results[0])) );

  /* NB. No need to do warm-ups here as we're only interested in the
   * median.
   */
  for( i = 0; i < n_iters; ++i ) {
    clock_gettime(CLOCK_REALTIME, &a);
    tx_ep->ping(tx_ep);
    rx_ep->pong(rx_ep);
    clock_gettime(CLOCK_REALTIME, &b);
    results[i] = timespec_diff_ns(b, a);
  }

  int median;
  qsort(results, n_iters, sizeof(int), ci_qsort_compare_int);
  ci_iarray_median(results, results + n_iters, &median);
  free(results);
  return median;
}


static int measure_overhead(const struct rtt_options* opts)
{
  return do_measure_overhead(opts, &rtt_dummy_ep, &rtt_dummy_ep);
}


static void do_pinger(const struct rtt_options* opts,
                      struct rtt_endpoint* tx_ep,
                      struct rtt_endpoint* rx_ep)
{
  int overhead = measure_overhead(opts);
  int n_warm_ups = opts->n_warm_ups;
  int n_iters = opts->n_iters;
  int* results;
  int i;

  RTT_TEST( results = malloc(n_iters * sizeof(results[0])) );

  for( i = 0; i < n_warm_ups; ++i ) {
    tx_ep->ping(tx_ep);
    rx_ep->pong(rx_ep);
  }

  if( tx_ep->reset_stats )
    tx_ep->reset_stats(tx_ep);
  if( rx_ep->reset_stats )
    rx_ep->reset_stats(rx_ep);

  /* Touch to ensure resident. */
  memset(results, 0, n_iters * sizeof(results[0]));
  struct timespec start, end;

  for( i = 0; i < n_iters; ++i ) {
    clock_gettime(CLOCK_REALTIME, &start);
    tx_ep->ping(tx_ep);
    rx_ep->pong(rx_ep);
    clock_gettime(CLOCK_REALTIME, &end);
    results[i] = timespec_diff_ns(end, start) - overhead;
    if( opts->inter_iter_gap_ns ) {
      do
        clock_gettime(CLOCK_REALTIME, &start);
      while( timespec_diff_ns(start, end) < opts->inter_iter_gap_ns );
    }
  }

  printf("# measurement_overhead: %d\n", overhead);
  if( tx_ep->dump_info != NULL )
    tx_ep->dump_info(tx_ep, stdout);
  if( rx_ep != tx_ep && rx_ep->dump_info != NULL )
    rx_ep->dump_info(rx_ep, stdout);
  for( i = 0; i < n_iters; ++i )
    printf("%d\n", results[i]);
}


static void do_ponger(const struct rtt_options* opts,
                      struct rtt_endpoint* tx_ep,
                      struct rtt_endpoint* rx_ep)
{
  int i;

  for( i = 0; i < opts->n_warm_ups; ++i ) {
    rx_ep->pong(rx_ep);
    tx_ep->ping(tx_ep);
  }

  if( tx_ep->reset_stats )
    tx_ep->reset_stats(tx_ep);
  if( rx_ep->reset_stats )
    rx_ep->reset_stats(rx_ep);

  for( i = 0; i < opts->n_iters; ++i ) {
    rx_ep->pong(rx_ep);
    tx_ep->ping(tx_ep);
  }

  if( tx_ep->dump_info != NULL )
    tx_ep->dump_info(tx_ep, stdout);
  if( rx_ep != tx_ep && rx_ep->dump_info != NULL )
    rx_ep->dump_info(rx_ep, stdout);
}


static void do_cleanup(struct rtt_endpoint* tx_ep,
                       struct rtt_endpoint* rx_ep)
{
  if( tx_ep->cleanup != NULL )
    tx_ep->cleanup(tx_ep);
  if( rx_ep != tx_ep && rx_ep->cleanup != NULL )
    rx_ep->cleanup(rx_ep);
}


int main(int argc, char* argv[])
{
  struct rtt_options opts;
  opts.ping_frame_len = 42;
  opts.pong_frame_len = 42;
  opts.n_warm_ups = 10000;
  opts.n_iters = 100000;
  opts.inter_iter_gap_ns = 0;

  int c;
  while( (c = getopt(argc, argv, "i:w:f:g:h")) != -1 )
    switch( c ) {
    case 'i':
      opts.n_iters = atoi(optarg);
      break;
    case 'w':
      opts.n_warm_ups = atoi(optarg);
      break;
    case 'f':
      opts.ping_frame_len = atoi(optarg);
      opts.pong_frame_len = atoi(optarg);
      break;
    case 'g':
      opts.inter_iter_gap_ns = atoi(optarg);
      break;
    case 'h':
      usage_msg(stdout);
      exit(0);
      break;
    case '?':
      usage_err();
    default:
      RTT_TEST( 0 );
    }

  argc -= optind;
  argv += optind;
  if( argc < 2 || argc > 3 )
    usage_err();
  const char* action = argv[0];
  const char* tx_ep_spec = argv[1];
  const char* rx_ep_spec = (argc >= 3) ? argv[2] : NULL;

  struct rtt_endpoint* tx_ep;
  if( spec_to_endpoint(&tx_ep, &opts,
                       RTT_DIR_TX | ((rx_ep_spec) ? 0 : RTT_DIR_RX),
                       tx_ep_spec) < 0 )
    return 2;
  struct rtt_endpoint* rx_ep;
  if( rx_ep_spec != NULL ) {
    if( spec_to_endpoint(&rx_ep, &opts, RTT_DIR_RX, rx_ep_spec) < 0 )
      return 3;
  }
  else {
    rx_ep = tx_ep;
  }

  if( ! strcmp(action, "ping") )
    do_pinger(&opts, tx_ep, rx_ep);
  else if( ! strcmp(action, "pong") )
    do_ponger(&opts, tx_ep, rx_ep);
  else
    usage_err();

  do_cleanup(tx_ep, rx_ep);
  return 0;
}
