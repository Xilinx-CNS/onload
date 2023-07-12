/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */
/* efexclusivity
 *
 */

#include "utils.h"

#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/pio.h>
#include <etherfabric/memreg.h>
#include <etherfabric/capabilities.h>
#include <etherfabric/checksum.h>
#include <etherfabric/efct_vi.h>
#include <ci/tools.h>
#include <ci/tools/ipcsum_base.h>
#include <ci/tools/ippacket.h>

#include <stdarg.h>
#include <stddef.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <limits.h>


struct efexclusivity_vi;

static enum ef_vi_flags cfg_vi_flags = 0;
static int cfg_excl = 0;
static int cfg_fst_rxq_no = 0;
static int cfg_snd_rxq_no = 0;
static unsigned cfg_raddr_offset = 0;
static unsigned cfg_port_offset = 0;
static unsigned cfg_timeout = 100;
static bool cfg_delete_fst = false;
static bool snd_filter_enabled = false;


struct efexclusivity_vi {
  ef_vi     vi;
  int       n_ev;
  int       i;
  ef_event  evs[EF_VI_EVENT_POLL_MIN_EVS];
  ef_pd     pd;
  ef_memreg memreg;
};

static struct efexclusivity_vi rx_vi;

static ef_driver_handle  driver_handle;

static int filter_add(ef_vi* vi, bool exclusive, int rxq_no, uint32_t raddr_he, uint16_t port_he, ef_filter_cookie* cookie, int i)
{
  int rc = 0;
  ef_filter_spec filter_spec;
  ef_filter_spec_init(&filter_spec, (exclusive ? EF_FILTER_FLAG_EXCLUSIVE_RXQ : 0));
  TRY(ef_filter_spec_set_ip4_local(&filter_spec, IPPROTO_UDP, htonl(raddr_he),
                                  htons(port_he)));
  if ( rxq_no >= 0 )
    rc = ef_filter_spec_set_dest(&filter_spec, rxq_no, 0);

  if ( rc != 0 ) {
    fprintf(stderr, "Specifying the filter hardware rxq failed with errno %d (%s).\n", errno, strerror(errno));
    fprintf(stderr, "This error occurred on call number %d.", i);
    return rc;
  }

  rc = ef_vi_filter_add(vi, driver_handle, &filter_spec, cookie);
  if ( rc != 0 ) {
    fprintf(stderr, "Inserting the filter has failed with errno %d (%s).\n", errno, strerror(errno));
    fprintf(stderr, "This error occurred on call number %d.", i);
  }

  return rc;
}

static int check_filter(ef_vi* vi, bool expected_exclusive, ef_filter_cookie* cookie)
{
  ef_filter_info filter_info = {};
  int expected_flag = (expected_exclusive ? EF_FILTER_IS_EXCLUSIVE : 0);

  TRY(ef_vi_filter_query(vi, driver_handle, cookie, &filter_info, sizeof(filter_info)));

  if ( ( filter_info.flags & EF_FILTER_IS_EXCLUSIVE ) != expected_flag ) {
      fprintf(stderr, "Inserted filter failed to be marked with the correct exclusivity state.");
      fprintf(stderr, "filter_flags %d, expected_exclusivity %d \n", filter_info.flags, expected_exclusive);
      return -EINVAL;
  }

  return 0;
}

static void filter_del(ef_vi* vi, ef_filter_cookie* cookie) {
  TRY(ef_vi_filter_del(vi, driver_handle, cookie));
}


static const int do_test(int ifindex, struct efexclusivity_vi* exclusivity_vi, void* pkt_mem,
                             size_t pkt_mem_bytes)
{
  ef_vi* vi = &exclusivity_vi->vi;
  enum ef_pd_flags pd_flags = 0;
  enum ef_vi_flags vi_flags = cfg_vi_flags;
  int rc;
  ef_filter_cookie fst_cookie = {};
  ef_filter_cookie snd_cookie = {};

  uint32_t raddr_he = 0xac010203;
  uint16_t port_he = 8080;

  raddr_he += cfg_raddr_offset;
  port_he  += cfg_port_offset;

  TRY(ef_pd_alloc(&exclusivity_vi->pd, driver_handle, ifindex, pd_flags));

  if( (rc = ef_vi_alloc_from_pd(vi, driver_handle, &exclusivity_vi->pd,
                                driver_handle, -1, -1, -1, NULL, -1,
                                vi_flags)) < 0 ) {
    if( rc == -EPERM ) {
      fprintf(stderr, "Failed to allocate VI without event merging\n");
      vi_flags |= EF_VI_RX_EVENT_MERGE;
      TRY( ef_vi_alloc_from_pd(vi, driver_handle, &exclusivity_vi->pd,
                               driver_handle, -1, -1, -1, NULL, -1,
                               vi_flags) );
    }
    else
      TRY( rc );
  }

  rc = filter_add(vi, cfg_excl & 1, cfg_fst_rxq_no, raddr_he, port_he, &fst_cookie, 1);
  if ( rc == 0 ) {

    TRY( check_filter(vi, cfg_excl & 1, &fst_cookie) );

    if ( cfg_delete_fst )
      filter_del(vi, &fst_cookie);

    if ( snd_filter_enabled ) {
      rc = filter_add(vi, cfg_excl & 2, cfg_snd_rxq_no, raddr_he + 1, port_he + 1, &snd_cookie, 2);
      if ( rc == 0 )
        TRY( check_filter(vi, cfg_excl & 2, &snd_cookie) );
    }

    if ( rc == 0 && cfg_timeout > 0 )
      sleep(cfg_timeout);
  }


  return rc;
}


static CI_NORETURN usage(const char* fmt, ...)
{
  if( fmt ) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "\n");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
  }
  fprintf(stderr, "\nusage:\n");
  fprintf(stderr, "  efexclusivity <interface>\n");
  fprintf(stderr, "\noptions:\n");
  fprintf(stderr, "  -e <bitmask>         - mark exclusivity for None (0), 1st (1) 2nd (2) or both (3) filters\n");
  fprintf(stderr, "  -a < rxq_no >        - set to -1 for any rxq, otherwise specify preferred rxq for the first filter\n");
  fprintf(stderr, "  -b < rxq_no >        - set to -1 for any rxq, otherwise specify preferred rxq for the second filter\n");
  fprintf(stderr, "  -i < ip >            - ip offset used for filters\n");
  fprintf(stderr, "  -p < p >             - port offset used for filters\n");
  fprintf(stderr, "  -t < timeout >       - timeout\n");
  fprintf(stderr, "  -d                   - Delete the first filter\n");
  fprintf(stderr, "\n");
  exit(1);
}


int main(int argc, char* argv[])
{
  int rx_ifindex = -1;
  void* pkt_mem;
  int pkt_mem_bytes;
  int rc;
  int c;

  printf("# ef_vi_version_str: %s\n", ef_vi_version_str());

  #define OPT_INT(s, p) do {                                 \
    long __v;                                                \
    if( ! parse_long(s, INT_MIN, INT_MAX, &__v) ) {          \
      usage("Unable to parse '%s': %s", s, strerror(errno)); \
    }                                                        \
    p = (int)__v;                                            \
  } while( 0 );

  #define OPT_UINT(s, p) do {                                \
    long __v;                                                \
    if( ! parse_long(s, 0, INT_MAX, &__v) ) {                \
      usage("Unable to parse '%s': %s", s, strerror(errno)); \
    }                                                        \
    p = (unsigned int)__v;                                   \
  } while( 0 );

  while( ( c = getopt (argc, argv, "e:a:b:t:i:p:d")) != -1 )
    switch( c ) {
      case 'e':
        OPT_INT(optarg, cfg_excl);
        break;
      case 'a':
        OPT_INT(optarg, cfg_fst_rxq_no);
        break;
      case 'b':
        OPT_INT(optarg, cfg_snd_rxq_no);
        snd_filter_enabled = true;
        break;
      case 't':
        OPT_UINT(optarg, cfg_timeout);
        break;
      case 'i':
        OPT_UINT(optarg, cfg_raddr_offset);
        break;
      case 'p':
        OPT_UINT(optarg, cfg_port_offset);
        break;
      case 'd':
        cfg_delete_fst = true;
        break;
    }

  #undef OPT_INT
  #undef OPT_UINT

  argc -= optind;
  argv += optind;

  if( argc != 1 )
    usage(NULL);

  if( ! parse_interface(argv[0], &rx_ifindex) )
    usage("Unable to parse RX interface '%s': %s", argv[1], strerror(errno));

  TRY(ef_driver_open(&driver_handle));

  rc = do_test(rx_ifindex, &rx_vi, pkt_mem, pkt_mem_bytes);

  if ( rc == 0 )
    printf("Test passed successfully");
  return 0;
}

/*! \cidoxg_end */
