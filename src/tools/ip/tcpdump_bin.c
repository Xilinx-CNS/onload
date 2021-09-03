/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2011-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  sasha
**  \brief  tcpdump process for onload stack
**   \date  2011/05/17
**    \cop  (c) Solarflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_tests_ef */
#define _GNU_SOURCE /* for strsignal */
#include <stdlib.h>
#include <ci/internal/ip.h>
#include <ci/internal/ip_signal.h>
#include "libc_compat.h"

#if CI_CFG_TCPDUMP
#if CI_HAVE_PCAP

#include <ci/app.h>
#include <onload/ioctl.h>
#include <onload/cplane_ops.h>
#include "libstack.h"
#include <pcap.h>
#include <net/if.h>
#include <fnmatch.h>

#if 0
#define LOG_DUMP(x) x
#else
#define LOG_DUMP(x)
#endif

struct oo_pcap_pkthdr {
  union{
    struct oo_timeval tv;
    struct oo_timespec ts;
  } t;
  ci_uint32 caplen;
  ci_uint32 len;
};

#define MAXIMUM_SNAPLEN 65535
static int cfg_snaplen = MAXIMUM_SNAPLEN;
static int cfg_dump_os = 1;
static int cfg_if_is_loop = 0;
static int cfg_dump_no_match_only = 0;

/* capture precision */
static const char *cfg_precision = "micro";
static int do_nano = 0;

/* Interface to dump */
static const char *cfg_interface = "any";
static int cfg_ifindex = -1;
static cicp_encap_t cfg_encap;
#define CI_HWPORT_ID_LO CI_CFG_MAX_HWPORTS
ci_int8 dump_hwports[CI_CFG_MAX_HWPORTS+2];

/* Data for dynamic update of the stack list */
static oo_fd onload_fd = (oo_fd)-1;
static pthread_t update_thread;
static pthread_t master_thread;
static int update_thread_started = 0;
static volatile int stacklist_has_update = 0;

/* Filter stack names */
#define MAX_PATTERNS 10
static const char *filter_patterns[MAX_PATTERNS];
static int filter_patterns_n = 0;

/* NB. Signed value important for use in division below. */
static ci_int64 cpu_khz;


static ci_cfg_desc cfg_opts[] = {
  {'s', "snaplen",   CI_CFG_UINT, &cfg_snaplen,
                "snarf snaplen bytes of data from each packet, man tcpdump"},
  {'i', "interface", CI_CFG_STR,  &cfg_interface,
                "interface to listen on, default to \"any\", man tcpdump"},
  {  1, "dump-os",   CI_CFG_FLAG, &cfg_dump_os, "dump packets sent via OS"},
  {'n', "no-match",  CI_CFG_FLAG, &cfg_dump_no_match_only,
                           "dump only packets not matching onload sockets"},
  {  2, "time-stamp-precision", CI_CFG_STR, &cfg_precision,
                 "set the timestamp precision, default to \"micro\", man tcpdump"},
};
#define N_CFG_OPTS (sizeof(cfg_opts) / sizeof(cfg_opts[0]))

#define USAGE_STR "[stack_id|stack_name ...] >pcap_file"

static void usage(const char* msg)
{
  if( msg ) {
    ci_log(" ");
    ci_log("%s", msg);
  }

  ci_log(" ");
  ci_log("usage:");
  ci_log("  %s [options] " USAGE_STR, ci_appname);

  ci_log(" ");
  ci_log("options:");
  ci_app_opt_usage(cfg_opts, N_CFG_OPTS);
  ci_log(" ");
  exit(-1);
}


struct frc_sync {
  uint64_t          sync_frc;
  uint64_t          sync_cost;
  int64_t           max_frc_diff;
  struct timespec   sync_ts;
};


static void frc_resync(struct frc_sync* fs)
{
  uint64_t after_frc, cost;

  if( fs->sync_cost == 0 ) {
    /* First time: Measure sync_cost and set other params. */
    int i;
    fs->max_frc_diff = cpu_khz * 1000 / 10;
    for( i = 0; i < 10; ++i ) {
      ci_frc64(&fs->sync_frc);
      clock_gettime(CLOCK_REALTIME, &fs->sync_ts);
      ci_frc64(&after_frc);
      cost = after_frc - fs->sync_frc;
      if( i == 0 )
        fs->sync_cost = cost;
      else
        fs->sync_cost = CI_MIN(fs->sync_cost, cost);
    }
    LOG_DUMP(ci_log("cpu_khz=%"PRId64" sync_cost=%"PRIu64"\n",
                    cpu_khz, fs->sync_cost));
  }

  /* Determine correspondence between frc and host clock. */
  do {
    ci_frc64(&fs->sync_frc);
    clock_gettime(CLOCK_REALTIME, &fs->sync_ts);
    ci_frc64(&after_frc);
  } while( after_frc - fs->sync_frc > fs->sync_cost * 3 );
}


static void pkt_tstamp(const ci_ip_pkt_fmt* pkt, struct timespec* ts_out)
{
  static struct frc_sync fs;
  int64_t ns, frc_diff = pkt->tstamp_frc - fs.sync_frc;

  /* This if() triggers on the first call. */
  if( frc_diff > fs.max_frc_diff ) {
    frc_resync(&fs);
    frc_diff = pkt->tstamp_frc - fs.sync_frc;
  }

  *ts_out = fs.sync_ts;
  ns = frc_diff * 1000000 / cpu_khz;
  if( ns >= 0 ) {
    while( ns >= 1000000000 ) {  /* NB. This loop is much cheaper than div */
      ts_out->tv_sec += 1;
      ns -= 1000000000;
    }
    ts_out->tv_nsec += ns;
    if( ts_out->tv_nsec >= 1000000000 ) {
      ts_out->tv_nsec -= 1000000000;
      ts_out->tv_sec += 1;
    }
  }
  else {
    while( ns <= -1000000000 ) {  /* NB. This loop is much cheaper than div */
      ts_out->tv_sec -= 1;
      ns += 1000000000;
    }
    if( -ns <= ts_out->tv_nsec ) {
      ts_out->tv_nsec += ns;
    }
    else {
      ts_out->tv_nsec += 1000000000 + ns;
      ts_out->tv_sec -= 1;
    }
  }
}


static inline ci_uint8 dump_hwport_val_get(void) {
  return cfg_dump_no_match_only ? OO_INTF_I_DUMP_NO_MATCH :
                                  OO_INTF_I_DUMP_ALL;
}


/* Using cicp_llap_retrieve(), convert cfg_ifindex to the interface bitmask
 * dump_hwports. */
static void ifindex_to_intf_i(ci_netif *ni)
{
  cicp_hwport_mask_t hwports;
  int rc;

  memset(dump_hwports, OO_INTF_I_DUMP_NONE, sizeof(dump_hwports));

  if( cfg_if_is_loop ) {
    dump_hwports[CI_HWPORT_ID_LO] = dump_hwport_val_get();
    LOG_DUMP(ci_log("dump on loopback"));
    return;
  }

  rc = oo_cp_find_llap(ni->cplane, cfg_ifindex, NULL/*mtu*/,
                       &hwports, NULL /*rxhwports*/, NULL/*mac*/, &cfg_encap);

  if( rc != 0 ) {
    ci_log("unknown interface %d: %s", cfg_ifindex, cfg_interface);
    goto suicide;
  }
  if( hwports == 0 ) {
    ci_log("non-onload interface %d: %s", cfg_ifindex, cfg_interface);
    goto suicide;
  }

  ci_assert_nequal(hwports, 0);
  {
    int i;
    for(i = 0; i < CI_CFG_MAX_HWPORTS; i++) {
      if( cp_hwport_make_mask(i) & hwports )
        dump_hwports[i] = dump_hwport_val_get();
    }
  }
  LOG_DUMP(ci_log("dump on hwports=%x", hwports));

  return;

suicide:
  /* XXX Fixme:
   * for pcap plugin we should exit graciously without killing others */
  /* for onload_tcpdump we should exit */
  libstack_netif_unlock(ni);
  exit(1);
}

/* Turn dumping on */
static void stack_dump_on(ci_netif *ni)
{
  int i;
  ci_assert(ci_netif_is_locked(ni));

  cpu_khz = IPTIMER_STATE(ni)->khz;

  {
    int i;
    /* Warn user if this is not the only tcpdump process running */
    for( i = 0;
         i < sizeof(ni->state->dump_intf) / sizeof(ni->state->dump_intf[0]);
         i++) {
      if( ni->state->dump_intf[i] != 0 ) {
        ci_log("ERROR: Onload stack [%d,%s] already has tcpdump process.  "
               "Multiple tcpdump processes for Onload do not work well.",
               ni->state->stack_id, ni->state->name);
        /* Detach just now, but if we are dumping every
         * stack, we will attach again and again. */
        stack_detach(stack_attached(ni->state->stack_id), 1);
        return;
      }
    }
  }

  /* No data from other tcpdump processes should be available. */
  ci_assert_equal(ni->state->dump_read_i, ni->state->dump_write_i);

  /* Init dump queue */
  for( i = 0; i < CI_CFG_DUMPQUEUE_LEN; i++ )
    ni->state->dump_queue[i] = OO_PP_NULL;

  /* Find interface details if unknown */
  if( dump_hwports[0] == -1 )
    ifindex_to_intf_i(ni);

  /* Set up dumping */
  ci_log("Onload stack [%d,%s]: start packet dump",
         ni->state->stack_id, ni->state->name);
  {
    ci_hwport_id_t hwport_i;
    int intf_i;
    for( hwport_i = 0;
         hwport_i < CI_CFG_MAX_HWPORTS;
         hwport_i++ ) {
      intf_i = ci_netif_get_hwport_to_intf_i(ni)[hwport_i];
      if( intf_i >= 0 )
        ni->state->dump_intf[intf_i] = dump_hwports[hwport_i];
    }
    ni->state->dump_intf[OO_INTF_I_LOOPBACK] = dump_hwports[CI_HWPORT_ID_LO];
  }
  ni->state->dump_intf[OO_INTF_I_SEND_VIA_OS] = cfg_dump_os ?
                                                OO_INTF_I_DUMP_ALL : 0;
  libstack_netif_unlock(ni);
}

/* Turn dumping off */
static void stack_dump_off(ci_netif *ni)
{
  memset(ni->state->dump_intf, 0, sizeof(ni->state->dump_intf));
  libstack_netif_lock(ni);
  oo_tcpdump_free_pkts(ni, ni->state->dump_read_i);
  ni->state->dump_read_i = ni->state->dump_write_i;
  ci_log("Onload stack [%d,%s]: stop packet dump",
         ni->state->stack_id, ni->state->name);
}

/* Dump and flush dumped data */
static void dump_data(const void *data, size_t size)
{
  if( fwrite(data, size, 1, stdout) != 1 ) {
    ci_log("Failed to dump packet data to stdout");
    exit(1);
  }
}
static void dump_flush(void)
{
  if( fflush(stdout) == EOF ) {
    ci_log("Failed to flush stdout");
    exit(1);
  }
}

/* Do dump */
static void stack_dump(ci_netif *ni)
{
  int strip_vlan = cfg_encap.type & CICP_LLAP_TYPE_VLAN;
  int do_strip_vlan = strip_vlan;
  ci_uint16 read_i = ni->state->dump_read_i;
  ci_uint16 i, fill_level = ni->state->dump_write_i - read_i;
  sigset_t sigset;

  if( fill_level == 0 )
    return;

  sigemptyset(&sigset);
  sigaddset(&sigset, SIGINT);

  /* Dump a batch of packets, then update dump_read_i.  Avoid writing
   * dump_read_i frequently since dirtying the cache line adds overhead to
   * the application we're monitoring.
   */
  if( fill_level > CI_CFG_DUMPQUEUE_LEN / 4 )
    fill_level = CI_CFG_DUMPQUEUE_LEN / 4;

  /* Barrier to ensure entries in dump ring are written. */
  ci_rmb();

  /* Prevent ^C from creating truncated dump file */
  CI_TEST( pthread_sigmask(SIG_BLOCK, &sigset, NULL) == 0 );

  for( i = 0; i < fill_level; ++i, ++read_i ) {
    struct oo_pcap_pkthdr hdr;
    struct timespec ts;
    int paylen;
    int fraglen;
    oo_pkt_p id;
    ci_ip_pkt_fmt *pkt;

    id = ni->state->dump_queue[read_i % CI_CFG_DUMPQUEUE_LEN];
    if( id == OO_PP_NULL )
      continue;
    pkt = PKT_CHK_NNL(ni, id);

    ci_assert_gt(pkt->refcount, 0);

    paylen = pkt->pay_len;

    /* If we are listening on a VLAN, take care of the additional header.
     */
    if( strip_vlan ) {
      if( pkt->vlan != cfg_encap.vlan_id ) {
        /* Need to do more detailed check if pkt->vlan == 0 as we can't then 
         * rely on it being accurate: Onload doesn't set it on the TX path
         */
        if( pkt->vlan == 0 ) {
          uint16_t* p_ether_type;
          p_ether_type = &(oo_ether_hdr(pkt)->ether_type);
          if( p_ether_type[0] != CI_ETHERTYPE_8021Q ||
              (CI_BSWAP_BE16(p_ether_type[1]) & 0xfff) != cfg_encap.vlan_id )
            continue;
        }
        else
          continue;
      }

      if( pkt->intf_i == OO_INTF_I_SEND_VIA_OS )
        do_strip_vlan = 0;
      else
        do_strip_vlan = 1;
    }

    /* For loopback, ensure that ethernet header is correct */
    if( pkt->intf_i == OO_INTF_I_LOOPBACK )
      memset(oo_ether_hdr(pkt), 0, 2 * ETH_ALEN);

    if( do_strip_vlan )
      paylen -= ETH_VLAN_HLEN;
    hdr.caplen = CI_MIN(cfg_snaplen, paylen);
    hdr.len = paylen;
    pkt_tstamp(pkt, &ts);
    hdr.t.ts.tv_sec = ts.tv_sec;
    if( do_nano )
      hdr.t.ts.tv_nsec = ts.tv_nsec;
    else
      hdr.t.tv.tv_usec = ts.tv_nsec / 1000;
    LOG_DUMP(ci_log("%u: got ni %d pkt %d len %d ref %d",
                    read_i, ni->state->stack_id,
                    OO_PKT_FMT(pkt), paylen, pkt->refcount));

    dump_data(&hdr, sizeof(hdr));
    fraglen = hdr.caplen;
    if( do_strip_vlan ) {
      if( pkt->n_buffers > 1 )
        fraglen = CI_MIN(fraglen, pkt->buf_len - ETH_VLAN_HLEN);
      dump_data(oo_ether_hdr(pkt), 2 * ETH_ALEN);
      dump_data((char *)oo_ether_hdr(pkt) + 2 * ETH_ALEN + ETH_VLAN_HLEN,
                fraglen - 2 * ETH_ALEN);
    }
    else {
      if( pkt->n_buffers > 1 )
        fraglen = CI_MIN(fraglen, pkt->buf_len);
      dump_data(oo_ether_hdr(pkt), fraglen);
    }

    /* Dump all scatter-gather chain */
    if( pkt->n_buffers  > 1 ) {
      ci_ip_pkt_fmt *frag = PKT_CHK_NNL(ni, pkt->frag_next);
      do {
        hdr.caplen -= fraglen;
        fraglen = CI_MIN(hdr.caplen, frag->buf_len);
        if( fraglen > 0 )
          dump_data(frag->dma_start, fraglen);
        if( OO_PP_IS_NULL(frag->frag_next) )
          break;
        frag = PKT_CHK_NNL(ni, frag->frag_next);
      } while( frag != NULL );
    }
  }

  /* Ensure we've finished reading before we release. */
  ci_mb();
  ni->state->dump_read_i = read_i;

  dump_flush();
  CI_TEST( pthread_sigmask(SIG_UNBLOCK, &sigset, NULL) == 0 );
}

/* Pre detach: almost the same as stack_dump_off, but dump packets instead
 * of dropping them. */
static void stack_pre_detach(ci_netif *ni)
{
  memset(ni->state->dump_intf, 0, sizeof(ni->state->dump_intf));
  ci_wmb();
  stack_dump(ni);

  /* The stack is dying, but we should free the last packets to check that
   * there is no packet leak */
#ifndef NDEBUG
  libstack_netif_lock(ni);
  oo_tcpdump_free_pkts(ni, ni->state->dump_read_i);
  libstack_netif_unlock(ni);
#endif

  ci_log("Onload stack [%d,%s] is now unused: stop dumping",
         ni->state->stack_id, ni->state->name);
}

/* Used in stack_verify_used: help to check if there are any stacks */
static void stackid_check(int id, void *arg)
{
  int *set = arg;
  *set = 1;
}
/* Verify that the given stack is really used */
static void stack_verify_used(ci_netif *ni)
{
  ci_netif_info_t info;

  info.mmap_bytes = 0;
  info.ni_exists = 0;

  info.ni_index = ni->state->stack_id;
  info.ni_orphan = 0;
  info.ni_subop = CI_DBG_NETIF_INFO_NOOP;
  CI_TRY(oo_ioctl(onload_fd, OO_IOC_DBG_GET_STACK_INFO, &info));

  ci_assert(info.ni_exists);

  if( info.rs_ref_count == 2 ) {
    int have_attached;
    LOG_DUMP(ci_log("We are the only user of stack %d", info.ni_index));
    stack_pre_detach(ni);
    stack_detach(stack_attached(info.ni_index), 0);

    /* Check that we have attached stacks */
    have_attached = 0;
    for_each_stack_id(stackid_check, &have_attached);
    if( !have_attached ) {
      ci_log("All stacks exited");
      exit(0);
    }
  }
}

static int stackfilter_match_name(ci_netif_info_t *info)
{
  int i;
  for( i = 0; i < filter_patterns_n; i++ ) {
    if( fnmatch(filter_patterns[i], info->ni_name, 0) == 0)
      return 1;
  }
  LOG_DUMP(ci_log("Onload stack [%d,%s]: not interested",
                  info->ni_index, info->ni_name));
  return 0; /* Not interested */
}

static void atexit_fn(void)
{
  if( update_thread_started ) {
    pthread_cancel(update_thread);
    pthread_join(update_thread, NULL);
  }

  for_each_stack(stack_dump_off, 0);
  libstack_end();

  CI_TRY(oo_fd_close(onload_fd));

  /* Do not use fflush, sice we exit via signal.  All our threads are
   * cancelled, so we are safe here. */
  fflush_unlocked(stdout);

  /* Never run this twice: */
  _exit(0);
}

static void signal_terminate(int sig)
{
  atexit_fn();
}

static void write_pcap_header(void)
{
  struct pcap_file_header hdr;

  if( do_nano )
    hdr.magic = 0xa1b23c4d; //pcap-ns
  else
    hdr.magic = 0xa1b2c3d4; //pcap
  hdr.version_major = PCAP_VERSION_MAJOR;
  hdr.version_minor = PCAP_VERSION_MINOR;
  hdr.thiszone = 0;
  hdr.sigfigs = 0;
  hdr.snaplen = cfg_snaplen;
  hdr.linktype = DLT_EN10MB;

  dump_data(&hdr, sizeof(hdr));
  dump_flush();
}

/* Thread to catch stack list updates.  This thread should not call
 * list_all_stacks2(), since libstack is not thread-safe.  So, we just set
 * stacklist_has_update flag and main thread should call
 * list_all_stacks2(). */
static void *update_stack_list_thread(void *arg)
{
  struct oo_stacklist_update param;

  param.timeout = -1;
  param.seq = *(ci_uint32 *)arg;
  LOG_DUMP(ci_log("%s: inital seq=%d", __func__, param.seq));
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
  while(1) {
    CI_TRY(oo_ioctl(onload_fd, OO_IOC_DBG_WAIT_STACKLIST_UPDATE, &param));
    stacklist_has_update = 1;
    LOG_DUMP(ci_log("%s: new seq=%d", __func__, param.seq));
  }

  /* Unreachable */
  return NULL;
}

/* Parse cfg_interface string and fill dump_hwports array.
 * We do exactly the same parsing as in tcpdump;
 * in case of error, we dump all interfaces, as with -iany */
static void parse_interface(void)
{
  int devnum;   /* pcap devnum */

  /* If cfg_interface is a number, we should parse it with
   * pcap_findalldevs(). */
  if( (devnum = atoi(cfg_interface)) != 0 ) {
    pcap_if_t *devpointer;
    char ebuf[PCAP_ERRBUF_SIZE];
    int i;

    if (devnum < 0) {
      ci_log("Error: infertace is negative number %d", devnum);
      goto error;
    }
    if( pcap_findalldevs(&devpointer, ebuf) < 0 ) {
      ci_log("Error: interface is a number %d, but pcap_findalldevs fails",
             devnum);
      goto error;
    }
    for( i = 0;
         i < devnum-1 && devpointer != NULL;
         i++, devpointer = devpointer->next );
    if( devpointer == NULL ) {
      ci_log("Error: no interface with pcap number %d", devnum);
      goto error;
    }
    cfg_interface = devpointer->name;
  }
  ci_log("Onload tcpdump on interface %s", cfg_interface);

  /* Now cfg_interface is an interface name.  Find the ifindex. */
  if( strcmp(cfg_interface, "any") == 0 ) {
    memset(dump_hwports, dump_hwport_val_get(), sizeof(dump_hwports));
    return;
  }
  else
  {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if( fd < 0 ) {
      ci_log("ERROR: can not create socket");
      exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, cfg_interface, sizeof(ifr.ifr_name));
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
      ci_log("Error: can not find ifindex for interface %s", cfg_interface);
      goto error;
    }
    cfg_ifindex = ifr.ifr_ifindex;
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
      ci_log("Error: can not find flags for interface %s", cfg_interface);
      goto error;
    }
    if( ifr.ifr_flags & IFF_LOOPBACK )
      cfg_if_is_loop = 1;
  }
  LOG_DUMP(ci_log("dump ifindex %d", cfg_ifindex));

  /* We can't use cicp_llap_retrieve() before we get any netif.  So, we set
   * a flag "fill me later" and return. */
  dump_hwports[0] = -1;
  return;

error:
  LOG_DUMP(ci_log("Error: dump all interfaces"));
  /* We do not exit in case of error: we just do our best and turn on
   * tcpdump on ALL interfaces.  If onload_tcpdump script is used,
   * tcpdump will report the proper error. */
  memset(dump_hwports, dump_hwport_val_get(), CI_CFG_MAX_INTERFACES);
  dump_hwports[OO_INTF_I_LOOPBACK] = dump_hwport_val_get();
}

int main(int argc, char* argv[])
{
  int attach_new_stacks = 0;
  stackfilter_t *stackfilter = NULL;
  struct oo_stacklist_update param;

  ci_app_usage = usage;
  cfg_lock = 1; /* lock when attaching */
  cfg_nopids = 1; /* pids are not needed, and can cause excessive delay */

  ci_app_getopt(USAGE_STR, &argc, argv, cfg_opts, N_CFG_OPTS);
  --argc; ++argv;
  master_thread = pthread_self();
  CI_TRY(libstack_init());

  if( strcmp(cfg_precision, "nano") == 0 ){
    do_nano = 1;
  }
  /* Fix cfg_snaplen value. */
  if( cfg_snaplen == 0 )
    cfg_snaplen = MAXIMUM_SNAPLEN; /* tcpdump compatibility */
  cfg_snaplen = CI_MAX(cfg_snaplen, 80);
  cfg_snaplen = CI_MIN(cfg_snaplen, MAXIMUM_SNAPLEN);

  /* Parse interfaces */
  parse_interface();

  /* Pcap file header */
  write_pcap_header();

  /* Get the initial seq no of stack list */
  CI_TRY(oo_fd_open(&onload_fd));
  param.timeout = 0;
  CI_TRY(oo_ioctl(onload_fd, OO_IOC_DBG_WAIT_STACKLIST_UPDATE, &param));

  /* Set up exit and signals before we attach to stacks */
  atexit(atexit_fn);
  ci_tp_init(NULL, signal_terminate);
  oo_init_signals();

  /* Attach to stacks: attach locks the stacks, stack_dump_on unlocks. */
  if( argc == 0 ) {
    attach_new_stacks = 1;
    list_all_stacks2(NULL, stack_dump_on, NULL, &onload_fd);
  }
  else {
    for( ; argc > 0 ; --argc, ++argv ) {
      unsigned stack_id;
      char dummy;

      if( sscanf(argv[0], " %u %c", &stack_id, &dummy) != 1 ) {
        if( filter_patterns_n == MAX_PATTERNS ) {
          ci_log("Too much stack name patterns: ignore '%s'", argv[0]);
          continue;
        }
        filter_patterns[filter_patterns_n++] = argv[0];
        attach_new_stacks = 1;
        continue;
      }
      if( ! stack_attach(stack_id) ) {
        ci_log("No such stack id: %d", stack_id);
        continue;
      }
      stack_dump_on(&stack_attached(stack_id)->ni);
    }
    if( attach_new_stacks ) {
      stackfilter = stackfilter_match_name;
      list_all_stacks2(stackfilter, stack_dump_on, NULL, &onload_fd);
    }
  }

  /* Create thread to notify us about stack list updates */
  pthread_create(&update_thread, NULL, update_stack_list_thread, &param.seq);
  update_thread_started = 1;

  while(1) {
    /* Wait for some stacks to be created if necessary. */
    if( dump_hwports[0] == -1 ) {
      if( !attach_new_stacks ) {
        ci_log("Failed to attach to any stacks, exit");
        exit(1);
      }
      while( ! stacklist_has_update )
        ci_spinloop_pause();
    }

    for_each_stack(stack_dump, 0);
    /* Re-enable signals */

    if( stacklist_has_update ) {
       stacklist_has_update = 0; /* drop flag before updating the list */
       if( attach_new_stacks ) {
         list_all_stacks2(stackfilter, stack_dump_on, stack_pre_detach,
                          &onload_fd);
       }
       else
         for_each_stack(stack_verify_used, 0);
    }
  }

  /* unreachable */
  return 0;
}

#else /* CI_HAVE_PCAP */

int main(int argc, char* argv[])
{
  ci_log("Onload was compiled without the libpcap development package.  "
         "You need to install the libpcap-devel or libpcap-dev package "
         "to run onload_tcpdump.");
  return 1;
}

#endif /* CI_HAVE_PCAP */
#else /* CI_CFG_TCPDUMP */

int main(int argc, char* argv[])
{
  ci_log("Onload was compiled without tcpdump support.  "
         "Please turn CI_CFG_TCPDUMP on.");
  return 1;
}

#endif /* CI_CFG_TCPDUMP */
