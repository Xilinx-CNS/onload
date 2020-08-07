/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */
/* efrink_consumer
 *
 * Comsume packets from a shared memory ring (which is being managed via
 * efrink_controller)
 *
 * Multiple copies of efrink_consumer can run at the same time
 * For best performance, all processes should share the same NUMA node / cache
 *
 */

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>

#include <ci/compat.h>
#include <ci/tools.h>
#include <ci/tools/ipcsum_base.h>
#include <ci/tools/ippacket.h>
#include <ci/net/ipv4.h>
#include "utils.h"
#include "efrink.h"


struct resources {
  /* shared memory for DMA */
  int                shm_fd;
  void*              pkt_bufs;

  /* statistics */
  uint64_t           n_rx_pkts;
  uint64_t           n_rx_bytes;
  uint64_t           n_gen_c_changed;
  uint64_t           n_invalid_csum;
};


struct pkt_data {
  int is_ip;
  int ip_id;
};


static int cfg_hexdump;
static int cfg_verbose;


/* Mutex to protect printing from different threads */
static pthread_mutex_t printf_mutex;


static void hexdump(const void* pv, int len)
{
  const unsigned char* p = (const unsigned char*) pv;
  int i;
  pthread_mutex_lock(&printf_mutex);
  for( i = 0; i < len; ++i ) {
    const char* eos;
    switch( i & 15 ) {
    case 0:
      printf("%08x  ", i);
      eos = "";
      break;
    case 1:
      eos = " ";
      break;
    case 15:
      eos = "\n";
      break;
    default:
      eos = (i & 1) ? " " : "";
      break;
    }
    printf("%02x%s", (unsigned) p[i], eos);
  }
  printf(((len & 15) == 0) ? "\n" : "\n\n");
  pthread_mutex_unlock(&printf_mutex);
}


static void parse_packet(const void* pkt, int len, struct pkt_data* pkt_data)
{
  const ci_ether_hdr* eth = pkt;
  if( eth->ether_type == CI_ETHERTYPE_IP ) {
    pkt_data->is_ip = 1;
    const ci_ip4_hdr* ip4 = (void*) ((char*) eth + ETH_HLEN);
    pkt_data->ip_id = ntohs(ip4->ip_id_be16);
  }
  else {
    pkt_data->is_ip = 0;
  }
}


static void loop_memread(struct resources* res)
{
  unsigned i, nic_i;
  int len, flags;
  uint64_t initial_gen_c;
  struct pkt_buf* pkt_buf;
  struct pkt_data pkt_data = {};

  i = nic_i = nic_id(0, res->pkt_bufs);

  while( 1 ) {
    LOGV("Currently looking at index i=%d\n",i);
    pkt_buf = pkt_buf_from_id(res->pkt_bufs, i);

    initial_gen_c = read_begin(pkt_buf);

    flags = pkt_buf->flags;
    len = pkt_buf->len;
    if( flags == FLAG_RX_GOOD ) {
      /* do something with the data e.g. copy the bits we're interested in */
      parse_packet((char*)pkt_buf + pkt_buf->rx_offset, len, &pkt_data);
      if( cfg_hexdump )
	hexdump((char*)pkt_buf + pkt_buf->rx_offset, len);
    }

    /* Now must check the buffer hasn't been changed while we
     * were reading it */
    if( is_read_valid(pkt_buf, initial_gen_c) ) {
      if( flags == FLAG_RX_GOOD ) {
        /* Read was OK - at this point can actually take action based on the
         * data e.g. by sending a response packet.
         * In this case we just log some info we've copied from the packet
         * and then increment stats */
        if( pkt_data.is_ip )
          LOGV("IP packet with IP ID %d\n",pkt_data.ip_id);
        else
          LOGV("Non-IP packet\n");
        ++res->n_rx_pkts;
        res->n_rx_bytes += len;
      } else {
        /* we have a packet, but NIC marked it as invalid checksum */
        ++res->n_invalid_csum;
      }
    } else {
      /* Warning - gen count has changed, so read is potentially invalid */
      ++res->n_gen_c_changed;
      continue; /* retry reading the same pkt_buf */
    }

    i = next_pkt_buf_id(i);
    nic_i = nic_id(i, res->pkt_bufs);
    if( id_difference(nic_i, i) > 100 ) {
      /* for a real app we might choose to skip to nic_i if we're consistently
       * too far behind */
      LOGV("Reading has fallen more than 100 buffers behind\n");
    }
  }
}


static void monitor(struct resources* res)
{
  /* Print approx packet rate and bandwidth every second. */

  uint64_t now_bytes, prev_bytes;
  struct timeval start, end;
  uint64_t prev_pkts, now_pkts;
  int ms, pkt_rate, mbps;

  pthread_mutex_lock(&printf_mutex);
  printf("#%9s %16s %16s %16s %16s\n",
         "pkt-rate", "bandwidth(Mbps)", "total-pkts", "total-gen-chngd",
         "total-csum-bad");
  pthread_mutex_unlock(&printf_mutex);

  prev_pkts = res->n_rx_pkts;
  prev_bytes = res->n_rx_bytes;
  gettimeofday(&start, NULL);

  while( 1 ) {
    sleep(1);
    now_pkts = res->n_rx_pkts;
    now_bytes = res->n_rx_bytes;
    gettimeofday(&end, NULL);
    ms = (end.tv_sec - start.tv_sec) * 1000;
    ms += (end.tv_usec - start.tv_usec) / 1000;
    pkt_rate = (int) ((now_pkts - prev_pkts) * 1000 / ms);
    mbps = (int) ((now_bytes - prev_bytes) * 8 / 1000 / ms);
    pthread_mutex_lock(&printf_mutex);
    printf("%10d %16d %16"PRIu64" %16"PRIu64" %16"PRIu64"\n",
           pkt_rate, mbps, now_pkts, res->n_gen_c_changed, res->n_invalid_csum);
    pthread_mutex_unlock(&printf_mutex);
    fflush(stdout);
    prev_pkts = now_pkts;
    prev_bytes = now_bytes;
    start = end;
  }
}


static void* monitor_fn(void* arg)
{
  struct resources* res = arg;
  monitor(res);
  return NULL;
}


static __attribute__ ((__noreturn__)) void usage(void)
{
  fprintf(stderr, "usage:\n");
  fprintf(stderr, "  rink_consumer\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "  -d       hexdump received packet\n");
  fprintf(stderr, "  -v       enable verbose logging\n");
  exit(1);
}


int main(int argc, char* argv[])
{
  pthread_t thread_id;
  struct resources* res;
  int c;

  while( (c = getopt (argc, argv, "dv")) != -1 )
    switch( c ) {
    case 'd':
      cfg_hexdump = 1;
      break;
    case 'v':
      cfg_verbose = 1;
      break;
    case '?':
      usage();
    default:
      TEST(0);
    }

  argc -= optind;
  argv += optind;
  if( argc > 0 )
    usage();

  TEST((res = calloc(1, sizeof(*res))) != NULL);

  /* Open shared memory */
  size_t alloc_size = PKT_BUFS_N * PKT_BUF_SIZE;
  alloc_size = ROUND_UP(alloc_size, huge_page_size);
  res->shm_fd = shmget(ftok(SHM_NAME, 'R'),
                       alloc_size,
                       SHM_HUGETLB | SHM_R );
  if( res->shm_fd < 0 ) {
    LOGW("shmget() failed. Check controller running.\n");
    TEST(0);
  }
  res->pkt_bufs = shmat(res->shm_fd, NULL, SHM_RDONLY);
  if( res->pkt_bufs == (char *)(-1) ) {
    LOGW("shmat() failed.\n");
    TEST(0);
  }


  pthread_mutex_init(&printf_mutex, NULL);
  TEST(pthread_create(&thread_id, NULL, monitor_fn, res) == 0);

  loop_memread(res);
  return 0;
}
