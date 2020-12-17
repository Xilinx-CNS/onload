/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2019 Xilinx, Inc. */
#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>

#include "utils.h"

/******************************************************************************/

#define PKT_POOL_SIZE        1 << 15
#define DEST_IPADDR          "239.100.10.1"
#define DEST_PORT            65456
#define REFILL_BATCH_SIZE    16
#define MAX_PKT_FRAGS        7
#define JUMBO_SIZE           9000
#define UDP_HEADER_LEN       42

/*
 * Hardware delivers at most ef_vi_receive_buffer_len() bytes to each
 * buffer (default 1792), and for best performance buffers should be
 * aligned on a 64-byte boundary.  Also, RX DMA will not cross a 4K
 * boundary.  The I/O address space may be discontiguous at 4K boundaries.
 * So easiest thing to do is to make buffers always be 2K in size.
 */
#define PKT_BUF_SIZE         2048

/*
 * Align address where data is delivered onto EF_VI_DMA_ALIGN boundary,
 * because that gives best performance.
 */
#define RX_DMA_OFF           ROUND_UP(sizeof(struct pkt_buf), EF_VI_DMA_ALIGN)


/*
 * A packet buffer is a memory allocations on the host which the card will
 * read from when sending packets, or write to when receiving packets.
 *
 * The packet buffer structure consists of:
 *     ef_addr    I/O address corresponding to the start
 *                of this pkt_buf struct
 *     rx_ptr     pointer to where received packets start
 *     id         packet buffer ID
 *     next       pointer to next buffer
 */
struct pkt_buf {
  ef_addr            ef_addr;
  void*              rx_ptr;
  int                id;
  struct pkt_buf*    next;
};

/*
 * Each packet buffer can hold up to (2048 - rx_prefix_len) bytes. A single
 * jumbo frame will be split across multiple packet buffers, so we aggregate
 * all packet data into a single region. Additional buffer ID, fragment
 * lengths and number of fragments are for reference (are not necessary).
 *
 * The jumbo frame structure consists of:
 *     in_pkt         Flag indicating processing frame
 *     buf_ids        Array of UIDs of each originating packet buffer buffer
 *     frag_data_len  Array of number of bytes payload in each fragment
 *     n_frags        Total number of fragments which contributed to this frame
 *     payload_bytes  Total number of bytes payload data in this frame
 */
typedef struct jumbo {
  int in_pkt;
  int buf_ids[MAX_PKT_FRAGS];
  unsigned int frag_data_len[MAX_PKT_FRAGS];
  unsigned int n_frags;
  unsigned int payload_bytes;
  char data[JUMBO_SIZE];
}jumbo_t;

/*
 * A set of packet buffers consists of a memory region partitioned up into a
 * pool of packet buffers. Memory is first registered with the NIC and then
 * arranged into packet buffers.
 *
 * The struct of packet buffers consists of
 *     mem            a pointer to the memory region
 *     ef_memreg      memory registered for DMA
 *     mem_size       size of the memory region
 *     num            number of packet buffers allocated
 *     pkt_buf        pool of free packet buffers
 *     free_pool_n    number of buffers in free pool
 */
struct pkt_bufs {
  void* mem;
  struct ef_memreg memreg;
  size_t mem_size;
  int num;
  struct pkt_buf* free_pool;
  int free_pool_n;
};

/*
 * There are 3 stages in setting up a VI:
 *     1) get a driver handle
 *     2) allocate a protection domain
 *     3) create an instance of a VI
 * Options can be set for the VI, and per-VI stats can also be maintained.
 *
 * The struct consists of
 *     dh              a driver handle
 *     pd              a protected domain
 *     vi              a VI instance
 *     pkt_mem         memory region being used for packet buffers
 *     fc              a cookie for identifying an installed filter
 *     rx_prefix_len   the length of the meta-data prefix region in
 *                     a packet buffer
 *     max_fill_level  The amount to fill the ring up to
 *
 */
typedef struct vi_resources {
  ef_driver_handle   dh;
  struct ef_pd       pd;
  struct ef_vi       vi;
  struct pkt_bufs    pkt_mem;
  ef_filter_cookie   fc;
  int                rx_prefix_len;
  int                max_fill_level;
} vi_resources_t;

/*
 * Configuration options:
 *     iface         interface to receive packets on. No default
 *     ip            Destination IP. Default is 239.100.10.1
 *     port          Destination port. Default is 65456
 *     verbose       toggle additional logging if this is set.
 *                   Default is to disable this
 *     dump_pkt      Boolean flag. If set, write out packet payload as text
 *     dump_hex      Boolean flag. If set, write out packet payload as hex
 *
 */
typedef struct cfg_opts {
  char iface[IFNAMSIZ];
  int verbose;
  int port;
  char ip[INET_ADDRSTRLEN];
  int dump_pkt;
  int dump_hex;
} cfg_opts_t;

/*
 * Application state information.
 *
 */
typedef struct app_state {
  int counter;

  cfg_opts_t cfg;
  vi_resources_t vir;

  jumbo_t jumbo;
} app_state_t;

/******************************************************************************/
/* DEBUG and user presentation functions */

static void dump_cfg(cfg_opts_t* cfg)
{
  printf("=================================================================\n");
  printf("App configuration settings:\n");
  printf("\tiface=%s, port=%d, ip=%s,\n"\
         "\tdump_pkt=%d dump_hex=%d, verbose=%d\n",
         cfg->iface, cfg->port, cfg->ip,
         cfg->dump_pkt, cfg->dump_hex, cfg->verbose);
  printf("=================================================================\n");
  return;
}

static void dump_payload(jumbo_t* j)
{
  int i;
  printf("payload (text format):\n");
  for( i = 0; i < j->payload_bytes; i++)
    printf("%c", j->data[i]);
  printf("\n");
  return;
}

static void hexdump(const void* pv, int len)
{
  const unsigned char* p = (const unsigned char*) pv;
  int i;
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
  printf("\n");
}

static void dump_jumbo_info(jumbo_t* j, cfg_opts_t* cfg)
{
  int i;
  printf("----------------\n");
  printf("Jumbo frame info\n");
  printf("\tPacket received: n_frags=%d, bytes=%d\n", j->n_frags, j->payload_bytes);
  printf("\tBuffer IDs: buf_ids=");
  for( i = 0; i <= j->n_frags; i++)
    printf("%d ", j->buf_ids[i]);
  printf("\n\tFragment lengths: ");
  for( i = 0; i <= j->n_frags; i++)
    printf("%d ", j->frag_data_len[i]);
  printf("\n");
  if( cfg->dump_pkt )
    dump_payload(j);
  if( cfg->dump_hex )
    hexdump(j->data, j->payload_bytes);
  printf("----------------\n");
}

static void usage(void)
{
  fprintf(stderr, "usage:\n");
  fprintf(stderr, "efjumborx [options] <interface>\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "options:\n");
  fprintf(stderr, "  -d   dump packet contents as text.\n"\
                  "       Writes the packet payload to stdout.\n"\
                  "       Cannot b set in conjunction with '-x'\n");
  fprintf(stderr, "  -x   dump packet contents as hex.\n"\
                  "       Writes the packet payload to stdout.\n"\
                  "       Cannot b set in conjunction with '-d'\n");
  fprintf(stderr, "  -i   Set the destination IP. "\
                  "Default is %s\n",DEST_IPADDR);
  fprintf(stderr, "  -p   Set the destination port. "\
                  "Default is %d\n",DEST_PORT);
  fprintf(stderr, "  -v   verbose. Enables "\
                  "additional logging output if set\n");
  fprintf(stderr, "\n");
}

/******************************************************************************/
/* initialisation functions */

static int set_defaults(app_state_t* as)
{
  cfg_opts_t* cfg = &as->cfg;

  cfg->dump_pkt = 0;
  cfg->verbose = 0;
  snprintf(cfg->ip, sizeof(cfg->ip), "%s", DEST_IPADDR);
  cfg->port = DEST_PORT;

  return 0;
}

static int parse_opts(int argc, char* argv[], app_state_t* as)
{
  int rc = 0;
  cfg_opts_t* cfg = &as->cfg;
  char const* opt_str = "hdxi:p:v";
  char c;

  while( (c = getopt(argc, argv, opt_str) ) != -1 )
    switch( c ) {
      case 'h':
        usage();
        exit(0);
        break;
      case 'd':
        cfg->dump_pkt = 1;
        break;
      case 'x':
        cfg->dump_hex = 1;
        break;
      case 'i':
        snprintf(cfg->ip, sizeof(cfg->ip), "%s", optarg);
        break;
      case 'p':
        cfg->port = atoi(optarg);
        break;
      case 'v':
        cfg->verbose = 1;
        break;
      default:
        printf("unsupported argument\n");
        exit(-1);
    }

  if( cfg->dump_pkt && cfg->dump_hex ) {
    fprintf(stderr,"ERROR: option -d and -x cannot both be set.\n");
    fprintf(stderr,"       please select one\n");
    exit(-1);
  }
  argc -= optind;
  argv += optind;
  if( argc < 1 ) {
    fprintf(stderr, "ERROR: No interface specified.\n");
    fprintf(stderr, "       Consult help (-h) for details.\n");
    exit(-1);
  }
  if( argc > 1 ) {
    fprintf(stderr,"ERROR: Too many arguments specified.\n");
    fprintf(stderr, "       Consult help (-h) for details.\n");
    exit(-1);
  }

  snprintf(cfg->iface, sizeof(cfg->iface), "%s", argv[0]);
  ++argv; --argc;

  return rc;
}

static int init_vi(app_state_t* as)
{
  int vi_flags, rc = 0;
  vi_resources_t* vr = &as->vir;
  cfg_opts_t* co = &as->cfg;

  TRY( ef_driver_open(&vr->dh) );
  TRY( ef_pd_alloc_by_name(&vr->pd, vr->dh, co->iface, EF_PD_DEFAULT) );
  vi_flags = EF_VI_FLAGS_DEFAULT;
  TRY( ef_vi_alloc_from_pd(&vr->vi, vr->dh, &vr->pd, vr->dh,
                           -1, -1, 0, NULL, -1, vi_flags) );
  vr->rx_prefix_len = ef_vi_receive_prefix_len(&vr->vi);
  vr->max_fill_level = ef_vi_receive_capacity(&vr->vi);

  return rc;
}

static void config_buffer(vi_resources_t* vr, int buf_num)
{
  struct pkt_buf* pkt_buf;

  /* derive the packet buffer pointer from the provided buffer ID */
  assert((unsigned) buf_num < (unsigned) vr->pkt_mem.num);
  pkt_buf =(struct pkt_buf*)((char*) vr->pkt_mem.mem +
           (size_t) buf_num * PKT_BUF_SIZE);
  pkt_buf->rx_ptr = (char*) pkt_buf + RX_DMA_OFF + vr->rx_prefix_len;
  pkt_buf->id = buf_num;
  pkt_buf->ef_addr = ef_memreg_dma_addr(&vr->pkt_mem.memreg,
                                        buf_num * PKT_BUF_SIZE);

  /* update pointer to free buffers */
  pkt_buf->next = vr->pkt_mem.free_pool;
  vr->pkt_mem.free_pool = pkt_buf;
  ++(vr->pkt_mem.free_pool_n);

  return;
}

/*
 * Packet memory is ensured to be correctly aligned, and is allocated. The
 * memory is partitioned up into a list of packet buffers.
 */
static int init_pkts_memory(app_state_t* as)
{
  vi_resources_t* vr = &as->vir;
  int i;

  vr->pkt_mem.num = PKT_POOL_SIZE;
  vr->pkt_mem.mem_size = vr->pkt_mem.num * PKT_BUF_SIZE;
  vr->pkt_mem.mem_size = ROUND_UP(vr->pkt_mem.mem_size, huge_page_size);

  /* register the memory so the NIC can access it. This is registered against
   * the protected domain*/
  TRY( posix_memalign(&vr->pkt_mem.mem, huge_page_size, vr->pkt_mem.mem_size) );
  ef_memreg_alloc(&vr->pkt_mem.memreg, vr->dh, &vr->pd, vr->dh,
                  vr->pkt_mem.mem, vr->pkt_mem.mem_size);
  memset(vr->pkt_mem.mem, 0, vr->pkt_mem.mem_size);

  /* configure packet buffers */
  for( i = 0; i < vr->pkt_mem.num; ++i ) {
    config_buffer(vr, i);
  }
  return 0;
}

/*
 * Add the necessary filter to the NIC filter table. In this case,
 * the app listens on a specified address. 
 */
static int add_filter(app_state_t* as)
{
  vi_resources_t* vr = &as->vir;
  cfg_opts_t* cfg = &as->cfg;
  ef_filter_spec fs;

  struct sockaddr_in daddr;

  inet_pton(AF_INET, cfg->ip, &(daddr.sin_addr));
  daddr.sin_family = AF_INET;
  daddr.sin_port = htons((cfg->port));

  ef_filter_spec_init(&fs, EF_FILTER_FLAG_NONE);
  TRY(ef_filter_spec_set_ip4_local(&fs,
                  IPPROTO_UDP,
                  daddr.sin_addr.s_addr,
                  daddr.sin_port));
  TRY(ef_vi_filter_add(&vr->vi, vr->dh, &fs, &(vr->fc)));

  return 0;
}

/******************************************************************************/
/* helper functions */

static void refill_rx_ring(app_state_t* as)
{
  vi_resources_t* vr = &as->vir;
  struct pkt_buf* pkt_buf;
  int i;
  int refill_level = vr->max_fill_level - REFILL_BATCH_SIZE;

  if( ef_vi_receive_space(&vr->vi) < REFILL_BATCH_SIZE )
    return;

  do {
    for( i = 0; i < REFILL_BATCH_SIZE; ++i ) {
      pkt_buf = vr->pkt_mem.free_pool;
      vr->pkt_mem.free_pool = vr->pkt_mem.free_pool->next;
      --(vr->pkt_mem.free_pool_n);
      ef_vi_receive_init(&vr->vi, pkt_buf->ef_addr + RX_DMA_OFF, pkt_buf->id);
    }
  } while( ef_vi_receive_fill_level(&vr->vi) < refill_level);
  ef_vi_receive_push(&vr->vi);
}

static inline struct pkt_buf* pkt_buf_from_id(app_state_t* as, int pkt_buf_i)
{
  vi_resources_t* vr = &as->vir;
  assert((unsigned) pkt_buf_i < (unsigned) vr->pkt_mem.num);
  return (void*) ((char*) vr->pkt_mem.mem + (size_t) pkt_buf_i * PKT_BUF_SIZE);
}

static inline void pkt_buf_free(app_state_t* as, struct pkt_buf* pkt_buf)
{
  vi_resources_t* vr = &as->vir;
  pkt_buf->next = vr->pkt_mem.free_pool;
  vr->pkt_mem.free_pool = pkt_buf;
  ++(vr->pkt_mem.free_pool_n);
}


/******************************************************************************/
/* event and packet handling */

static int handle_rx(app_state_t* as, ef_event* ev)
{
  struct pkt_buf* pkt_buf;
  int pkt_buf_id = EF_EVENT_RX_RQ_ID(*ev);
  jumbo_t* jp = &(as->jumbo);

  int is_start = EF_EVENT_RX_SOP(*ev);
  int is_cont = EF_EVENT_RX_CONT(*ev);
  int bytes = EF_EVENT_RX_BYTES(*ev) - as->vir.rx_prefix_len;

  pkt_buf = pkt_buf_from_id(as, pkt_buf_id);
  if( as->cfg.verbose )
    printf("RX Handling: rx flags=%d, is_start=%d, is_cont=%d\n",
           ev->rx.flags, is_start, is_cont);

  /* 
   * Check to ensure that we have not ended up in an inconsistent
   * state. Such a state is either
   *     we get SOP but in_ptk is TRUE
   *     we get !SOP but in_pkt is FALSE
   */
  if ( (is_start && jp->in_pkt) || (!is_start && !jp->in_pkt) ) {
    fprintf(stderr, "ERROR: bad state\n");
    return -1;
  }
  if( is_start ) {
    jp->in_pkt = 1;
    jp->buf_ids[0] = pkt_buf_id;
    jp->frag_data_len[0] = bytes - UDP_HEADER_LEN;
    jp->payload_bytes = bytes - UDP_HEADER_LEN;
    jp->n_frags = 0;
    memcpy(&jp->data[0],
           (char *)pkt_buf->rx_ptr + UDP_HEADER_LEN,
           jp->frag_data_len[0]);
  }
  else {
    jp->n_frags++;
    jp->buf_ids[jp->n_frags] = pkt_buf_id;
    /* bytes is the total number of bytes from the jumbo frame which
     * have been received. Consequently, some arithmetic needs to be
     * done to determine the number of bytes per fragment */
    jp->frag_data_len[jp->n_frags] = bytes - UDP_HEADER_LEN - jp->payload_bytes;
    memcpy(&jp->data[jp->payload_bytes],
           pkt_buf->rx_ptr,
           jp->frag_data_len[jp->n_frags] );
    jp->payload_bytes += jp->frag_data_len[jp->n_frags];
  }
  if( !is_cont ) {
    jp->in_pkt = 0;
    if( as->cfg.verbose )
      dump_jumbo_info(jp, &as->cfg);
    else{
      printf("packet received: n_frags=%d, bytes=%d\n",
             jp->n_frags, jp->payload_bytes);
      if( as->cfg.dump_pkt )
        dump_payload(jp);
      else if( as->cfg.dump_hex )
        hexdump(jp->data, jp->payload_bytes);
    }
  }

  pkt_buf_free(as, pkt_buf);

  return 0;
}

static int handle_rx_discard(app_state_t* as, ef_event* ev)
{
  struct pkt_buf* pkt_buf;
  int pkt_buf_id = EF_EVENT_RX_DISCARD_RQ_ID(*ev);
  int bytes = EF_EVENT_RX_DISCARD_BYTES(*ev) - as->vir.rx_prefix_len;
  int discard_type = EF_EVENT_RX_DISCARD_TYPE(*ev);
  char* discard_str;

  switch (discard_type) {
    case EF_EVENT_RX_DISCARD_CSUM_BAD:
      discard_str="BAD_CHECKSUM";
      break;
    case EF_EVENT_RX_DISCARD_MCAST_MISMATCH:
      discard_str="MCAST_MISMATCH";
      break;
    case EF_EVENT_RX_DISCARD_CRC_BAD:
      discard_str="BAD_CRC";
      break;
    case EF_EVENT_RX_DISCARD_TRUNC:
      discard_str="TRUNC";
      break;
    case EF_EVENT_RX_DISCARD_RIGHTS:
      discard_str="RIGHTS";
      break;
    case EF_EVENT_RX_DISCARD_EV_ERROR:
      discard_str="EV_ERROR";
      break;
    case EF_EVENT_RX_DISCARD_OTHER:
      discard_str="OTHER";
      break;
    default:
      discard_str="UNKNOWN";
      break;
  }
  printf("ERROR: discard %d bytes of type %d (%s)\n",
         bytes, discard_type, discard_str);

  pkt_buf = pkt_buf_from_id(as, pkt_buf_id);
  pkt_buf_free(as, pkt_buf);

  return 0;
}

static int handle_events(app_state_t* as)
{
  vi_resources_t* vr = &as->vir;
  ef_event evs[32];
  int i, n_ev;

  n_ev = ef_eventq_poll(&vr->vi, evs, sizeof(evs) / sizeof(evs[0]));
  if (n_ev > 0) {
    for( i=0; i < n_ev; ++i ) {
      switch( EF_EVENT_TYPE(evs[i]) ) {
      case EF_EVENT_TYPE_RX:
        TRY( handle_rx(as, &evs[i]) );
        break;
      case EF_EVENT_TYPE_RX_DISCARD:
        TRY( handle_rx_discard(as, &evs[i]) );
        break;
      default:
        if( as->cfg.verbose )
          printf("ERROR: unexpected event type=%d\n",
                 (int) EF_EVENT_TYPE(evs[i]));
        return(-1);
        break;

      }
    }
  }
  /* refill the RX ring. */
  refill_rx_ring(as);

  return 0;
}

/******************************************************************************/

int main(int argc, char* argv[]) {
  int rc = 0;
  app_state_t as;

  memset(&as, 0, sizeof(as));
  TRY( set_defaults(&as) );
  TRY( parse_opts(argc, argv, &as) );

  if( as.cfg.verbose )
    dump_cfg(&as.cfg);

  TRY( init_vi(&as) );
  TRY( init_pkts_memory(&as) );
  /* refill ring before subscribing, so that packets are not dropped */
  refill_rx_ring(&as);
  TRY( add_filter(&as) );

  printf("App now up and running:\n"\
         "\tListening on interface %s\n"
         "\tListening to address %s, port %d\n",
         as.cfg.iface, as.cfg.ip, as.cfg.port );
  printf("=================================================================\n");

  while(1)
    TRY( handle_events(&as) );

  return rc;
}
