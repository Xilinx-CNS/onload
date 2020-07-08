/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2014-2019 Xilinx, Inc. */
/* efforward_packed
 *
 * Forward packets between ports, using packed-stream mode for receive.
 *
 * 2014 Solarflare Communications Inc.
 * Author: David Riddoch
 * Date: 2014/10/06
 */

#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <etherfabric/packedstream.h>

#include "utils.h"


#define MAX_PORTS  8


struct buf {
  int                      buf_id;
  int                      port_id;
  int                      full;
  int                      refs;
  ef_packed_stream_packet* ps_pkt_start;
  ef_packed_stream_packet* ps_pkt_end;
  struct buf*              next;
  ef_addr                  ef_addr[MAX_PORTS];
};


struct port {
  int                      port_id;
  ef_driver_handle         dh;
  struct ef_pd             pd;
  struct ef_vi             vi;
  struct ef_memreg         memreg;
  struct buf*              current_buf;
  struct buf*              posted_bufs;
  struct buf**             posted_bufs_tail;
  struct buf*              tx_bufs;
  struct buf**             tx_bufs_tail;
  bool                     tx_stopped;
  int                      max_fill;
  int                      fwd_to;
  ef_packed_stream_params  ps_params;
  const char*              interface;
  const char*              filter;
  struct buf*              free_bufs;
};


struct thread {
  struct port  ports[MAX_PORTS];
  int          ports_n;
  struct buf** bufs;
  int          bufs_n;
  int          n_rx_pkts;
  uint64_t     n_rx_bytes;
};


static int cfg_verbose;
static int cfg_max_fill;


static inline void posted_buf_put(struct port* p, struct buf* buf)
{
  buf->next = NULL;
  *(p->posted_bufs_tail) = buf;
  p->posted_bufs_tail = &buf->next;
}


static inline struct buf* posted_buf_get(struct port* p)
{
  struct buf* buf = p->posted_bufs;
  if( buf != NULL ) {
    p->posted_bufs = buf->next;
    if( p->posted_bufs == NULL )
      p->posted_bufs_tail = &(p->posted_bufs);
  }
  return buf;
}


static inline void buf_release(struct thread* thread, struct buf* buf)
{
  assert(buf->refs > 0);
  if( --(buf->refs) == 0 ) {
    struct port* p = &(thread->ports[buf->port_id]);
    assert( p->port_id == buf->port_id );
    LOGV("RELEASE: port=%d buf=%d\n", p->port_id, buf->buf_id);
    buf->next = p->free_bufs;
    p->free_bufs = buf;
  }
}


static inline struct buf* thread_buf(struct thread* thread, int buf_id)
{
  return thread->bufs[buf_id];
}


static void handle_rx_ps(struct thread* thread, struct port* rx_port,
                         const ef_event* pev)
{
  int n_pkts, n_bytes, rc;
  struct buf* buf;

  if( EF_EVENT_RX_PS_NEXT_BUFFER(*pev) ) {
    struct buf* next_buf = posted_buf_get(rx_port);
    if( rx_port->current_buf != NULL ) {
      LOGV("RX_NEXT_BUF: prev=%d refs=%d next=%d\n",
           rx_port->current_buf->buf_id,
           rx_port->current_buf->refs, next_buf->buf_id);
      rx_port->current_buf->full = 1;
    }
    buf = rx_port->current_buf = next_buf;
    buf->ps_pkt_start =
      ef_packed_stream_packet_first(buf, rx_port->ps_params.psp_start_offset);
    buf->ps_pkt_end = buf->ps_pkt_start;
    buf->full = 0;
    assert(buf->refs == 1);
    struct port* tx_port = &(thread->ports[rx_port->fwd_to]);
    *(tx_port->tx_bufs_tail) = buf;
    tx_port->tx_bufs_tail = &(buf->next);
  }
  else {
    buf = rx_port->current_buf;
  }

  rc = ef_vi_packed_stream_unbundle(&rx_port->vi, pev, &buf->ps_pkt_end,
                                    &n_pkts, &n_bytes);
  thread->n_rx_pkts += n_pkts;
  thread->n_rx_bytes += n_bytes;
  buf->refs += n_pkts;

  LOGV("RX: rc=%d port=%d n_pkts=%d n_bytes=%d %d.refs=%d\n",
       rc, rx_port->port_id, n_pkts, n_bytes, buf->buf_id, buf->refs);
  (void) rc;
}


static void do_sends(struct thread* thread, struct port* port)
{
  bool did_tx = false;
  int n = 0;

  while( 1 ) {
    struct buf* buf = port->tx_bufs;
    ef_packed_stream_packet* ps_pkt = buf->ps_pkt_start;
    assert(buf->refs > 0);
    assert(buf->ps_pkt_start <= buf->ps_pkt_end);
    while( ps_pkt < buf->ps_pkt_end ) {
      uintptr_t off = ((uintptr_t) ef_packed_stream_packet_payload(ps_pkt) -
                       (uintptr_t) buf);
      int rc = ef_vi_transmit_init(&(port->vi),
                                   buf->ef_addr[port->port_id] + off,
                                   ps_pkt->ps_cap_len, buf->buf_id);
      if( rc == 0 ) {
        did_tx = true;
        ++n;
      }
      else {
        port->tx_stopped = true;
        goto done;
      }
      ps_pkt = ef_packed_stream_packet_next(ps_pkt);
      buf->ps_pkt_start = ps_pkt;
    }
    if( ! buf->full ) {
      goto done;
    }
    else {
      LOGV("TX_NEXT_BUF:\n");
      port->tx_bufs = buf->next;
      buf_release(thread, buf);
      if( port->tx_bufs == NULL ) {
        port->tx_bufs_tail = &(port->tx_bufs);
        goto done;
      }
    }
  }

 done:
  if( did_tx ) {
    ef_vi_transmit_push(&(port->vi));
    LOGV("TX: port=%d n_pkts=%d\n", port->port_id, n);
  }
}


static void complete_tx(struct thread* thread, struct port* port, int rq_id)
{
  assert((unsigned) rq_id < (unsigned) thread->bufs_n);
  struct buf* buf = thread_buf(thread, rq_id);
  LOGV("COMPLETE: port=%d %d.refs=%d\n", port->port_id, buf->buf_id, buf->refs);
  buf_release(thread, buf);
}


static void port_fill_rx_ring(struct port* port)
{
  while( ef_vi_receive_fill_level(&(port->vi)) < port->max_fill &&
         port->free_bufs != NULL ) {
    struct buf* buf = port->free_bufs;
    port->free_bufs = buf->next;
    assert( buf->refs == 0 );
    buf->refs = 1;
    TRY( ef_vi_receive_post(&port->vi, buf->ef_addr[port->port_id], 0) );
    posted_buf_put(port, buf);
  }
}


static inline bool tx_is_low(ef_vi* vi)
{
  return ef_vi_transmit_fill_level(vi) < ef_vi_transmit_capacity(vi) / 2;
}


static void thread_main_loop(struct thread* thread)
{
  ef_request_id ids[EF_VI_TRANSMIT_BATCH];
  ef_event evs[16];
  int i, j, n, n_ev, port_i = 0;
  struct port* port;

  while( 1 )
    for( port_i = 0; port_i < thread->ports_n; ++port_i ) {
      port = &(thread->ports[port_i]);
      n_ev = ef_eventq_poll(&port->vi, evs, sizeof(evs) / sizeof(evs[0]));
      for( i = 0; i < n_ev; ++i ) {
        switch( EF_EVENT_TYPE(evs[i]) ) {
        case EF_EVENT_TYPE_RX_PACKED_STREAM:
          handle_rx_ps(thread, port, &(evs[i]));
          break;
        case EF_EVENT_TYPE_TX:
          n = ef_vi_transmit_unbundle(&port->vi, &evs[i], ids);
          for( j = 0; j < n; ++j )
            complete_tx(thread, port, ids[j]);
          break;
        default:
          LOGE("ERROR: unexpected event type=%d\n",
               (int) EF_EVENT_TYPE(evs[i]));
          break;
        }
      }
      port_fill_rx_ring(port);
      if( port->tx_stopped && tx_is_low(&(port->vi)) )
        port->tx_stopped = false;
      if( port->tx_bufs != NULL && ! port->tx_stopped )
        do_sends(thread, port);
    }
}

/**********************************************************************/

static void monitor(struct thread* thread)
{
  /* Print approx packet rate and bandwidth every second. */

  uint64_t now_bytes, prev_bytes;
  struct timeval start, end;
  int prev_pkts, now_pkts;
  int ms, pkt_rate, mbps;

  prev_pkts = thread->n_rx_pkts;
  prev_bytes = thread->n_rx_bytes;
  gettimeofday(&start, NULL);

  while( 1 ) {
    sleep(1);
    now_pkts = thread->n_rx_pkts;
    now_bytes = thread->n_rx_bytes;
    gettimeofday(&end, NULL);
    ms = (end.tv_sec - start.tv_sec) * 1000;
    ms += (end.tv_usec - start.tv_usec) / 1000;
    pkt_rate = (int) ((int64_t) (now_pkts - prev_pkts) * 1000 / ms);
    mbps = (int) ((now_bytes - prev_bytes) * 8 / 1000 / ms);
    printf("%8d %10d\n", pkt_rate, mbps);
    fflush(stdout);
    prev_pkts = now_pkts;
    prev_bytes = now_bytes;
    start = end;
  }
}


static void* monitor_fn(void* arg)
{
  struct thread* thread = arg;
  monitor(thread);
  return NULL;
}


static void usage_msg(FILE* s)
{
  fprintf(s, "\nusage:\n");
  fprintf(s, "  efforward_packed [options] <rx_intf>:<tx_idx>[:filter]...\n");

  fprintf(s, "\noptions:\n");
  fprintf(s, "  -v               verbose logging (debug builds only)\n");
  fprintf(s, "  -f <max-fill>    set max RX ring fill level\n");

  fprintf(s, "\nexamples:\n");
  fprintf(s, "  # Reflect packets arriving on eth4 back to sender\n");
  fprintf(s, "  efforward_packed eth4:0\n\n");

  fprintf(s, "  # Forward eth4 to eth5\n");
  fprintf(s, "  efforward_packed eth4:1 eth5:-1\n\n");

  fprintf(s, "  # Forward eth4 to eth5 and eth5 to eth4\n");
  fprintf(s, "  efforward_packed eth4:1 eth5:0\n\n");
}


static __attribute__ ((__noreturn__)) void usage_err(void)
{
  usage_msg(stderr);
  exit(1);
}


static struct port* add_port(struct thread* thread, const char* rx_intf,
                             const char* tx_port_id, const char* filter)
{
  struct port* p = &(thread->ports[thread->ports_n]);
  p->port_id = (thread->ports_n)++;
  p->posted_bufs = NULL;
  p->posted_bufs_tail = &(p->posted_bufs);
  p->tx_bufs = NULL;
  p->tx_bufs_tail = &(p->tx_bufs);
  p->tx_stopped = false;
  p->interface = strdup(rx_intf);
  p->fwd_to = atoi(tx_port_id);

  int rxq_cap = (p->fwd_to >= 0) ? -1 : 0;
  if( rxq_cap == 0 ) {
    TEST( filter == NULL );
    p->filter = NULL;
  }
  else {
    p->filter = strdup(filter ? filter : "all");
  }

  TRY(ef_driver_open(&p->dh));
  TRY(ef_pd_alloc_by_name(&p->pd, p->dh, p->interface, EF_PD_RX_PACKED_STREAM));
  TRY(ef_vi_alloc_from_pd(&p->vi, p->dh, &p->pd, p->dh,
                          -1, rxq_cap, 2048, NULL, -1,
                          EF_VI_RX_PACKED_STREAM |
                          EF_VI_RX_PS_BUF_SIZE_64K |
                          EF_VI_TX_PUSH_DISABLE));
  TRY(ef_vi_packed_stream_get_params(&p->vi, &(p->ps_params)));
  /* To keep things simple, we insist that all ports support the same
   * packed buffer size.
   */
  TEST(p->ps_params.psp_buffer_size ==
       thread->ports[0].ps_params.psp_buffer_size);
  TEST(p->ps_params.psp_buffer_align ==
       thread->ports[0].ps_params.psp_buffer_align);
  p->max_fill =
    cfg_max_fill ? cfg_max_fill : p->ps_params.psp_max_usable_buffers;
  if( p->fwd_to < 0 )
    p->max_fill = 0;

  return p;
}


static void port_install_filters(struct port* port)
{
  ef_filter_spec filter_spec;

 if( port->fwd_to < 0 )
    return;

 if( ! strcmp(port->filter, "all") ) {
   ef_filter_spec_init(&filter_spec, EF_FILTER_FLAG_NONE);
   TRY( ef_filter_spec_set_unicast_all(&filter_spec) );
   TRY( ef_vi_filter_add(&(port->vi), port->dh, &filter_spec, NULL) );
   ef_filter_spec_init(&filter_spec, EF_FILTER_FLAG_NONE);
   TRY( ef_filter_spec_set_multicast_all(&filter_spec) );
   TRY( ef_vi_filter_add(&(port->vi), port->dh, &filter_spec, NULL) );
 }
 else {
   if( filter_parse(&filter_spec, port->filter, NULL) != 0 ) {
     LOGE("ERROR: Bad filter spec '%s'\n", port->filter);
     exit(1);
   }
   TRY( ef_vi_filter_add(&(port->vi), port->dh, &filter_spec, NULL) );
 }
}


int main(int argc, char* argv[])
{
  pthread_t thread_id;
  struct thread* thread;
  int port_id, i, c;
  int n_bufs_wanted = 0;

  while( (c = getopt (argc, argv, "vf:")) != -1 )
    switch( c ) {
    case 'v':
      cfg_verbose = 1;
      break;
    case 'f':
      cfg_max_fill = atoi(optarg);
      break;
    case '?':
      usage_err();
    default:
      TEST(0);
    }

  argc -= optind;
  argv += optind;
  if( argc < 1 )
    usage_err();

  thread = calloc(1, sizeof(*thread));
  thread->ports_n = 0;

  for( i = 0; i < argc; ++i ) {
    const char* rx_intf = strtok(argv[i], ":");
    const char* tx_port_id = strtok(NULL, ":");
    const char* filter = strtok(NULL, "~");
    if( rx_intf == NULL || tx_port_id == NULL )
      usage_err();
    struct port* port = add_port(thread, rx_intf, tx_port_id, filter);
    /* max_fill for RX plus one for TX. */
    if( port->max_fill )
      n_bufs_wanted += port->max_fill + 1;
  }

  for( port_id = 0; port_id < thread->ports_n; ++port_id ) {
    struct port* p = &(thread->ports[port_id]);
    if( p->max_fill && (unsigned) p->fwd_to >= (unsigned) thread->ports_n ) {
      LOGE("ERROR: Bad tx port id '%d'\n", p->fwd_to);
      exit(1);
    }
    if( p->fwd_to >= 0 )
      LOGI("p%d %s (%s, vi%d) => %s\n", p->port_id, p->interface, p->filter,
           ef_vi_instance(&(p->vi)), thread->ports[p->fwd_to].interface);
    else
      LOGI("p%d %s TX_ONLY vi%d\n", p->port_id, p->interface,
           ef_vi_instance(&(p->vi)));
  }

  /* Packed stream mode requires large contiguous buffers, so allocate
   * huge pages.  (Also makes consuming packets more efficient of
   * course).
   */
  const ef_packed_stream_params* psp = &(thread->ports[0].ps_params);
  size_t buf_size = psp->psp_buffer_size;
  size_t alloc_size = n_bufs_wanted * buf_size;
  alloc_size = (alloc_size + huge_page_size - 1) & ~(huge_page_size - 1);

  LOGI("psp_buffer_size=%d\n", psp->psp_buffer_size);
  LOGI("psp_buffer_align=%d\n", psp->psp_buffer_align);
  LOGI("psp_start_offset=%d\n", psp->psp_start_offset);
  LOGI("psp_max_usable_buffers=%d\n", psp->psp_max_usable_buffers);
  LOGI("n_bufs=%d\n", n_bufs_wanted);
  LOGI("n_huge_pages=%d\n", (int) (alloc_size / huge_page_size));
  LOGI("working_set_Kb=%d\n", (int) (n_bufs_wanted * buf_size / 1024));

  void* ptr;
  ptr = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB, -1, 0);
  TEST(ptr != MAP_FAILED);
  TEST(((uintptr_t) ptr & (psp->psp_buffer_align - 1)) == 0);

  thread->bufs_n = n_bufs_wanted;
  thread->bufs = calloc(thread->bufs_n, sizeof(thread->bufs[0]));
  struct buf* all_bufs = NULL;
  for( i = 0; i < thread->bufs_n; ++i ) {
    struct buf* buf = (void*) ((char*) ptr + i * buf_size);
    buf->buf_id = i;
    buf->refs = 0;
    thread->bufs[i] = buf;
    buf->next = all_bufs;
    all_bufs = buf;
  }

  /* DMA map the buffers for use with each port. */
  for( port_id = 0; port_id < thread->ports_n; ++port_id ) {
    struct port* p = &(thread->ports[port_id]);
    TRY(ef_memreg_alloc(&p->memreg, p->dh, &p->pd, p->dh, ptr, alloc_size));
    for( i = 0; i < thread->bufs_n; ++i ) {
      struct buf* buf = thread_buf(thread, i);
      buf->ef_addr[p->port_id] = ef_memreg_dma_addr(&p->memreg, i * buf_size);
    }
  }

  /* Assign some buffers to each port. */
  for( port_id = 0; port_id < thread->ports_n; ++port_id ) {
    struct port* p = &(thread->ports[port_id]);
    if( p->max_fill == 0 )
      continue;
    for( i = 0; i < p->max_fill + 1; ++i ) {
      struct buf* buf = all_bufs;
      all_bufs = all_bufs->next;
      buf->port_id = port_id;
      buf->next = p->free_bufs;
      p->free_bufs = buf;
    }
  }
  TEST( all_bufs == NULL );

  TEST(pthread_create(&thread_id, NULL, monitor_fn, thread) == 0);

  /* Install filters at the last minute.  Reason is that as soon as we
   * install filters packets are directed to our RXQ.  If we do this before
   * posting buffers, we'll get no-desc drops reported.  Also if done much
   * before starting the event loop then we'll build up a backlog that will
   * never clear if packets are arriving at line rate.
   */
  for( port_id = 0; port_id < thread->ports_n; ++port_id )
    port_fill_rx_ring(&(thread->ports[port_id]));
  for( port_id = 0; port_id < thread->ports_n; ++port_id )
    port_install_filters(&(thread->ports[port_id]));

  thread_main_loop(thread);

  return 0;
}
