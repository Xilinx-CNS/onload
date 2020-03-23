/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/*
 * This file contains functions for filtering Onload dump output by string.
 * It is shared by onload_stackdump and orm_json.
 *
 * The filtering itself (ab)uses libpcap's capabilities by using the filter
 * compiler and executor over Onload's cached socket headers. This approach
 * works for common types of filtering but may fall over with more complicated
 * expressions (e.g. packet lengths will be wrong, MAC addresses may not be
 * available, directionality information is not available, etc.)
 *
 * Note that the capabilities herein use global variables for state. This is
 * fine for onload_stackdump and orm_json, but be careful if using this code
 * for anything else.
 */

#ifndef CI_SOCKBUF_FILTER_H
#define CI_SOCKBUF_FILTER_H
#include <stddef.h>
#include <ci/internal/ip.h>


#if CI_HAVE_PCAP
#include <pcap/pcap.h>

typedef struct {
  struct bpf_program sock_filter;
  pcap_t* sockbuf_pcap;
} sockbuf_filter_t;
#else
typedef struct { } sockbuf_filter_t; /* dummy entry */
#endif


static int/*bool*/ sockbuf_filter_prepare(sockbuf_filter_t* sft,
                                          const char* filter)

{
#if CI_HAVE_PCAP
  sft->sockbuf_pcap = pcap_open_dead(1 /*LINKTYPE_ETHERNET*/, 64);
  if( ! sft->sockbuf_pcap ) {
    fprintf(stderr, "Unable to open libpcap\n");
    return 0;
  }
  if( pcap_compile(sft->sockbuf_pcap, &sft->sock_filter, filter, 1,
                   PCAP_NETMASK_UNKNOWN) ) {
    pcap_perror(sft->sockbuf_pcap, "orm_json");
    pcap_close(sft->sockbuf_pcap);
    return 0;
  }
  return 1;

#else
  (void)filter;
  fprintf(stderr, "Onload was compiled without the libpcap development "
                  "package. You need to install the libpcap-devel or "
                  "libpcap-dev package to use the --filter option of this "
                  "tool.");
  return 0;
#endif
}

static void sockbuf_filter_free(sockbuf_filter_t* sft)
{
#if CI_HAVE_PCAP
  if( sft->sockbuf_pcap ) {
    pcap_freecode(&sft->sock_filter);
    pcap_close(sft->sockbuf_pcap);
  }
#endif
}

static int/*bool*/ sockbuf_filter_matches(const sockbuf_filter_t* sft,
                                          citp_waitable_obj* w)
{
#if !CI_HAVE_PCAP
  (void)w;
  return 1;
#else
  struct pcap_pkthdr hdr;
  int offset;

  if( ! sft->sockbuf_pcap )
    return 1;
  if( ! (w->waitable.state & (CI_TCP_STATE_TCP | CI_TCP_STATE_UDP)) )
    return 1;
  offset = w->sock.pkt.ether_offset;
  if( w->waitable.state == CI_TCP_LISTEN )
    offset = 4;    /* hack because listen sockets don't set this */
  hdr.caplen = offsetof(ci_ip_cached_hdrs, ipx)
               - offsetof(ci_ip_cached_hdrs, ether_header)
               - offset
               + (w->sock.pkt.ether_type == ETHERTYPE_IPV6 ?
                   sizeof(w->sock.pkt.ipx) : sizeof(ci_ip4_hdr))
               + (w->waitable.state == CI_TCP_STATE_UDP ?
                   sizeof(ci_udp_hdr) : sizeof(ci_tcp_hdr));
  hdr.len = 1024;     /* totally arbitrary value */
  /* Cast to non-const below is for pre-1.4 versions of libpcap, which didn't
   * have the prototype marked as such */
  return pcap_offline_filter((struct bpf_program*)&sft->sock_filter, &hdr,
                             w->sock.pkt.ether_header + offset);
#endif
}

#endif /* CI_SOCKBUF_FILTER_H */
