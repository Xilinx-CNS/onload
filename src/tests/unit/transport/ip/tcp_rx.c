/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2022 AMD, Inc. */

/* Functions under test */
#include <ci/internal/ip.h>

/* Test infrastructure */
#include "unit_test.h"

/* Expectations */
static ci_netif* expect_ni;
static ci_ip_pkt_fmt* expect_pkt;
static ci_tcp_hdr* expect_tcp;

/* Dependencies */
/* TODO These should allow control of return value and side effects to exercise
 *      various control paths in the caller
 */
void ci_assert_valid_pkt(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                         ci_boolean_t ni_locked,
                         const char* file, int line)
{
  CHECK(ni, ==, expect_ni);
  CHECK(pkt, ==, expect_pkt);
  CHECK_TRUE(ni_locked);
}

static int filter_count;

int
ci_netif_filter_for_each_match(ci_netif* ni,
                               unsigned laddr, unsigned lport,
                               unsigned raddr, unsigned rport,
                               unsigned protocol, int intf_i, int vlan,
                               int (*callback)(ci_sock_cmn*, void*),
                               void* callback_arg, ci_uint32* hash_out)
{
  CHECK(ni, ==, expect_ni);
  CHECK(protocol, ==, RX_PKT_PROTOCOL(expect_pkt));
  CHECK(intf_i, ==, expect_pkt->intf_i);
  CHECK(vlan, ==, expect_pkt->vlan);

  switch( filter_count++ ) {
  case 0:
    /* First attempt: established connections with src->dest addr/port */
    CHECK(laddr, ==, oo_ip_hdr(expect_pkt)->ip_daddr_be32);
    CHECK(lport, ==, expect_tcp->tcp_dest_be16);
    CHECK(raddr, ==, oo_ip_hdr(expect_pkt)->ip_saddr_be32);
    CHECK(rport, ==, expect_tcp->tcp_source_be16);
    break;

  case 1:
    /* Second attempt: listeners with dest addr/port */
    CHECK(laddr, ==, oo_ip_hdr(expect_pkt)->ip_daddr_be32);
    CHECK(lport, ==, expect_tcp->tcp_dest_be16);
    CHECK(raddr, ==, 0);
    CHECK(rport, ==, 0);
    break;

  case 2:
    /* Third attempt: listeners with port only */
    CHECK(laddr, ==, 0);
    CHECK(lport, ==, expect_tcp->tcp_dest_be16);
    CHECK(raddr, ==, 0);
    CHECK(rport, ==, 0);
    break;
  }

  return 0;
}

int ci_netif_pkt_pass_to_kernel(ci_netif* ni, ci_ip_pkt_fmt* pkt)
{
  CHECK(ni, ==, expect_ni);
  CHECK(pkt, ==, expect_pkt);

  return 1;
}

/* TODO parametrise, or have multiple variants, to test multiple control paths.
 * This just tests a simple path: a TCP/IPv4 packet with no matching filter is
 * passed to the kernel. */
static void test_ci_tcp_handle_rx(void)
{
  STATE_ALLOC(ci_netif, netif);
  STATE_ALLOC(ci_netif_state, ns);
  STATE_ALLOC(struct ci_netif_poll_state, ps);
  STATE_ALLOC(ci_ip_pkt_fmt, pkt);
  STATE_ALLOC(ci_tcp_hdr, tcp);

  expect_ni = netif;
  expect_pkt = pkt;
  expect_tcp = tcp;
  filter_count = 0;

  /* pre: netif must have a valid state */
  netif->state = ns;
  STATE_STASH(netif);

  /* pre: pkt identifies as TCP, and passes basic sanity tests */
  pkt->frag_next = OO_PP_ID_NULL;
  pkt->pkt_eth_payload_off = 14;
  pkt->pay_len = 100;
  RX_PKT_PROTOCOL(pkt) = IPPROTO_TCP;
  oo_ip_hdr(pkt)->ip_daddr_be32 = 0x01234567;
  oo_ip_hdr(pkt)->ip_saddr_be32 = 0x89abcdef;
  STATE_STASH(pkt);

  tcp->tcp_dest_be16 = 0x1234;
  tcp->tcp_source_be16 = 0x5678;
  STATE_STASH(tcp);

  /* call function under test */
  ci_tcp_handle_rx(netif, ps, pkt, tcp, 42);

  /* post: statistics are updated */
  STATE_CHECK(ns, stats_snapshot.tcp.tcp_in_segs, 1);
  STATE_CHECK(ns, stats.no_match_pass_to_kernel_tcp, 1);

  /* post: payload length is recorded */
  STATE_CHECK(pkt, pf.tcp_rx.pay_len, 42);

  /* post: filter matches were attempted thrice */
  CHECK(filter_count, ==, 3);

  STATE_FREE(netif);
  STATE_FREE(ns);
  STATE_FREE(ps);
  STATE_FREE(pkt);
  STATE_FREE(tcp);
}

int main(void)
{
  TEST_RUN(test_ci_tcp_handle_rx);
  TEST_END();
}

