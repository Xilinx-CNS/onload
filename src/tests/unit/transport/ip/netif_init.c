/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Xilinx, Inc. */

/* Functions under test */
#include <ci/internal/ip.h>

/* Test infrastructure */
#include "unit_test.h"

/* Dependencies */
#include <onload/ul/per_thread.h>
__thread struct oo_per_thread oo_per_thread;

#include <ci/internal/efabcfg.h>
ci_cfg_opts_t ci_cfg_opts;

const char* onload_version;
const char onload_short_version[] = "SHORT_TEST";
const char onload_copyright[] = "COPYRIGHT";
const char onload_product[] = "PRODUCT";

int (*ci_sys_open)(const char*, int, ...);
int (*ci_sys_close)(int);
ssize_t (*ci_sys_read)(int, void*, size_t);

/* Parametrised test case */
static void test_ci_netif_set_rxq_limit_(
    int rxq_limit, int rxq_min, int max_rx_packets, int nic_n, int vi_cap,
    int expect_rc, int expect_rxq_limit)
{
  int i, rc;
  STATE_ALLOC(ci_netif, ni);
  STATE_ALLOC(ci_netif_state, ns);

  ni->state = ns;
  NI_OPTS(ni).rxq_limit = rxq_limit;
  NI_OPTS(ni).rxq_min = rxq_min;
  NI_OPTS(ni).max_rx_packets = max_rx_packets;
  ni->nic_n = nic_n;
  for( i = 0; i < nic_n; ++i )
    ni->nic_hw[i].vis[0].vi_rxq.mask = vi_cap;
  STATE_STASH(ni);

  *(ci_int32*)&ns->nic_n = nic_n;
  STATE_STASH(ns);

  rc = ci_netif_set_rxq_limit(ni);

  CHECK(rc, ==, expect_rc);
  STATE_CHECK(ns, opts.rxq_limit, expect_rxq_limit);
  STATE_CHECK(ns, rxq_limit, expect_rxq_limit);

  STATE_FREE(ni);
  STATE_FREE(ns);
}

static void test_ci_netif_set_rxq_limit(void)
{
#define TEST test_ci_netif_set_rxq_limit_
  /* User option is used if no further constraints */
  TEST(1000, 100, 2000, 1, 2047, 0, 1000);

  /* Constrained to the amount needed to fill a vi rx ring */
  TEST(1000, 100, 2000, 1, 511, 0, 511);
  TEST(1000, 100, 2000, 2, 255, 0, 255);

  /* Constrained to 80% of max_rx_packets across all vi rx rings */
  TEST(1000, 100, 1000, 1, 2047, 0, 800);
  TEST(1000, 100, 1000, 2, 2047, 0, 400);

  /* No nics gives an almost-but-not-quite-zero limit */
  TEST(1000, 100, 2000, 0, 2047, 0, 16);
  TEST(1000, 100, 2000, 0, 511, 0, 16);
  TEST(1000, 100, 1000, 0, 2047, 0, 16);
  TEST(1000, 2000, 1000, 0, 2047, 0, 16);

  /* rxq_limit < rxq_min gives an error and a different small limit */
  TEST(1000, 2000, 2000, 1, 2047, -ENOMEM, 33);
  TEST(1000, 2000, 2000, 2, 255, -ENOMEM, 33);
  TEST(1000, 2000, 1000, 2, 2047, -ENOMEM, 33);
}

int main(void)
{
  TEST_RUN(test_ci_netif_set_rxq_limit);
  TEST_END();
}

