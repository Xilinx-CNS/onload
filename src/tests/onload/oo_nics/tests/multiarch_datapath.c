/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include "../oo_nics_test.h"
#include "../../../tap/tap.h"
#include "../oo_nics.h"
#include <string.h>

static struct oo_cplane_handle mock_cplane;

/* Standard multiarch setup: hwport 0 = FF, hwport 1 = LLCT,
 * sharing the same net_device (identifying them as a multiarch pair). */
static struct net_device shared_netdev = { .ifindex = 1 };

static void setup_multiarch_pair(tcp_helper_resource_t* trs)
{
  memset(trs, 0, sizeof(*trs));
  trs->netif.cplane = &mock_cplane;
  test_set_cplane_hwports(cp_hwport_make_mask(0) | cp_hwport_make_mask(1));
  test_add_hwport(0, 0, &shared_netdev);  /* FF */
  test_add_hwport(1, 1, &shared_netdev);  /* LLCT */
}


static void test_tx_enterprise(void)
{
  tcp_helper_resource_t trs;
  int rc;

  setup_multiarch_pair(&trs);
  NI_OPTS(&trs.netif).multiarch_tx_datapath = EF_MULTIARCH_DATAPATH_FF;
  NI_OPTS(&trs.netif).multiarch_rx_datapath = EF_MULTIARCH_DATAPATH_BOTH;

  rc = oo_get_nics(&trs, -1);
  ok(rc == 0, "tx enterprise: success");
  ok(trs.netif.tx_hwport_mask == cp_hwport_make_mask(0),
     "tx enterprise: tx_mask has FF hwport only");
  ok(trs.netif.rx_hwport_mask ==
     (cp_hwport_make_mask(0) | cp_hwport_make_mask(1)),
     "tx enterprise: rx_mask has both");
  ok(trs.netif.multiarch_hwport_mask ==
     (cp_hwport_make_mask(0) | cp_hwport_make_mask(1)),
     "tx enterprise: multiarch_mask includes both datapaths");

  test_cleanup();
}

static void test_tx_express(void)
{
  tcp_helper_resource_t trs;
  int rc;

  setup_multiarch_pair(&trs);
  NI_OPTS(&trs.netif).multiarch_tx_datapath = EF_MULTIARCH_DATAPATH_LLCT;
  NI_OPTS(&trs.netif).multiarch_rx_datapath = EF_MULTIARCH_DATAPATH_BOTH;

  rc = oo_get_nics(&trs, -1);
  ok(rc == 0, "tx express: success");
  ok(trs.netif.tx_hwport_mask == cp_hwport_make_mask(1),
     "tx express: tx_mask has LLCT hwport only");

  test_cleanup();
}

static void test_rx_enterprise(void)
{
  tcp_helper_resource_t trs;
  int rc;

  setup_multiarch_pair(&trs);
  NI_OPTS(&trs.netif).multiarch_tx_datapath = EF_MULTIARCH_DATAPATH_LLCT;
  NI_OPTS(&trs.netif).multiarch_rx_datapath = EF_MULTIARCH_DATAPATH_FF;

  rc = oo_get_nics(&trs, -1);
  ok(rc == 0, "rx enterprise: success");
  ok(trs.netif.rx_hwport_mask == cp_hwport_make_mask(0),
     "rx enterprise: rx_mask has FF hwport only");

  test_cleanup();
}

static void test_rx_express(void)
{
  tcp_helper_resource_t trs;
  int rc;

  setup_multiarch_pair(&trs);
  NI_OPTS(&trs.netif).multiarch_tx_datapath = EF_MULTIARCH_DATAPATH_LLCT;
  NI_OPTS(&trs.netif).multiarch_rx_datapath = EF_MULTIARCH_DATAPATH_LLCT;

  rc = oo_get_nics(&trs, -1);
  ok(rc == 0, "rx express: success");
  ok(trs.netif.rx_hwport_mask == cp_hwport_make_mask(1),
     "rx express: rx_mask has LLCT hwport only");

  test_cleanup();
}

static void test_rx_both(void)
{
  tcp_helper_resource_t trs;
  int rc;

  setup_multiarch_pair(&trs);
  NI_OPTS(&trs.netif).multiarch_tx_datapath = EF_MULTIARCH_DATAPATH_LLCT;
  NI_OPTS(&trs.netif).multiarch_rx_datapath = EF_MULTIARCH_DATAPATH_BOTH;

  rc = oo_get_nics(&trs, -1);
  ok(rc == 0, "rx both: success");
  ok(trs.netif.rx_hwport_mask ==
     (cp_hwport_make_mask(0) | cp_hwport_make_mask(1)),
     "rx both: rx_mask has both hwports");

  test_cleanup();
}

int test_multiarch_datapath(void)
{
  plan(12);

  test_tx_enterprise();
  test_tx_express();
  test_rx_enterprise();
  test_rx_express();
  test_rx_both();

  return exit_status();
}
