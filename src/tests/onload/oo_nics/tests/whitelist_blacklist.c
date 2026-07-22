/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include "../oo_nics_test.h"
#include "../../../tap/tap.h"
#include "../oo_nics.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>


static struct oo_cplane_handle mock_cplane;

static void setup_two_interfaces(tcp_helper_resource_t* trs)
{
  struct net_device* nd;

  memset(trs, 0, sizeof(*trs));
  trs->netif.cplane = &mock_cplane;

  test_set_cplane_hwports(cp_hwport_make_mask(0) | cp_hwport_make_mask(1));

  /* Register two interfaces with name->ifindex->hwport mappings */
  test_add_interface("eth0", 1, cp_hwport_make_mask(0));
  test_add_interface("eth1", 2, cp_hwport_make_mask(1));

  /* Retrieve mock net_device pointers via the same lookup path that
   * oo_dev_get_by_name uses in production, so they share the same object. */
  nd = dev_get_by_name(NULL, "eth0");
  test_add_hwport(0, 0, nd);
  nd = dev_get_by_name(NULL, "eth1");
  test_add_hwport(1, 0, nd);
}


static void test_no_lists(void)
{
  tcp_helper_resource_t trs;
  int rc;

  setup_two_interfaces(&trs);

  rc = oo_get_nics(&trs, -1);
  ok(rc == 0, "no lists: success");
  ok(trs.netif.nic_n == 2, "no lists: both NICs used");
  ok(trs.netif.tx_hwport_mask ==
     (cp_hwport_make_mask(0) | cp_hwport_make_mask(1)),
     "no lists: all hwports in tx_mask");
  ok(trs.netif.rx_hwport_mask ==
     (cp_hwport_make_mask(0) | cp_hwport_make_mask(1)),
     "no lists: all hwports in rx_mask");

  test_cleanup();
}

static void test_whitelist_single(void)
{
  tcp_helper_resource_t trs;
  int rc;

  setup_two_interfaces(&trs);
  snprintf(NI_OPTS(&trs.netif).iface_whitelist,
           sizeof(NI_OPTS(&trs.netif).iface_whitelist), "%s", "eth0");

  rc = oo_get_nics(&trs, -1);
  ok(rc == 0, "whitelist eth0: success");
  ok(trs.netif.nic_n == 1, "whitelist eth0: one NIC used");
  ok(trs.netif.tx_hwport_mask == cp_hwport_make_mask(0),
     "whitelist eth0: only hwport 0 in tx_mask");
  ok(trs.netif.rx_hwport_mask == cp_hwport_make_mask(0),
     "whitelist eth0: only hwport 0 in rx_mask");

  test_cleanup();
}

static void test_blacklist_single(void)
{
  tcp_helper_resource_t trs;
  int rc;

  setup_two_interfaces(&trs);
  snprintf(NI_OPTS(&trs.netif).iface_blacklist,
           sizeof(NI_OPTS(&trs.netif).iface_blacklist), "%s", "eth0");

  rc = oo_get_nics(&trs, -1);
  ok(rc == 0, "blacklist eth0: success");
  ok(trs.netif.nic_n == 1, "blacklist eth0: one NIC used");
  ok(trs.netif.tx_hwport_mask == cp_hwport_make_mask(1),
     "blacklist eth0: only hwport 1 in tx_mask");
  ok(trs.netif.rx_hwport_mask == cp_hwport_make_mask(1),
     "blacklist eth0: only hwport 1 in rx_mask");

  test_cleanup();
}

static void test_whitelist_and_blacklist(void)
{
  tcp_helper_resource_t trs;
  struct net_device* nd;
  int rc;

  memset(&trs, 0, sizeof(trs));
  trs.netif.cplane = &mock_cplane;
  test_set_cplane_hwports(cp_hwport_make_mask(0) |
                          cp_hwport_make_mask(1) |
                          cp_hwport_make_mask(2));
  test_add_interface("eth0", 1, cp_hwport_make_mask(0));
  test_add_interface("eth1", 2, cp_hwport_make_mask(1));
  test_add_interface("eth2", 3, cp_hwport_make_mask(2));
  nd = dev_get_by_name(NULL, "eth0");
  test_add_hwport(0, 0, nd);
  nd = dev_get_by_name(NULL, "eth1");
  test_add_hwport(1, 0, nd);
  nd = dev_get_by_name(NULL, "eth2");
  test_add_hwport(2, 0, nd);

  /* Whitelist eth0 and eth1, blacklist eth1 */
  snprintf(NI_OPTS(&trs.netif).iface_whitelist,
           sizeof(NI_OPTS(&trs.netif).iface_whitelist), "%s", "eth0 eth1");
  snprintf(NI_OPTS(&trs.netif).iface_blacklist,
           sizeof(NI_OPTS(&trs.netif).iface_blacklist), "%s", "eth1");

  rc = oo_get_nics(&trs, -1);
  ok(rc == 0, "whitelist+blacklist: success");
  ok(trs.netif.nic_n == 1, "whitelist+blacklist: one NIC (eth0 only)");
  ok(trs.netif.tx_hwport_mask == cp_hwport_make_mask(0),
     "whitelist+blacklist: only hwport 0 in tx_mask");
  ok(trs.netif.rx_hwport_mask == cp_hwport_make_mask(0),
     "whitelist+blacklist: only hwport 0 in rx_mask");

  test_cleanup();
}

static void test_unknown_interface_in_whitelist(void)
{
  tcp_helper_resource_t trs;
  int rc;

  setup_two_interfaces(&trs);
  snprintf(NI_OPTS(&trs.netif).iface_whitelist,
           sizeof(NI_OPTS(&trs.netif).iface_whitelist), "%s", "nonexistent");

  rc = oo_get_nics(&trs, -1);
  ok(rc == -ENODEV, "unknown whitelist: returns -ENODEV (no matching NICs)");
  ok(trs.netif.nic_n == 0, "unknown whitelist: zero NICs discovered");

  test_cleanup();
}

static void test_blacklist_all(void)
{
  tcp_helper_resource_t trs;
  int rc;

  setup_two_interfaces(&trs);
  snprintf(NI_OPTS(&trs.netif).iface_blacklist,
           sizeof(NI_OPTS(&trs.netif).iface_blacklist), "%s", "eth0 eth1");

  rc = oo_get_nics(&trs, -1);
  ok(rc == -ENODEV, "blacklist all: returns -ENODEV");
  ok(trs.netif.nic_n == 0, "blacklist all: zero NICs discovered");

  test_cleanup();
}

static void test_whitelist_interface_not_in_cplane(void)
{
  tcp_helper_resource_t trs;
  int rc;

  setup_two_interfaces(&trs);
  /* eth2 is known to the OS but has no Solarflare hwports in the cplane */
  test_add_interface("eth2", 3, 0);
  snprintf(NI_OPTS(&trs.netif).iface_whitelist,
           sizeof(NI_OPTS(&trs.netif).iface_whitelist), "%s", "eth2");

  rc = oo_get_nics(&trs, -1);
  ok(rc == -ENODEV,
     "whitelist non-SF interface: returns -ENODEV");
  ok(trs.netif.nic_n == 0,
     "whitelist non-SF interface: zero NICs discovered");

  test_cleanup();
}

int test_whitelist_blacklist(void)
{
  plan(22);

  test_no_lists();
  test_whitelist_single();
  test_blacklist_single();
  test_whitelist_and_blacklist();
  test_unknown_interface_in_whitelist();
  test_blacklist_all();
  test_whitelist_interface_not_in_cplane();

  return exit_status();
}
