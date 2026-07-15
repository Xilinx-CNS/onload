/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include "../oo_nics_test.h"
#include "../../../tap/tap.h"
#include "../oo_nics.h"
#include <string.h>
#include <errno.h>


static struct oo_cplane_handle mock_cplane;

static void test_single_nic(void)
{
  tcp_helper_resource_t trs;
  struct net_device netdev = { .ifindex = 1 };
  int rc;

  memset(&trs, 0, sizeof(trs));
  trs.netif.cplane = &mock_cplane;
  test_set_cplane_hwports(cp_hwport_make_mask(0));
  test_add_hwport(0, 0, &netdev);

  rc = oo_get_nics(&trs, -1);
  ok(rc == 0, "single NIC returns success");
  ok(trs.netif.nic_n == 1, "one NIC discovered");
  ok(trs.netif.tx_hwport_mask == cp_hwport_make_mask(0),
     "tx_hwport_mask includes hwport 0");
  ok(trs.netif.rx_hwport_mask == cp_hwport_make_mask(0),
     "rx_hwport_mask includes hwport 0");
  ok(trs.netif.multiarch_hwport_mask == 0,
     "no multiarch hwports");
  ok(trs.netif.hwport_to_intf_i[0] == 0,
     "hwport 0 maps to intf_i 0");
  ok(trs.netif.intf_i_to_hwport[0] == 0,
     "intf_i 0 maps to hwport 0");

  test_cleanup();
}

static void test_multiple_nics(void)
{
  tcp_helper_resource_t trs;
  struct net_device netdev0 = { .ifindex = 1 };
  struct net_device netdev1 = { .ifindex = 2 };
  int rc;

  memset(&trs, 0, sizeof(trs));
  trs.netif.cplane = &mock_cplane;
  test_set_cplane_hwports(cp_hwport_make_mask(0) | cp_hwport_make_mask(1));
  test_add_hwport(0, 0, &netdev0);
  test_add_hwport(1, 0, &netdev1);

  rc = oo_get_nics(&trs, -1);
  ok(rc == 0, "two NICs returns success");
  ok(trs.netif.nic_n == 2, "two NICs discovered");
  ok(trs.netif.tx_hwport_mask ==
     (cp_hwport_make_mask(0) | cp_hwport_make_mask(1)),
     "tx_hwport_mask includes both hwports");

  test_cleanup();
}

static void test_no_nics(void)
{
  tcp_helper_resource_t trs;
  int rc;

  memset(&trs, 0, sizeof(trs));
  trs.netif.cplane = &mock_cplane;
  test_set_cplane_hwports(0);

  rc = oo_get_nics(&trs, -1);
  ok(rc == -ENODEV, "no NICs returns -ENODEV");
  ok(trs.netif.nic_n == 0, "zero NICs discovered");

  test_cleanup();
}

static void test_null_efrm_client_skipped(void)
{
  tcp_helper_resource_t trs;
  struct net_device netdev1 = { .ifindex = 2 };
  int rc;

  memset(&trs, 0, sizeof(trs));
  trs.netif.cplane = &mock_cplane;
  /* hwport 0 is in cplane mask but has no efrm_client (not registered) */
  test_set_cplane_hwports(cp_hwport_make_mask(0) | cp_hwport_make_mask(1));
  /* Only register hwport 1 */
  test_add_hwport(1, 0, &netdev1);

  rc = oo_get_nics(&trs, -1);
  ok(rc == 0, "returns success with one usable NIC");
  ok(trs.netif.nic_n == 1, "only one NIC discovered");
  ok(trs.netif.hwport_to_intf_i[1] == 0,
     "hwport 1 maps to intf_i 0");

  test_cleanup();
}

static void test_unplugged_vf_skipped(void)
{
  tcp_helper_resource_t trs;
  struct net_device netdev0 = { .ifindex = 1 };
  struct net_device netdev1 = { .ifindex = 2 };
  struct efhw_nic* nic;
  int rc;

  memset(&trs, 0, sizeof(trs));
  trs.netif.cplane = &mock_cplane;
  test_set_cplane_hwports(cp_hwport_make_mask(0) | cp_hwport_make_mask(1));
  test_add_hwport(0, 0, &netdev0);
  test_add_hwport(1, 0, &netdev1);

  /* Mark hwport 0 as unplugged VF */
  oo_nics[0].oo_nic_flags |= OO_NIC_UNPLUGGED;
  nic = efrm_client_get_nic(oo_nics[0].efrm_client);
  nic->devtype.function = EFHW_FUNCTION_VF;

  rc = oo_get_nics(&trs, -1);
  ok(rc == 0, "returns success");
  ok(trs.netif.nic_n == 1, "unplugged VF is skipped");
  ok(trs.netif.hwport_to_intf_i[1] == 0,
     "only hwport 1 is used");

  test_cleanup();
}

static void test_no_hw_mode(void)
{
  tcp_helper_resource_t trs;
  int rc;

  memset(&trs, 0, sizeof(trs));
  trs.netif.cplane = &mock_cplane;
  test_set_cplane_hwports(cp_hwport_make_mask(0));
  NI_OPTS(&trs.netif).no_hw = 1;

  rc = oo_get_nics(&trs, -1);
  ok(rc == 0, "no_hw mode returns success");
  ok(trs.netif.nic_n == 0, "no NICs in no_hw mode");

  test_cleanup();
}

static void test_ifindices_too_many(void)
{
  tcp_helper_resource_t trs;
  int rc;

  memset(&trs, 0, sizeof(trs));
  trs.netif.cplane = &mock_cplane;

  rc = oo_get_nics(&trs, CI_CFG_MAX_INTERFACES + 1);
  ok(rc == -E2BIG, "too many ifindices: returns -E2BIG");
  ok(trs.netif.nic_n == 0, "too many ifindices: zero NICs");

  test_cleanup();
}

static void test_ifindices_positive(void)
{
  tcp_helper_resource_t trs;
  int rc;

  memset(&trs, 0, sizeof(trs));
  trs.netif.cplane = &mock_cplane;

  rc = oo_get_nics(&trs, 1);
  ok(rc == -EINVAL, "positive ifindices_len: returns -EINVAL");
  ok(trs.netif.nic_n == 0, "positive ifindices_len: zero NICs");

  test_cleanup();
}

static void test_packed_stream_skipped(void)
{
  tcp_helper_resource_t trs;
  struct net_device netdev0 = { .ifindex = 1 };
  struct net_device netdev1 = { .ifindex = 2 };
  struct efhw_nic* nic;
  int rc;

  memset(&trs, 0, sizeof(trs));
  trs.netif.cplane = &mock_cplane;
  test_set_cplane_hwports(cp_hwport_make_mask(0) | cp_hwport_make_mask(1));
  test_add_hwport(0, 0, &netdev0);
  test_add_hwport(1, 0, &netdev1);

  nic = efrm_client_get_nic(oo_nics[0].efrm_client);
  nic->flags |= NIC_FLAG_PACKED_STREAM;

  rc = oo_get_nics(&trs, -1);
  ok(rc == 0, "packed stream: returns success");
  ok(trs.netif.nic_n == 1, "packed stream: NIC is skipped");
  ok(trs.netif.hwport_to_intf_i[1] == 0,
     "packed stream: only hwport 1 is used");

  test_cleanup();
}

static void test_unplugged_pf_not_skipped(void)
{
  tcp_helper_resource_t trs;
  struct net_device netdev = { .ifindex = 1 };
  int rc;

  memset(&trs, 0, sizeof(trs));
  trs.netif.cplane = &mock_cplane;
  test_set_cplane_hwports(cp_hwport_make_mask(0));
  test_add_hwport(0, 0, &netdev);

  oo_nics[0].oo_nic_flags |= OO_NIC_UNPLUGGED;

  rc = oo_get_nics(&trs, -1);
  ok(rc == 0, "unplugged PF: returns success");
  ok(trs.netif.nic_n == 1, "unplugged PF: NIC is not skipped");

  test_cleanup();
}

int test_basic(void)
{
  plan(29);

  test_single_nic();
  test_multiple_nics();
  test_no_nics();
  test_null_efrm_client_skipped();
  test_unplugged_vf_skipped();
  test_no_hw_mode();
  test_ifindices_too_many();
  test_ifindices_positive();
  test_packed_stream_skipped();
  test_unplugged_pf_not_skipped();

  return exit_status();
}
