/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include "../onload_kernel_compat.h"
#include "../stack.h"
#include "../../tap/tap.h"
#include "../oof_test.h"
#include "../cplane.h"
#include "../utils.h"
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>
#include <arpa/inet.h>


static void check_all_filters(tcp_helper_resource_t* thr)
{
  int rc;
  rc = ooft_stack_check_sw_filters(thr);
  cmp_ok(rc, "==", 0, "check sw filters");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "check hw filters");
}


/* Build a heterogeneous namespace: two X4 interfaces (each an FF port
 * shadowed by a CT/LL sibling) plus two X2 interfaces (FF only, no LL
 * sibling).  This models a 5/8-port X4 where some ports have express
 * (LL) capability and others are enterprise-only.
 *
 * With X4 registered first, the hwports are:
 *   0,1 = EF10_FF, hidden_by_ll (shadowed by CT siblings)
 *   2,3 = EF10CT  (LL, express datapath for the X4 interfaces)
 *   4,5 = EF10_FF (enterprise-only, no LL sibling)
 *
 * Registering X2 first reverses those groups: enterprise FF ports are 0,1,
 * shadow FF ports are 2,3, and CT ports are 4,5.  In both layouts, a
 * unicast socket must select CT plus enterprise FF in BOTH mode, all FF in
 * FF mode, and CT only in LL mode.  The test runs the full mode matrix for
 * both registration orders.
 *
 * This is the behaviour that uniform-NIC tests never exercise: the
 * per-port selection in ooft_endpoint_want_unicast_hwport /
 * tcp_helper_hwport_to_stack_id must vary across a single namespace.
 */
static void build_mixed_cplane(int x4_first)
{
  unsigned char mac0[6] = { 0,1,0,0,0,0 };
  unsigned char mac1[6] = { 0,1,0,0,0,1 };
  unsigned char mac2[6] = { 0,1,0,0,0,2 };
  unsigned char mac3[6] = { 0,1,0,0,0,3 };

  if( x4_first ) {
    TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X4_FF));
    TRY(ooft_cplane_add_nic(current_ns(), OOFT_NIC_X2_FF,
                            mac2, inet_addr("1.0.0.2"),
                            mac3, inet_addr("1.0.0.3")));
  }
  else {
    TRY(ooft_cplane_add_nic(current_ns(), OOFT_NIC_X2_FF,
                            mac0, inet_addr("1.0.0.0"),
                            mac1, inet_addr("1.0.0.1")));
    TRY(ooft_cplane_add_nic(current_ns(), OOFT_NIC_X4_FF,
                            mac2, inet_addr("1.0.0.2"),
                            mac3, inet_addr("1.0.0.3")));
  }
}


static void run_mode(enum ooft_rx_mode mode, const char* layout_name,
                     const char* mode_name, int x4_first,
                     const char* express_addr, const char* enterprise_addr)
{
  tcp_helper_resource_t* thr;
  struct ooft_endpoint* semi;
  struct ooft_endpoint* full;
  ci_dllist hw_semi;
  ci_dllist hw_full;
  struct oof_manager* fm;
  int rc;

  diag("=== layout %s, mode %s ===", layout_name, mode_name);

  test_alloc(32);
  thr = ooft_alloc_stack_mode(8, mode);
  fm = thr->ofn->ofn_filter_manager;
  build_mixed_cplane(x4_first);

  ci_dllist_init(&hw_semi);
  ci_dllist_init(&hw_full);

  /* Semi-wild socket on an X4-interface address.  The expectation helper
   * computes the documented mode-appropriate port set. */
  semi = ooft_alloc_endpoint(thr, IPPROTO_UDP, inet_addr(express_addr),
                             htons(2000), INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(semi, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(semi, 0);
  cmp_ok(rc, "==", 0, "add semi-wild on express-capable interface");
  check_all_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_semi);

  /* Full-match socket on an enterprise-only address.  All ports here
   * support 5-tuple, so this installs real 5-tuple HW filters on the
   * same per-port subset. */
  full = ooft_alloc_endpoint(thr, IPPROTO_UDP, inet_addr(enterprise_addr),
                             htons(3000), inet_addr("2.0.0.0"), htons(4000));
  ooft_endpoint_expect_unicast_filters(full, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(full, 0);
  cmp_ok(rc, "==", 0, "add full-match on enterprise-only interface");
  check_all_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_full);

  /* Tear down. */
  ooft_endpoint_expect_sw_remove_all(full);
  ooft_hw_filter_expect_remove_list(&hw_full);
  oof_socket_del(fm, &full->skf);
  check_all_filters(thr);

  ooft_endpoint_expect_sw_remove_all(semi);
  ooft_hw_filter_expect_remove_list(&hw_semi);
  oof_socket_del(fm, &semi->skf);
  check_all_filters(thr);

  ooft_free_stack(thr);
  test_cleanup();
}


int test_mixed_unicast(void)
{
  new_test();
  plan(NO_PLAN);

  run_mode(OOFT_RX_BOTH, "X4 first", "OOFT_RX_BOTH", 1,
           "1.0.0.0", "1.0.0.2");
  run_mode(OOFT_RX_FF, "X4 first", "OOFT_RX_FF", 1,
           "1.0.0.0", "1.0.0.2");
  run_mode(OOFT_RX_LL, "X4 first", "OOFT_RX_LL", 1,
           "1.0.0.0", "1.0.0.2");

  run_mode(OOFT_RX_BOTH, "X2 first", "OOFT_RX_BOTH", 0,
           "1.0.0.2", "1.0.0.0");
  run_mode(OOFT_RX_FF, "X2 first", "OOFT_RX_FF", 0,
           "1.0.0.2", "1.0.0.0");
  run_mode(OOFT_RX_LL, "X2 first", "OOFT_RX_LL", 0,
           "1.0.0.2", "1.0.0.0");

  done_testing();
}
