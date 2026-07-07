/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include "../onload_kernel_compat.h"
#include "../stack.h"
#include "../../tap/tap.h"
#include "../oof_test.h"
#include "../cplane.h"
#include "../utils.h"
#include "../efrm_interface.h"
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>
#include <arpa/inet.h>


static void check_all_filters(tcp_helper_resource_t* thr1,
                              tcp_helper_resource_t* thr2)
{
  int rc;
  rc = ooft_stack_check_sw_filters(thr1);
  cmp_ok(rc, "==", 0, "check sw filters stack 1");
  rc = ooft_stack_check_sw_filters(thr2);
  cmp_ok(rc, "==", 0, "check sw filters stack 2");
  rc = ooft_ns_check_hw_filters(thr1->ns);
  cmp_ok(rc, "==", 0, "check hw filters");
}


/* Cross-stack wild HW-filter redirect (fixup_wild) in a heterogeneous
 * namespace.  This is the mixed-config analogue of filter_redirect
 * scenario A: unshare, redirect, then re-share on restore.
 *
 * The namespace mixes two X4 interfaces (express: FF ports shadowed by
 * CT/LL siblings, addrs 1.0.0.0 and 1.0.0.1) with two X2 interfaces
 * (enterprise: FF only, addrs 1.0.0.2 and 1.0.0.3).  A wild socket's
 * semi-wild HW filters therefore span a heterogeneous set of ports (CT
 * ports 2,3 plus FF ports 4,5 in OOFT_RX_BOTH mode).  The redirect and
 * unshare machinery must move that whole mixed set between stacks, which
 * uniform-NIC tests never exercise.
 */
int test_mixed_filter_redirect(void)
{
  tcp_helper_resource_t* thr1;
  tcp_helper_resource_t* thr2;
  struct ooft_endpoint* wild_a;
  struct ooft_endpoint* wild_b;
  struct ooft_endpoint* full_a;
  ci_dllist hw_wild_a;
  ci_dllist hw_redirected;
  struct oof_manager* fm;
  int rc;
  int i;
  static const char* addrs[4] = { "1.0.0.0", "1.0.0.1", "1.0.0.2", "1.0.0.3" };

  new_test();
  plan(NO_PLAN);

  test_alloc(32);
  thr1 = ooft_alloc_stack_mode(8, OOFT_RX_BOTH);
  thr2 = ooft_alloc_stack_mode(4, OOFT_RX_BOTH);
  fm = thr1->ofn->ofn_filter_manager;

  TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X4_FF));
  TRY(ooft_cplane_add_nic(current_ns(), OOFT_NIC_X2_FF,
                          (unsigned char[6]){ 0,1,0,0,0,2 }, inet_addr("1.0.0.2"),
                          (unsigned char[6]){ 0,1,0,0,0,3 }, inet_addr("1.0.0.3")));

  ci_dllist_init(&hw_wild_a);
  ci_dllist_init(&hw_redirected);

  /* Add wild UDP in stack A on port 2000.  Each configured address gets
   * semi-wild HW filters across the complete mixed selected port set: CT
   * ports 2,3 and enterprise FF ports 4,5. */
  wild_a = ooft_alloc_endpoint(thr1, IPPROTO_UDP, INADDR_ANY, htons(2000),
                               INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(wild_a, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(wild_a, 0);
  cmp_ok(rc, "==", 0, "add wild A");
  check_all_filters(thr1, thr2);
  ooft_cplane_claim_added_hw_filters(cp, &hw_wild_a);

  /* Add full-match UDP in stack A on an express address, sharing A's
   * wild filter (no new HW). */
  full_a = ooft_alloc_endpoint(thr1, IPPROTO_UDP, inet_addr("1.0.0.0"),
                               htons(2000), inet_addr("2.0.0.0"), htons(3000));
  ooft_endpoint_expect_unicast_filters(full_a, 0);
  rc = ooft_endpoint_add(full_a, 0);
  cmp_ok(rc, "==", 0, "add full-match A (shares wild)");
  check_all_filters(thr1, thr2);

  /* Add wild UDP in stack B on port 2000.  fixup_wild will:
   * 1. Unshare full_a — give it its own 5-tuple HW filters across the
   *    mixed port set.
   * 2. Redirect A's wild HW filters (the whole heterogeneous set) to B. */
  wild_b = ooft_alloc_endpoint(thr2, IPPROTO_UDP, INADDR_ANY, htons(2000),
                               INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(wild_b, 0);
  ooft_hw_filter_expect_remove_list(&hw_wild_a);
  for( i = 0; i < 4; i++ )
    ooft_endpoint_expect_hw_unicast(wild_b, inet_addr(addrs[i]), 0);
  ooft_endpoint_expect_hw_unicast(full_a, full_a->laddr_be, 0);
  rc = ooft_endpoint_add(wild_b, 0);
  cmp_ok(rc, "==", 0, "add wild B (triggers redirect + unshare)");
  check_all_filters(thr1, thr2);
  ooft_cplane_claim_added_hw_filters(cp, &hw_redirected);

  /* Delete wild B.  fixup_wild will:
   * 1. Redirect the wild HW filters back from B to A.
   * 2. Re-share: full_a releases its own HW filters and shares A's wild. */
  ooft_endpoint_expect_sw_remove_all(wild_b);
  ooft_hw_filter_expect_remove_list(&hw_redirected);
  for( i = 0; i < 4; i++ )
    ooft_endpoint_expect_hw_unicast(wild_a, inet_addr(addrs[i]), 0);
  oof_socket_del(fm, &wild_b->skf);
  check_all_filters(thr1, thr2);
  ooft_cplane_claim_added_hw_filters(cp, &hw_wild_a);

  /* Clean up: delete full-match (shares wild, no HW change), then wild A. */
  ooft_endpoint_expect_sw_remove_all(full_a);
  oof_socket_del(fm, &full_a->skf);
  check_all_filters(thr1, thr2);

  ooft_endpoint_expect_sw_remove_all(wild_a);
  ooft_hw_filter_expect_remove_list(&hw_wild_a);
  oof_socket_del(fm, &wild_a->skf);
  check_all_filters(thr1, thr2);

  ooft_free_stack(thr1);
  ooft_free_stack(thr2);
  test_cleanup();
  done_testing();
}
