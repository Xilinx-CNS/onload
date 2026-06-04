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


static void check_filters(tcp_helper_resource_t* thr)
{
  int rc;
  rc = ooft_stack_check_sw_filters(thr);
  cmp_ok(rc, "==", 0, "check sw filters");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "check hw filters");
}


/* BR-4.03: Two wild UDP sockets in the same stack on the same port.
 * Only the most recently added (at list head) gets a SW filter.
 * Any other is "hidden".
 *
 * BR-4.04: A semi-wild socket in the same stack prevents a wild socket
 * from getting a SW filter for the semi-wild's address.
 *
 * BR-4.09: Adding a semi-wild socket to a stack that already has a wild
 * socket removes the wild's SW filter for that address (the semi-wild
 * hides the wild).
 */
int test_hidden_socket(void)
{
  tcp_helper_resource_t* thr;
  struct ooft_endpoint* sockA;
  struct ooft_endpoint* sockB;
  struct ooft_endpoint* sockC;
  ci_dllist hw_A;
  ci_dllist hw_B;
  int rc;
  struct oof_manager* fm;

  new_test();
  plan(45);

  test_alloc(32);
  thr = ooft_alloc_stack(16);
  fm = thr->ofn->ofn_filter_manager;
  TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X2_FF));

  ci_dllist_init(&hw_A);
  ci_dllist_init(&hw_B);

  /* --- Scenario A (BR-4.03): Two wild sockets, same stack, same port --- */
  diag("Scenario A: two wild sockets in same stack");

  sockA = ooft_alloc_endpoint(thr, IPPROTO_UDP, INADDR_ANY, htons(2000), 0, 0);
  sockB = ooft_alloc_endpoint(thr, IPPROTO_UDP, INADDR_ANY, htons(2000), 0, 0);

  /* Add first wild — expect SW filters for both local addrs + HW filters */
  ooft_endpoint_expect_unicast_filters(sockA, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(sockA, 0);
  cmp_ok(rc, "==", 0, "add wild A");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_A);

  /* Add second wild in same stack — sockB is pushed to the list head.
   * oof_socket_add_wild finds sockA via oof_wild_socket_matching_stack
   * and removes its SW filters; sockB installs its own (BR-4.03).
   * No new HW filter (LPA already has one from sockA). */
  ooft_endpoint_expect_sw_remove_all(sockA);
  ooft_endpoint_expect_unicast_filters(sockB, 0);
  rc = ooft_endpoint_add(sockB, 0);
  cmp_ok(rc, "==", 0, "add wild B (same stack)");
  check_filters(thr);

  /* Delete B (head of list) — sockA becomes first-in-stack again,
   * gets its SW filters back. */
  ooft_endpoint_expect_sw_remove_all(sockB);
  ooft_endpoint_expect_unicast_filters(sockA, 0);
  oof_socket_del(fm, &sockB->skf);
  check_filters(thr);

  /* Delete A — all filters removed */
  ooft_endpoint_expect_sw_remove_all(sockA);
  ooft_hw_filter_expect_remove_list(&hw_A);
  oof_socket_del(fm, &sockA->skf);
  check_filters(thr);

  /* --- Scenario B (BR-4.04): Semi-wild hides wild for same addr --- */
  diag("Scenario B: semi-wild hides wild for same address");

  sockA = ooft_alloc_endpoint(thr, IPPROTO_UDP, inet_addr("1.0.0.0"),
                              htons(3000), 0, 0);
  sockB = ooft_alloc_endpoint(thr, IPPROTO_UDP, INADDR_ANY, htons(3000), 0, 0);

  /* Add semi-wild on addr 1.0.0.0 */
  ooft_endpoint_expect_unicast_filters(sockA, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(sockA, 0);
  cmp_ok(rc, "==", 0, "add semi-wild A");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_A);

  /* Add wild in same stack — for addr 1.0.0.0, the semi-wild already
   * covers this stack, so wild does NOT get SW filter for 1.0.0.0.
   * Wild does get SW filter for 1.0.0.1 (no semi-wild covers it).
   * HW filter for 1.0.0.1 is also installed. */
  ooft_endpoint_expect_sw_add(sockB, IPPROTO_UDP,
                              inet_addr("1.0.0.1"), htons(3000), 0, 0);
  ooft_endpoint_expect_hw_unicast(sockB, inet_addr("1.0.0.1"), 0);
  rc = ooft_endpoint_add(sockB, 0);
  cmp_ok(rc, "==", 0, "add wild B (same stack)");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_B);

  /* Delete wild — its SW filter for 1.0.0.1 removed, HW filter for
   * 1.0.0.1 removed. Semi-wild's coverage is unchanged. */
  ooft_endpoint_expect_sw_remove_all(sockB);
  ooft_hw_filter_expect_remove_list(&hw_B);
  oof_socket_del(fm, &sockB->skf);
  check_filters(thr);

  /* Delete semi-wild */
  ooft_endpoint_expect_sw_remove_all(sockA);
  ooft_hw_filter_expect_remove_list(&hw_A);
  oof_socket_del(fm, &sockA->skf);
  check_filters(thr);

  /* --- Scenario C (BR-4.09): Semi-wild hides wild's SW filter --- */
  diag("Scenario C: semi-wild added over wild hides wild SW filter");

  sockA = ooft_alloc_endpoint(thr, IPPROTO_UDP, INADDR_ANY, htons(4000), 0, 0);
  sockB = ooft_alloc_endpoint(thr, IPPROTO_UDP, inet_addr("1.0.0.0"),
                              htons(4000), 0, 0);

  /* Add wild — SW + HW for both addrs */
  ooft_endpoint_expect_unicast_filters(sockA, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(sockA, 0);
  cmp_ok(rc, "==", 0, "add wild A");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_A);

  /* Add semi-wild on 1.0.0.0 in same stack.  oof_socket_add_wild finds
   * the wild via oof_wild_socket_matching_stack and removes its SW filter
   * for 1.0.0.0.  The semi-wild installs its own SW filter for 1.0.0.0.
   * No HW change (filter already exists, same stack). */
  ooft_endpoint_expect_sw_remove_addr(sockA, inet_addr("1.0.0.0"));
  ooft_endpoint_expect_unicast_filters(sockB, 0);
  rc = ooft_endpoint_add(sockB, 0);
  cmp_ok(rc, "==", 0, "add semi-wild B (hides wild for 1.0.0.0)");
  check_filters(thr);

  /* Delete semi-wild — wild regains its SW filter for 1.0.0.0 */
  ooft_endpoint_expect_sw_remove_all(sockB);
  ooft_endpoint_expect_sw_add(sockA, IPPROTO_UDP,
                              inet_addr("1.0.0.0"), htons(4000), 0, 0);
  oof_socket_del(fm, &sockB->skf);
  check_filters(thr);

  /* Delete wild */
  ooft_endpoint_expect_sw_remove_all(sockA);
  ooft_hw_filter_expect_remove_list(&hw_A);
  oof_socket_del(fm, &sockA->skf);
  check_filters(thr);

  /* --- Scenario D (BR-4.04): All addresses covered by semi-wilds --- */
  diag("Scenario D: semi-wilds on every address block wild entirely");

  sockA = ooft_alloc_endpoint(thr, IPPROTO_UDP, inet_addr("1.0.0.0"),
                              htons(5000), 0, 0);
  sockB = ooft_alloc_endpoint(thr, IPPROTO_UDP,
                              inet_addr("1.0.0.1"), htons(5000), 0, 0);
  sockC = ooft_alloc_endpoint(thr, IPPROTO_UDP, 0, htons(5000), 0, 0);

  /* Add semi-wild on 1.0.0.0 */
  ooft_endpoint_expect_unicast_filters(sockA, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(sockA, 0);
  cmp_ok(rc, "==", 0, "D: add semi-wild A (1.0.0.0)");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_A);

  /* Add semi-wild on 1.0.0.1 */
  ooft_endpoint_expect_unicast_filters(sockB, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(sockB, 0);
  cmp_ok(rc, "==", 0, "D: add semi-wild B (1.0.0.1)");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_B);

  /* Add wild in same stack — every address already has a same-stack
   * semi-wild, so oof_socket_steal_or_add_wild skips all addresses.
   * The wild gets no SW filters and no HW filters. */
  rc = ooft_endpoint_add(sockC, 0);
  cmp_ok(rc, "==", 0, "D: add wild C (fully hidden)");
  check_filters(thr);

  /* Delete wild — no filter changes (it had none) */
  oof_socket_del(fm, &sockC->skf);
  check_filters(thr);

  /* Delete semi-wilds */
  ooft_endpoint_expect_sw_remove_all(sockB);
  ooft_hw_filter_expect_remove_list(&hw_B);
  oof_socket_del(fm, &sockB->skf);
  check_filters(thr);

  ooft_endpoint_expect_sw_remove_all(sockA);
  ooft_hw_filter_expect_remove_list(&hw_A);
  oof_socket_del(fm, &sockA->skf);
  check_filters(thr);

  ooft_free_stack(thr);
  test_cleanup();
  done_testing();
}
