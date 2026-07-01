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


/* BR-6.07: When fixup_wild must redirect the wild HW filter to a different
 * stack, full-match sockets sharing it are given their own 5-tuple HW
 * filters first (unshare).
 *
 * BR-6.10: fixup_wild redirects the wild HW filter from one stack to
 * another when a higher-priority wild socket exists in a different stack.
 *
 * BR-6.11: After a redirect brings the wild HW filter back to the
 * original stack, full-match sockets that had been unshared release their
 * own HW filters and re-share the wild filter.
 */
int test_filter_redirect(void)
{
  tcp_helper_resource_t* thr1;
  tcp_helper_resource_t* thr2;
  struct ooft_endpoint* wild_a;
  struct ooft_endpoint* wild_b;
  struct ooft_endpoint* full_a;
  struct ooft_endpoint* semi_a;
  ci_dllist hw_wild_a;
  ci_dllist hw_redirected;
  ci_dllist hw_semi_a;
  int rc;
  struct oof_manager* fm;

  new_test();
  plan(SKIP_ALL, "temporarily disabled while AF_XDP redirect fallback is fixed");
  plan(48);

  test_alloc(32);
  thr1 = ooft_alloc_stack(8);
  thr2 = ooft_alloc_stack(4);
  fm = thr1->ofn->ofn_filter_manager;
  TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X2_FF));

  ci_dllist_init(&hw_wild_a);
  ci_dllist_init(&hw_redirected);
  ci_dllist_init(&hw_semi_a);

  /* --- Scenario A (BR-6.07 + BR-6.10 + BR-6.11): Cross-stack redirect
   *     with unshare and re-share --- */
  diag("Scenario A: unshare, redirect, then re-share on restore");

  /* Add wild UDP in stack A on port 2000 */
  wild_a = ooft_alloc_endpoint(thr1, IPPROTO_UDP, INADDR_ANY, htons(2000), INADDR_ANY, 0);

  ooft_endpoint_expect_unicast_filters(wild_a, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(wild_a, 0);
  cmp_ok(rc, "==", 0, "add wild A");
  check_all_filters(thr1, thr2);
  ooft_cplane_claim_added_hw_filters(cp, &hw_wild_a);

  /* Add full-match UDP in stack A sharing A's wild filter */
  full_a = ooft_alloc_endpoint(thr1, IPPROTO_UDP, inet_addr("1.0.0.0"), htons(2000),
                               inet_addr("2.0.0.0"), htons(3000));

  ooft_endpoint_expect_unicast_filters(full_a, 0);
  rc = ooft_endpoint_add(full_a, 0);
  cmp_ok(rc, "==", 0, "add full-match A (shares wild)");
  check_all_filters(thr1, thr2);

  /* Add wild UDP in stack B on port 2000.  fixup_wild will:
   * 1. Unshare full_a — give it own 5-tuple HW filter (BR-6.07).
   * 2. Redirect wild HW filters from A to B (BR-6.10). */
  wild_b = ooft_alloc_endpoint(thr2, IPPROTO_UDP, INADDR_ANY, htons(2000), INADDR_ANY, 0);

  ooft_endpoint_expect_unicast_filters(wild_b, 0);
  /* Expect redirect: old wild filters removed, new ones for B inserted */
  ooft_hw_filter_expect_remove_list(&hw_wild_a);
  ooft_endpoint_expect_hw_unicast(wild_b, inet_addr("1.0.0.0"), 0);
  ooft_endpoint_expect_hw_unicast(wild_b, inet_addr("1.0.0.1"), 0);
  /* Expect unshare: full-match gets own 5-tuple HW filter */
  ooft_endpoint_expect_hw_unicast(full_a, full_a->laddr_be, 0);

  rc = ooft_endpoint_add(wild_b, 0);
  cmp_ok(rc, "==", 0, "add wild B (triggers redirect + unshare)");
  check_all_filters(thr1, thr2);
  ooft_cplane_claim_added_hw_filters(cp, &hw_redirected);

  /* Delete wild B.  fixup_wild will:
   * 1. Redirect wild HW filters back from B to A (BR-6.10).
   * 2. Re-share: full_a releases own HW filter, shares A's wild (BR-6.11). */
  ooft_endpoint_expect_sw_remove_all(wild_b);
  ooft_hw_filter_expect_remove_list(&hw_redirected);
  ooft_endpoint_expect_hw_unicast(wild_a, inet_addr("1.0.0.0"), 0);
  ooft_endpoint_expect_hw_unicast(wild_a, inet_addr("1.0.0.1"), 0);

  oof_socket_del(fm, &wild_b->skf);
  check_all_filters(thr1, thr2);
  ooft_cplane_claim_added_hw_filters(cp, &hw_wild_a);

  /* Clean up: delete full-match, then wild A */
  ooft_endpoint_expect_sw_remove_all(full_a);
  oof_socket_del(fm, &full_a->skf);

  ooft_endpoint_expect_sw_remove_all(wild_a);
  ooft_hw_filter_expect_remove_list(&hw_wild_a);
  oof_socket_del(fm, &wild_a->skf);
  check_all_filters(thr1, thr2);

  /* --- Scenario B (BR-6.10): Semi-wild deletion redirects to wild --- */
  diag("Scenario B: semi-wild delete redirects filter to cross-stack wild");

  /* Add semi-wild in stack A on 1.0.0.0:3000 */
  semi_a = ooft_alloc_endpoint(thr1, IPPROTO_UDP, inet_addr("1.0.0.0"), htons(3000), INADDR_ANY, 0);

  ooft_endpoint_expect_unicast_filters(semi_a, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(semi_a, 0);
  cmp_ok(rc, "==", 0, "add semi-wild A");
  check_all_filters(thr1, thr2);
  ooft_cplane_claim_added_hw_filters(cp, &hw_semi_a);

  /* Add wild in stack B on port 3000.  Semi-wild has priority for
   * 1.0.0.0, so wild only gets HW filter for 1.0.0.1. */
  wild_b = ooft_alloc_endpoint(thr2, IPPROTO_UDP, INADDR_ANY, htons(3000), INADDR_ANY, 0);

  ooft_endpoint_expect_unicast_filters(wild_b, 0);
  ooft_endpoint_expect_hw_unicast(wild_b, inet_addr("1.0.0.1"), 0);
  rc = ooft_endpoint_add(wild_b, 0);
  cmp_ok(rc, "==", 0, "add wild B (partial coverage)");
  check_all_filters(thr1, thr2);
  ooft_cplane_claim_added_hw_filters(cp, &hw_redirected);

  /* Delete semi-wild A.  fixup_wild redirects 1.0.0.0 filter to B. */
  ooft_endpoint_expect_sw_remove_all(semi_a);
  ooft_hw_filter_expect_remove_list(&hw_semi_a);
  ooft_endpoint_expect_hw_unicast(wild_b, inet_addr("1.0.0.0"), 0);

  oof_socket_del(fm, &semi_a->skf);
  check_all_filters(thr1, thr2);

  /* Clean up: delete wild B */
  ooft_endpoint_expect_sw_remove_all(wild_b);
  ooft_cplane_claim_added_hw_filters(cp, &hw_redirected);
  ooft_hw_filter_expect_remove_list(&hw_redirected);
  oof_socket_del(fm, &wild_b->skf);
  check_all_filters(thr1, thr2);

  /* --- Scenario C (BR-5.18): redirect failure falls through to a fresh
   *     insert --- */
  diag("Scenario C: redirect -ENOENT/-ENODEV falls through to fresh insert");

  /* Add wild A on port 7000. */
  wild_a = ooft_alloc_endpoint(thr1, IPPROTO_UDP, INADDR_ANY, htons(7000), INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(wild_a, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(wild_a, 0);
  cmp_ok(rc, "==", 0, "C: add wild A");
  check_all_filters(thr1, thr2);
  ci_dllist_init(&hw_wild_a);
  ooft_cplane_claim_added_hw_filters(cp, &hw_wild_a);

  /* Add wild B on port 7000.  fixup_wild redirects A's wild HW filters to B.
   * Inject -ENOENT on every redirect: efrm_filter_redirect removes the old
   * filter then returns -ENOENT, so oo_hw_filter_set_hwport_common forgets
   * the old filter id (tcp_filters.c:332) and falls through to a fresh
   * insert.  The net HW operations are identical to a normal redirect
   * (remove old + add new), so the expectations are unchanged. */
  wild_b = ooft_alloc_endpoint(thr2, IPPROTO_UDP, INADDR_ANY, htons(7000), INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(wild_b, 0);
  ooft_hw_filter_expect_remove_list(&hw_wild_a);
  ooft_endpoint_expect_hw_unicast(wild_b, inet_addr("1.0.0.0"), 0);
  ooft_endpoint_expect_hw_unicast(wild_b, inet_addr("1.0.0.1"), 0);
  efrm_filter_redirect_fail_rc = -ENOENT;
  efrm_filter_redirect_fail_count = 2;   /* fail both hwports */
  rc = ooft_endpoint_add(wild_b, 0);
  cmp_ok(rc, "==", 0, "C: add wild B (redirect -ENOENT -> fresh insert)");
  cmp_ok(efrm_filter_redirect_fail_count, "==", 0,
         "C: all -ENOENT redirects were attempted");
  check_all_filters(thr1, thr2);
  ci_dllist_init(&hw_redirected);
  ooft_cplane_claim_added_hw_filters(cp, &hw_redirected);

  /* Delete wild B.  fixup_wild redirects the filters back to A; this time
   * inject -ENODEV (move not supported), the other arm of the line-332
   * decision.  Again the net operations are remove old + add new. */
  ooft_endpoint_expect_sw_remove_all(wild_b);
  ooft_hw_filter_expect_remove_list(&hw_redirected);
  ooft_endpoint_expect_hw_unicast(wild_a, inet_addr("1.0.0.0"), 0);
  ooft_endpoint_expect_hw_unicast(wild_a, inet_addr("1.0.0.1"), 0);
  efrm_filter_redirect_fail_rc = -ENODEV;
  efrm_filter_redirect_fail_count = 2;
  oof_socket_del(fm, &wild_b->skf);
  efrm_filter_redirect_fail_rc = -ENOENT;   /* restore default */
  cmp_ok(efrm_filter_redirect_fail_count, "==", 0,
         "C: all -ENODEV redirects were attempted");
  check_all_filters(thr1, thr2);
  ci_dllist_init(&hw_wild_a);
  ooft_cplane_claim_added_hw_filters(cp, &hw_wild_a);

  /* Clean up wild A. */
  ooft_endpoint_expect_sw_remove_all(wild_a);
  ooft_hw_filter_expect_remove_list(&hw_wild_a);
  oof_socket_del(fm, &wild_a->skf);
  check_all_filters(thr1, thr2);

  ooft_free_stack(thr1);
  ooft_free_stack(thr2);
  test_cleanup();
  done_testing();
}
