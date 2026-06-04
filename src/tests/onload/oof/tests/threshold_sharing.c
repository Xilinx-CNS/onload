/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include "../onload_kernel_compat.h"
#include "../stack.h"
#include "../../tap/tap.h"
#include "../oof_test.h"
#include "../cplane.h"
#include "../oof_impl.h"
#include "../utils.h"
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>


static void check_all_filters(tcp_helper_resource_t* thr1,
                              tcp_helper_resource_t* thr2)
{
  int rc;
  rc = ooft_stack_check_sw_filters(thr1);
  cmp_ok(rc, "==", 0, "check sw filters stack 1");
  if( thr2 != NULL ) {
    ok(thr1->ns == thr2->ns, "stacks share namespace");
    rc = ooft_stack_check_sw_filters(thr2);
    cmp_ok(rc, "==", 0, "check sw filters stack 2");
  }
  rc = ooft_ns_check_hw_filters(thr1->ns);
  cmp_ok(rc, "==", 0, "check hw filters");
}


/* BR-6.05: Threshold selection - keep_thresh when no wild socket wants the
 * filter, steal_thresh when one does.
 *
 * BR-6.06: When sharers exceed the threshold, unsharing is suppressed and
 * the wild socket (if any) does not get the filter.
 *
 * BR-7.14: When passive count exceeds keep_thresh and the listener is
 * deleted, passives keep sharing the wild HW filter.
 */
int test_threshold_sharing(void)
{
  tcp_helper_resource_t* thr1;
  tcp_helper_resource_t* thr2;
  struct ooft_endpoint* listener;
  struct ooft_endpoint* passive[4];
  struct ooft_endpoint* wild_b;
  ci_dllist hw_listener;
  ci_dllist hw_passive;
  int rc, i;
  struct oof_manager* fm;
  int saved_keep, saved_steal;

  new_test();
  plan(66);

  test_alloc(32);
  thr1 = ooft_alloc_stack(16);
  thr2 = ooft_alloc_stack(4);
  fm = thr1->ofn->ofn_filter_manager;
  TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X2_FF));

  ci_dllist_init(&hw_listener);
  ci_dllist_init(&hw_passive);

  saved_keep = oof_shared_keep_thresh;
  saved_steal = oof_shared_steal_thresh;

  /* --- Scenario A (BR-6.05 + BR-7.14): passives exceed keep_thresh --- */
  diag("Scenario A: passives exceed keep_thresh, keep sharing");

  oof_shared_keep_thresh = 2;

  listener = ooft_alloc_endpoint(thr1, IPPROTO_TCP, inet_addr("1.0.0.0"),
                                 htons(4000), INADDR_ANY, 0);

  ooft_endpoint_expect_unicast_filters(listener, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(listener, 0);
  cmp_ok(rc, "==", 0, "add listener");
  check_all_filters(thr1, NULL);
  ooft_cplane_claim_added_hw_filters(cp, &hw_listener);

  /* Add 4 passive sockets (all share listener's HW filter) */
  for( i = 0; i < 4; i++ ) {
    in_addr_t lip = inet_addr("1.0.0.0");
    in_addr_t rip = inet_addr("2.0.0.0") + i;
    in_port_t rport = htons(5000 + i);
    ci_addr_t laddr = CI_ADDR_FROM_IP4(lip);
    ci_addr_t raddr = CI_ADDR_FROM_IP4(rip);
    passive[i] = ooft_alloc_endpoint(thr1, IPPROTO_TCP, lip, htons(4000),
                                     rip, rport);
    ooft_endpoint_expect_unicast_filters(passive[i], 0);
    rc = oof_socket_share(fm, &passive[i]->skf, &listener->skf,
                          AF_SPACE_FLAG_IP4, laddr, raddr,
                          passive[i]->lport_be, passive[i]->rport_be);
    cmp_ok(rc, "==", 0, "share passive");
  }
  check_all_filters(thr1, NULL);

  /* Delete listener. fixup_wild: no wild socket, sharers=4 > thresh=2 ->
   * passives KEEP sharing, HW filter retained. */
  ooft_endpoint_expect_sw_remove_all(listener);
  oof_socket_del(fm, &listener->skf);
  /* HW filter should NOT be removed (sharers > keep_thresh) */
  check_all_filters(thr1, NULL);

  /* Clean up passives - delete them one by one.
   * Deleting passive[0]: sharers 4->3, fixup_wild: 3 > 2 -> suppress.
   * Deleting passive[1]: sharers 3->2, fixup_wild: 2 > 2 is false ->
   *   unshare: passive[2] and [3] each get own 5-tuple HW filter,
   *   wild HW filter cleared. */
  ooft_endpoint_expect_sw_remove_all(passive[0]);
  oof_socket_del(fm, &passive[0]->skf);
  check_all_filters(thr1, NULL);

  ooft_endpoint_expect_sw_remove_all(passive[1]);
  ooft_hw_filter_expect_remove_list(&hw_listener);
  for( i = 2; i < 4; i++ )
    ooft_endpoint_expect_hw_unicast(passive[i], passive[i]->laddr_be, 0);
  oof_socket_del(fm, &passive[1]->skf);
  check_all_filters(thr1, NULL);
  ooft_cplane_claim_added_hw_filters(cp, &hw_passive);

  /* passive[2] and [3] now have own HW filters */
  ooft_hw_filter_expect_remove_list(&hw_passive);
  for( i = 2; i < 4; i++ ) {
    ooft_endpoint_expect_sw_remove_all(passive[i]);
    oof_socket_del(fm, &passive[i]->skf);
  }
  check_all_filters(thr1, NULL);

  /* --- Scenario B (BR-6.06): steal_thresh blocks cross-stack steal --- */
  diag("Scenario B: steal_thresh blocks filter stealing");

  oof_shared_steal_thresh = 2;
  oof_shared_keep_thresh = saved_keep;

  listener = ooft_alloc_endpoint(thr1, IPPROTO_TCP, inet_addr("1.0.0.0"),
                                 htons(5000), INADDR_ANY, 0);
  wild_b = ooft_alloc_endpoint(thr2, IPPROTO_TCP, inet_addr("1.0.0.0"),
                               htons(5000), INADDR_ANY, 0);

  ooft_endpoint_expect_unicast_filters(listener, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(listener, 0);
  cmp_ok(rc, "==", 0, "add listener in stack A");
  check_all_filters(thr1, thr2);
  ooft_cplane_claim_added_hw_filters(cp, &hw_listener);

  /* Add 3 passives in stack A */
  for( i = 0; i < 3; i++ ) {
    in_addr_t lip = inet_addr("1.0.0.0");
    in_addr_t rip = inet_addr("2.0.0.0") + i;
    in_port_t rport = htons(6000 + i);
    ci_addr_t laddr = CI_ADDR_FROM_IP4(lip);
    ci_addr_t raddr = CI_ADDR_FROM_IP4(rip);
    passive[i] = ooft_alloc_endpoint(thr1, IPPROTO_TCP, lip, htons(5000),
                                     rip, rport);
    ooft_endpoint_expect_unicast_filters(passive[i], 0);
    rc = oof_socket_share(fm, &passive[i]->skf, &listener->skf,
                          AF_SPACE_FLAG_IP4, laddr, raddr,
                          passive[i]->lport_be, passive[i]->rport_be);
    cmp_ok(rc, "==", 0, "share passive in stack A");
  }
  check_all_filters(thr1, thr2);

  /* Add semi-wild in stack B - fixup_wild: sharers=3 > steal_thresh=2 ->
   * stack B does NOT steal the filter.  lpa_filter still points at
   * stack A (the listener's stack). */
  ooft_endpoint_expect_unicast_filters(wild_b, 0);
  rc = ooft_endpoint_add(wild_b, 0);
  cmp_ok(rc, "==", 0, "add semi-wild in stack B (blocked by threshold)");
  ok(listener->skf.sf_local_port->lp_addr[listener->skf.sf_la_i]
       .lpa_filter.trs == oof_cb_socket_stack(&listener->skf),
     "B: lpa_filter still owned by stack A after suppressed steal");
  check_all_filters(thr1, thr2);

  /* Clean up: delete wild_b first (listener still owns lpa_filter in
   * the same stack, so no redirect needed), then passives with
   * intermediate checks, then listener clears the HW filter. */
  ooft_endpoint_expect_sw_remove_all(wild_b);
  oof_socket_del(fm, &wild_b->skf);
  check_all_filters(thr1, thr2);

  for( i = 0; i < 3; i++ ) {
    ooft_endpoint_expect_sw_remove_all(passive[i]);
    oof_socket_del(fm, &passive[i]->skf);
    check_all_filters(thr1, thr2);
  }

  ooft_endpoint_expect_sw_remove_all(listener);
  ooft_hw_filter_expect_remove_list(&hw_listener);
  oof_socket_del(fm, &listener->skf);
  check_all_filters(thr1, thr2);

  /* --- Scenario C (BR-6.05): sharers below keep_thresh get unshared --- */
  diag("Scenario C: sharers below keep_thresh get unshared");

  oof_shared_keep_thresh = 5;
  oof_shared_steal_thresh = saved_steal;

  listener = ooft_alloc_endpoint(thr1, IPPROTO_TCP, inet_addr("1.0.0.0"),
                                 htons(6000), INADDR_ANY, 0);

  ooft_endpoint_expect_unicast_filters(listener, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(listener, 0);
  cmp_ok(rc, "==", 0, "add listener for unshare test");
  check_all_filters(thr1, NULL);
  ooft_cplane_claim_added_hw_filters(cp, &hw_listener);

  /* Add 2 passives */
  for( i = 0; i < 2; i++ ) {
    in_addr_t lip = inet_addr("1.0.0.0");
    in_addr_t rip = inet_addr("2.0.0.0") + i;
    in_port_t rport = htons(7000 + i);
    ci_addr_t laddr = CI_ADDR_FROM_IP4(lip);
    ci_addr_t raddr = CI_ADDR_FROM_IP4(rip);
    passive[i] = ooft_alloc_endpoint(thr1, IPPROTO_TCP, lip, htons(6000),
                                     rip, rport);
    ooft_endpoint_expect_unicast_filters(passive[i], 0);
    rc = oof_socket_share(fm, &passive[i]->skf, &listener->skf,
                          AF_SPACE_FLAG_IP4, laddr, raddr,
                          passive[i]->lport_be, passive[i]->rport_be);
    cmp_ok(rc, "==", 0, "share passive for unshare test");
  }
  check_all_filters(thr1, NULL);

  /* Delete listener. fixup_wild: no wild socket, sharers=2 <= thresh=5 ->
   * each passive gets its own 5-tuple HW filter, wild HW filter removed. */
  ooft_endpoint_expect_sw_remove_all(listener);
  ooft_hw_filter_expect_remove_list(&hw_listener);
  for( i = 0; i < 2; i++ )
    ooft_endpoint_expect_hw_unicast(passive[i], passive[i]->laddr_be, 0);
  oof_socket_del(fm, &listener->skf);
  check_all_filters(thr1, NULL);
  ooft_cplane_claim_added_hw_filters(cp, &hw_passive);

  /* Clean up passives (each now has own HW filter) */
  ooft_hw_filter_expect_remove_list(&hw_passive);
  for( i = 0; i < 2; i++ ) {
    ooft_endpoint_expect_sw_remove_all(passive[i]);
    oof_socket_del(fm, &passive[i]->skf);
  }
  check_all_filters(thr1, NULL);

  oof_shared_keep_thresh = saved_keep;
  oof_shared_steal_thresh = saved_steal;

  ooft_free_stack(thr1);
  ooft_free_stack(thr2);
  test_cleanup();
  done_testing();
}
