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


/* BR-7.11: Optimized del_sw path for sharing full-match (TCP passive)
 * sockets. When sf_full_match_filter is empty (sharing), lp_refs > 1,
 * and lpa_n_full_sharers > 1, del_sw fully removes the socket atomically
 * and returns 0.
 *
 * BR-7.12: When the optimization conditions are not met for sharing
 * full-match sockets (e.g. the last sharer), del_sw returns 1 and the
 * caller must follow up with oof_socket_del().
 *
 * Scenario C covers the same return-1 cleanup contract for a full-match
 * socket with its own HW filter.
 */
int test_del_sw(void)
{
  tcp_helper_resource_t* thr;
  struct ooft_endpoint* listener;
  struct ooft_endpoint* passive1;
  struct ooft_endpoint* passive2;
  struct ooft_endpoint* passive3;
  struct ooft_endpoint* active;
  ci_dllist hw_listener;
  ci_dllist hw_active;
  int rc;
  struct oof_manager* fm;

  new_test();
  plan(29);

  test_alloc(32);
  thr = ooft_alloc_stack(8);
  fm = thr->ofn->ofn_filter_manager;
  TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X2_FF));

  ci_dllist_init(&hw_listener);
  ci_dllist_init(&hw_active);

  /* --- Scenario A (BR-7.11): Optimized del_sw for sharing passive --- */
  diag("Scenario A: optimized del_sw (sharing, not last)");

  listener = ooft_alloc_endpoint(thr, IPPROTO_TCP, inet_addr("1.0.0.0"), htons(4000), INADDR_ANY, 0);
  passive1 = ooft_alloc_endpoint(thr, IPPROTO_TCP, inet_addr("1.0.0.0"), htons(4000),
                                 inet_addr("2.0.0.0"), htons(5000));
  passive2 = ooft_alloc_endpoint(thr, IPPROTO_TCP, inet_addr("1.0.0.0"), htons(4000),
                                 inet_addr("3.0.0.0"), htons(6000));
  passive3 = ooft_alloc_endpoint(thr, IPPROTO_TCP, inet_addr("1.0.0.0"), htons(4000),
                                 inet_addr("4.0.0.0"), htons(7000));

  /* Add listener */
  ooft_endpoint_expect_unicast_filters(listener, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(listener, 0);
  cmp_ok(rc, "==", 0, "add listener");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_listener);

  /* Add 3 passive sockets via oof_socket_share */
  {
    ci_addr_t laddr = CI_ADDR_FROM_IP4(passive1->laddr_be);

    ooft_endpoint_expect_unicast_filters(passive1, 0);
    rc = oof_socket_share(fm, &passive1->skf, &listener->skf,
                          AF_SPACE_FLAG_IP4, laddr,
                          CI_ADDR_FROM_IP4(passive1->raddr_be),
                          passive1->lport_be, passive1->rport_be);
    cmp_ok(rc, "==", 0, "share passive1");

    ooft_endpoint_expect_unicast_filters(passive2, 0);
    rc = oof_socket_share(fm, &passive2->skf, &listener->skf,
                          AF_SPACE_FLAG_IP4, laddr,
                          CI_ADDR_FROM_IP4(passive2->raddr_be),
                          passive2->lport_be, passive2->rport_be);
    cmp_ok(rc, "==", 0, "share passive2");

    ooft_endpoint_expect_unicast_filters(passive3, 0);
    rc = oof_socket_share(fm, &passive3->skf, &listener->skf,
                          AF_SPACE_FLAG_IP4, laddr,
                          CI_ADDR_FROM_IP4(passive3->raddr_be),
                          passive3->lport_be, passive3->rport_be);
    cmp_ok(rc, "==", 0, "share passive3");
  }
  check_filters(thr);

  /* del_sw on passive1: sharing (no own HW filter), lp_refs=4 > 1,
   * lpa_n_full_sharers=3 > 1 → optimized path, returns 0. */
  ooft_endpoint_expect_sw_remove_all(passive1);
  rc = oof_socket_del_sw(fm, &passive1->skf);
  cmp_ok(rc, "==", 0, "del_sw passive1 returns 0 (optimized)");
  ok(passive1->skf.sf_local_port == NULL, "passive1 fully cleaned up");
  check_filters(thr);

  /* del_sw on passive2: lp_refs=3 > 1, sharers=2 > 1 → still optimized */
  ooft_endpoint_expect_sw_remove_all(passive2);
  rc = oof_socket_del_sw(fm, &passive2->skf);
  cmp_ok(rc, "==", 0, "del_sw passive2 returns 0 (optimized)");
  ok(passive2->skf.sf_local_port == NULL, "passive2 fully cleaned up");
  check_filters(thr);

  /* --- Scenario B (BR-7.12): Non-optimized del_sw — last sharer --- */
  diag("Scenario B: non-optimized del_sw (last sharer)");

  /* passive3 is now the last sharer (sharers=1), so del_sw returns 1 */
  ooft_endpoint_expect_sw_remove_all(passive3);
  rc = oof_socket_del_sw(fm, &passive3->skf);
  cmp_ok(rc, "==", 1, "del_sw passive3 returns 1 (last sharer)");
  ok(passive3->skf.sf_flags & OOF_SOCKET_SW_FILTER_WAS_REMOVED,
     "passive3 SW_FILTER_WAS_REMOVED set");

  /* Must follow up with oof_socket_del to clean up HW filters */
  oof_socket_del(fm, &passive3->skf);
  check_filters(thr);

  /* Clean up listener */
  ooft_endpoint_expect_sw_remove_all(listener);
  ooft_hw_filter_expect_remove_list(&hw_listener);
  oof_socket_del(fm, &listener->skf);
  check_filters(thr);

  /* --- Scenario C: del_sw on socket with own HW filter --- */
  diag("Scenario C: del_sw on full-match with own HW filter");

  active = ooft_alloc_endpoint(thr, IPPROTO_TCP, inet_addr("1.0.0.0"), htons(2000),
                               inet_addr("2.0.0.0"), htons(3000));

  ooft_endpoint_expect_unicast_filters(active, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(active, 0);
  cmp_ok(rc, "==", 0, "add active TCP");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_active);

  /* del_sw: has own HW filter → returns 1 */
  ooft_endpoint_expect_sw_remove_all(active);
  rc = oof_socket_del_sw(fm, &active->skf);
  cmp_ok(rc, "==", 1, "del_sw active returns 1 (has HW filter)");
  ok(active->skf.sf_flags & OOF_SOCKET_SW_FILTER_WAS_REMOVED,
     "active SW_FILTER_WAS_REMOVED set");

  /* Follow up with oof_socket_del */
  ooft_hw_filter_expect_remove_list(&hw_active);
  oof_socket_del(fm, &active->skf);
  check_filters(thr);

  ooft_free_stack(thr);
  test_cleanup();
  done_testing();
}
