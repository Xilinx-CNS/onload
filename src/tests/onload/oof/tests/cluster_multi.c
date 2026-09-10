/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include "../onload_kernel_compat.h"
#include "../stack.h"
#include "../stack_interface.h"
#include "../../tap/tap.h"
#include "../oof_test.h"
#include "../cplane.h"
#include "../efrm.h"
#include "../utils.h"
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>
#include <arpa/inet.h>


static void check_all_filters(tcp_helper_resource_t* thr1,
                              tcp_helper_resource_t* thr2)
{
  int rc;
  ok(thr1->ns == thr2->ns, "stacks share namespace");
  rc = ooft_stack_check_sw_filters(thr1);
  cmp_ok(rc, "==", 0, "check sw filters stack 1");
  rc = ooft_stack_check_sw_filters(thr2);
  cmp_ok(rc, "==", 0, "check sw filters stack 2");
  rc = ooft_ns_check_hw_filters(thr1->ns);
  cmp_ok(rc, "==", 0, "check hw filters");
}


/* BR-4.15 (cluster foot-in-the-door), BR-4.16 (duplicate stack rejection),
 * BR-4.17 (cluster HW filter sharing), BR-4.18 (no-unicast arming).
 *
 * Two stacks in the same cluster share a port via SO_REUSEPORT.
 *
 * Scenario A: Wild foot-in-the-door — second stack adds wild on same
 *   port, gets SW only (HW shared). Delete order tests fixup_wild sharing.
 *
 * Scenario B: Duplicate stack rejection — same stack adds wild twice
 *   on same port, second returns -EADDRINUSE.
 *
 * Scenario C: Semi-wild foot-in-the-door — same as A but semi-wild.
 *
 * Scenario D: No-unicast arming — dummy→replace→arm(NO_UCAST) path.
 *
 * Scenario E: Full-match does not share a cluster's wild filter — a
 *   non-clustered connected socket on a port owned by a SO_REUSEPORT
 *   cluster gets its own 5-tuple HW filter, because
 *   oof_socket_can_share_hw_filter returns false (filter->thc != skf_thc).
 *   This is the only path that exercises the thc==skf_thc condition's
 *   false side.
 */
int test_cluster_multi(void)
{
  tcp_helper_resource_t* thr1;
  tcp_helper_resource_t* thr2;
  tcp_helper_resource_t* thr3;
  tcp_helper_cluster_t* thc;
  struct ooft_endpoint* ep1;
  struct ooft_endpoint* ep2;
  struct ooft_endpoint* ep3;
  struct ooft_endpoint* ep4;
  struct ooft_endpoint* ep5;
  struct ooft_endpoint* ep6;
  struct ooft_endpoint* old_ep;
  struct ooft_endpoint* new_ep;
  struct ooft_endpoint* ep_wild;
  struct ooft_endpoint* ep_full;
  struct oof_manager* fm;
  int rc;

  new_test();
  plan(77);

  test_alloc(32);
  thr1 = ooft_alloc_stack(8);
  thr2 = ooft_alloc_stack(8);
  thr3 = ooft_alloc_stack(8);  /* non-clustered, for Scenario E */
  thc = ooft_alloc_cluster("multi_cluster");
  ooft_stack_set_cluster(thr1, thc);
  ooft_stack_set_cluster(thr2, thc);
  fm = thr1->ofn->ofn_filter_manager;
  TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X2_FF));

  /* --- Scenario A (BR-4.15, BR-4.17): Wild foot-in-the-door --- */
  diag("Scenario A: wild foot-in-the-door with cluster HW sharing");

  ep1 = ooft_alloc_endpoint(thr1, IPPROTO_UDP, INADDR_ANY, htons(2000), INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(ep1, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(ep1, OOF_SOCKET_ADD_FLAG_CLUSTERED);
  cmp_ok(rc, "==", 0, "add clustered wild from stack 1");
  check_all_filters(thr1, thr2);

  ep2 = ooft_alloc_endpoint(thr2, IPPROTO_UDP, INADDR_ANY, htons(2000), INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(ep2, 0);
  rc = ooft_endpoint_add(ep2, OOF_SOCKET_ADD_FLAG_CLUSTERED);
  cmp_ok(rc, "==", 0, "add clustered wild from stack 2 (SW only)");
  check_all_filters(thr1, thr2);

  /* Delete ep1 first (HW filter owner). fixup_wild finds ep2; same thc
   * means oof_socket_can_share_hw_filter returns true — HW stays. */
  ooft_endpoint_expect_sw_remove_all(ep1);
  oof_socket_del(fm, &ep1->skf);
  check_all_filters(thr1, thr2);

  /* Delete ep2 (last user) — HW filter removed. */
  ooft_endpoint_expect_sw_remove_all(ep2);
  ooft_hw_filter_expect_remove_all(thr1->ns);
  oof_socket_del(fm, &ep2->skf);
  check_all_filters(thr1, thr2);

  /* --- Scenario B (BR-4.16): Duplicate stack rejection --- */
  diag("Scenario B: duplicate stack rejected with -EADDRINUSE");

  ep3 = ooft_alloc_endpoint(thr1, IPPROTO_UDP, INADDR_ANY, htons(3000), INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(ep3, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(ep3, OOF_SOCKET_ADD_FLAG_CLUSTERED);
  cmp_ok(rc, "==", 0, "add clustered wild from stack 1");
  check_all_filters(thr1, thr2);

  ep4 = ooft_alloc_endpoint(thr1, IPPROTO_UDP, INADDR_ANY, htons(3000), INADDR_ANY, 0);
  rc = ooft_endpoint_add(ep4, OOF_SOCKET_ADD_FLAG_CLUSTERED);
  cmp_ok(rc, "==", -EADDRINUSE, "duplicate stack wild rejected");
  check_all_filters(thr1, thr2);

  ooft_endpoint_expect_sw_remove_all(ep3);
  ooft_hw_filter_expect_remove_all(thr1->ns);
  oof_socket_del(fm, &ep3->skf);
  check_all_filters(thr1, thr2);

  /* --- Scenario C (BR-4.15): Semi-wild foot-in-the-door --- */
  diag("Scenario C: semi-wild foot-in-the-door");

  ep5 = ooft_alloc_endpoint(thr1, IPPROTO_UDP, inet_addr("1.0.0.0"), htons(4000), INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(ep5, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(ep5, OOF_SOCKET_ADD_FLAG_CLUSTERED);
  cmp_ok(rc, "==", 0, "add clustered semi-wild from stack 1");
  check_all_filters(thr1, thr2);

  ep6 = ooft_alloc_endpoint(thr2, IPPROTO_UDP, inet_addr("1.0.0.0"), htons(4000), INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(ep6, 0);
  rc = ooft_endpoint_add(ep6, OOF_SOCKET_ADD_FLAG_CLUSTERED);
  cmp_ok(rc, "==", 0, "add clustered semi-wild from stack 2 (SW only)");
  check_all_filters(thr1, thr2);

  ooft_endpoint_expect_sw_remove_all(ep5);
  oof_socket_del(fm, &ep5->skf);
  check_all_filters(thr1, thr2);

  ooft_endpoint_expect_sw_remove_all(ep6);
  ooft_hw_filter_expect_remove_all(thr1->ns);
  oof_socket_del(fm, &ep6->skf);
  check_all_filters(thr1, thr2);

  /* --- Scenario D (BR-4.18): No-unicast arming --- */
  diag("Scenario D: no-unicast arming skips filter installation");

  old_ep = ooft_alloc_endpoint(thr1, IPPROTO_UDP, inet_addr("1.0.0.0"), htons(5000), INADDR_ANY, 0);
  rc = ooft_endpoint_add(old_ep,
                         OOF_SOCKET_ADD_FLAG_CLUSTERED |
                         OOF_SOCKET_ADD_FLAG_DUMMY |
                         OOF_SOCKET_ADD_FLAG_NO_STACK);
  cmp_ok(rc, "==", 0, "add dummy stackless clustered socket");
  ok((old_ep->skf.sf_flags & OOF_SOCKET_DUMMY) != 0,
     "dummy flag set");
  ok((old_ep->skf.sf_flags & OOF_SOCKET_NO_STACK) != 0,
     "NO_STACK flag set");

  new_ep = ooft_alloc_endpoint(thr1, IPPROTO_UDP, inet_addr("1.0.0.0"), htons(5000), INADDR_ANY, 0);
  rc = oof_socket_replace(fm, &old_ep->skf, &new_ep->skf);
  cmp_ok(rc, "==", 0, "replace dummy with real socket");
  ok((new_ep->skf.sf_flags & OOF_SOCKET_DUMMY) != 0,
     "replaced socket still DUMMY");
  ok((new_ep->skf.sf_flags & OOF_SOCKET_NO_STACK) == 0,
     "replaced socket NO_STACK cleared");

  rc = ooft_endpoint_add(new_ep,
                         OOF_SOCKET_ADD_FLAG_CLUSTERED |
                         OOF_SOCKET_ADD_FLAG_NO_UCAST);
  cmp_ok(rc, "==", 0, "arm with NO_UCAST");
  ok((new_ep->skf.sf_flags & OOF_SOCKET_DUMMY) == 0,
     "DUMMY cleared after arming");
  ok((new_ep->skf.sf_flags & OOF_SOCKET_NO_UCAST) != 0,
     "NO_UCAST set after arming");

  /* NO_UCAST means no filters were installed, so delete has no filter
   * side effects. */
  oof_socket_del(fm, &new_ep->skf);
  check_all_filters(thr1, thr2);

  /* --- Scenario E (BR-5.01, BR-5.02; MC/DC for
   *     oof_socket_can_share_hw_filter): full-match does not share a
   *     cluster's wild filter --- */
  diag("Scenario E: non-clustered full-match gets its own HW filter");

  /* Clustered wild on port 6000 from stack 1 installs a clustered wild HW
   * filter (filter->thc == cluster, filter->trs == NULL) on each local
   * address's LPA. */
  ep_wild = ooft_alloc_endpoint(thr1, IPPROTO_UDP, INADDR_ANY, htons(6000), INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(ep_wild, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(ep_wild, OOF_SOCKET_ADD_FLAG_CLUSTERED);
  cmp_ok(rc, "==", 0, "E: add clustered wild from stack 1");
  check_all_filters(thr1, thr2);

  /* A connected (full-match) socket from a non-clustered stack on the same
   * port. oof_socket_can_share_hw_filter uses oof_socket_thc_safe(), which
   * returns the *stack's* cluster: for thr3 that is NULL. So against the
   * clustered wild filter, filter->trs == NULL (first OR term false),
   * filter->thc != NULL (true), filter->thc != skf_thc (NULL) — the socket
   * cannot share and gets its own 5-tuple HW filter. This is the only path
   * that drives the thc==skf_thc condition false while its guard is true. */
  ep_full = ooft_alloc_endpoint(thr3, IPPROTO_UDP, inet_addr("1.0.0.0"),
                                htons(6000), inet_addr("2.0.0.0"),
                                htons(7000));
  ooft_endpoint_expect_unicast_filters(ep_full, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(ep_full, 0);
  cmp_ok(rc, "==", 0, "E: non-clustered full-match gets own HW filter");
  rc = ooft_stack_check_sw_filters(thr3);
  cmp_ok(rc, "==", 0, "E: full-match sw filter installed");
  rc = ooft_ns_check_hw_filters(thr1->ns);
  cmp_ok(rc, "==", 0, "E: own full-match hw alongside clustered wild");

  /* Tear down the full-match first: its own 5-tuple filters are removed on
   * both hwports; the clustered wild filter is untouched. */
  ooft_endpoint_expect_sw_remove_all(ep_full);
  ooft_client_expect_hw_remove_ip(oo_nics[0].efrm_client,
                                  tcp_helper_rx_vi_id(thr3, 0),
                                  tcp_helper_vi_hw_stack_id(thr3, 0),
                                  EFX_FILTER_VID_UNSPEC, IPPROTO_UDP,
                                  inet_addr("1.0.0.0"), htons(6000),
                                  inet_addr("2.0.0.0"), htons(7000));
  ooft_client_expect_hw_remove_ip(oo_nics[1].efrm_client,
                                  tcp_helper_rx_vi_id(thr3, 1),
                                  tcp_helper_vi_hw_stack_id(thr3, 1),
                                  EFX_FILTER_VID_UNSPEC, IPPROTO_UDP,
                                  inet_addr("1.0.0.0"), htons(6000),
                                  inet_addr("2.0.0.0"), htons(7000));
  oof_socket_del(fm, &ep_full->skf);
  rc = ooft_stack_check_sw_filters(thr3);
  cmp_ok(rc, "==", 0, "E: full-match sw removed");
  rc = ooft_ns_check_hw_filters(thr1->ns);
  cmp_ok(rc, "==", 0, "E: full-match hw removed, clustered wild remains");

  /* Tear down the clustered wild — removes the remaining HW filters. */
  ooft_endpoint_expect_sw_remove_all(ep_wild);
  ooft_cplane_expect_hw_remove_all(cp);
  oof_socket_del(fm, &ep_wild->skf);
  check_all_filters(thr1, thr2);

  ooft_free_stack(thr3);
  ooft_free_stack(thr2);
  ooft_free_stack(thr1);
  ooft_free_cluster(thc);
  test_cleanup();
  done_testing();
}
