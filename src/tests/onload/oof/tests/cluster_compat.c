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


/* BR-4.11: Cluster compatibility rejection — clustered and non-clustered
 * sockets cannot coexist on the same port.
 *
 * BR-5.09: Clustered full-match sockets are rejected with -EINVAL.
 */
int test_cluster_compat(void)
{
  tcp_helper_resource_t* thr_c;
  tcp_helper_resource_t* thr_nc;
  tcp_helper_cluster_t* thc;
  struct ooft_endpoint* clustered;
  struct ooft_endpoint* non_clustered;
  struct ooft_endpoint* full;
  struct oof_manager* fm;
  int rc;

  new_test();
  plan(82);

  test_alloc(32);
  thr_c = ooft_alloc_stack(16);
  thr_nc = ooft_alloc_stack(16);
  fm = thr_c->ofn->ofn_filter_manager;
  thc = ooft_alloc_cluster("test_cluster");
  ooft_stack_set_cluster(thr_c, thc);
  TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X2_FF));

  /* --- Scenario A (BR-4.11): Clustered wild blocks non-clustered wild --- */
  diag("Scenario A: clustered wild blocks non-clustered wild");

  clustered = ooft_alloc_endpoint(thr_c, IPPROTO_UDP, INADDR_ANY, htons(2000), INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(clustered, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(clustered, OOF_SOCKET_ADD_FLAG_CLUSTERED);
  cmp_ok(rc, "==", 0, "add clustered wild");
  check_all_filters(thr_c, thr_nc);

  non_clustered = ooft_alloc_endpoint(thr_nc, IPPROTO_UDP, INADDR_ANY, htons(2000),
                                      INADDR_ANY, 0);
  rc = ooft_endpoint_add(non_clustered, 0);
  cmp_ok(rc, "==", -EADDRINUSE, "non-clustered wild rejected");
  check_all_filters(thr_c, thr_nc);

  ooft_endpoint_expect_sw_remove_all(clustered);
  ooft_hw_filter_expect_remove_all(thr_c->ns);
  oof_socket_del(fm, &clustered->skf);

  /* --- Scenario B (BR-4.11): Non-clustered wild blocks clustered wild --- */
  diag("Scenario B: non-clustered wild blocks clustered wild");

  non_clustered = ooft_alloc_endpoint(thr_nc, IPPROTO_UDP, INADDR_ANY, htons(3000),
                                      INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(non_clustered, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(non_clustered, 0);
  cmp_ok(rc, "==", 0, "add non-clustered wild");
  check_all_filters(thr_c, thr_nc);

  clustered = ooft_alloc_endpoint(thr_c, IPPROTO_UDP, INADDR_ANY, htons(3000), INADDR_ANY, 0);
  rc = ooft_endpoint_add(clustered, OOF_SOCKET_ADD_FLAG_CLUSTERED);
  cmp_ok(rc, "==", -EADDRINUSE, "clustered wild rejected");
  check_all_filters(thr_c, thr_nc);

  ooft_endpoint_expect_sw_remove_all(non_clustered);
  ooft_hw_filter_expect_remove_all(thr_nc->ns);
  oof_socket_del(fm, &non_clustered->skf);

  /* --- Scenario C (BR-4.11): Semi-wild cluster compatibility --- */
  diag("Scenario C: clustered wild blocks non-clustered semi-wild");

  clustered = ooft_alloc_endpoint(thr_c, IPPROTO_UDP, INADDR_ANY, htons(4000), INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(clustered, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(clustered, OOF_SOCKET_ADD_FLAG_CLUSTERED);
  cmp_ok(rc, "==", 0, "add clustered wild");
  check_all_filters(thr_c, thr_nc);

  non_clustered = ooft_alloc_endpoint(thr_nc, IPPROTO_UDP, inet_addr("1.0.0.0"), htons(4000),
                                      INADDR_ANY, 0);
  rc = ooft_endpoint_add(non_clustered, 0);
  cmp_ok(rc, "==", -EADDRINUSE, "non-clustered semi-wild rejected");
  check_all_filters(thr_c, thr_nc);

  ooft_endpoint_expect_sw_remove_all(clustered);
  ooft_hw_filter_expect_remove_all(thr_c->ns);
  oof_socket_del(fm, &clustered->skf);

  /* --- Scenario D (BR-5.09): Clustered full-match rejected --- */
  diag("Scenario D: clustered full-match rejected with -EINVAL");

  clustered = ooft_alloc_endpoint(thr_c, IPPROTO_UDP, INADDR_ANY, htons(5000), INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(clustered, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(clustered, OOF_SOCKET_ADD_FLAG_CLUSTERED);
  cmp_ok(rc, "==", 0, "add clustered wild");
  check_all_filters(thr_c, thr_nc);

  full = ooft_alloc_endpoint(thr_c, IPPROTO_UDP, inet_addr("1.0.0.0"), htons(5000),
                             inet_addr("2.0.0.0"), htons(6000));
  rc = ooft_endpoint_add(full, OOF_SOCKET_ADD_FLAG_CLUSTERED);
  cmp_ok(rc, "==", -EINVAL, "clustered full-match rejected");
  check_all_filters(thr_c, thr_nc);

  ooft_endpoint_expect_sw_remove_all(clustered);
  ooft_hw_filter_expect_remove_all(thr_c->ns);
  oof_socket_del(fm, &clustered->skf);

  /* --- Scenario E (BR-4.11): Non-clustered semi-wild blocks clustered wild.
   *     This exercises oof_are_all_addrs_cluster_compatible iterating
   *     lpa_semi_wild_socks, a different path from the wild-list check. --- */
  diag("Scenario E: non-clustered semi-wild blocks clustered wild");

  non_clustered = ooft_alloc_endpoint(thr_nc, IPPROTO_UDP, inet_addr("1.0.0.0"), htons(6000),
                                      INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(non_clustered, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(non_clustered, 0);
  cmp_ok(rc, "==", 0, "add non-clustered semi-wild");
  check_all_filters(thr_c, thr_nc);

  clustered = ooft_alloc_endpoint(thr_c, IPPROTO_UDP, INADDR_ANY, htons(6000), INADDR_ANY, 0);
  rc = ooft_endpoint_add(clustered, OOF_SOCKET_ADD_FLAG_CLUSTERED);
  cmp_ok(rc, "==", -EADDRINUSE, "clustered wild rejected by semi-wild");
  check_all_filters(thr_c, thr_nc);

  ooft_endpoint_expect_sw_remove_all(non_clustered);
  ooft_hw_filter_expect_remove_all(thr_nc->ns);
  oof_socket_del(fm, &non_clustered->skf);
  check_all_filters(thr_c, thr_nc);

  /* --- Scenario F: NO_UCAST non-clustered coexists with clustered --- */
  diag("Scenario F: non-clustered NO_UCAST bypasses cluster compat check");

  clustered = ooft_alloc_endpoint(thr_c, IPPROTO_UDP, INADDR_ANY, htons(7000), INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(clustered, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(clustered, OOF_SOCKET_ADD_FLAG_CLUSTERED);
  cmp_ok(rc, "==", 0, "add clustered wild");
  check_all_filters(thr_c, thr_nc);

  non_clustered = ooft_alloc_endpoint(thr_nc, IPPROTO_UDP, INADDR_ANY, htons(7000),
                                      INADDR_ANY, 0);
  rc = ooft_endpoint_add(non_clustered, OOF_SOCKET_ADD_FLAG_NO_UCAST);
  cmp_ok(rc, "==", 0, "non-clustered NO_UCAST accepted");
  check_all_filters(thr_c, thr_nc);

  oof_socket_del(fm, &non_clustered->skf);
  ooft_endpoint_expect_sw_remove_all(clustered);
  ooft_hw_filter_expect_remove_all(thr_c->ns);
  oof_socket_del(fm, &clustered->skf);
  check_all_filters(thr_c, thr_nc);

  /* --- Scenario G: NO_UCAST clustered coexists with non-clustered --- */
  diag("Scenario G: clustered NO_UCAST bypasses cluster compat check");

  non_clustered = ooft_alloc_endpoint(thr_nc, IPPROTO_UDP, INADDR_ANY, htons(8000),
                                      INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(non_clustered, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(non_clustered, 0);
  cmp_ok(rc, "==", 0, "add non-clustered wild");
  check_all_filters(thr_c, thr_nc);

  clustered = ooft_alloc_endpoint(thr_c, IPPROTO_UDP, INADDR_ANY, htons(8000), INADDR_ANY, 0);
  rc = ooft_endpoint_add(clustered,
                         OOF_SOCKET_ADD_FLAG_CLUSTERED | OOF_SOCKET_ADD_FLAG_NO_UCAST);
  cmp_ok(rc, "==", 0, "clustered NO_UCAST accepted");
  check_all_filters(thr_c, thr_nc);

  oof_socket_del(fm, &clustered->skf);
  ooft_endpoint_expect_sw_remove_all(non_clustered);
  ooft_hw_filter_expect_remove_all(thr_nc->ns);
  oof_socket_del(fm, &non_clustered->skf);
  check_all_filters(thr_c, thr_nc);

  ooft_free_stack(thr_nc);
  ooft_free_stack(thr_c);
  ooft_free_cluster(thc);
  test_cleanup();
  done_testing();
}
