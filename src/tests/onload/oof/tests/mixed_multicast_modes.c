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


static void check_all_filters(tcp_helper_resource_t* stack_a,
                              tcp_helper_resource_t* stack_b)
{
  int rc;

  rc = ooft_stack_check_sw_filters(stack_a);
  cmp_ok(rc, "==", 0, "check sw filters stack A");
  rc = ooft_stack_check_sw_filters(stack_b);
  cmp_ok(rc, "==", 0, "check sw filters stack B");
  rc = ooft_ns_check_hw_filters(stack_a->ns);
  cmp_ok(rc, "==", 0, "check hw filters");
}


/* Multicast replication in a heterogeneous namespace with stacks using
 * different receive modes.
 *
 * Stack A (BOTH) and stack B (FF) join the same group on one X4 express
 * interface and one X2 enterprise interface.  On the express interface,
 * A uses CT while B uses the shadow FF port.  On the enterprise interface,
 * both use FF; multicast replication permits one filter per stack there.
 */
int test_mixed_multicast_modes(void)
{
  tcp_helper_resource_t* stack_a;
  tcp_helper_resource_t* stack_b;
  struct ooft_endpoint* endpoint_a;
  struct ooft_endpoint* endpoint_b;
  struct ooft_ifindex* express;
  struct ooft_ifindex* enterprise;
  ci_dllist hw_a_express;
  ci_dllist hw_b_express;
  ci_dllist hw_a_enterprise;
  ci_dllist hw_b_enterprise;
  struct oof_manager* fm;
  unsigned group_be = inet_addr("230.1.2.3");
  int rc;

  new_test();
  plan(NO_PLAN);

  test_alloc(32);
  stack_a = ooft_alloc_stack_mode(64, OOFT_RX_BOTH);
  stack_b = ooft_alloc_stack_mode(64, OOFT_RX_FF);
  fm = stack_a->ofn->ofn_filter_manager;

  TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X4_FF));
  TRY(ooft_cplane_add_nic(current_ns(), OOFT_NIC_X2_FF,
                          (unsigned char[6]){ 0,1,0,0,0,2 },
                          inet_addr("1.0.0.2"),
                          (unsigned char[6]){ 0,1,0,0,0,3 },
                          inet_addr("1.0.0.3")));

  express = ooft_idx_from_id(1);
  enterprise = ooft_idx_from_id(3);
  TEST(express);
  TEST(enterprise);
  ok(express->hwport_mask_ll != 0, "express interface has LL datapath");
  ok(enterprise->hwport_mask_ll == 0,
     "enterprise interface has no LL datapath");
  ci_dllist_init(&hw_a_express);
  ci_dllist_init(&hw_b_express);
  ci_dllist_init(&hw_a_enterprise);
  ci_dllist_init(&hw_b_enterprise);

  endpoint_a = ooft_alloc_endpoint(stack_a, IPPROTO_UDP, group_be,
                                   htons(2000), INADDR_ANY, 0);
  endpoint_b = ooft_alloc_endpoint(stack_b, IPPROTO_UDP, group_be,
                                   htons(2000), INADDR_ANY, 0);
  rc = ooft_endpoint_add(endpoint_a, 0);
  cmp_ok(rc, "==", 0, "add multicast endpoint in stack A");
  rc = ooft_endpoint_add(endpoint_b, 0);
  cmp_ok(rc, "==", 0, "add multicast endpoint in stack B");
  check_all_filters(stack_a, stack_b);

  /* Express interface: BOTH chooses CT and FF chooses its shadow FF port. */
  ooft_endpoint_expect_multicast_filters(endpoint_a, express,
                                         express->hwport_mask_ll, group_be);
  rc = ooft_endpoint_mcast_add(endpoint_a, group_be, express);
  cmp_ok(rc, "==", 0, "stack A joins express interface on CT");
  check_all_filters(stack_a, stack_b);
  ooft_cplane_claim_added_hw_filters(cp, &hw_a_express);

  ooft_endpoint_expect_multicast_filters(endpoint_b, express,
                                         express->hwport_mask_ff, group_be);
  rc = ooft_endpoint_mcast_add(endpoint_b, group_be, express);
  cmp_ok(rc, "==", 0, "stack B joins express interface on FF");
  check_all_filters(stack_a, stack_b);
  ooft_cplane_claim_added_hw_filters(cp, &hw_b_express);

  /* Enterprise interface: both stacks use FF.  It supports multicast
   * replication, so each stack receives its own filter on this port. */
  ooft_endpoint_expect_multicast_hw_filters(endpoint_a, enterprise,
                                            enterprise->hwport_mask_ff,
                                            group_be);
  rc = ooft_endpoint_mcast_add(endpoint_a, group_be, enterprise);
  cmp_ok(rc, "==", 0, "stack A joins enterprise interface on FF");
  check_all_filters(stack_a, stack_b);
  ooft_cplane_claim_added_hw_filters(cp, &hw_a_enterprise);

  ooft_endpoint_expect_multicast_hw_filters(endpoint_b, enterprise,
                                            enterprise->hwport_mask_ff,
                                            group_be);
  rc = ooft_endpoint_mcast_add(endpoint_b, group_be, enterprise);
  cmp_ok(rc, "==", 0, "stack B joins enterprise interface on FF");
  check_all_filters(stack_a, stack_b);
  ooft_cplane_claim_added_hw_filters(cp, &hw_b_enterprise);

  /* Remove A's memberships.  B's CT/FF coverage and software filter must
   * remain while its memberships are still present. */
  ooft_hw_filter_expect_remove_list(&hw_a_express);
  ooft_endpoint_mcast_del(endpoint_a, group_be, express);
  check_all_filters(stack_a, stack_b);

  ooft_hw_filter_expect_remove_list(&hw_a_enterprise);
  ooft_endpoint_expect_sw_remove_all(endpoint_a);
  ooft_endpoint_mcast_del(endpoint_a, group_be, enterprise);
  check_all_filters(stack_a, stack_b);

  /* Now remove B's memberships and its final software filter. */
  ooft_hw_filter_expect_remove_list(&hw_b_express);
  ooft_endpoint_mcast_del(endpoint_b, group_be, express);
  check_all_filters(stack_a, stack_b);

  ooft_hw_filter_expect_remove_list(&hw_b_enterprise);
  ooft_endpoint_expect_sw_remove_all(endpoint_b);
  ooft_endpoint_mcast_del(endpoint_b, group_be, enterprise);
  check_all_filters(stack_a, stack_b);

  oof_socket_del(fm, &endpoint_a->skf);
  oof_socket_del(fm, &endpoint_b->skf);
  check_all_filters(stack_a, stack_b);

  ooft_free_stack(stack_a);
  ooft_free_stack(stack_b);
  test_cleanup();
  done_testing();
}
