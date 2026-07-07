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


/* Cross-stack wild-filter redirect between stacks with different receive
 * modes in a heterogeneous namespace.
 *
 * Stack A is OOFT_RX_BOTH, so its wild filters use CT ports 2,3 for the X4
 * interfaces and enterprise FF ports 4,5.  Stack B is OOFT_RX_FF.  Moving
 * the filter to B must remove the CT filters, install shadow FF ports 0,1,
 * and redirect the enterprise FF filters on ports 4,5.  Deleting B reverses
 * that transition.
 */
int test_mixed_filter_redirect_ff(void)
{
  tcp_helper_resource_t* stack_a;
  tcp_helper_resource_t* stack_b;
  struct ooft_endpoint* wild_a;
  struct ooft_endpoint* wild_b;
  ci_dllist hw_a;
  ci_dllist hw_b;
  struct oof_manager* fm;
  int rc;
  int i;
  static const char* addrs[4] = {
    "1.0.0.0", "1.0.0.1", "1.0.0.2", "1.0.0.3"
  };

  new_test();
  plan(NO_PLAN);

  test_alloc(32);
  stack_a = ooft_alloc_stack_mode(8, OOFT_RX_BOTH);
  stack_b = ooft_alloc_stack_mode(4, OOFT_RX_FF);
  fm = stack_a->ofn->ofn_filter_manager;

  TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X4_FF));
  TRY(ooft_cplane_add_nic(current_ns(), OOFT_NIC_X2_FF,
                          (unsigned char[6]){ 0,1,0,0,0,2 },
                          inet_addr("1.0.0.2"),
                          (unsigned char[6]){ 0,1,0,0,0,3 },
                          inet_addr("1.0.0.3")));

  ci_dllist_init(&hw_a);
  ci_dllist_init(&hw_b);

  /* Stack A owns the wild filter on its BOTH-mode set: CT 2,3 and FF 4,5. */
  wild_a = ooft_alloc_endpoint(stack_a, IPPROTO_UDP, INADDR_ANY, htons(2000),
                               INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(wild_a, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(wild_a, 0);
  cmp_ok(rc, "==", 0, "add wild A in BOTH mode");
  check_all_filters(stack_a, stack_b);
  ooft_cplane_claim_added_hw_filters(cp, &hw_a);

  /* Stack B takes ownership.  Its FF-only mode drops CT 2,3, adds shadow
   * FF 0,1, and redirects enterprise FF 4,5. */
  wild_b = ooft_alloc_endpoint(stack_b, IPPROTO_UDP, INADDR_ANY, htons(2000),
                               INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(wild_b, 0);
  ooft_hw_filter_expect_remove_list(&hw_a);
  for( i = 0; i < 4; i++ )
    ooft_endpoint_expect_hw_unicast(wild_b, inet_addr(addrs[i]), 0);
  rc = ooft_endpoint_add(wild_b, 0);
  cmp_ok(rc, "==", 0, "add wild B in FF mode (redirect)");
  check_all_filters(stack_a, stack_b);
  ooft_cplane_claim_added_hw_filters(cp, &hw_b);

  /* On return to stack A, FF 0,1 are removed, CT 2,3 are restored, and
   * enterprise FF 4,5 redirect back. */
  ooft_endpoint_expect_sw_remove_all(wild_b);
  ooft_hw_filter_expect_remove_list(&hw_b);
  for( i = 0; i < 4; i++ )
    ooft_endpoint_expect_hw_unicast(wild_a, inet_addr(addrs[i]), 0);
  oof_socket_del(fm, &wild_b->skf);
  check_all_filters(stack_a, stack_b);
  ooft_cplane_claim_added_hw_filters(cp, &hw_a);

  ooft_endpoint_expect_sw_remove_all(wild_a);
  ooft_hw_filter_expect_remove_list(&hw_a);
  oof_socket_del(fm, &wild_a->skf);
  check_all_filters(stack_a, stack_b);

  ooft_free_stack(stack_a);
  ooft_free_stack(stack_b);
  test_cleanup();
  done_testing();
}
