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
#include <arpa/inet.h>


static void check_all_filters(tcp_helper_resource_t* stack_a,
                              tcp_helper_resource_t* stack_b)
{
  int rc;
  rc = ooft_stack_check_sw_filters(stack_a);
  cmp_ok(rc, "==", 0, "check sw filters stack A");
  if( stack_b != NULL ) {
    rc = ooft_stack_check_sw_filters(stack_b);
    cmp_ok(rc, "==", 0, "check sw filters stack B");
  }
  rc = ooft_ns_check_hw_filters(stack_a->ns);
  cmp_ok(rc, "==", 0, "check hw filters");
}


/* Wild-filter sharing and threshold-driven unsharing over a heterogeneous
 * port set - the mixed-config analogue of threshold_sharing.
 *
 * The namespace mixes two X4 express interfaces (FF ports shadowed by
 * CT/LL siblings, addrs 1.0.0.0 and 1.0.0.1) with two X2 enterprise
 * interfaces (FF only, addrs 1.0.0.2 and 1.0.0.3).  A listener on an
 * express address gets a wild HW filter spanning the mixed port set
 * (CT ports 2,3 plus FF ports 4,5 in OOFT_RX_BOTH mode).  Passive
 * sockets share that single filter; when sharers drop below keep_thresh
 * they unshare into their own 5-tuple HW filters across the whole mixed
 * set.  This exercises the share/unshare machinery over a non-uniform
 * port set, which uniform-NIC tests never covered.
 */
int test_mixed_threshold_sharing(void)
{
  tcp_helper_resource_t* stack_a;
  tcp_helper_resource_t* stack_b;
  struct ooft_endpoint* listener;
  struct ooft_endpoint* passive[4];
  struct ooft_endpoint* wild_b;
  ci_dllist hw_listener;
  ci_dllist hw_passive;
  struct oof_manager* fm;
  int rc, i;
  int saved_keep, saved_steal;

  new_test();
  plan(NO_PLAN);

  test_alloc(32);
  stack_a = ooft_alloc_stack_mode(16, OOFT_RX_BOTH);
  stack_b = ooft_alloc_stack_mode(4, OOFT_RX_BOTH);
  fm = stack_a->ofn->ofn_filter_manager;

  TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X4_FF));
  TRY(ooft_cplane_add_nic(current_ns(), OOFT_NIC_X2_FF,
                          (unsigned char[6]){ 0,1,0,0,0,2 }, inet_addr("1.0.0.2"),
                          (unsigned char[6]){ 0,1,0,0,0,3 }, inet_addr("1.0.0.3")));

  ci_dllist_init(&hw_listener);
  ci_dllist_init(&hw_passive);

  saved_keep = oof_shared_keep_thresh;
  saved_steal = oof_shared_steal_thresh;

  /* --- Scenario A: passives exceed keep_thresh, keep sharing --- */
  diag("Scenario A: passives exceed keep_thresh, keep sharing mixed filter");

  oof_shared_keep_thresh = 2;

  /* Listener on an express address; its wild HW filter spans the mixed
   * port set. */
  listener = ooft_alloc_endpoint(stack_a, IPPROTO_TCP, inet_addr("1.0.0.0"),
                                 htons(4000), INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(listener, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(listener, 0);
  cmp_ok(rc, "==", 0, "add listener");
  check_all_filters(stack_a, NULL);
  ooft_cplane_claim_added_hw_filters(cp, &hw_listener);

  /* Add 4 passives, all sharing the listener's wild HW filter. */
  for( i = 0; i < 4; i++ ) {
    in_addr_t lip = inet_addr("1.0.0.0");
    in_addr_t rip = inet_addr("2.0.0.0") + i;
    in_port_t rport = htons(5000 + i);
    ci_addr_t laddr = CI_ADDR_FROM_IP4(lip);
    ci_addr_t raddr = CI_ADDR_FROM_IP4(rip);
    passive[i] = ooft_alloc_endpoint(stack_a, IPPROTO_TCP, lip, htons(4000),
                                     rip, rport);
    ooft_endpoint_expect_unicast_filters(passive[i], 0);
    rc = oof_socket_share(fm, &passive[i]->skf, &listener->skf,
                          AF_SPACE_FLAG_IP4, laddr, raddr,
                          passive[i]->lport_be, passive[i]->rport_be);
    cmp_ok(rc, "==", 0, "share passive");
    check_all_filters(stack_a, NULL);
  }

  /* Delete listener: no wild socket, sharers=4 > keep_thresh=2 ->
   * passives KEEP sharing, the mixed-set HW filter is retained. */
  ooft_endpoint_expect_sw_remove_all(listener);
  oof_socket_del(fm, &listener->skf);
  check_all_filters(stack_a, NULL);

  /* Delete passives one by one.
   * passive[0]: sharers 4->3, 3 > 2 -> suppress unshare.
   * passive[1]: sharers 3->2, 2 > 2 is false -> unshare: passive[2] and
   *   [3] each get their own 5-tuple HW filters across the mixed set, and
   *   the shared wild HW filter is cleared. */
  ooft_endpoint_expect_sw_remove_all(passive[0]);
  oof_socket_del(fm, &passive[0]->skf);
  check_all_filters(stack_a, NULL);

  ooft_endpoint_expect_sw_remove_all(passive[1]);
  ooft_hw_filter_expect_remove_list(&hw_listener);
  for( i = 2; i < 4; i++ )
    ooft_endpoint_expect_hw_unicast(passive[i], passive[i]->laddr_be, 0);
  oof_socket_del(fm, &passive[1]->skf);
  check_all_filters(stack_a, NULL);
  ooft_cplane_claim_added_hw_filters(cp, &hw_passive);

  /* passive[2] and [3] now own their filters across the mixed set. */
  ooft_hw_filter_expect_remove_list(&hw_passive);
  for( i = 2; i < 4; i++ ) {
    ooft_endpoint_expect_sw_remove_all(passive[i]);
    oof_socket_del(fm, &passive[i]->skf);
  }
  check_all_filters(stack_a, NULL);

  /* --- Scenario B: sharers below keep_thresh unshare on listener delete --- */
  diag("Scenario B: sharers below keep_thresh unshare across mixed set");

  oof_shared_keep_thresh = 5;

  listener = ooft_alloc_endpoint(stack_a, IPPROTO_TCP, inet_addr("1.0.0.0"),
                                 htons(6000), INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(listener, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(listener, 0);
  cmp_ok(rc, "==", 0, "add listener for unshare test");
  check_all_filters(stack_a, NULL);
  ci_dllist_init(&hw_listener);
  ooft_cplane_claim_added_hw_filters(cp, &hw_listener);

  for( i = 0; i < 2; i++ ) {
    in_addr_t lip = inet_addr("1.0.0.0");
    in_addr_t rip = inet_addr("2.0.0.0") + i;
    in_port_t rport = htons(7000 + i);
    ci_addr_t laddr = CI_ADDR_FROM_IP4(lip);
    ci_addr_t raddr = CI_ADDR_FROM_IP4(rip);
    passive[i] = ooft_alloc_endpoint(stack_a, IPPROTO_TCP, lip, htons(6000),
                                     rip, rport);
    ooft_endpoint_expect_unicast_filters(passive[i], 0);
    rc = oof_socket_share(fm, &passive[i]->skf, &listener->skf,
                          AF_SPACE_FLAG_IP4, laddr, raddr,
                          passive[i]->lport_be, passive[i]->rport_be);
    cmp_ok(rc, "==", 0, "share passive for unshare test");
    check_all_filters(stack_a, NULL);
  }

  /* Delete listener: sharers=2 <= keep_thresh=5 -> each passive gets its
   * own 5-tuple HW filter across the mixed set, wild HW filter removed. */
  ooft_endpoint_expect_sw_remove_all(listener);
  ooft_hw_filter_expect_remove_list(&hw_listener);
  for( i = 0; i < 2; i++ )
    ooft_endpoint_expect_hw_unicast(passive[i], passive[i]->laddr_be, 0);
  oof_socket_del(fm, &listener->skf);
  check_all_filters(stack_a, NULL);
  ci_dllist_init(&hw_passive);
  ooft_cplane_claim_added_hw_filters(cp, &hw_passive);

  ooft_hw_filter_expect_remove_list(&hw_passive);
  for( i = 0; i < 2; i++ ) {
    ooft_endpoint_expect_sw_remove_all(passive[i]);
    oof_socket_del(fm, &passive[i]->skf);
  }
  check_all_filters(stack_a, NULL);

  /* --- Scenario C: steal_thresh blocks a cross-stack steal --- */
  diag("Scenario C: steal_thresh blocks stealing the mixed filter");

  oof_shared_keep_thresh = saved_keep;
  oof_shared_steal_thresh = 2;

  listener = ooft_alloc_endpoint(stack_a, IPPROTO_TCP, inet_addr("1.0.0.0"),
                                 htons(8000), INADDR_ANY, 0);
  wild_b = ooft_alloc_endpoint(stack_b, IPPROTO_TCP, inet_addr("1.0.0.0"),
                               htons(8000), INADDR_ANY, 0);

  ooft_endpoint_expect_unicast_filters(listener, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(listener, 0);
  cmp_ok(rc, "==", 0, "add listener in stack A");
  check_all_filters(stack_a, stack_b);
  ci_dllist_init(&hw_listener);
  ooft_cplane_claim_added_hw_filters(cp, &hw_listener);

  for( i = 0; i < 3; i++ ) {
    in_addr_t lip = inet_addr("1.0.0.0");
    in_addr_t rip = inet_addr("2.0.0.0") + i;
    in_port_t rport = htons(9000 + i);
    ci_addr_t laddr = CI_ADDR_FROM_IP4(lip);
    ci_addr_t raddr = CI_ADDR_FROM_IP4(rip);
    passive[i] = ooft_alloc_endpoint(stack_a, IPPROTO_TCP, lip, htons(8000),
                                     rip, rport);
    ooft_endpoint_expect_unicast_filters(passive[i], 0);
    rc = oof_socket_share(fm, &passive[i]->skf, &listener->skf,
                          AF_SPACE_FLAG_IP4, laddr, raddr,
                          passive[i]->lport_be, passive[i]->rport_be);
    cmp_ok(rc, "==", 0, "share passive for steal test");
    check_all_filters(stack_a, stack_b);
  }

  /* With three sharers and steal_thresh=2, the competing wild socket must
   * not take over the mixed CT+FF filter. */
  ooft_endpoint_expect_unicast_filters(wild_b, 0);
  rc = ooft_endpoint_add(wild_b, 0);
  cmp_ok(rc, "==", 0, "add wild B (steal blocked by threshold)");
  ok(listener->skf.sf_local_port->lp_addr[listener->skf.sf_la_i]
       .lpa_filter.trs == oof_cb_socket_stack(&listener->skf),
     "mixed filter remains owned by stack A");
  check_all_filters(stack_a, stack_b);

  ooft_endpoint_expect_sw_remove_all(wild_b);
  oof_socket_del(fm, &wild_b->skf);
  check_all_filters(stack_a, stack_b);

  for( i = 0; i < 3; i++ ) {
    ooft_endpoint_expect_sw_remove_all(passive[i]);
    oof_socket_del(fm, &passive[i]->skf);
    check_all_filters(stack_a, stack_b);
  }

  ooft_endpoint_expect_sw_remove_all(listener);
  ooft_hw_filter_expect_remove_list(&hw_listener);
  oof_socket_del(fm, &listener->skf);
  check_all_filters(stack_a, stack_b);

  oof_shared_keep_thresh = saved_keep;
  oof_shared_steal_thresh = saved_steal;

  ooft_free_stack(stack_a);
  ooft_free_stack(stack_b);
  test_cleanup();
  done_testing();
}
