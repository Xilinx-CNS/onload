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


static void check_filters(tcp_helper_resource_t* thr)
{
  int rc;
  rc = ooft_stack_check_sw_filters(thr);
  cmp_ok(rc, "==", 0, "check sw filters");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "check hw filters");
}


/* BR-3.09 (port-down + port-up), BR-3.10 (port removal),
 * BR-3.11 (two-phase flush), BR-3.12 (filter update effects).
 *
 * Scenario A: Bring hwport 0 down with active UDP and TCP sockets.
 *   - UDP filters on hw0 are removed (no drop filters for UDP).
 *   - TCP filters on hw0 are redirected to DROP.
 *   - All filters on hw1 are unchanged.
 *   - SW filters are unchanged.
 *
 * Scenario B: Bring hwport 0 back up.
 *   - UDP filters on hw0 are reinstalled.
 *   - TCP drop filters on hw0 are redirected back to the real VI.
 *
 * Scenario C: Remove hwport 0 (two-phase flush).
 *   - Phase 1: hw0 is neither up nor down — all filters removed.
 *   - Phase 2: hw0 is marked down — TCP gets DROP filter, UDP stays removed.
 */
int test_hwport_lifecycle(void)
{
  tcp_helper_resource_t* thr;
  struct ooft_endpoint* udp_wild;
  struct ooft_endpoint* tcp_listen;
  struct ooft_endpoint* tcp_passive;
  ci_dllist hw_udp;
  ci_dllist hw_listen;
  ci_dllist hw0_udp;
  ci_dllist hw0_tcp;
  unsigned op_seq_before_remove;
  unsigned phase1_remove_seq;
  unsigned phase2_insert_seq;
  struct ooft_hwport* hw0;
  struct ooft_hwport* hw1;
  struct oof_manager* fm;
  int rc;

  new_test();
  plan(24);

  test_alloc(32);
  thr = ooft_alloc_stack(8);
  fm = thr->ofn->ofn_filter_manager;
  TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X2_FF));

  ci_dllist_init(&hw_udp);
  ci_dllist_init(&hw_listen);
  ci_dllist_init(&hw0_udp);
  ci_dllist_init(&hw0_tcp);

  hw0 = ooft_hwport_from_id(0);
  hw1 = ooft_hwport_from_id(1);
  TEST(hw0);
  TEST(hw1);

  /* Set up sockets: UDP wild and TCP listener */
  udp_wild = ooft_alloc_endpoint(thr, IPPROTO_UDP, 0, htons(2000), 0, 0);
  tcp_listen = ooft_alloc_endpoint(thr, IPPROTO_TCP, 1, htons(3000), 0, 0);
  tcp_passive = ooft_alloc_endpoint(thr, IPPROTO_TCP, 1, htons(3000),
                                    2, htons(4000));

  ooft_endpoint_expect_unicast_filters(udp_wild, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(udp_wild, 0);
  cmp_ok(rc, "==", 0, "add UDP wild");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_udp);

  ooft_endpoint_expect_unicast_filters(tcp_listen, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(tcp_listen, 0);
  cmp_ok(rc, "==", 0, "add TCP listener");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_listen);

  ooft_endpoint_expect_unicast_filters(tcp_passive, 0);
  {
    ci_addr_t laddr = CI_ADDR_FROM_IP4(tcp_passive->laddr_be);
    ci_addr_t raddr = CI_ADDR_FROM_IP4(tcp_passive->raddr_be);
    rc = oof_socket_share(fm, &tcp_passive->skf, &tcp_listen->skf,
                          AF_SPACE_FLAG_IP4, laddr, raddr,
                          tcp_passive->lport_be, tcp_passive->rport_be);
  }
  cmp_ok(rc, "==", 0, "add TCP passive (shares listener)");
  check_filters(thr);

  TEST_DEBUG(oof_onload_manager_dump(&efab_tcp_driver, dump, "\n"));

  /* --- Scenario A (BR-3.09 port-down, BR-3.12): hwport 0 goes down --- */
  diag("Scenario A: hwport 0 down");

  /* UDP: filters on hw0 are simply removed (no drop filters for UDP) */
  ooft_client_hw_filter_matches_hwport(&hw_udp, &hw0_udp, hw0);
  ooft_hw_filter_expect_remove_list(&hw0_udp);

  /* TCP: filters on hw0 are redirected to DROP.
   * The redirect does a remove of the existing filter then insert of the
   * drop filter (with dmaq_id = EFX_FILTER_RX_DMAQ_ID_DROP). */
  ooft_client_hw_filter_matches_hwport(&hw_listen, &hw0_tcp, hw0);
  ooft_hw_filter_expect_remove_list(&hw0_tcp);
  ooft_client_expect_hw_add_ip(oo_nics[hw0->id].efrm_client,
                               EFX_FILTER_RX_DMAQ_ID_DROP,
                               tcp_helper_vi_hw_stack_id(thr, hw0->id),
                               EFX_FILTER_VID_UNSPEC, IPPROTO_TCP,
                               tcp_listen->laddr_be, tcp_listen->lport_be,
                               0, 0);

  ooft_hwport_up_down(hw0, 0);
  check_filters(thr);

  /* Claim the drop filter so we can track it for the up transition */
  ooft_cplane_claim_added_hw_filters(cp, &hw0_tcp);

  /* --- Scenario B (BR-3.09 port-up): hwport 0 comes back up --- */
  diag("Scenario B: hwport 0 back up");

  /* UDP: filters on hw0 are reinstalled (hw1 unchanged — REDIRECT-NOP) */
  ooft_client_expect_hw_add_ip(oo_nics[hw0->id].efrm_client,
                               tcp_helper_rx_vi_id(thr, hw0->id),
                               tcp_helper_vi_hw_stack_id(thr, hw0->id),
                               EFX_FILTER_VID_UNSPEC, IPPROTO_UDP,
                               inet_addr("1.0.0.0"), htons(2000), 0, 0);
  ooft_client_expect_hw_add_ip(oo_nics[hw0->id].efrm_client,
                               tcp_helper_rx_vi_id(thr, hw0->id),
                               tcp_helper_vi_hw_stack_id(thr, hw0->id),
                               EFX_FILTER_VID_UNSPEC, IPPROTO_UDP,
                               inet_addr("1.0.0.1"), htons(2000), 0, 0);

  /* TCP: drop filter on hw0 is redirected back to real VI.
   * This is another redirect: remove the drop filter, add the real one. */
  ooft_hw_filter_expect_remove_list(&hw0_tcp);
  ooft_client_expect_hw_add_ip(oo_nics[hw0->id].efrm_client,
                               tcp_helper_rx_vi_id(thr, hw0->id),
                               tcp_helper_vi_hw_stack_id(thr, hw0->id),
                               EFX_FILTER_VID_UNSPEC, IPPROTO_TCP,
                               tcp_listen->laddr_be, tcp_listen->lport_be,
                               0, 0);

  ooft_hwport_up_down(hw0, 1);
  check_filters(thr);

  /* Clean up scenario A/B: delete all sockets, expect all filter removal.
   * hw_listen contains a stale hw0 TCP filter (its filter_id was invalidated
   * by the Scenario A redirect cycle). Extract only the hw1 entry. */
  {
    ci_dllist hw1_listen;
    ci_dllist_init(&hw1_listen);
    ooft_client_hw_filter_matches_hwport(&hw_listen, &hw1_listen, hw1);

    ooft_endpoint_expect_sw_remove_all(tcp_passive);
    oof_socket_del(fm, &tcp_passive->skf);

    ooft_endpoint_expect_sw_remove_all(tcp_listen);
    ooft_endpoint_expect_sw_remove_all(udp_wild);
    ooft_hw_filter_expect_remove_list(&hw1_listen);
    ooft_hw_filter_expect_remove_list(&hw_udp);
    ooft_cplane_expect_hw_remove_all(cp);
    oof_socket_del(fm, &tcp_listen->skf);
    oof_socket_del(fm, &udp_wild->skf);
  }

  /* --- Scenario C (BR-3.10, BR-3.11): hwport 0 removed --- */
  diag("Scenario C: hwport 0 removed (two-phase flush)");

  ci_dllist_init(&hw_udp);
  ci_dllist_init(&hw_listen);
  ci_dllist_init(&hw0_udp);
  ci_dllist_init(&hw0_tcp);

  /* Fresh sockets */
  udp_wild = ooft_alloc_endpoint(thr, IPPROTO_UDP, 0, htons(5000), 0, 0);
  tcp_listen = ooft_alloc_endpoint(thr, IPPROTO_TCP, 1, htons(6000), 0, 0);

  ooft_endpoint_expect_unicast_filters(udp_wild, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(udp_wild, 0);
  cmp_ok(rc, "==", 0, "add UDP wild (scenario C)");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_udp);

  ooft_endpoint_expect_unicast_filters(tcp_listen, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(tcp_listen, 0);
  cmp_ok(rc, "==", 0, "add TCP listener (scenario C)");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_listen);

  /* Port removal two-phase cycle (oof_filters.c __oof_do_deferred_work):
   *
   * oof_hwport_removed sets hwports_up_new &= ~hw0, hwports_down_new |= hw0,
   * hwports_removed |= hw0.
   *
   * Phase 1: fm_hwports_up = hwports_up_new & ~hwports_removed  (hw0 cleared)
   *          fm_hwports_down = hwports_down_new & ~hwports_removed (hw0 cleared)
   *          hw0 is neither up nor down — filters are simply removed.
   *
   * Phase 2: fm_hwports_up = hwports_up_new   (hw0 still cleared — was cleared
   *                                             by oof_hwport_removed)
   *          fm_hwports_down = hwports_down_new (hw0 set)
   *          hw0 is now DOWN: TCP gets DROP filter, UDP stays removed. */

  /* Phase 1: expect removal of all hw0 filters */
  op_seq_before_remove = ooft_client_removed_max_op_seq_since(
                                   oo_nics[hw0->id].efrm_client, 0);
  ooft_client_hw_filter_matches_hwport(&hw_udp, &hw0_udp, hw0);
  ooft_hw_filter_expect_remove_list(&hw0_udp);
  ooft_client_hw_filter_matches_hwport(&hw_listen, &hw0_tcp, hw0);
  ooft_hw_filter_expect_remove_list(&hw0_tcp);

  /* Phase 2: expect TCP DROP filter on hw0 (same as port-down).
   * UDP stays removed — hw0 is not in fm_hwports_up. */
  ooft_client_expect_hw_add_ip(oo_nics[hw0->id].efrm_client,
                               EFX_FILTER_RX_DMAQ_ID_DROP,
                               tcp_helper_vi_hw_stack_id(thr, hw0->id),
                               EFX_FILTER_VID_UNSPEC, IPPROTO_TCP,
                               tcp_listen->laddr_be, tcp_listen->lport_be,
                               0, 0);

  ooft_hwport_removed(hw0);
  check_filters(thr);

  /* Claim the TCP DROP filter for cleanup tracking */
  ooft_cplane_claim_added_hw_filters(cp, &hw0_tcp);
  phase1_remove_seq = ooft_client_removed_max_op_seq_since(
                                   oo_nics[hw0->id].efrm_client,
                                   op_seq_before_remove);
  phase2_insert_seq = ooft_hw_filter_min_op_seq(&hw0_tcp);
  ok(phase1_remove_seq != 0 && phase2_insert_seq > phase1_remove_seq,
     "removed-port filters are removed before the drop filter is inserted");

  /* Clean up: hw0 has TCP DROP only, hw1 has original TCP + UDP.
   * hw_listen has hw1 TCP, hw_udp has hw1 UDP entries. */
  ooft_endpoint_expect_sw_remove_all(udp_wild);
  ooft_endpoint_expect_sw_remove_all(tcp_listen);
  ooft_hw_filter_expect_remove_list(&hw_listen);
  ooft_hw_filter_expect_remove_list(&hw_udp);
  ooft_hw_filter_expect_remove_list(&hw0_tcp);
  oof_socket_del(fm, &tcp_listen->skf);
  oof_socket_del(fm, &udp_wild->skf);
  check_filters(thr);

  ooft_free_stack(thr);
  test_cleanup();
  done_testing();
}
