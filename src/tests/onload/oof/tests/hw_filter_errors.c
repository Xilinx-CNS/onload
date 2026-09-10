/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include "../onload_kernel_compat.h"
#include "../stack.h"
#include "../stack_interface.h"
#include "../../tap/tap.h"
#include "../oof_test.h"
#include "../cplane.h"
#include "../efrm.h"
#include "../oo_hw_filter.h"
#include "../utils.h"
#include "../efrm_interface.h"
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>


static void check_all_filters(tcp_helper_resource_t* thr1,
                              tcp_helper_resource_t* thr2)
{
  int rc;
  rc = ooft_stack_check_sw_filters(thr1);
  cmp_ok(rc, "==", 0, "check sw filters stack 1");
  if( thr2 != NULL ) {
    rc = ooft_stack_check_sw_filters(thr2);
    cmp_ok(rc, "==", 0, "check sw filters stack 2");
  }
  rc = ooft_ns_check_hw_filters(thr1->ns);
  cmp_ok(rc, "==", 0, "check hw filters");
}


/* BR-5.05: Full-match HW filter insertion failure — socket add fails and
 * SW filters are rolled back.
 *
 * BR-6.08: When fixup_wild tries to unshare full-match sockets from a
 * wild HW filter and the 5-tuple filter insert fails, the error is
 * absorbed — the new wild socket gets SW filters only.
 *
 * BR-5.14 / ERR-5.04: Partial HW filter success (-EFILTERSSOME).  When a
 * filter installs on some, but not all, hwports, the test checks that the
 * successfully installed HW filter and the required SW state are retained.
 * These scenarios exercise the partial-success paths that the full-failure
 * cases above do not reach.
 */
int test_hw_filter_errors(void)
{
  tcp_helper_resource_t* thr1;
  tcp_helper_resource_t* thr2;
  struct ooft_endpoint* wild_a;
  struct ooft_endpoint* full_b;
  struct ooft_endpoint* listener;
  struct ooft_endpoint* passive[2];
  struct ooft_endpoint* wild_b;
  struct ooft_endpoint* full_c;
  struct ooft_endpoint* semi_c;
  struct ooft_endpoint* nic_down;
  struct ooft_endpoint* eacc_g;
  struct ooft_endpoint* eacc_h;
  ci_dllist hw_wild;
  ci_dllist hw_listener;
  struct oof_manager* fm;
  int rc, i;

  new_test();
  plan(102);

  test_alloc(32);
  thr1 = ooft_alloc_stack(16);
  thr2 = ooft_alloc_stack(8);
  fm = thr1->ofn->ofn_filter_manager;
  TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X2_FF));

  ci_dllist_init(&hw_wild);
  ci_dllist_init(&hw_listener);

  /* --- Scenario A (BR-5.05): Full-match HW filter insert fails --- */
  diag("Scenario A: full-match HW filter insert fails with -EBUSY");

  wild_a = ooft_alloc_endpoint(thr1, IPPROTO_UDP, 0, htons(2000), 0, 0);
  ooft_endpoint_expect_unicast_filters(wild_a, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(wild_a, 0);
  cmp_ok(rc, "==", 0, "add wild UDP in stack A");
  check_all_filters(thr1, thr2);
  ooft_cplane_claim_added_hw_filters(cp, &hw_wild);

  /* oof_socket_add inserts SW filter first, then attempts HW.  Both hwports
   * will fail with -EBUSY, causing SW rollback.  We must expect both the
   * SW add and its removal. */
  efrm_filter_insert_fail_count = 2;

  full_b = ooft_alloc_endpoint(thr2, IPPROTO_UDP, 1, htons(2000),
                               2, htons(3000));
  ooft_endpoint_expect_unicast_filters(full_b, 0);
  ooft_endpoint_add_sw_filter(&full_b->sw_filters_to_remove, IPPROTO_UDP,
                              full_b->laddr_be, full_b->lport_be,
                              full_b->raddr_be, full_b->rport_be);
  rc = ooft_endpoint_add(full_b, 0);
  efrm_filter_insert_fail_count = 0;
  cmp_ok(rc, "==", -EBUSY, "full-match rejected with -EBUSY");
  check_all_filters(thr1, thr2);

  /* Clean up wild_a */
  ooft_endpoint_expect_sw_remove_all(wild_a);
  ooft_hw_filter_expect_remove_list(&hw_wild);
  oof_socket_del(fm, &wild_a->skf);
  check_all_filters(thr1, thr2);

  /* --- Scenario B (BR-6.08): Unshare fails completely --- */
  diag("Scenario B: unshare fails completely, wild gets SW only");

  listener = ooft_alloc_endpoint(thr1, IPPROTO_TCP, 1, htons(4000), 0, 0);
  ooft_endpoint_expect_unicast_filters(listener, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(listener, 0);
  cmp_ok(rc, "==", 0, "add listener in stack A");
  check_all_filters(thr1, thr2);
  ooft_cplane_claim_added_hw_filters(cp, &hw_listener);

  for( i = 0; i < 2; i++ ) {
    ci_addr_t laddr = CI_ADDR_FROM_IP4(1);
    ci_addr_t raddr = CI_ADDR_FROM_IP4(i + 2);
    passive[i] = ooft_alloc_endpoint(thr1, IPPROTO_TCP, 1, htons(4000),
                                     i + 2, htons(5000 + i));
    ooft_endpoint_expect_unicast_filters(passive[i], 0);
    rc = oof_socket_share(fm, &passive[i]->skf, &listener->skf,
                          AF_SPACE_FLAG_IP4, laddr, raddr,
                          passive[i]->lport_be, passive[i]->rport_be);
    cmp_ok(rc, "==", 0, "share passive %d", i);
    check_all_filters(thr1, thr2);
  }

  /* oof_full_socks_add_hw_filters iterates lpa_full_socks in LIFO order,
   * so passive[1] is attempted first.  Both hwports fail → total failure.
   * fixup_wild absorbs the error; wild_b gets SW filters only. */
  efrm_filter_insert_fail_count = 2;

  wild_b = ooft_alloc_endpoint(thr2, IPPROTO_TCP, 1, htons(4000), 0, 0);
  ooft_endpoint_expect_unicast_filters(wild_b, 0);
  rc = ooft_endpoint_add(wild_b, 0);
  efrm_filter_insert_fail_count = 0;
  cmp_ok(rc, "==", 0, "add semi-wild in stack B (unshare failed)");
  check_all_filters(thr1, thr2);

  /* Clean up: wild_b, passives, listener */
  ooft_endpoint_expect_sw_remove_all(wild_b);
  oof_socket_del(fm, &wild_b->skf);
  check_all_filters(thr1, thr2);
  for( i = 0; i < 2; i++ ) {
    ooft_endpoint_expect_sw_remove_all(passive[i]);
    oof_socket_del(fm, &passive[i]->skf);
    check_all_filters(thr1, thr2);
  }
  ooft_endpoint_expect_sw_remove_all(listener);
  ooft_hw_filter_expect_remove_list(&hw_listener);
  oof_socket_del(fm, &listener->skf);
  check_all_filters(thr1, thr2);

  /* --- Scenario C (BR-6.08): Partial unshare with rollback --- */
  diag("Scenario C: partial unshare triggers rollback");

  listener = ooft_alloc_endpoint(thr1, IPPROTO_TCP, 1, htons(5000), 0, 0);
  ooft_endpoint_expect_unicast_filters(listener, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(listener, 0);
  cmp_ok(rc, "==", 0, "add listener in stack A");
  check_all_filters(thr1, thr2);
  ooft_cplane_claim_added_hw_filters(cp, &hw_listener);

  for( i = 0; i < 2; i++ ) {
    ci_addr_t laddr = CI_ADDR_FROM_IP4(1);
    ci_addr_t raddr = CI_ADDR_FROM_IP4(i + 2);
    passive[i] = ooft_alloc_endpoint(thr1, IPPROTO_TCP, 1, htons(5000),
                                     i + 2, htons(6000 + i));
    ooft_endpoint_expect_unicast_filters(passive[i], 0);
    rc = oof_socket_share(fm, &passive[i]->skf, &listener->skf,
                          AF_SPACE_FLAG_IP4, laddr, raddr,
                          passive[i]->lport_be, passive[i]->rport_be);
    cmp_ok(rc, "==", 0, "share passive %d", i);
    check_all_filters(thr1, thr2);
  }

  /* oof_full_socks_add_hw_filters iterates LIFO: passive[1] first.
   * fail_after=2: passive[1]'s 5-tuple inserts on both hwports succeed
   * (2 inserts), then all subsequent inserts fail (passive[0]).
   * oof_full_socks_del_hw_filters rolls back passive[1]'s 2 HW filters.
   * Expect passive[1]'s HW filter add (which will be rolled back). */
  efrm_filter_insert_fail_after = 2;
  efrm_filter_rollback_remove_count = 2;
  ooft_endpoint_expect_hw_unicast(passive[1], passive[1]->laddr_be, 0);

  wild_b = ooft_alloc_endpoint(thr2, IPPROTO_TCP, 1, htons(5000), 0, 0);
  ooft_endpoint_expect_unicast_filters(wild_b, 0);
  rc = ooft_endpoint_add(wild_b, 0);
  efrm_filter_insert_fail_after = -1;
  cmp_ok(rc, "==", 0, "add semi-wild in stack B (partial unshare rolled back)");
  cmp_ok(efrm_filter_rollback_remove_count, "==", 0,
         "expected rollback HW removals consumed");
  check_all_filters(thr1, thr2);

  /* Clean up */
  ooft_endpoint_expect_sw_remove_all(wild_b);
  oof_socket_del(fm, &wild_b->skf);
  check_all_filters(thr1, thr2);
  for( i = 0; i < 2; i++ ) {
    ooft_endpoint_expect_sw_remove_all(passive[i]);
    oof_socket_del(fm, &passive[i]->skf);
    check_all_filters(thr1, thr2);
  }
  ooft_endpoint_expect_sw_remove_all(listener);
  ooft_hw_filter_expect_remove_list(&hw_listener);
  oof_socket_del(fm, &listener->skf);
  check_all_filters(thr1, thr2);

  /* --- Scenario D (BR-5.14 / ERR-5.04): partial HW success -EFILTERSSOME --- */
  diag("Scenario D: full-match partial HW install is kept (-EFILTERSSOME)");

  /* A standalone full-match socket has no wild filter, so it takes the
   * own-5-tuple path.  With fail_count=1, the insert on hw0 fails and the
   * insert on hw1 succeeds.  The test expects -EFILTERSSOME to be propagated
   * while the socket retains its SW filter and the HW filter on hw1. */
  efrm_filter_insert_fail_count = 1;

  full_c = ooft_alloc_endpoint(thr1, IPPROTO_UDP, 1, htons(6000),
                               2, htons(7000));
  /* SW filter installed and kept (flag 0 => no HW expected by the helper). */
  ooft_endpoint_expect_unicast_filters(full_c, 0);
  /* hw0 fails (not recorded); hw1's 5-tuple is installed and kept. */
  ooft_client_expect_hw_add_ip(oo_nics[1].efrm_client,
                               tcp_helper_rx_vi_id(thr1, 1),
                               tcp_helper_vi_hw_stack_id(thr1, 1),
                               EFX_FILTER_VID_UNSPEC, IPPROTO_UDP,
                               full_c->laddr_be, full_c->lport_be,
                               full_c->raddr_be, full_c->rport_be);
  rc = ooft_endpoint_add(full_c, 0);
  efrm_filter_insert_fail_count = 0;
  cmp_ok(rc, "==", -EFILTERSSOME, "full-match partial HW install -> -EFILTERSSOME");
  check_all_filters(thr1, thr2);

  /* hw0 failed and hw1 succeeded, so the partial HW filter remains on hw1. */
  cmp_ok(oo_hw_filter_hwports(&full_c->skf.sf_full_match_filter), "==",
         1u << 1, "partial HW filter kept on hw1 only");

  /* Socket kept with SW filter + the hw1 HW filter; teardown removes both. */
  ooft_endpoint_expect_sw_remove_all(full_c);
  ooft_client_expect_hw_remove_ip(oo_nics[1].efrm_client,
                                  tcp_helper_rx_vi_id(thr1, 1),
                                  tcp_helper_vi_hw_stack_id(thr1, 1),
                                  EFX_FILTER_VID_UNSPEC, IPPROTO_UDP,
                                  full_c->laddr_be, full_c->lport_be,
                                  full_c->raddr_be, full_c->rport_be);
  oof_socket_del(fm, &full_c->skf);
  check_all_filters(thr1, thr2);

  /* --- Scenario E (BR-5.14 / ERR-5.04): partial HW on a semi-wild socket --- */
  diag("Scenario E: semi-wild partial HW install keeps SW + partial HW");

  /* A semi-wild socket installs its wild HW filter on all available hwports.
   * With fail_count=1, the insert on hw0 fails and the insert on hw1 succeeds.
   * The test expects -EFILTERSSOME while retaining both the SW filter and the
   * partial HW filter on hw1. */
  efrm_filter_insert_fail_count = 1;

  semi_c = ooft_alloc_endpoint(thr1, IPPROTO_UDP, 1, htons(9000), 0, 0);
  /* SW filter for 1.0.0.0 installed and kept. */
  ooft_endpoint_expect_sw_add(semi_c, IPPROTO_UDP, semi_c->laddr_be,
                              semi_c->lport_be, 0, 0);
  /* hw0 fails (not recorded); hw1's wild filter is installed and kept. */
  ooft_client_expect_hw_add_ip(oo_nics[1].efrm_client,
                               tcp_helper_rx_vi_id(thr1, 1),
                               tcp_helper_vi_hw_stack_id(thr1, 1),
                               EFX_FILTER_VID_UNSPEC, IPPROTO_UDP,
                               semi_c->laddr_be, semi_c->lport_be, 0, 0);
  rc = ooft_endpoint_add(semi_c, 0);
  efrm_filter_insert_fail_count = 0;
  cmp_ok(rc, "==", -EFILTERSSOME, "semi-wild partial HW install -> -EFILTERSSOME");
  /* The SW filter must be preserved (check_all_filters fails here without the
   * guards: the SW filter would have been removed during the add). */
  check_all_filters(thr1, thr2);

  /* Teardown: the SW filter and the hw1 wild HW filter are both removed. */
  ooft_endpoint_expect_sw_remove_all(semi_c);
  ooft_client_expect_hw_remove_ip(oo_nics[1].efrm_client,
                                  tcp_helper_rx_vi_id(thr1, 1),
                                  tcp_helper_vi_hw_stack_id(thr1, 1),
                                  EFX_FILTER_VID_UNSPEC, IPPROTO_UDP,
                                  semi_c->laddr_be, semi_c->lport_be, 0, 0);
  oof_socket_del(fm, &semi_c->skf);
  check_all_filters(thr1, thr2);

  /* --- Scenario F (BR-5.17): NIC down on insert, -ENETDOWN: socket kept,
   *     no HW --- */
  diag("Scenario F: NIC-down (-ENETDOWN) on insert keeps socket, no HW filter");

  /* Simulate the NIC going away: efrm_filter_insert returns -ENETDOWN on
   * both hwports. oo_hw_filter_set_hwport_common treats -ENETDOWN as
   * non-fatal ("hardware has gone away", tcp_filters.c) — it records a
   * negative filter id and reports success — so the socket add succeeds with
   * no HW filter installed; filters are (re)installed when the NIC returns. */
  efrm_filter_insert_fail_rc = -ENETDOWN;
  efrm_filter_insert_fail_count = 2;   /* both hwports of the semi-wild filter */

  nic_down = ooft_alloc_endpoint(thr1, IPPROTO_UDP, 1, htons(9100), 0, 0);
  ooft_endpoint_expect_sw_add(nic_down, IPPROTO_UDP, nic_down->laddr_be,
                              nic_down->lport_be, 0, 0);
  rc = ooft_endpoint_add(nic_down, 0);
  efrm_filter_insert_fail_count = 0;
  efrm_filter_insert_fail_rc = -EBUSY;  /* restore default for any later use */
  cmp_ok(rc, "==", 0, "NIC-down: semi-wild add succeeds (-ENETDOWN non-fatal)");
  /* SW filter present; no HW filter installed (both inserts returned
   * -ENETDOWN before reaching the harness's filter bookkeeping). */
  check_all_filters(thr1, thr2);

  /* Teardown: only the SW filter is removed (no HW filter was installed). */
  ooft_endpoint_expect_sw_remove_all(nic_down);
  oof_socket_del(fm, &nic_down->skf);
  check_all_filters(thr1, thr2);

  /* --- Scenario G (BR-5.15): firewall block on one port, -EACCES:
   *     filter considered added on the remaining port(s) --- */
  diag("Scenario G: partial -EACCES is treated as added (port blocked)");

  /* A standalone full-match socket installs its own 5-tuple on both hwports.
   * With one hwport blocked by the firewall (-EACCES) and the other
   * succeeding, oo_hw_filter_add_hwports treats the filter as fully added
   * (the blocked port is dropped, not an error): the add returns 0 with the
   * HW filter present on the unblocked hwport only. */
  efrm_filter_insert_fail_rc = -EACCES;
  efrm_filter_insert_fail_count = 1;

  eacc_g = ooft_alloc_endpoint(thr1, IPPROTO_UDP, 1, htons(9200),
                               2, htons(9300));
  ooft_endpoint_expect_unicast_filters(eacc_g, 0);   /* SW filter */
  ooft_client_expect_hw_add_ip(oo_nics[1].efrm_client,
                               tcp_helper_rx_vi_id(thr1, 1),
                               tcp_helper_vi_hw_stack_id(thr1, 1),
                               EFX_FILTER_VID_UNSPEC, IPPROTO_UDP,
                               eacc_g->laddr_be, eacc_g->lport_be,
                               eacc_g->raddr_be, eacc_g->rport_be);
  rc = ooft_endpoint_add(eacc_g, 0);
  efrm_filter_insert_fail_count = 0;
  efrm_filter_insert_fail_rc = -EBUSY;
  cmp_ok(rc, "==", 0, "partial -EACCES: add succeeds (blocked port dropped)");
  cmp_ok(oo_hw_filter_hwports(&eacc_g->skf.sf_full_match_filter), "==",
         1u << 1, "HW filter on the unblocked hwport (hw1) only");
  check_all_filters(thr1, thr2);

  ooft_endpoint_expect_sw_remove_all(eacc_g);
  ooft_client_expect_hw_remove_ip(oo_nics[1].efrm_client,
                                  tcp_helper_rx_vi_id(thr1, 1),
                                  tcp_helper_vi_hw_stack_id(thr1, 1),
                                  EFX_FILTER_VID_UNSPEC, IPPROTO_UDP,
                                  eacc_g->laddr_be, eacc_g->lport_be,
                                  eacc_g->raddr_be, eacc_g->rport_be);
  oof_socket_del(fm, &eacc_g->skf);
  check_all_filters(thr1, thr2);

  /* --- Scenario H (BR-5.16 / ERR-5.02): firewall block on all ports,
   *     -EACCES -> -ERFKILL --- */
  diag("Scenario H: full -EACCES is reported as -ERFKILL, socket rejected");

  /* When every hwport is blocked by the firewall, oo_hw_filter_set clears
   * the (empty) filter and __oof_hw_filter_set converts -EACCES to -ERFKILL
   * so the caller can distinguish a firewall block from other errors. The
   * full-match add rolls back its SW filter and returns -ERFKILL. */
  efrm_filter_insert_fail_rc = -EACCES;
  efrm_filter_insert_fail_count = 2;

  eacc_h = ooft_alloc_endpoint(thr1, IPPROTO_UDP, 1, htons(9400),
                               2, htons(9500));
  ooft_endpoint_expect_unicast_filters(eacc_h, 0);   /* SW added... */
  ooft_endpoint_add_sw_filter(&eacc_h->sw_filters_to_remove, IPPROTO_UDP,
                              eacc_h->laddr_be, eacc_h->lport_be,
                              eacc_h->raddr_be, eacc_h->rport_be); /* ...then removed */
  rc = ooft_endpoint_add(eacc_h, 0);
  efrm_filter_insert_fail_count = 0;
  efrm_filter_insert_fail_rc = -EBUSY;
  cmp_ok(rc, "==", -ERFKILL, "full -EACCES: add rejected with -ERFKILL");
  check_all_filters(thr1, thr2);

  ooft_free_stack(thr2);
  ooft_free_stack(thr1);
  test_cleanup();
  done_testing();
}
