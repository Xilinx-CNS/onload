/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include "../onload_kernel_compat.h"
#include "../stack.h"
#include "../../tap/tap.h"
#include "../oof_test.h"
#include "../cplane.h"
#include "../efrm_interface.h"
#include "../oof_impl.h"
#include "../utils.h"
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>


static struct oof_local_port_addr*
skf_lpa(struct oof_socket* skf)
{
  return &skf->sf_local_port->lp_addr[skf->sf_la_i];
}


static void check_filters(tcp_helper_resource_t* thr)
{
  int rc;
  rc = ooft_stack_check_sw_filters(thr);
  cmp_ok(rc, "==", 0, "check sw filters");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "check hw filters");
}


static void check_filters3(tcp_helper_resource_t* a, tcp_helper_resource_t* b)
{
  int rc;
  rc = ooft_stack_check_sw_filters(a);
  cmp_ok(rc, "==", 0, "check sw filters c1");
  rc = ooft_stack_check_sw_filters(b);
  cmp_ok(rc, "==", 0, "check sw filters c2");
  rc = ooft_ns_check_hw_filters(a->ns);
  cmp_ok(rc, "==", 0, "check hw filters (cluster)");
}


/* Find the ooft_addr for laddr_be on an interface, or NULL. */
static struct ooft_addr* find_addr(struct ooft_ifindex* idx, unsigned laddr_be)
{
  ci_dllink* link;
  CI_DLLIST_FOR_EACH(link, &idx->addrs) {
    struct ooft_addr* addr = CI_CONTAINER(struct ooft_addr, idx_link, link);
    if( addr->laddr_be == laddr_be )
      return addr;
  }
  return NULL;
}


/* Exercises the address re-activation path of __oof_manager_addr_add
 * (is_new == 0), which is reached when an address that still has bound
 * sockets is removed (slot retained, flagged OOF_LPA_FLAG_REMOVED) and
 * then re-added.
 *
 * BR-3.04: re-activation clears OOF_LPA_FLAG_REMOVED and reinstalls HW/SW
 *   filters for semi-wild and full-match sockets still bound.
 * BR-3.03/BR-3.06: the same address contributed by two interfaces — adding
 *   the second is a no-op (already active) and removing one keeps it active.
 * BR-3.14: when a wild/semi-wild SW filter re-insert fails during
 *   re-activation, the wild HW filter is cleared (Scenario C, no full-match
 *   sharer and no clustered sibling) — but is retained when a clustered
 *   sibling stack still needs the shared filter (Scenario D).
 */
int test_addr_reactivate(void)
{
  tcp_helper_resource_t* thr;
  tcp_helper_resource_t* thr_c1;
  tcp_helper_resource_t* thr_c2;
  tcp_helper_cluster_t* thc;
  struct ooft_endpoint* listener;
  struct ooft_endpoint* passive;
  struct ooft_endpoint* semi;
  struct ooft_endpoint* ec1;
  struct ooft_endpoint* ec2;
  ci_dllist hw_filters;
  int rc;
  struct oof_manager* fm;
  struct ooft_ifindex* idx0;
  struct ooft_ifindex* idx1;
  struct ooft_addr* a;
  const unsigned addr0 = inet_addr("1.0.0.0");

  new_test();
  plan(54);

  test_alloc(32);
  thr = ooft_alloc_stack(8);
  thr_c1 = ooft_alloc_stack(8);
  thr_c2 = ooft_alloc_stack(8);
  thc = ooft_alloc_cluster("reactivate_cluster");
  ooft_stack_set_cluster(thr_c1, thc);
  ooft_stack_set_cluster(thr_c2, thc);
  fm = thr->ofn->ofn_filter_manager;
  TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X2_FF));

  ci_dllist_init(&hw_filters);
  idx0 = ooft_idx_from_id(1);
  idx1 = ooft_idx_from_id(2);
  TEST(idx0);
  TEST(idx1);

  /* --- Scenario A (BR-3.04): re-activate a removed-but-retained address,
   *     with a semi-wild listener and a full-match passive socket. --- */
  diag("Scenario A: re-activation reinstalls wild + full-match filters");

  listener = ooft_alloc_endpoint(thr, IPPROTO_TCP, addr0, htons(4000), 0, 0);
  passive  = ooft_alloc_endpoint(thr, IPPROTO_TCP, addr0, htons(4000),
                                 inet_addr("2.0.0.0"), htons(5000));

  ooft_endpoint_expect_unicast_filters(listener, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(listener, 0);
  cmp_ok(rc, "==", 0, "add listener");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_filters);

  {
    ci_addr_t laddr = CI_ADDR_FROM_IP4(passive->laddr_be);
    ci_addr_t raddr = CI_ADDR_FROM_IP4(passive->raddr_be);
    ooft_endpoint_expect_unicast_filters(passive, 0);
    rc = oof_socket_share(fm, &passive->skf, &listener->skf,
                          AF_SPACE_FLAG_IP4, laddr, raddr,
                          passive->lport_be, passive->rport_be);
    cmp_ok(rc, "==", 0, "share passive");
    check_filters(thr);
  }

  /* Remove the address.  HW filters and the listener's semi-wild SW filter
   * are cleared; the passive's full-match SW filter persists.  The address
   * slot is retained (sockets still bound) and flagged REMOVED. */
  ooft_endpoint_expect_sw_remove_all(listener);
  ooft_hw_filter_expect_remove_list(&hw_filters);
  a = find_addr(idx0, addr0);
  TEST(a);
  ooft_del_addr(current_ns(), idx0, a);
  ok(skf_lpa(&listener->skf)->lpa_flags & OOF_LPA_FLAG_REMOVED,
     "A: LPA flagged REMOVED after addr removal");
  check_filters(thr);

  /* Re-add the address: re-activation reinstalls the listener's wild HW + SW
   * filters and the passive's full-match HW filter (re-shared). */
  ooft_endpoint_expect_sw_add(listener, IPPROTO_TCP, addr0, htons(4000), 0, 0);
  ooft_endpoint_expect_hw_unicast(listener, addr0, OOFT_EXPECT_FLAG_HW);
  ooft_alloc_addr(current_ns(), idx0, addr0);
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_filters);

  /* Cleanup: passive first (it shares the listener's HW filter). */
  ooft_endpoint_expect_sw_remove_all(passive);
  oof_socket_del(fm, &passive->skf);
  ooft_endpoint_expect_sw_remove_all(listener);
  ooft_hw_filter_expect_remove_list(&hw_filters);
  oof_socket_del(fm, &listener->skf);
  check_filters(thr);

  /* --- Scenario B (BR-3.03/BR-3.06): same address on two interfaces. --- */
  diag("Scenario B: same address contributed by two interfaces");

  /* idx0 already has addr0 (re-added above). */
  semi = ooft_alloc_endpoint(thr, IPPROTO_UDP, addr0, htons(6000), 0, 0);
  ooft_endpoint_expect_unicast_filters(semi, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(semi, 0);
  cmp_ok(rc, "==", 0, "add semi-wild");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_filters);

  /* Add the same address on idx1: recorded as a contributor only, the
   * address is already active so no filters change (BR-3.03). */
  ooft_alloc_addr(current_ns(), idx1, addr0);
  check_filters(thr);

  /* Remove idx0's contribution: idx1 still contributes, address stays
   * active, no filter change (BR-3.06). */
  a = find_addr(idx0, addr0);
  TEST(a);
  ooft_del_addr(current_ns(), idx0, a);
  check_filters(thr);

  /* Remove idx1's contribution: last interface gone, filters cleared. */
  ooft_endpoint_expect_sw_remove_all(semi);
  ooft_hw_filter_expect_remove_list(&hw_filters);
  a = find_addr(idx1, addr0);
  TEST(a);
  ooft_del_addr(current_ns(), idx1, a);
  check_filters(thr);

  oof_socket_del(fm, &semi->skf);
  check_filters(thr);

  /* --- Scenario C (BR-3.14): SW re-insert failure on re-activation
   *     clears the wild HW filter. --- */
  diag("Scenario C: SW re-insert failure clears wild HW filter");

  /* Re-add addr0 on idx0 for this scenario. */
  ooft_alloc_addr(current_ns(), idx0, addr0);

  semi = ooft_alloc_endpoint(thr, IPPROTO_UDP, addr0, htons(7000), 0, 0);
  ooft_endpoint_expect_unicast_filters(semi, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(semi, 0);
  cmp_ok(rc, "==", 0, "add semi-wild C");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_filters);

  /* Remove the address — slot retained (socket bound), flagged REMOVED. */
  ooft_endpoint_expect_sw_remove_all(semi);
  ooft_hw_filter_expect_remove_list(&hw_filters);
  a = find_addr(idx0, addr0);
  TEST(a);
  ooft_del_addr(current_ns(), idx0, a);
  ok(skf_lpa(&semi->skf)->lpa_flags & OOF_LPA_FLAG_REMOVED,
     "C: LPA flagged REMOVED after addr removal");
  check_filters(thr);

  /* Arm the SW-insert injector for addr0, then re-activate.  The HW filter
   * is reinstalled (oof_hw_filter_set) and then cleared again when the SW
   * re-insert fails, because no full-match sharer or clustered sibling needs
   * it.  Net effect: no SW filter and no HW filter for the semi-wild. */
  oof_sw_filter_insert_fail_count = 1;
  oof_sw_filter_insert_fail_laddr = addr0;
  /* OOFT_NIC_X2_FF has two hwports, so the reinstalled wild HW filter
   * covers both.  The failure-path rollback removes both → 2 removals. */
  efrm_filter_rollback_remove_count = 2;
  ooft_endpoint_expect_hw_unicast(semi, addr0, OOFT_EXPECT_FLAG_HW);
  ooft_alloc_addr(current_ns(), idx0, addr0);
  cmp_ok(oof_sw_filter_insert_fail_count, "==", 0, "SW insert failure injected");
  cmp_ok(efrm_filter_rollback_remove_count, "==", 0,
         "C: expected rollback HW removals consumed");
  /* The reinstalled HW filter's removal on the failure path is already
   * asserted above via efrm_filter_rollback_remove_count; no HW filters
   * remain at this point. */
  check_filters(thr);
  oof_sw_filter_insert_fail_laddr = 0;

  /* The semi-wild SW filter was never installed (its re-insert was the
   * injected failure), but on socket delete OOF still issues a remove for
   * it — harmless in production (a no-op on the kernel SW table).  Reconcile
   * the harness' bookkeeping so that expected remove is accounted for. */
  ooft_endpoint_add_sw_filter(&semi->sw_filters_added, IPPROTO_UDP,
                              addr0, htons(7000), 0, 0);
  ooft_endpoint_expect_sw_remove_all(semi);
  oof_socket_del(fm, &semi->skf);
  check_filters(thr);

  /* --- Scenario D (BR-3.14): SW re-insert failure retains the wild HW
   *     filter when a clustered sibling stack still needs it. --- */
  diag("Scenario D: clustered sibling retains wild HW filter on SW failure");

  /* addr0 is present on idx0 (re-added during Scenario C).  Two clustered
   * semi-wild sockets on addr0, one per stack of the same cluster, share a
   * single clustered wild HW filter. */
  ec1 = ooft_alloc_endpoint(thr_c1, IPPROTO_UDP, addr0, htons(8000), 0, 0);
  ooft_endpoint_expect_unicast_filters(ec1, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(ec1, OOF_SOCKET_ADD_FLAG_CLUSTERED);
  cmp_ok(rc, "==", 0, "D: add clustered semi-wild c1");
  check_filters3(thr_c1, thr_c2);
  ooft_cplane_claim_added_hw_filters(cp, &hw_filters);

  ec2 = ooft_alloc_endpoint(thr_c2, IPPROTO_UDP, addr0, htons(8000), 0, 0);
  ooft_endpoint_expect_unicast_filters(ec2, 0);  /* SW only, shares HW */
  rc = ooft_endpoint_add(ec2, OOF_SOCKET_ADD_FLAG_CLUSTERED);
  cmp_ok(rc, "==", 0, "D: add clustered semi-wild c2 (SW only)");
  check_filters3(thr_c1, thr_c2);

  /* Remove addr0: HW cleared, both semi-wild SW removed, slot retained. */
  ooft_endpoint_expect_sw_remove_all(ec1);
  ooft_endpoint_expect_sw_remove_all(ec2);
  ooft_hw_filter_expect_remove_list(&hw_filters);
  a = find_addr(idx0, addr0);
  TEST(a);
  ooft_del_addr(current_ns(), idx0, a);
  check_filters3(thr_c1, thr_c2);

  /* Re-activate, failing BOTH clustered SW re-inserts for addr0.  Each
   * failing socket finds the other as a same-cluster, different-stack
   * sibling (oof_socket_has_cluster_sibling), so the reinstalled cluster HW
   * filter is retained rather than cleared. */
  oof_sw_filter_insert_fail_count = 2;
  oof_sw_filter_insert_fail_laddr = addr0;
  ooft_endpoint_expect_hw_unicast(ec1, addr0, OOFT_EXPECT_FLAG_HW);
  ooft_alloc_addr(current_ns(), idx0, addr0);
  cmp_ok(oof_sw_filter_insert_fail_count, "==", 0, "D: both SW re-inserts failed");
  check_filters3(thr_c1, thr_c2);
  oof_sw_filter_insert_fail_laddr = 0;
  ooft_cplane_claim_added_hw_filters(cp, &hw_filters);

  /* Cleanup.  Neither clustered SW filter was actually installed (both
   * re-inserts failed), but oof_socket_del_wild_sw unconditionally calls
   * oof_cb_sw_filter_remove (harmless no-op in production).  Inject
   * phantom entries into sw_filters_added so the harness can match the
   * unconditional removes.  ec2 shares ec1's cluster HW filter, so
   * delete ec2 first (HW retained), then ec1 (last user, HW removed). */
  ooft_endpoint_add_sw_filter(&ec2->sw_filters_added, IPPROTO_UDP,
                              addr0, htons(8000), 0, 0);
  ooft_endpoint_expect_sw_remove_all(ec2);
  oof_socket_del(fm, &ec2->skf);
  ooft_endpoint_add_sw_filter(&ec1->sw_filters_added, IPPROTO_UDP,
                              addr0, htons(8000), 0, 0);
  ooft_endpoint_expect_sw_remove_all(ec1);
  ooft_hw_filter_expect_remove_list(&hw_filters);
  oof_socket_del(fm, &ec1->skf);
  check_filters3(thr_c1, thr_c2);

  ooft_free_stack(thr_c2);
  ooft_free_stack(thr_c1);
  ooft_free_cluster(thc);
  ooft_free_stack(thr);
  test_cleanup();
  done_testing();
}
