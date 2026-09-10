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
#include "../efrm_interface.h"
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


/* BR-5.11 (primary port selection strips fallback),
 * BR-5.12 (failed primary ports fall back to alternate),
 * BR-5.13 (successful fallback yields overall success).
 *
 * On X4 NICs each interface has both an LL (primary) and FF (fallback)
 * hwport.  oo_hw_filter_add_hwports first tries the LL ports; if they
 * fail, it retries on the FF fallback ports.
 *
 * Scenario A: Fail both LL hwports with efrm_filter_insert_fail_count=2.
 *   The fallback pass installs filters on the FF ports.  Socket add
 *   succeeds (BR-5.13).
 *
 * Scenario B: Fail all 4 hwports (2 LL + 2 FF) with fail_count=4.
 *   No fallback available.  Socket add returns -EBUSY, SW is rolled back.
 */
int test_llct_hw_fallback(void)
{
  tcp_helper_resource_t* thr;
  struct ooft_endpoint* semi_wild;
  struct ooft_endpoint* semi_wild_b;
  struct ooft_endpoint* semi_wild_c;
  ci_dllist hw_fallback;
  struct ooft_hwport* hw_ff0;
  struct ooft_hwport* hw_ff1;
  struct ooft_ifindex* idx0;
  struct oof_manager* fm;
  int rc;

  new_test();
  plan(14);

  test_alloc(32);
  thr = ooft_alloc_stack_mode(8, OOFT_RX_BOTH);
  fm = thr->ofn->ofn_filter_manager;
  TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X4_FF));
  idx0 = ooft_idx_from_id(1);
  ooft_alloc_addr(current_ns(), idx0, inet_addr("1.0.0.2"));

  ci_dllist_init(&hw_fallback);

  /* X4 layout: hwport 0=FF(fallback), 1=FF(fallback), 2=LL, 3=LL.
   * oo_hw_filter_primary_ports strips FF fallback ports from the initial
   * install set, so the first pass only tries LL ports 2 and 3. */
  hw_ff0 = ooft_hwport_from_id(0);
  hw_ff1 = ooft_hwport_from_id(1);
  TEST(hw_ff0);
  TEST(hw_ff1);

  /* --- Scenario A (BR-5.11/5.12/5.13): LL fails, FF fallback succeeds --- */
  diag("Scenario A: LL hwport failure with FF fallback");

  semi_wild = ooft_alloc_endpoint(thr, IPPROTO_TCP,
                                  inet_addr("1.0.0.0"), htons(3000),
                                  INADDR_ANY, 0);

  /* Expect SW filter (no HW — we set HW expectations manually below) */
  ooft_endpoint_expect_unicast_filters(semi_wild, 0);

  /* Expect HW filters on FF fallback ports (0 and 1), not LL ports.
   * Both get the same filter spec — the semi-wild address 1.0.0.0:3000
   * is installed on all hwports in the available mask. */
  ooft_client_expect_hw_add_ip(oo_nics[hw_ff0->id].efrm_client,
                               tcp_helper_rx_vi_id(thr, hw_ff0->id),
                               tcp_helper_vi_hw_stack_id(thr, hw_ff0->id),
                               EFX_FILTER_VID_UNSPEC, IPPROTO_TCP,
                               semi_wild->laddr_be, semi_wild->lport_be, 0, 0);
  ooft_client_expect_hw_add_ip(oo_nics[hw_ff1->id].efrm_client,
                               tcp_helper_rx_vi_id(thr, hw_ff1->id),
                               tcp_helper_vi_hw_stack_id(thr, hw_ff1->id),
                               EFX_FILTER_VID_UNSPEC, IPPROTO_TCP,
                               semi_wild->laddr_be, semi_wild->lport_be, 0, 0);

  /* Fail the first 2 inserts (LL ports 2 and 3).  The fallback pass
   * on FF ports 0 and 1 will succeed. */
  efrm_filter_insert_fail_count = 2;
  rc = ooft_endpoint_add(semi_wild, 0);
  cmp_ok(rc, "==", 0, "semi-wild add succeeds via FF fallback");
  cmp_ok(efrm_filter_insert_fail_count, "==", 0,
         "primary insert failures consumed before FF fallback");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_fallback);

  /* --- Scenario B: all ports fail --- */
  diag("Scenario B: all hwports fail, no fallback available");

  semi_wild_b = ooft_alloc_endpoint(thr, IPPROTO_TCP,
                                    inet_addr("1.0.0.1"), htons(4000), INADDR_ANY, 0);

  /* Expect SW filter add then two removals: __oof_socket_add_wild rolls
   * back on HW failure (remove #1), then oof_socket_add_wild calls
   * __oof_socket_del_wild for cleanup (remove #2). */
  ooft_endpoint_expect_unicast_filters(semi_wild_b, 0);
  ooft_endpoint_add_sw_filter(&semi_wild_b->sw_filters_to_remove,
                              IPPROTO_TCP,
                              semi_wild_b->laddr_be, semi_wild_b->lport_be,
                              0, 0);
  ooft_endpoint_add_sw_filter(&semi_wild_b->sw_filters_to_remove,
                              IPPROTO_TCP,
                              semi_wild_b->laddr_be, semi_wild_b->lport_be,
                              0, 0);

  /* Fail all 4 inserts: 2 LL primary + 2 FF fallback */
  efrm_filter_insert_fail_count = 4;
  rc = ooft_endpoint_add(semi_wild_b, 0);
  cmp_ok(rc, "==", -EBUSY, "semi-wild rejected when all ports fail");
  cmp_ok(efrm_filter_insert_fail_count, "==", 0,
         "all primary and fallback insert failures consumed");
  check_filters(thr);

  /* --- Scenario C: all ports fail with -EACCES (firewall) --- */
  diag("Scenario C: all hwports blocked by firewall (-EACCES -> -ERFKILL)");

  /* Same shape as Scenario B but the failure is a firewall block. Both the
   * primary (LL) and fallback (FF) passes fail with -EACCES, so
   * oo_hw_filter_update_error is reached with rc_old == -EACCES (the branch
   * Scenario B exercises with -EBUSY). oo_hw_filter_add_hwports returns
   * -EACCES, which __oof_hw_filter_set converts to -ERFKILL; the semi-wild
   * add rolls back its SW filter and returns -ERFKILL. */
  semi_wild_c = ooft_alloc_endpoint(thr, IPPROTO_TCP,
                                    inet_addr("1.0.0.2"), htons(5000),
                                    INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(semi_wild_c, 0);
  ooft_endpoint_add_sw_filter(&semi_wild_c->sw_filters_to_remove, IPPROTO_TCP,
                              semi_wild_c->laddr_be, semi_wild_c->lport_be,
                              0, 0);
  ooft_endpoint_add_sw_filter(&semi_wild_c->sw_filters_to_remove, IPPROTO_TCP,
                              semi_wild_c->laddr_be, semi_wild_c->lport_be,
                              0, 0);

  efrm_filter_insert_fail_rc = -EACCES;
  efrm_filter_insert_fail_count = 4;   /* 2 LL primary + 2 FF fallback */
  rc = ooft_endpoint_add(semi_wild_c, 0);
  efrm_filter_insert_fail_rc = -EBUSY;
  cmp_ok(rc, "==", -ERFKILL, "semi-wild rejected with -ERFKILL when firewall blocks all ports");
  cmp_ok(efrm_filter_insert_fail_count, "==", 0,
         "all primary and fallback firewall failures consumed");
  check_filters(thr);

  /* --- Cleanup: delete Scenario A's socket --- */
  diag("Cleanup");
  ooft_endpoint_expect_sw_remove_all(semi_wild);
  ooft_hw_filter_expect_remove_list(&hw_fallback);
  oof_socket_del(fm, &semi_wild->skf);
  check_filters(thr);

  ooft_free_stack(thr);
  test_cleanup();
  done_testing();
}
