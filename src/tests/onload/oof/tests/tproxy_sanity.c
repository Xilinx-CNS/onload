/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include "../onload_kernel_compat.h"
#include "../stack.h"
#include "../../tap/tap.h"
#include "../oof_test.h"
#include "../cplane.h"
#include "../utils.h"
#include "../efrm_interface.h"
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>


int test_tproxy_sanity(void)
{
  tcp_helper_resource_t *thr;
  struct ooft_ifindex *idx0;
  struct oof_manager* fm;
  int rc;

  new_test();
  plan(18);

  /* Part A (BR-9.03, BR-9.06, BR-9.07, BR-9.11): Basic install
   * and free.
   *
   * oof_tproxy_install allocates an oof_tproxy, calls
   * oof_tproxy_filter_update which installs:
   *   - MAC filter
   *   - ARP ethertype filter with kernel redirect (BR-9.06)
   *   - IP-protocol filters with MAC+VLAN (BR-9.07)
   * oof_tproxy_free removes the tproxy and clears all filters (BR-9.11). */

  test_alloc(32);
  thr = ooft_alloc_stack(64);
  TRY(ooft_default_cplane_init(current_ns()));
  fm = thr->ofn->ofn_filter_manager;
  idx0 = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));

  ooft_expect_tproxy_filters(thr, idx0);

  rc = oof_tproxy_install(fm, thr, NULL, idx0->id);
  cmp_ok(rc, "==", 0, "A: tproxy install");

  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "A: tproxy filters installed");

  ooft_expect_tproxy_filters_remove(thr, idx0);

  rc = oof_tproxy_free(fm, thr, NULL, idx0->id);
  cmp_ok(rc, "==", 0, "A: tproxy free");

  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "A: tproxy filters removed");

  ooft_free_stack(thr);
  test_cleanup();

  /* Part B (BR-9.02): Duplicate install on the same ifindex is rejected
   * with -EALREADY. */

  test_alloc(32);
  thr = ooft_alloc_stack(64);
  TRY(ooft_default_cplane_init(current_ns()));
  fm = thr->ofn->ofn_filter_manager;
  idx0 = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));

  ooft_expect_tproxy_filters(thr, idx0);

  rc = oof_tproxy_install(fm, thr, NULL, idx0->id);
  cmp_ok(rc, "==", 0, "B: first install");

  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "B: filters after first install");

  rc = oof_tproxy_install(fm, thr, NULL, idx0->id);
  cmp_ok(rc, "==", -EALREADY, "B: duplicate rejected");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "B: duplicate made no HW filter changes");

  ooft_expect_tproxy_filters_remove(thr, idx0);
  rc = oof_tproxy_free(fm, thr, NULL, idx0->id);
  cmp_ok(rc, "==", 0, "B: free");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "B: filters after free");

  ooft_free_stack(thr);
  test_cleanup();

  /* Part C (BR-9.12): Free on an ifindex with no tproxy returns -ENOENT. */

  test_alloc(32);
  thr = ooft_alloc_stack(64);
  TRY(ooft_default_cplane_init(current_ns()));
  fm = thr->ofn->ofn_filter_manager;
  idx0 = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));

  rc = oof_tproxy_free(fm, thr, NULL, idx0->id);
  cmp_ok(rc, "==", -ENOENT, "C: free unknown");

  ooft_free_stack(thr);
  test_cleanup();

  /* Part D (BR-9.16): Filter update failure during install rolls back the
   * oof_tproxy allocation.  The MAC filter is the first to be inserted, so
   * failing it suffices. */

  test_alloc(32);
  thr = ooft_alloc_stack(64);
  TRY(ooft_default_cplane_init(current_ns()));
  fm = thr->ofn->ofn_filter_manager;
  idx0 = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));

  efrm_filter_insert_fail_count = 1;

  rc = oof_tproxy_install(fm, thr, NULL, idx0->id);
  cmp_ok(rc, "==", -EBUSY, "D: install fails with propagated error");

  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "D: failed install made no HW filter changes");

  rc = oof_tproxy_free(fm, thr, NULL, idx0->id);
  cmp_ok(rc, "==", -ENOENT, "D: no tproxy after failed install");

  efrm_filter_insert_fail_count = 0;

  ooft_expect_tproxy_filters(thr, idx0);
  rc = oof_tproxy_install(fm, thr, NULL, idx0->id);
  cmp_ok(rc, "==", 0, "D: install succeeds after reset");

  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "D: filters installed after reset");

  ooft_expect_tproxy_filters_remove(thr, idx0);
  rc = oof_tproxy_free(fm, thr, NULL, idx0->id);
  cmp_ok(rc, "==", 0, "D: free after successful install");

  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "D: filters removed after free");

  ooft_free_stack(thr);
  test_cleanup();

  done_testing();
}
