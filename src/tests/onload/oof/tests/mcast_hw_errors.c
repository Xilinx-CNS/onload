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
#include <arpa/inet.h>


int test_mcast_hw_errors(void)
{
  tcp_helper_resource_t *thr;
  struct ooft_endpoint *e;
  struct ooft_ifindex *idx, *idx1;
  const char* group = "230.1.2.3";
  unsigned group_be = inet_addr(group);
  int rc;

  new_test();
  plan(19);

  /* Part A (BR-8.07, BR-8.13, ERR-8.05): Membership rollback on HW
   * filter failure.
   *
   * oof_mcast_install inserts a SW filter first, then attempts HW filter
   * install.  If HW fails with a hard error (not -EFILTERSSOME), the
   * membership is rolled back: SW filter removed.
   *
   * Part B: Retry after resetting error injection — should succeed. */

  test_alloc(32);
  thr = ooft_alloc_stack(64);
  TRY(ooft_default_cplane_init(current_ns()));
  idx = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));

  e = ooft_alloc_endpoint(thr, IPPROTO_UDP, INADDR_ANY, htons(2000),
                          INADDR_ANY, 0);

  ooft_endpoint_expect_unicast_filters(e, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(e, 0);
  cmp_ok(rc, "==", 0, "A: add endpoint");

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "A: sw filters after add");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "A: hw filters after add");

  /* Fail both hwports so the result is a hard error (not -EFILTERSSOME) */
  efrm_filter_insert_fail_count = 2;

  ooft_endpoint_expect_sw_add(e, IPPROTO_UDP, group_be, htons(2000), 0, 0);
  ooft_endpoint_add_sw_filter(&e->sw_filters_to_remove, IPPROTO_UDP,
                              group_be, htons(2000), 0, 0);

  rc = ooft_endpoint_mcast_add(e, group_be, idx);
  ok(rc != 0 && rc != -EFILTERSSOME,
     "A: mcast join fails with hard error (rc=%d)", rc);

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "A: sw filters rolled back cleanly");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "A: no stale hw filters");

  /* The rolled-back mcast filter leaves stale entries in sw_filters_added
   * and sw_filters_removed.  Remove only the mcast entry so that
   * ooft_endpoint_expect_sw_remove_all in Part B cleanup is accurate. */
  {
    struct ooft_sw_filter* f;
    struct ooft_sw_filter* tmp;
    CI_DLLIST_FOR_EACH3(struct ooft_sw_filter, f, socket_link,
                        &e->sw_filters_added, tmp)
      if( f->laddr_be == group_be ) {
        ci_dllist_remove_safe(&f->socket_link);
        free(f);
      }
    CI_DLLIST_FOR_EACH3(struct ooft_sw_filter, f, socket_link,
                        &e->sw_filters_removed, tmp)
      if( f->laddr_be == group_be ) {
        ci_dllist_remove_safe(&f->socket_link);
        free(f);
      }
  }

  /* Part B: Retry after resetting error injection */
  efrm_filter_insert_fail_count = 0;

  ooft_endpoint_expect_multicast_filters(e, idx, idx->hwport_mask, group_be);
  rc = ooft_endpoint_mcast_add(e, group_be, idx);
  cmp_ok(rc, "==", 0, "B: mcast join succeeds on retry");

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "B: sw filters after retry");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "B: hw filters after retry");

  ooft_endpoint_expect_sw_remove_all(e);
  ooft_cplane_expect_hw_remove_all(cp);
  oof_socket_del(thr->ofn->ofn_filter_manager, &e->skf);

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "B: sw filters after del");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "B: hw filters after del");

  ooft_free_stack(thr);
  test_cleanup();

  /* Part C (BR-8.07, ERR-8.04): Partial HW failure on second interface join.
   *
   * After a successful join on idx0, a second join on idx1 tries to
   * expand the mcast_filter's hwport_mask.  The existing filter on
   * hwport 0 stays via redirect-NOP; the insert on hwport 1 fails.
   * Result: -EFILTERSSOME.  Membership is retained (not rolled back). */

  test_alloc(32);
  thr = ooft_alloc_stack(64);
  TRY(ooft_default_cplane_init(current_ns()));
  idx = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));
  idx1 = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs)->next);

  e = ooft_alloc_endpoint(thr, IPPROTO_UDP, INADDR_ANY, htons(3000),
                          INADDR_ANY, 0);

  ooft_endpoint_expect_unicast_filters(e, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(e, 0);
  cmp_ok(rc, "==", 0, "C: add endpoint");

  ooft_endpoint_expect_multicast_filters(e, idx, idx->hwport_mask, group_be);
  rc = ooft_endpoint_mcast_add(e, group_be, idx);
  cmp_ok(rc, "==", 0, "C: mcast join idx0");

  efrm_filter_insert_fail_count = 2;

  rc = ooft_endpoint_mcast_add(e, group_be, idx1);
  cmp_ok(rc, "==", -EFILTERSSOME,
         "C: second join returns -EFILTERSSOME (rc=%d)", rc);
  cmp_ok(ooft_endpoint_mcast_membership_count_for(e, group_be, idx1),
         "==", 1, "C: second membership retained after -EFILTERSSOME");

  efrm_filter_insert_fail_count = 0;

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "C: sw filters preserved");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "C: hw filters preserved");

  ooft_endpoint_expect_sw_remove_all(e);
  ooft_cplane_expect_hw_remove_all(cp);
  oof_socket_del(thr->ofn->ofn_filter_manager, &e->skf);

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "C: sw filters after del");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "C: hw filters after del");

  ooft_free_stack(thr);
  test_cleanup();

  done_testing();
}
