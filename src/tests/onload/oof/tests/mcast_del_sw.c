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


int test_mcast_del_sw(void)
{
  tcp_helper_resource_t *thr;
  struct ooft_endpoint *e;
  struct ooft_ifindex* idx;
  struct oof_manager* fm;
  const char* group = "230.1.2.3";
  int rc;

  new_test();
  plan(17);

  /* Part A (BR-8.28): del_sw on unicast socket with active mcast membership.
   *
   * oof_socket_del_sw calls oof_socket_mcast_remove_sw to strip mcast SW
   * filters and returns 1 (HW filters remain for both unicast and mcast).
   * A follow-up oof_socket_del is needed to clean up HW filters. */

  test_alloc(32);
  thr = ooft_alloc_stack(64);
  TRY(ooft_default_cplane_init(current_ns()));
  fm = thr->ofn->ofn_filter_manager;
  idx = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));

  e = ooft_alloc_endpoint(thr, IPPROTO_UDP, INADDR_ANY, htons(2000),
                          INADDR_ANY, 0);

  ooft_endpoint_expect_unicast_filters(e, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(e, 0);
  cmp_ok(rc, "==", 0, "A: add endpoint");

  ooft_endpoint_expect_multicast_filters(e, idx, idx->hwport_mask,
                                         inet_addr(group));
  rc = ooft_endpoint_mcast_add(e, inet_addr(group), idx);
  cmp_ok(rc, "==", 0, "A: mcast join");

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "A: sw filters after join");
  ok(ci_dllist_not_empty(&e->sw_filters_added),
     "A: sw filter installed after mcast join");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "A: hw filters after join");

  /* del_sw removes all SW filters (unicast + mcast) but leaves HW */
  ooft_endpoint_expect_sw_remove_all(e);
  rc = oof_socket_del_sw(fm, &e->skf);
  cmp_ok(rc, "==", 1, "A: del_sw returns 1 (HW filters remain)");
  ok(e->skf.sf_flags & OOF_SOCKET_SW_FILTER_WAS_REMOVED,
     "A: SW_FILTER_WAS_REMOVED flag set");

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "A: all sw filters removed");

  /* Follow up with oof_socket_del to clean up HW */
  ooft_cplane_expect_hw_remove_all(cp);
  oof_socket_del(fm, &e->skf);

  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "A: all hw filters removed");

  ooft_free_stack(thr);
  test_cleanup();

  /* Part B (BR-8.27, BR-8.28): del_sw on socket bound to multicast laddr
   * (no unicast filters).
   *
   * When bound to a multicast address, oof_socket_add installs no unicast
   * filters.  Only mcast filters exist after joining a group.  del_sw
   * removes the mcast SW filter and returns 1 (mcast HW remains). */

  test_alloc(32);
  thr = ooft_alloc_stack(64);
  TRY(ooft_default_cplane_init(current_ns()));
  fm = thr->ofn->ofn_filter_manager;
  idx = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));

  e = ooft_alloc_endpoint(thr, IPPROTO_UDP, inet_addr(group), htons(2000),
                          INADDR_ANY, 0);

  rc = ooft_endpoint_add(e, 0);
  cmp_ok(rc, "==", 0, "B: add mcast-laddr endpoint (no filters)");
  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "B: no sw filters after add (mcast-laddr gets none)");

  ooft_endpoint_expect_multicast_filters(e, idx, idx->hwport_mask,
                                         inet_addr(group));
  rc = ooft_endpoint_mcast_add(e, inet_addr(group), idx);
  cmp_ok(rc, "==", 0, "B: mcast join");
  ok(ci_dllist_not_empty(&e->sw_filters_added),
     "B: sw filter installed after mcast join");

  /* del_sw removes mcast SW filter; HW remains */
  ooft_endpoint_expect_sw_remove_all(e);
  rc = oof_socket_del_sw(fm, &e->skf);
  cmp_ok(rc, "==", 1, "B: del_sw returns 1 (mcast HW remains)");
  ok(e->skf.sf_flags & OOF_SOCKET_SW_FILTER_WAS_REMOVED,
     "B: SW_FILTER_WAS_REMOVED flag set");

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "B: mcast sw filter removed");

  /* Clean up HW via full socket del */
  ooft_cplane_expect_hw_remove_all(cp);
  oof_socket_del(fm, &e->skf);

  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "B: all hw filters removed");

  ooft_free_stack(thr);
  test_cleanup();

  done_testing();
}
