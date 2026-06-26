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


int test_mcast_input_validation(void)
{
  tcp_helper_resource_t *thr;
  struct ooft_endpoint *e;
  struct ooft_ifindex* idx;
  struct oof_manager* fm;
  const char* group = "230.1.2.3";
  int rc;

  new_test();
  plan(15);

  test_alloc(32);

  thr = ooft_alloc_stack(64);

  TRY(ooft_default_cplane_init(current_ns()));
  TEST_DEBUG(oof_onload_manager_dump(&efab_tcp_driver, dump, "\n"));

  fm = thr->ofn->ofn_filter_manager;
  idx = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));

  e = ooft_alloc_endpoint(thr, IPPROTO_UDP, INADDR_ANY, htons(2000),
                          INADDR_ANY, 0);

  ooft_endpoint_expect_unicast_filters(e, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(e, 0);
  cmp_ok(rc, "==", 0, "add endpoint");

  /* Part A (BR-8.01): Non-multicast address rejected */
  rc = oof_socket_mcast_add(fm, &e->skf, inet_addr("1.2.3.4"), idx->id);
  cmp_ok(rc, "==", -EINVAL, "non-multicast address returns -EINVAL");

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "no unexpected sw filter changes");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "no unexpected hw filter changes");

  /* Part B (BR-8.02): Unknown ifindex rejected */
  rc = oof_socket_mcast_add(fm, &e->skf, inet_addr(group), 999);
  cmp_ok(rc, "==", -ENODEV, "unknown ifindex returns -ENODEV");

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "no unexpected sw filter changes");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "no unexpected hw filter changes");

  /* Part C (BR-8.04): Duplicate membership ignored */
  ooft_endpoint_expect_multicast_filters(e, idx, idx->hwport_mask,
                                         inet_addr(group));
  rc = ooft_endpoint_mcast_add(e, inet_addr(group), idx);
  cmp_ok(rc, "==", 0, "first mcast join succeeds");

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "first join sw filters correct");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "first join hw filters correct");

  /* Second join of same group on same interface — should be silently
   * ignored, no new filters added. */
  rc = ooft_endpoint_mcast_add(e, inet_addr(group), idx);
  cmp_ok(rc, "==", 0, "duplicate mcast join returns 0");
  cmp_ok(ooft_endpoint_mcast_membership_count_for(e, inet_addr(group), idx),
         "==", 1, "duplicate mcast join does not add membership");

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "no extra sw filters after duplicate join");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "no extra hw filters after duplicate join");

  /* Teardown */
  ooft_endpoint_expect_sw_remove_all(e);
  ooft_cplane_expect_hw_remove_all(cp);
  oof_socket_del(fm, &e->skf);

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "teardown sw filters clean");

  ooft_free_stack(thr);
  test_cleanup();

  done_testing();
}
