/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#include "../onload_kernel_compat.h"
#include "../stack.h"
#include "../../tap/tap.h"
#include "../oof_test.h"
#include "../cplane.h"
#include "../utils.h"
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>
#include <arpa/inet.h>


int test_replication_sanity(void)
{
  tcp_helper_resource_t *thr1, *thr2;
  struct ooft_endpoint *e1, *e2;
  struct ooft_ifindex* idx;
  const char* group = "230.1.2.3";
  int rc;

  new_test();
  plan(12);

  test_alloc(32);

  thr1 = ooft_alloc_stack(64);
  thr2 = ooft_alloc_stack(64);

  TRY(ooft_default_cplane_init(current_ns()));
  TEST_DEBUG(oof_onload_manager_dump(&efab_tcp_driver, dump, "\n"));

  e1 = ooft_alloc_endpoint(thr1, IPPROTO_UDP, INADDR_ANY, htons(2000),
                           INADDR_ANY, 0);
  e2 = ooft_alloc_endpoint(thr2, IPPROTO_UDP, INADDR_ANY, htons(2000),
                           INADDR_ANY, 0);

  ooft_endpoint_expect_unicast_filters(e1, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(e1, 0);
  cmp_ok(rc, "==", 0, "add endpoint");

  /* Adding a second unicast socket for the same addr will steal the filter.
   * That's the only thing we've got at the moment, so we can just claim all
   * installed hw filters for remove. */
  ooft_cplane_expect_hw_remove_all(cp);

  ooft_endpoint_expect_unicast_filters(e2, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(e2, 0);
  cmp_ok(rc, "==", 0, "add endpoint");

  idx = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));
  ooft_endpoint_expect_multicast_filters(e1, idx, idx->hwport_mask,
                                         inet_addr(group));
  rc = ooft_endpoint_mcast_add(e1, inet_addr(group), idx);
  cmp_ok(rc, "==", 0, "mcast add endpoint");

  ooft_endpoint_expect_multicast_filters(e2, idx, idx->hwport_mask,
                                         inet_addr(group));
  rc = ooft_endpoint_mcast_add(e2, inet_addr(group), idx);
  cmp_ok(rc, "==", 0, "mcast add endpoint");

  TEST_DEBUG(oof_onload_manager_dump(&efab_tcp_driver, dump, "\n"));

  rc = ooft_endpoint_check_sw_filters(e1);
  cmp_ok(rc, "==", 0, "check stack 1 sw filters");
  rc = ooft_ns_check_hw_filters(thr1->ns);
  cmp_ok(rc, "==", 0, "check stack 1 hw filters");

  rc = ooft_endpoint_check_sw_filters(e2);
  cmp_ok(rc, "==", 0, "check stack 2 sw filters");
  rc = ooft_ns_check_hw_filters(thr2->ns);
  cmp_ok(rc, "==", 0, "check stack 2 hw filters");

  ooft_endpoint_expect_sw_remove_all(e1);
  ooft_endpoint_expect_sw_remove_all(e2);
  ooft_cplane_expect_hw_remove_all(cp);

  /* Remove socket from stack 1 first, as it's currently hidden so has no
   * hw filters, so we don't trigger, and have to deal with, fixup wild
   * redirecting. */
  oof_socket_del(thr1->ofn->ofn_filter_manager, &e1->skf);
  oof_socket_del(thr2->ofn->ofn_filter_manager, &e2->skf);

  rc = ooft_endpoint_check_sw_filters(e1);
  cmp_ok(rc, "==", 0, "check stack 1 sw filters");
  rc = ooft_ns_check_hw_filters(thr1->ns);
  cmp_ok(rc, "==", 0, "check stack 1 hw filters");

  rc = ooft_endpoint_check_sw_filters(e2);
  cmp_ok(rc, "==", 0, "check stack 2 sw filters");
  rc = ooft_ns_check_hw_filters(thr2->ns);
  cmp_ok(rc, "==", 0, "check stack 2 hw filters");

  ooft_free_stack(thr1);
  ooft_free_stack(thr2);
  test_cleanup();

  done_testing();
}

