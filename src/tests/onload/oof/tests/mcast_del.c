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


int test_mcast_del(void)
{
  tcp_helper_resource_t *thr;
  struct ooft_endpoint *e1;
  struct ooft_ifindex *idx0, *idx1;
  const char* group = "230.1.2.3";
  int rc;

  new_test();
  plan(23);

  test_alloc(32);

  thr = ooft_alloc_stack(64);

  TRY(ooft_default_cplane_init(current_ns()));
  TEST_DEBUG(oof_onload_manager_dump(&efab_tcp_driver, dump, "\n"));

  idx0 = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));

  /* Part A (BR-8.17): Direct mcast_del removes a single membership.
   * Existing tests all use oof_socket_del which calls mcast_del_all. */
  e1 = ooft_alloc_endpoint(thr, IPPROTO_UDP, INADDR_ANY, htons(2000),
                           INADDR_ANY, 0);

  ooft_endpoint_expect_unicast_filters(e1, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(e1, 0);
  cmp_ok(rc, "==", 0, "A: add endpoint");

  ooft_endpoint_expect_multicast_filters(e1, idx0, idx0->hwport_mask,
                                         inet_addr(group));
  rc = ooft_endpoint_mcast_add(e1, inet_addr(group), idx0);
  cmp_ok(rc, "==", 0, "A: mcast join");

  rc = ooft_endpoint_check_sw_filters(e1);
  cmp_ok(rc, "==", 0, "A: sw filters after join");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "A: hw filters after join");

  /* Now remove just the mcast membership, leaving the socket alive */
  ooft_endpoint_expect_multicast_filters_remove(e1, idx0, idx0->hwport_mask,
                                                inet_addr(group));
  /* SW filter for mcast group removed because no filters remain for maddr */
  ooft_endpoint_expect_sw_remove_addr(e1, inet_addr(group));
  ooft_endpoint_mcast_del(e1, inet_addr(group), idx0);

  rc = ooft_endpoint_check_sw_filters(e1);
  cmp_ok(rc, "==", 0, "A: sw filters after mcast del");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "A: hw filters after mcast del");

  /* Socket still active - clean up unicast filters */
  ooft_endpoint_expect_sw_remove_all(e1);
  ooft_cplane_expect_hw_remove_all(cp);
  oof_socket_del(thr->ofn->ofn_filter_manager, &e1->skf);

  rc = ooft_endpoint_check_sw_filters(e1);
  cmp_ok(rc, "==", 0, "A: teardown sw filters");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "A: teardown hw filters");

  ooft_free_stack(thr);
  test_cleanup();

  /* Part B (BR-8.23): SW filter lifetime across multi-interface join.
   * When a socket joins the same group on two interfaces, only one SW
   * filter is installed (dedup via oof_socket_has_maddr_filter).
   * Removing one membership must NOT remove the SW filter if the other
   * membership still holds a filter for the same maddr. */
  test_alloc(32);
  thr = ooft_alloc_stack(64);
  TRY(ooft_default_cplane_init(current_ns()));
  idx0 = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));
  idx1 = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs)->next);

  e1 = ooft_alloc_endpoint(thr, IPPROTO_UDP, INADDR_ANY, htons(2000),
                           INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(e1, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(e1, 0);
  cmp_ok(rc, "==", 0, "B: add endpoint");

  /* First join on idx0: SW + HW filters installed */
  ooft_endpoint_expect_multicast_filters(e1, idx0, idx0->hwport_mask,
                                         inet_addr(group));
  rc = ooft_endpoint_mcast_add(e1, inet_addr(group), idx0);
  cmp_ok(rc, "==", 0, "B: mcast join idx0");

  /* Second join on idx1: HW filters only (no new SW filter -
   * oof_socket_has_maddr_filter returns true) */
  ooft_endpoint_expect_multicast_hw_filters(e1, idx1, idx1->hwport_mask,
                                            inet_addr(group));
  rc = ooft_endpoint_mcast_add(e1, inet_addr(group), idx1);
  cmp_ok(rc, "==", 0, "B: mcast join idx1");

  rc = ooft_endpoint_check_sw_filters(e1);
  cmp_ok(rc, "==", 0, "B: sw filters after both joins");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "B: hw filters after both joins");

  /* BR-8.21: before removal, hwport mask covers both interfaces */
  {
    struct oof_mcast_member* mm;
    int found = 0;
    CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                        &e1->skf.sf_mcast_memberships)
      if( mm->mm_maddr == inet_addr(group) && mm->mm_filter != NULL ) {
        found = 1;
        cmp_ok(mm->mm_filter->mf_hwport_mask, "==",
               idx0->hwport_mask | idx1->hwport_mask,
               "B: mf_hwport_mask covers both interfaces before del");
        break;
      }
    ok(found, "B: found mcast filter before idx0 del");
  }

  /* Remove membership on idx0: HW filter removed, but SW filter stays
   * because membership on idx1 still has a filter for this maddr */
  ooft_endpoint_expect_multicast_filters_remove(e1, idx0, idx0->hwport_mask,
                                                inet_addr(group));
  ooft_endpoint_mcast_del(e1, inet_addr(group), idx0);

  rc = ooft_endpoint_check_sw_filters(e1);
  cmp_ok(rc, "==", 0, "B: sw filter preserved after idx0 del");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "B: hw filters after idx0 del");

  /* BR-8.21: hwport mask shrinks to only the remaining interface */
  {
    struct oof_mcast_member* mm;
    int found = 0;
    CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                        &e1->skf.sf_mcast_memberships)
      if( mm->mm_maddr == inet_addr(group) && mm->mm_ifindex == idx1->id ) {
        found = 1;
        ok(mm->mm_filter != NULL, "B: idx1 membership still has filter");
        cmp_ok(mm->mm_filter->mf_hwport_mask, "==", idx1->hwport_mask,
               "B: mf_hwport_mask shrunk to idx1 only");
        break;
      }
    if( !found ) {
      ok(0, "B: idx1 membership still has filter");
      ok(0, "B: mf_hwport_mask shrunk to idx1 only");
    }
  }

  /* Remove membership on idx1: HW filter AND SW filter removed */
  ooft_endpoint_expect_multicast_filters_remove(e1, idx1, idx1->hwport_mask,
                                                inet_addr(group));
  ooft_endpoint_expect_sw_remove_addr(e1, inet_addr(group));
  ooft_endpoint_mcast_del(e1, inet_addr(group), idx1);

  rc = ooft_endpoint_check_sw_filters(e1);
  cmp_ok(rc, "==", 0, "B: sw filter removed after idx1 del");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "B: hw filters after idx1 del");

  ooft_endpoint_expect_sw_remove_all(e1);
  ooft_cplane_expect_hw_remove_all(cp);
  oof_socket_del(thr->ofn->ofn_filter_manager, &e1->skf);

  rc = ooft_endpoint_check_sw_filters(e1);
  cmp_ok(rc, "==", 0, "B: teardown sw filters");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "B: teardown hw filters");

  ooft_free_stack(thr);
  test_cleanup();

  done_testing();
}
