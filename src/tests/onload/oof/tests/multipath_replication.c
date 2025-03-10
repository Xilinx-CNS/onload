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


int test_multipath_replication(void)
{
  tcp_helper_resource_t *thr1, *thr2, *thr3, *thr4;
  struct ooft_endpoint *e1, *e2, *e3, *e4;
  struct ooft_ifindex* idx;
  const char* group = "230.1.2.3";
  int rc;

  new_test();
  plan(22);

  test_alloc(32);

  thr1 = ooft_alloc_stack_mode(64, OOFT_RX_BOTH);
  thr2 = ooft_alloc_stack_mode(64, OOFT_RX_BOTH);
  thr3 = ooft_alloc_stack_mode(64, OOFT_RX_BOTH);
  thr4 = ooft_alloc_stack_mode(64, OOFT_RX_BOTH);

  TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X4_LL));
  TEST_DEBUG(oof_onload_manager_dump(&efab_tcp_driver, dump, "\n"));

  e1 = ooft_alloc_endpoint(thr1, IPPROTO_UDP, INADDR_ANY, htons(2000),
                           INADDR_ANY, 0);
  e2 = ooft_alloc_endpoint(thr2, IPPROTO_UDP, INADDR_ANY, htons(2000),
                           INADDR_ANY, 0);
  e3 = ooft_alloc_endpoint(thr3, IPPROTO_UDP, INADDR_ANY, htons(2000),
                           INADDR_ANY, 0);
  e4 = ooft_alloc_endpoint(thr4, IPPROTO_UDP, INADDR_ANY, htons(2000),
                           INADDR_ANY, 0);

  /* Part 1: Create all 4 sockets sharing a port. This will result in SW
   * filters for all sockets, with the most recently created socket stealing
   * the HW filters. */

  ooft_endpoint_expect_unicast_filters(e1, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(e1, 0);
  cmp_ok(rc, "==", 0, "add stack 1 endpoint");

  /* Adding a second unicast socket for the same addr will steal the filter.
   * That's the only thing we've got at the moment, so we can just claim all
   * installed hw filters for remove. */
  ooft_cplane_expect_hw_remove_all(cp);

  ooft_endpoint_expect_unicast_filters(e2, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(e2, 0);
  cmp_ok(rc, "==", 0, "add stack 2 endpoint");

  /* And again ... */
  ooft_cplane_expect_hw_remove_all(cp);

  ooft_endpoint_expect_unicast_filters(e3, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(e3, 0);
  cmp_ok(rc, "==", 0, "add stack 3 endpoint");

  /* And again ... */
  ooft_cplane_expect_hw_remove_all(cp);

  ooft_endpoint_expect_unicast_filters(e4, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(e4, 0);
  cmp_ok(rc, "==", 0, "add stack 4 endpoint");

  /* Part 2: Check that multicast filters work as expected by joining
   * different sockets to the same group. The first socket will get a filter
   * on the LL path, and the next two will get filters on the FF path. */

  /* First endpoint gets a filter on the LL datapath */
  idx = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));
  ooft_endpoint_expect_multicast_filters(e1, idx, idx->hwport_mask_ll,
                                         inet_addr(group));
  rc = ooft_endpoint_mcast_add(e1, inet_addr(group), idx);
  cmp_ok(rc, "==", 0, "mcast add stack 1 endpoint");

  /* Second endpoint gets a filter on the FF datapath */
  ooft_endpoint_expect_multicast_filters(e2, idx, idx->hwport_mask_ff,
                                         inet_addr(group));
  rc = ooft_endpoint_mcast_add(e2, inet_addr(group), idx);
  cmp_ok(rc, "==", 0, "mcast add stack 2 endpoint");

  /* Third endpoint gets a filter on the FF datapath */
  ooft_endpoint_expect_multicast_filters(e3, idx, idx->hwport_mask_ff,
                                         inet_addr(group));
  rc = ooft_endpoint_mcast_add(e3, inet_addr(group), idx);
  cmp_ok(rc, "==", 0, "mcast add stack 3 endpoint");

  TEST_DEBUG(oof_onload_manager_dump(&efab_tcp_driver, dump, "\n"));

  rc = ooft_endpoint_check_sw_filters(e1);
  cmp_ok(rc, "==", 0, "check stack 1 sw filters");
  rc = ooft_ns_check_hw_filters(thr1->ns);
  cmp_ok(rc, "==", 0, "check stack 1 hw filters");

  rc = ooft_endpoint_check_sw_filters(e2);
  cmp_ok(rc, "==", 0, "check stack 2 sw filters");
  rc = ooft_ns_check_hw_filters(thr2->ns);
  cmp_ok(rc, "==", 0, "check stack 2 hw filters");

  rc = ooft_endpoint_check_sw_filters(e3);
  cmp_ok(rc, "==", 0, "check stack 3 sw filters");
  rc = ooft_ns_check_hw_filters(thr3->ns);
  cmp_ok(rc, "==", 0, "check stack 3 hw filters");

  /* Part 3: Remove the membership for the socket with the LL filter and
   * join the fourth socket to the group. It should now be able to use the
   * LL path for its filter. */

  ooft_endpoint_expect_sw_remove_all(e1);
  ooft_endpoint_expect_multicast_filters_remove(e1, idx, idx->hwport_mask_ll,
                                                inet_addr(group));
  oof_socket_del(thr1->ofn->ofn_filter_manager, &e1->skf);

  rc = ooft_endpoint_check_sw_filters(e1);
  cmp_ok(rc, "==", 0, "check stack 1 sw filters");
  rc = ooft_ns_check_hw_filters(thr1->ns);
  cmp_ok(rc, "==", 0, "check stack 1 hw filters");

  ooft_free_stack(thr1);

  ooft_endpoint_expect_multicast_filters(e4, idx, idx->hwport_mask_ll,
                                         inet_addr(group));
  rc = ooft_endpoint_mcast_add(e4, inet_addr(group), idx);
  cmp_ok(rc, "==", 0, "mcast add stack 4 endpoint");

  /* Part 4: Tear everything down. */

  ooft_endpoint_expect_sw_remove_all(e2);
  ooft_endpoint_expect_sw_remove_all(e3);
  ooft_endpoint_expect_sw_remove_all(e4);
  ooft_cplane_expect_hw_remove_all(cp);
  oof_socket_del(thr2->ofn->ofn_filter_manager, &e2->skf);
  oof_socket_del(thr3->ofn->ofn_filter_manager, &e3->skf);
  oof_socket_del(thr4->ofn->ofn_filter_manager, &e4->skf);

  rc = ooft_endpoint_check_sw_filters(e2);
  cmp_ok(rc, "==", 0, "check stack 2 sw filters");
  rc = ooft_ns_check_hw_filters(thr2->ns);
  cmp_ok(rc, "==", 0, "check stack 2 hw filters");

  rc = ooft_endpoint_check_sw_filters(e3);
  cmp_ok(rc, "==", 0, "check stack 3 sw filters");
  rc = ooft_ns_check_hw_filters(thr3->ns);
  cmp_ok(rc, "==", 0, "check stack 3 hw filters");

  rc = ooft_endpoint_check_sw_filters(e4);
  cmp_ok(rc, "==", 0, "check stack 4 sw filters");
  rc = ooft_ns_check_hw_filters(thr4->ns);
  cmp_ok(rc, "==", 0, "check stack 4 hw filters");

  ooft_free_stack(thr2);
  ooft_free_stack(thr3);
  ooft_free_stack(thr4);
  test_cleanup();

  done_testing();
}

