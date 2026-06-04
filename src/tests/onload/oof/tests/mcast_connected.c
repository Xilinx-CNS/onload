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


int test_mcast_connected(void)
{
  tcp_helper_resource_t *thr;
  struct ooft_endpoint *e;
  struct ooft_ifindex *idx;
  struct oof_manager* fm;
  const char* group = "230.1.2.3";
  unsigned group_be = inet_addr(group);
  const char* remote = "10.0.0.1";
  unsigned remote_be = inet_addr(remote);
  uint16_t rport_be = htons(5000);
  int rc;

  new_test();
  plan(20);

  /* Part A (BR-8.24 replication-port subset, BR-8.25): Connected mcast on
   * replication ports.
   *
   * Bind to mcast laddr, add, connect, join group.  On replication-
   * capable ports oof_udp_connect_mcast_laddr installs a full-match
   * SW filter (OOF_SOCKET_MCAST_FULL_SW_FILTER) but no full-match HW
   * filter (hwports_full == 0).  Wild-match HW filters are installed
   * by oof_mcast_install via OOF_MCAST_WILD_HWPORTS. */

  test_alloc(32);
  thr = ooft_alloc_stack(64);
  TRY(ooft_default_cplane_init(current_ns()));
  fm = thr->ofn->ofn_filter_manager;
  idx = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));

  /* Allocate with raddr=0 so oof_socket_add doesn't set sf_raddr.
   * Set raddr/rport after add, before connect. */
  e = ooft_alloc_endpoint(thr, IPPROTO_UDP, group_be, htons(2000),
                          INADDR_ANY, 0);

  rc = ooft_endpoint_add(e, 0);
  cmp_ok(rc, "==", 0, "A: add mcast-laddr endpoint");

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "A: no filters after add");

  /* Set remote address for connect */
  e->raddr_be = remote_be;
  e->rport_be = rport_be;

  rc = ooft_endpoint_udp_connect(e, 0);
  cmp_ok(rc, "==", 0, "A: udp connect");

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "A: no filters after connect");

  /* Join group matching laddr.  This triggers:
   *  1. oof_udp_connect_mcast_laddr:
   *     - oof_socket_del_wild_sw removes wild SW (no-op but harness records)
   *     - oof_socket_add_full_sw installs full-match SW filter
   *     - No full-match HW (all ports are replication-capable)
   *  2. oof_mcast_install installs wild-match HW filters
   *     - Skips mcast SW filter because OOF_CONNECTED_MCAST is true */
  ooft_endpoint_add_sw_filter(&e->sw_filters_to_remove, IPPROTO_UDP,
                              group_be, htons(2000), 0, 0);
  ooft_endpoint_expect_sw_add(e, IPPROTO_UDP, group_be, htons(2000),
                              remote_be, rport_be);
  ooft_endpoint_expect_multicast_hw_filters(e, idx, idx->hwport_mask,
                                            group_be);

  rc = ooft_endpoint_mcast_add(e, group_be, idx);
  cmp_ok(rc, "==", 0, "A: mcast join");

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "A: full-match sw filter installed");
  ok(e->skf.sf_flags & OOF_SOCKET_MCAST_FULL_SW_FILTER,
     "A: MCAST_FULL_SW_FILTER flag set");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "A: wild-match hw filters installed");

  /* Clean up via oof_socket_del: oof_socket_mcast_remove clears wild
   * HW filters; then the mcast-laddr connected path removes the
   * full-match SW filter and clears full-match HW. */
  ooft_endpoint_expect_sw_remove_all(e);
  ooft_cplane_expect_hw_remove_all(cp);
  oof_socket_del(fm, &e->skf);

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "A: all filters removed");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "A: all hw filters removed");

  ooft_free_stack(thr);
  test_cleanup();

  /* Part B (BR-8.26): mcast_del on connected socket removes full-match SW.
   *
   * After joining the group as in Part A, calling ooft_endpoint_mcast_del
   * triggers oof_socket_mcast_del_connected.  With all ports replication-
   * capable, hwports_full == 0 and hwports == 0 after removal, so
   * the full-match SW filter is removed and OOF_SOCKET_MCAST_FULL_SW_FILTER
   * is cleared. */

  test_alloc(32);
  thr = ooft_alloc_stack(64);
  TRY(ooft_default_cplane_init(current_ns()));
  fm = thr->ofn->ofn_filter_manager;
  idx = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));

  e = ooft_alloc_endpoint(thr, IPPROTO_UDP, group_be, htons(2000),
                          INADDR_ANY, 0);

  rc = ooft_endpoint_add(e, 0);
  cmp_ok(rc, "==", 0, "B: add endpoint");

  e->raddr_be = remote_be;
  e->rport_be = rport_be;

  rc = ooft_endpoint_udp_connect(e, 0);
  cmp_ok(rc, "==", 0, "B: udp connect");

  ooft_endpoint_add_sw_filter(&e->sw_filters_to_remove, IPPROTO_UDP,
                              group_be, htons(2000), 0, 0);
  ooft_endpoint_expect_sw_add(e, IPPROTO_UDP, group_be, htons(2000),
                              remote_be, rport_be);
  ooft_endpoint_expect_multicast_hw_filters(e, idx, idx->hwport_mask,
                                            group_be);
  rc = ooft_endpoint_mcast_add(e, group_be, idx);
  cmp_ok(rc, "==", 0, "B: mcast join");

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "B: filters after join");
  ok(e->skf.sf_flags & OOF_SOCKET_MCAST_FULL_SW_FILTER,
     "B: MCAST_FULL_SW_FILTER flag set");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "B: hw filters after join");

  /* Remove the mcast membership directly.  oof_mcast_remove removes
   * wild HW filters (SW filter removal skipped for connected mcast);
   * oof_socket_mcast_del_connected removes the full-match SW filter
   * (hwports == 0 → cleanup path). */
  ooft_endpoint_expect_multicast_filters_remove(e, idx, idx->hwport_mask,
                                                group_be);
  ooft_endpoint_add_sw_filter(&e->sw_filters_to_remove, IPPROTO_UDP,
                              group_be, htons(2000), remote_be, rport_be);
  ooft_endpoint_mcast_del(e, group_be, idx);

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "B: full-match sw filter removed after mcast del");
  ok((e->skf.sf_flags & OOF_SOCKET_MCAST_FULL_SW_FILTER) == 0,
     "B: MCAST_FULL_SW_FILTER flag cleared");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "B: hw filters removed after mcast del");

  /* Socket still alive with no filters.  oof_socket_del still calls
   * oof_socket_del_full_sw unconditionally for connected mcast-laddr
   * sockets (safe no-op in the connected-mcast-laddr branch of
   * oof_socket_del). */
  ooft_endpoint_add_sw_filter(&e->sw_filters_to_remove, IPPROTO_UDP,
                              group_be, htons(2000), remote_be, rport_be);
  oof_socket_del(fm, &e->skf);

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "B: clean after socket del");

  ooft_free_stack(thr);
  test_cleanup();

  done_testing();
}
