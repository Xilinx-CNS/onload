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
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>
#include <arpa/inet.h>


static void check_filters(struct ooft_endpoint* ep, tcp_helper_resource_t* thr,
                          const char* when)
{
  int rc;
  rc = ooft_endpoint_check_sw_filters(ep);
  cmp_ok(rc, "==", 0, "check sw filters %s", when);
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "check hw filters %s", when);
}


/* BR-8.35 (deferred mcast install via oof_socket_add),
 * BR-8.36 (mcast_install iteration logic),
 * BR-8.38 (mcast_del_all bulk removal).
 *
 * Scenario A: Join multicast groups before adding the socket.
 *   oof_socket_mcast_add queues memberships without filters (no sf_local_port).
 *   oof_socket_add then calls oof_socket_mcast_install to install them.
 *
 * Scenario B: Bulk removal via oof_socket_mcast_del_all.
 *   Add socket, join two groups, then call mcast_del_all.
 *   All mcast filters removed; unicast filters remain.
 */
int test_mcast_install(void)
{
  tcp_helper_resource_t* thr;
  struct ooft_endpoint* ep;
  struct ooft_ifindex* idx;
  struct oof_manager* fm;
  const unsigned group1 = inet_addr("230.1.2.3");
  const unsigned group2 = inet_addr("230.1.2.4");
  int rc;

  new_test();
  plan(21);

  test_alloc(32);
  thr = ooft_alloc_stack(64);
  fm = thr->ofn->ofn_filter_manager;
  TRY(ooft_default_cplane_init(current_ns()));
  idx = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));

  /* --- Scenario A (BR-8.35, BR-8.36): deferred mcast filter install --- */
  diag("Scenario A: join groups before socket_add");

  ep = ooft_alloc_endpoint(thr, IPPROTO_UDP, INADDR_ANY, htons(2000),
                           INADDR_ANY, 0);

  /* Join two groups while the socket is not yet added to OOF (sf_local_port
   * still NULL) — memberships queued in sf_mcast_memberships but no filters
   * installed. */
  rc = ooft_endpoint_mcast_add(ep, group1, idx);
  cmp_ok(rc, "==", 0, "mcast_add group1 before socket_add");
  rc = ooft_endpoint_mcast_add(ep, group2, idx);
  cmp_ok(rc, "==", 0, "mcast_add group2 before socket_add");

  /* Now add the socket — oof_socket_add calls oof_socket_mcast_install
   * which installs filters for the queued memberships. */
  ooft_endpoint_expect_unicast_filters(ep, OOFT_EXPECT_FLAG_HW);
  ooft_endpoint_expect_multicast_filters(ep, idx, idx->hwport_mask, group1);
  ooft_endpoint_expect_multicast_filters(ep, idx, idx->hwport_mask, group2);
  rc = ooft_endpoint_add(ep, 0);
  cmp_ok(rc, "==", 0, "add socket with pending memberships");
  check_filters(ep, thr, "after socket_add");

  /* Clean up */
  ooft_endpoint_expect_sw_remove_all(ep);
  ooft_cplane_expect_hw_remove_all(cp);
  oof_socket_del(fm, &ep->skf);
  check_filters(ep, thr, "after del");

  /* --- Scenario B (BR-8.38): bulk mcast removal via mcast_del_all --- */
  diag("Scenario B: mcast_del_all removes all groups");

  ep = ooft_alloc_endpoint(thr, IPPROTO_UDP, INADDR_ANY, htons(3000),
                           INADDR_ANY, 0);

  ooft_endpoint_expect_unicast_filters(ep, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(ep, 0);
  cmp_ok(rc, "==", 0, "add socket");
  check_filters(ep, thr, "after socket_add");

  /* Join two groups */
  ooft_endpoint_expect_multicast_filters(ep, idx, idx->hwport_mask, group1);
  rc = ooft_endpoint_mcast_add(ep, group1, idx);
  cmp_ok(rc, "==", 0, "mcast_add group1");
  check_filters(ep, thr, "after mcast_add group1");

  ooft_endpoint_expect_multicast_filters(ep, idx, idx->hwport_mask, group2);
  rc = ooft_endpoint_mcast_add(ep, group2, idx);
  cmp_ok(rc, "==", 0, "mcast_add group2");
  check_filters(ep, thr, "after mcast_add group2");

  /* Remove all mcast memberships — unicast filters stay */
  ooft_endpoint_expect_sw_remove_addr(ep, group1);
  ooft_endpoint_expect_sw_remove_addr(ep, group2);
  ooft_endpoint_expect_multicast_filters_remove(ep, idx, idx->hwport_mask,
                                                group1);
  ooft_endpoint_expect_multicast_filters_remove(ep, idx, idx->hwport_mask,
                                                group2);
  oof_socket_mcast_del_all(fm, &ep->skf);
  cmp_ok(ooft_endpoint_mcast_membership_count(ep), "==", 0,
         "mcast_del_all removed all memberships");
  check_filters(ep, thr, "after mcast_del_all");

  /* Clean up unicast filters */
  ooft_endpoint_expect_sw_remove_all(ep);
  ooft_cplane_expect_hw_remove_all(cp);
  oof_socket_del(fm, &ep->skf);
  check_filters(ep, thr, "after del");

  ooft_free_stack(thr);
  test_cleanup();
  done_testing();
}
