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


/* Multicast joins in a heterogeneous namespace.
 *
 * Build one namespace mixing:
 *   - two X4 interfaces (idx 1,2): each an FF port shadowed by a CT/LL
 *     sibling, so they have an express (LL) datapath.
 *   - two X2 interfaces (idx 3,4): FF only, no LL sibling (enterprise).
 *
 * A single socket joins the same group on one express interface and one
 * enterprise interface.  Each interface must place its multicast HW
 * filter on its own datapath: the express interface uses its LL ports
 * (hwport_mask_ll), the enterprise interface uses its FF ports
 * (hwport_mask_ff, which is its whole mask).  This is the per-interface
 * analogue of mixed_unicast, and models an app that joins a group on
 * several NICs of differing capability.
 */
int test_mixed_multicast(void)
{
  tcp_helper_resource_t* thr;
  struct ooft_endpoint* e;
  struct ooft_ifindex* express;
  struct ooft_ifindex* enterprise;
  unsigned char mac2[6] = { 0,1,0,0,0,2 };
  unsigned char mac3[6] = { 0,1,0,0,0,3 };
  const char* group = "230.1.2.3";
  struct oof_manager* fm;
  int rc;

  new_test();
  plan(NO_PLAN);

  test_alloc(32);
  thr = ooft_alloc_stack_mode(64, OOFT_RX_BOTH);
  fm = thr->ofn->ofn_filter_manager;

  TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X4_FF));
  TRY(ooft_cplane_add_nic(current_ns(), OOFT_NIC_X2_FF,
                          mac2, inet_addr("1.0.0.2"),
                          mac3, inet_addr("1.0.0.3")));

  /* idx ids start at 1; X4 pair are 1,2 (express), X2 pair are 3,4. */
  express = ooft_idx_from_id(1);
  enterprise = ooft_idx_from_id(3);
  TEST(express);
  TEST(enterprise);
  /* Sanity: the express interface has an LL datapath, the enterprise
   * one does not. */
  ok(express->hwport_mask_ll != 0, "express interface has LL datapath");
  ok(enterprise->hwport_mask_ll == 0, "enterprise interface has no LL datapath");

  e = ooft_alloc_endpoint(thr, IPPROTO_UDP, inet_addr(group), htons(2000),
                          INADDR_ANY, 0);

  /* Bound to a multicast address, so no filters until the group is
   * joined. */
  rc = ooft_endpoint_add(e, 0);
  cmp_ok(rc, "==", 0, "add endpoint");
  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "check no sw filters before join");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "check no hw filters before join");

  /* Join on the express interface: HW filter lands on its LL ports. */
  ooft_endpoint_expect_multicast_filters(e, express, express->hwport_mask_ll,
                                         inet_addr(group));
  rc = ooft_endpoint_mcast_add(e, inet_addr(group), express);
  cmp_ok(rc, "==", 0, "mcast join on express interface");
  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "check sw filters after express join");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "check hw filters after express join");

  /* Join the same group on the enterprise interface: HW filter lands on
   * its FF ports.  The SW filter is per-socket-per-group and already
   * exists from the express join, so only HW filters are added here. */
  ooft_endpoint_expect_multicast_hw_filters(e, enterprise,
                                            enterprise->hwport_mask_ff,
                                            inet_addr(group));
  rc = ooft_endpoint_mcast_add(e, inet_addr(group), enterprise);
  cmp_ok(rc, "==", 0, "mcast join on enterprise interface");
  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "check sw filters after enterprise join");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "check hw filters after enterprise join");

  /* Leave the express group: only its LL HW filter goes; the SW filter
   * stays as the enterprise membership still holds it. */
  ooft_endpoint_expect_multicast_filters_remove(e, express,
                                                express->hwport_mask_ll,
                                                inet_addr(group));
  ooft_endpoint_mcast_del(e, inet_addr(group), express);
  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "check sw filters after express leave");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "check hw filters after express leave");

  /* Leave the enterprise group: last membership, so its FF HW filter and
   * the shared SW filter are both removed. */
  ooft_endpoint_expect_multicast_filters_remove(e, enterprise,
                                                enterprise->hwport_mask_ff,
                                                inet_addr(group));
  ooft_endpoint_expect_sw_remove_all(e);
  ooft_endpoint_mcast_del(e, inet_addr(group), enterprise);
  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "check sw filters after enterprise leave");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "check hw filters after enterprise leave");

  oof_socket_del(fm, &e->skf);
  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "check sw filters after close");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "check hw filters after close");

  ooft_free_stack(thr);
  test_cleanup();
  done_testing();
}
