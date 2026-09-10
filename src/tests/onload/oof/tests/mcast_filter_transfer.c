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


/* BR-8.19: Multicast HW filter ownership transfer on non-VLAN-capable
 * hardware.
 *
 * An oof_mcast_filter is unique per {stack, maddr, vlan_id}.  On hwports
 * that do not support VLAN filters, two filters that differ only by VLAN id
 * are indistinguishable in hardware: the second filter does not install its
 * own HW filter but instead relies on the coverage already provided by the
 * first (see oof_mcast_filter_duplicate_hwports, BR-8.16).
 *
 * When the membership that *owns* the shared HW filter is removed,
 * oof_mcast_remove must hand the HW filter over to the sibling filter via
 * oof_hw_filter_transfer rather than clearing it.  This avoids a window in
 * which no HW filter is installed for traffic the sibling still wants.
 *
 * Topology: ONE non-VLAN-capable hwport (OOFT_HWPORT_EF10_LL — sets
 * OOF_HWPORT_FLAG_MCAST_REPLICATE but not OOF_HWPORT_FLAG_VLAN_FILTERS),
 * shared by TWO interfaces with different VLAN ids.  A single UDP socket
 * joins the same group on both interfaces.
 *
 * oof_hw_filter_transfer makes no efrm calls — it only reassigns the
 * per-hwport filter_id from the old filter struct to the new one.  So the
 * observable behaviour is:
 *   - join on idx0 (vlan 100): SW + HW filter installed on the shared port.
 *   - join on idx1 (vlan 200): nothing — SW deduped, HW is a duplicate.
 *   - remove idx0 membership: NOTHING happens at the efrm level (ownership
 *     transfers to idx1's filter).  A buggy implementation that cleared the
 *     filter would re-install it for the sibling via the re-check loop,
 *     surfacing as an unexpected HW filter add.
 *   - remove idx1 membership: the (now solely-owned) HW filter is removed.
 */
int test_mcast_filter_transfer(void)
{
  tcp_helper_resource_t* thr;
  struct ooft_endpoint* e;
  struct ooft_hwport* hw;
  struct ooft_ifindex* idx0;
  struct ooft_ifindex* idx1;
  struct net* ns;
  const char* group = "239.1.2.3";
  unsigned char mac0[6] = { 0,1,0,0,0,0 };
  unsigned char mac1[6] = { 0,1,0,0,0,1 };
  int rc;

  new_test();
  plan(15);

  test_alloc(32);
  thr = ooft_alloc_stack(64);
  ns = current_ns();

  /* Build the custom topology by hand (the default cplane uses VLAN-capable
   * X2 NICs).  One EF10_LL hwport, two interfaces with distinct VLAN ids
   * both routed through it, one address each. */
  hw = ooft_alloc_hwport(cp, ns, OOFT_HWPORT_EF10_LL);

  idx0 = ooft_alloc_ifindex(cp, ns, 100, mac0);
  idx1 = ooft_alloc_ifindex(cp, ns, 200, mac1);
  ooft_add_hwport_to_ifindex(idx0, hw, ns);
  ooft_add_hwport_to_ifindex(idx1, hw, ns);
  ooft_alloc_addr(ns, idx0, inet_addr("1.0.0.0"));
  ooft_alloc_addr(ns, idx1, inet_addr("1.0.0.1"));
  idx0->up = 1;
  idx1->up = 1;
  ooft_hwport_up_down(hw, 1);

  /* Base wild UDP socket — installs unicast filters for both addresses on
   * the shared hwport. */
  e = ooft_alloc_endpoint(thr, IPPROTO_UDP, INADDR_ANY, htons(2000),
                          INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(e, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(e, 0);
  cmp_ok(rc, "==", 0, "add endpoint");

  /* Join on idx0 (vlan 100): first filter for the group — SW + HW on the
   * shared port.  The port is non-VLAN-capable so the installed spec uses
   * EFX_FILTER_VID_UNSPEC. */
  ooft_endpoint_expect_multicast_filters(e, idx0, idx0->hwport_mask,
                                         inet_addr(group));
  rc = ooft_endpoint_mcast_add(e, inet_addr(group), idx0);
  cmp_ok(rc, "==", 0, "join group on idx0");

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "sw filters after join idx0");
  rc = ooft_ns_check_hw_filters(ns);
  cmp_ok(rc, "==", 0, "hw filters after join idx0");

  /* Join on idx1 (vlan 200): a second oof_mcast_filter is created (different
   * vlan) but installs NO HW filter — the shared non-VLAN port is already
   * covered by idx0's filter (duplicate), and the SW filter is deduped
   * (oof_socket_has_maddr_filter).  Expect no new filters. */
  rc = ooft_endpoint_mcast_add(e, inet_addr(group), idx1);
  cmp_ok(rc, "==", 0, "join group on idx1");

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "no new sw filter for idx1 (dedup)");
  rc = ooft_ns_check_hw_filters(ns);
  cmp_ok(rc, "==", 0, "no new hw filter for idx1 (duplicate)");
  cmp_ok(ooft_endpoint_mcast_filter_count_for_addr(e, inet_addr(group)),
         "==", 2, "distinct vlan memberships use distinct mcast filters");

  /* Remove the idx0 membership — the owner of the shared HW filter.
   * Ownership must transfer to idx1's filter: no efrm add or remove, and
   * the SW filter is preserved because idx1's membership still holds a
   * filter for this group.  We register NO expectations: any efrm activity
   * (e.g. a bug that clears then re-installs the filter) would be flagged. */
  ooft_endpoint_mcast_del(e, inet_addr(group), idx0);

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "sw filter preserved after idx0 del (transfer)");
  rc = ooft_ns_check_hw_filters(ns);
  cmp_ok(rc, "==", 0, "hw filter transferred, no churn, after idx0 del");
  cmp_ok(ooft_endpoint_mcast_filter_count_for_addr(e, inet_addr(group)),
         "==", 1, "idx1 mcast filter remains after transfer");

  /* Remove the idx1 membership — the last holder.  The HW filter (now owned
   * by idx1's filter after the transfer) is cleared, and the SW filter for
   * the group is removed. */
  ooft_endpoint_expect_multicast_filters_remove(e, idx1, idx1->hwport_mask,
                                                inet_addr(group));
  ooft_endpoint_expect_sw_remove_addr(e, inet_addr(group));
  ooft_endpoint_mcast_del(e, inet_addr(group), idx1);

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "sw filter removed after idx1 del");
  rc = ooft_ns_check_hw_filters(ns);
  cmp_ok(rc, "==", 0, "hw filter removed after idx1 del");

  /* Tear down the socket — removes the unicast filters. */
  ooft_endpoint_expect_sw_remove_all(e);
  ooft_cplane_expect_hw_remove_all(cp);
  oof_socket_del(thr->ofn->ofn_filter_manager, &e->skf);

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "teardown sw filters");
  rc = ooft_ns_check_hw_filters(ns);
  cmp_ok(rc, "==", 0, "teardown hw filters");

  ooft_free_stack(thr);
  test_cleanup();

  done_testing();
}
