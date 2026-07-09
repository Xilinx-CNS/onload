/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include "../onload_kernel_compat.h"
#include "../stack.h"
#include "../../tap/tap.h"
#include "../oof_test.h"
#include "../cplane.h"
#include "../efrm.h"
#include "../utils.h"
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>
#include <arpa/inet.h>


static void expect_hw_filter_remove_all_on_mask(unsigned hwport_mask)
{
  int i;

  for( i = 0; i < CI_CFG_MAX_HWPORTS; i++ )
    if( (1 << i) & hwport_mask )
      ooft_client_expect_hw_remove_all(oo_nics[i].efrm_client);
}


/* Count mcast HW filters for the given group on a single hwport's client.
 * Non-destructive: does not move filters out of hw_filters_added. */
static int mcast_hw_filter_count(struct efrm_client* client, unsigned group_be)
{
  struct efx_filter_spec match_spec;
  struct ooft_hw_filter* filter;
  ci_dllink* link;
  int count = 0;

  memset(&match_spec, 0, sizeof(match_spec));
  match_spec.loc_host[0] = group_be;
  match_spec.ip_proto = IPPROTO_UDP;

  CI_DLLIST_FOR_EACH(link, &client->hw_filters_added) {
    filter = HW_FILTER_FROM_LINK(link);
    if( ooft_client_hw_filter_match(&match_spec, &filter->spec,
                                    EFX_FILTER_MATCH_LOC_HOST |
                                    EFX_FILTER_MATCH_IP_PROTO) )
      ++count;
  }
  return count;
}


/* Count mcast SW filters for the given group on an endpoint.
 * Non-destructive: does not disturb sw_filters_added. */
static int mcast_sw_filter_count(struct ooft_endpoint* ep, unsigned group_be)
{
  struct ooft_sw_filter* filter;
  ci_dllink* link;
  int count = 0;

  CI_DLLIST_FOR_EACH(link, &ep->sw_filters_added) {
    filter = CI_CONTAINER(struct ooft_sw_filter, socket_link, link);
    if( filter->laddr_be == group_be )
      ++count;
  }
  return count;
}


int test_mcast_interface_update(void)
{
  tcp_helper_resource_t *thr;
  struct ooft_endpoint *e;
  struct ooft_ifindex *idx0, *idx1;
  struct oof_manager* fm;
  struct net* ns;
  const char* group = "230.1.2.3";
  int rc;

  new_test();
  plan(43);

  /* Part A (BR-8.30): Interface removal cleans up mcast memberships.
   *
   * When an interface is removed (oof_mcast_update_interface with
   * hwports=0 followed by oof_mcast_update_filters), all mcast
   * memberships on that interface are removed — the oof_mcast_member
   * is freed, HW and SW filters are cleared. */

  test_alloc(32);
  thr = ooft_alloc_stack(64);
  TRY(ooft_default_cplane_init(current_ns()));
  fm = thr->ofn->ofn_filter_manager;
  ns = current_ns();
  idx0 = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));
  idx1 = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs)->next);

  e = ooft_alloc_endpoint(thr, IPPROTO_UDP, INADDR_ANY, htons(2000),
                          INADDR_ANY, 0);

  ooft_endpoint_expect_unicast_filters(e, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(e, 0);
  cmp_ok(rc, "==", 0, "A: add endpoint");
  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "A: sw filters after add");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "A: hw filters after add");

  ooft_endpoint_expect_multicast_filters(e, idx0, idx0->hwport_mask,
                                         inet_addr(group));
  rc = ooft_endpoint_mcast_add(e, inet_addr(group), idx0);
  cmp_ok(rc, "==", 0, "A: mcast join on idx0");

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "A: sw filters after join");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "A: hw filters after join");

  /* Simulate interface removal: update_interface with hwports=0 removes
   * the lid; update_filters sees lid==NULL → remove=1, frees membership,
   * removes HW and SW filters. Deferred work also removes unicast filters
   * on the now-unavailable hwport. */
  expect_hw_filter_remove_all_on_mask(idx0->hwport_mask);
  ooft_endpoint_expect_sw_remove_addr(e, inet_addr(group));

  oof_onload_mcast_update_interface(idx0->id, 0, 0, idx0->vlan_id,
                                    idx0->mac, ns, &efab_tcp_driver);
  oof_onload_mcast_update_filters(idx0->id, ns, &efab_tcp_driver);

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "A: mcast sw filter removed by interface update");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "A: mcast hw filter removed by interface update");
  cmp_ok(ooft_endpoint_mcast_membership_count_for(e, inet_addr(group), idx0),
         "==", 0, "A: membership removed by interface update");

  /* Socket is still alive with unicast filters — verify clean del */
  ooft_endpoint_expect_sw_remove_all(e);
  ooft_cplane_expect_hw_remove_all(cp);
  oof_socket_del(fm, &e->skf);

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "A: unicast sw filters removed on del");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "A: unicast hw filters removed on del");

  ooft_free_stack(thr);
  test_cleanup();

  /* Part B (BR-8.30): Interface removal with memberships on multiple interfaces.
   * Removing one interface should only clean up memberships on that
   * interface, leaving the other intact. */

  test_alloc(32);
  thr = ooft_alloc_stack(64);
  TRY(ooft_default_cplane_init(current_ns()));
  fm = thr->ofn->ofn_filter_manager;
  ns = current_ns();
  idx0 = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));
  idx1 = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs)->next);

  e = ooft_alloc_endpoint(thr, IPPROTO_UDP, INADDR_ANY, htons(3000),
                          INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(e, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(e, 0);
  cmp_ok(rc, "==", 0, "B: add endpoint");
  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "B: sw filters after add");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "B: hw filters after add");

  /* Join on both interfaces */
  ooft_endpoint_expect_multicast_filters(e, idx0, idx0->hwport_mask,
                                         inet_addr(group));
  rc = ooft_endpoint_mcast_add(e, inet_addr(group), idx0);
  cmp_ok(rc, "==", 0, "B: mcast join idx0");
  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "B: sw filters after idx0 join");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "B: hw filters after idx0 join");

  ooft_endpoint_expect_multicast_hw_filters(e, idx1, idx1->hwport_mask,
                                            inet_addr(group));
  rc = ooft_endpoint_mcast_add(e, inet_addr(group), idx1);
  cmp_ok(rc, "==", 0, "B: mcast join idx1");

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "B: sw filters after both joins");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "B: hw filters after both joins");
  cmp_ok(ooft_endpoint_mcast_membership_count(e), "==", 2,
         "B: two memberships before interface removal");

  /* Remove idx0 only — idx1 membership should survive. Deferred work also
   * removes unicast filters on idx0's now-unavailable hwport. */
  expect_hw_filter_remove_all_on_mask(idx0->hwport_mask);
  oof_onload_mcast_update_interface(idx0->id, 0, 0, idx0->vlan_id,
                                    idx0->mac, ns, &efab_tcp_driver);
  oof_onload_mcast_update_filters(idx0->id, ns, &efab_tcp_driver);

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "B: sw filters intact (idx1 membership preserves)");
  cmp_ok(mcast_sw_filter_count(e, inet_addr(group)), "==", 1,
         "B: mcast sw filter still installed for idx1");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "B: hw filters correct (idx0 removed, idx1 remains)");
  cmp_ok(mcast_hw_filter_count(
           oo_nics[__builtin_ctz(idx1->hwport_mask)].efrm_client,
           inet_addr(group)),
         "==", 1, "B: idx1 mcast hw filter still installed");
  cmp_ok(ooft_endpoint_mcast_membership_count_for(e, inet_addr(group), idx0),
         "==", 0, "B: idx0 membership removed");
  cmp_ok(ooft_endpoint_mcast_membership_count_for(e, inet_addr(group), idx1),
         "==", 1, "B: idx1 membership preserved");

  /* Clean up */
  ooft_endpoint_expect_sw_remove_all(e);
  ooft_cplane_expect_hw_remove_all(cp);
  oof_socket_del(fm, &e->skf);

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "B: sw filters removed on del");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "B: hw filters removed on del");

  ooft_free_stack(thr);
  test_cleanup();

  /* Part C (BR-8.29): Interface metadata update changes mcast HW filters.
   *
   * When an interface's hwport_mask changes (e.g. a bond slave is added),
   * oof_mcast_update_interface updates the lid, then
   * oof_mcast_update_filters recalculates mm_hwport_mask and adjusts
   * the HW filter coverage via oof_mcast_update. */

  test_alloc(32);
  thr = ooft_alloc_stack(64);
  TRY(ooft_default_cplane_init(current_ns()));
  fm = thr->ofn->ofn_filter_manager;
  ns = current_ns();
  idx0 = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));
  idx1 = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs)->next);

  e = ooft_alloc_endpoint(thr, IPPROTO_UDP, INADDR_ANY, htons(4000),
                          INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(e, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(e, 0);
  cmp_ok(rc, "==", 0, "C: add endpoint");
  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "C: sw filters after add");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "C: hw filters after add");

  /* Join mcast on idx0 — HW filter on idx0's hwport only */
  ooft_endpoint_expect_multicast_filters(e, idx0, idx0->hwport_mask,
                                         inet_addr(group));
  rc = ooft_endpoint_mcast_add(e, inet_addr(group), idx0);
  cmp_ok(rc, "==", 0, "C: mcast join on idx0");

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "C: sw filters after join");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "C: hw filters after join");

  /* Update idx0's interface to include idx1's hwport as well — simulates
   * a bond slave addition.  The mcast HW filter should expand to cover
   * the new hwport. */
  {
    unsigned new_mask = idx0->hwport_mask | idx1->hwport_mask;

    ooft_endpoint_expect_multicast_hw_filters(e, idx0, idx1->hwport_mask,
                                              inet_addr(group));

    oof_onload_mcast_update_interface(idx0->id, 1, new_mask, idx0->vlan_id,
                                      idx0->mac, ns, &efab_tcp_driver);
    oof_onload_mcast_update_filters(idx0->id, ns, &efab_tcp_driver);

    rc = ooft_endpoint_check_sw_filters(e);
    cmp_ok(rc, "==", 0, "C: sw filters after expand");
    rc = ooft_ns_check_hw_filters(thr->ns);
    cmp_ok(rc, "==", 0, "C: hw filter expanded to new hwport");
  }

  /* Restore idx0's original hwport mask — mcast HW filter should shrink */
  ooft_endpoint_expect_multicast_filters_remove(e, idx0, idx1->hwport_mask,
                                                inet_addr(group));

  oof_onload_mcast_update_interface(idx0->id, 1, idx0->hwport_mask,
                                    idx0->vlan_id, idx0->mac, ns,
                                    &efab_tcp_driver);
  oof_onload_mcast_update_filters(idx0->id, ns, &efab_tcp_driver);

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "C: sw filter intact after shrink");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "C: hw filter shrunk back to original hwport");
  cmp_ok(mcast_hw_filter_count(
           oo_nics[__builtin_ctz(idx0->hwport_mask)].efrm_client,
           inet_addr(group)),
         "==", 1, "C: original hwport mcast hw filter still installed after shrink");
  cmp_ok(mcast_hw_filter_count(
           oo_nics[__builtin_ctz(idx1->hwport_mask)].efrm_client,
           inet_addr(group)),
         "==", 0, "C: removed hwport mcast hw filter absent after shrink");

  /* Clean up */
  ooft_endpoint_expect_sw_remove_all(e);
  ooft_cplane_expect_hw_remove_all(cp);
  oof_socket_del(fm, &e->skf);

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "C: sw filters removed on del");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "C: clean after del");

  ooft_free_stack(thr);
  test_cleanup();

  done_testing();
}
