/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include "../onload_kernel_compat.h"
#include "../stack.h"
#include "../../tap/tap.h"
#include "../oof_test.h"
#include "../cplane.h"
#include "../utils.h"
#include "../efrm_interface.h"
#include "../oof_impl.h"
#include "../oof_tproxy_ipproto.h"
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>
#include "../stack_interface.h"


/* BR-9.08 (IP_PROTO_MAC fallback to global IP_PROTO),
 * BR-9.13 (last tproxy free clears global filters).
 *
 * These tests set efrm_filter_insert_fail_proto_mac so that IP_PROTO_MAC
 * filter insertions return -EPROTONOSUPPORT, triggering the global filter
 * fallback path in oof_tproxy_filter_update.
 */
static bool tproxy_global_filters_cleared(struct oof_manager* fm)
{
  int i;

  for( i = 0; i < (int)OOF_TPROXY_GLOBAL_FILTER_COUNT; i++ )
    if( fm->fm_tproxy_global_filters[i] != 0 )
      return false;

  return true;
}


int test_tproxy_global(void)
{
  tcp_helper_resource_t *thr;
  struct ooft_ifindex *idx0;
  struct oof_manager *fm;
  int rc, i;

  new_test();
  plan(6);

  /* --- Scenario A (BR-9.08): IP_PROTO_MAC fallback to global --- */
  diag("Scenario A: global filter fallback on -EPROTONOSUPPORT");

  test_alloc(32);
  thr = ooft_alloc_stack(64);
  TRY(ooft_default_cplane_init(current_ns()));
  fm = thr->ofn->ofn_filter_manager;
  idx0 = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));

  efrm_filter_insert_fail_proto_mac = 1;

  ooft_expect_tproxy_filters_global(thr, idx0);
  rc = oof_tproxy_install(fm, thr, NULL, idx0->id);
  cmp_ok(rc, "==", 0, "A: tproxy install with global fallback");

  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "A: MAC+ARP filters installed");

  for( i = 0; i < (int)OOF_TPROXY_GLOBAL_FILTER_COUNT; i++ )
    if( !(fm->fm_tproxy_global_filters[i] & idx0->hwport_mask) )
      break;
  cmp_ok(i, "==", (int)OOF_TPROXY_GLOBAL_FILTER_COUNT,
         "A: global filters set for all protocols");

  /* --- Scenario B (BR-9.13): Last tproxy free clears global --- */
  diag("Scenario B: last tproxy free clears global filters");

  ooft_expect_tproxy_filters_remove(thr, idx0);
  rc = oof_tproxy_free(fm, thr, NULL, idx0->id);
  cmp_ok(rc, "==", 0, "B: tproxy free");

  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "B: all HW filters cleared");

  ok(tproxy_global_filters_cleared(fm),
     "B: global filters zero for all protocols");

  efrm_filter_insert_fail_proto_mac = 0;

  ooft_free_stack(thr);
  test_cleanup();

  done_testing();
}


static bool check_hw_filters_all(struct ooft_hwport* hw0,
                                 struct ooft_hwport* hw1,
                                 struct ooft_hwport* hw2)
{
  int rc = 0;
  rc |= ooft_client_check_hw_filters(&hw0->client);
  rc |= ooft_client_check_hw_filters(&hw1->client);
  rc |= ooft_client_check_hw_filters(&hw2->client);
  return rc == 0;
}


/* BR-9.17 (add merges hwports with existing global filters),
 * BR-9.18 (add increments per-hwport reference counts),
 * BR-9.19 (remove decrements refcount; last ref clears HW filter).
 *
 * Two namespaces share hwport 1.  Both install tproxy with global
 * filter fallback.  The shared hwport gets refcount 2.  Freeing ns1's
 * tproxy decrements to 1 (filter stays); freeing ns2's decrements to 0
 * (filter cleared).
 */
int test_tproxy_global_refcount(void)
{
  struct ooft_task* proc1;
  struct ooft_task* proc2;
  struct net* ns1;
  struct net* ns2;
  tcp_helper_resource_t* thr1;
  tcp_helper_resource_t* thr2;
  struct oof_manager* fm1;
  struct oof_manager* fm2;
  struct oo_filter_ns_manager* ofnm;
  struct ooft_hwport* hw0;
  struct ooft_hwport* hw1;
  struct ooft_hwport* hw2;
  struct ooft_ifindex* idx1;
  struct ooft_ifindex* idx2;
  ci_dllist ns1_hw0_filters;
  ci_dllist ns1_hw1_filters;
  ci_dllist ns2_hw1_filters;
  ci_dllist ns2_hw2_filters;
  int rc, j;

  new_test();
  plan(18);

  test_alloc(32);

  /* --- Cplane: 3 hwports, 2 namespaces sharing hwport 1 ---
   *
   * Stack must be allocated before cplane init so that the oof_manager
   * exists when ooft_add_hwport_to_ifindex registers interface details.
   * Hwport up/down goes last so both managers see the events.
   */

  proc1 = current;
  ns1 = current_ns();
  thr1 = ooft_alloc_stack(64);
  fm1 = thr1->ofn->ofn_filter_manager;

  hw0 = ooft_alloc_hwport(cp, ns1, OOFT_HWPORT_EF10_FF);
  hw1 = ooft_alloc_hwport(cp, ns1, OOFT_HWPORT_EF10_FF);
  hw2 = ooft_alloc_hwport(cp, ns1, OOFT_HWPORT_EF10_FF);

  unsigned char mac1[6] = { 0,1,0,0,0,0 };
  idx1 = ooft_alloc_ifindex(cp, ns1, EFX_FILTER_VID_UNSPEC, mac1);
  ooft_add_hwport_to_ifindex(idx1, hw0, ns1);
  ooft_add_hwport_to_ifindex(idx1, hw1, ns1);
  ooft_alloc_addr(ns1, idx1, inet_addr("1.0.0.0"));
  idx1->up = 1;

  ns2 = ooft_alloc_namespace(cp);
  proc2 = context_alloc(ns2);
  current = proc2;
  thr2 = ooft_alloc_stack(64);
  fm2 = thr2->ofn->ofn_filter_manager;

  unsigned char mac2[6] = { 0,1,0,0,0,2 };
  idx2 = ooft_alloc_ifindex(cp, ns2, EFX_FILTER_VID_UNSPEC, mac2);
  ooft_add_hwport_to_ifindex(idx2, hw1, ns2);
  ooft_add_hwport_to_ifindex(idx2, hw2, ns2);
  ooft_alloc_addr(ns2, idx2, inet_addr("1.0.0.2"));
  idx2->up = 1;

  ooft_hwport_up_down(hw0, 1);
  ooft_hwport_up_down(hw1, 1);
  ooft_hwport_up_down(hw2, 1);

  ofnm = thr1->ofn->ofn_ns_manager;

  ci_dllist_init(&ns1_hw0_filters);
  ci_dllist_init(&ns1_hw1_filters);
  ci_dllist_init(&ns2_hw1_filters);
  ci_dllist_init(&ns2_hw2_filters);

  efrm_filter_insert_fail_proto_mac = 1;

  /* --- Scenario C (BR-9.17, BR-9.18): two-namespace install --- */
  diag("Scenario C: two-namespace install with shared hwport");

  /* C1: ns1 installs tproxy on idx1 (hwports {0,1}) */
  ooft_expect_tproxy_filters_global(thr1, idx1);
  rc = oof_tproxy_install(fm1, thr1, NULL, idx1->id);
  cmp_ok(rc, "==", 0, "C1: ns1 tproxy install");

  ok(check_hw_filters_all(hw0, hw1, hw2),
     "C1: HW filters correct after ns1 install");

  ooft_client_claim_added_hw_filters(&hw0->client, &ns1_hw0_filters);
  ooft_client_claim_added_hw_filters(&hw1->client, &ns1_hw1_filters);

  /* C2: ns2 installs tproxy on idx2 (hwports {1,2}).
   * Hwport 1 already has global IP-proto filters from ns1, so the
   * callback merges (BR-9.17) and only inserts on hwport 2.
   */
  {
    int vi_id2 = tcp_helper_rx_vi_id(thr2, hw1->id);
    int stack_id2 = tcp_helper_vi_hw_stack_id(thr2, hw1->id);

    /* Per-interface MAC + ARP on hwport 1 (ns2's mac) */
    ooft_client_expect_hw_add_mac(&hw1->client, vi_id2, stack_id2,
                                  mac2, EFX_FILTER_VID_UNSPEC);
    ooft_client_expect_hw_add_ethertype(&hw1->client, 0, mac2,
                                        EFX_FILTER_VID_UNSPEC,
                                        htons(0x0806));
  }
  {
    int vi_id2 = tcp_helper_rx_vi_id(thr2, hw2->id);
    int stack_id2 = tcp_helper_vi_hw_stack_id(thr2, hw2->id);

    /* Per-interface MAC + ARP on hwport 2 */
    ooft_client_expect_hw_add_mac(&hw2->client, vi_id2, stack_id2,
                                  mac2, EFX_FILTER_VID_UNSPEC);
    ooft_client_expect_hw_add_ethertype(&hw2->client, 0, mac2,
                                        EFX_FILTER_VID_UNSPEC,
                                        htons(0x0806));

    /* Global IP-proto on hwport 2 only (hwport 1 already has them) */
    for( j = 0; j < (int)OOF_TPROXY_IPPROTO_FILTER_COUNT; j++ )
      ooft_client_expect_hw_add_ipproto(&hw2->client, 0,
                                        htons(oof_tproxy_ipprotos[j][0]),
                                        oof_tproxy_ipprotos[j][1]);
  }

  rc = oof_tproxy_install(fm2, thr2, NULL, idx2->id);
  cmp_ok(rc, "==", 0, "C2: ns2 tproxy install (merge)");

  ok(check_hw_filters_all(hw0, hw1, hw2),
     "C2: HW filters correct after ns2 install");

  ooft_client_claim_added_hw_filters(&hw1->client, &ns2_hw1_filters);
  ooft_client_claim_added_hw_filters(&hw2->client, &ns2_hw2_filters);

  /* Verify refcounts (BR-9.18): check proto 0 as representative */
  cmp_ok(ofnm->ofnm_tproxy_filters[0].otf_filter_refs[hw0->id], "==", 1,
         "C2: refcount[hw0]=1 (ns1 only)");
  cmp_ok(ofnm->ofnm_tproxy_filters[0].otf_filter_refs[hw1->id], "==", 2,
         "C2: refcount[hw1]=2 (shared)");
  cmp_ok(ofnm->ofnm_tproxy_filters[0].otf_filter_refs[hw2->id], "==", 1,
         "C2: refcount[hw2]=1 (ns2 only)");

  /* --- Scenario D (BR-9.19 partial): ns1 frees, shared hwport keeps --- */
  diag("Scenario D: ns1 frees tproxy, shared hwport filter survives");

  /* hwport 0: all filters removed */
  ooft_hw_filter_expect_remove_list(&ns1_hw0_filters);

  /* hwport 1: ns1's per-interface (MAC+ARP) removed, IP-proto stays.
   * Split ns1_hw1_filters: MAC/ARP have EFX_FILTER_MATCH_LOC_MAC set,
   * IP-proto filters do not.
   */
  {
    struct ooft_hw_filter* f;
    struct ooft_hw_filter* f_tmp;

    CI_DLLIST_FOR_EACH3(struct ooft_hw_filter, f, client_link,
                        &ns1_hw1_filters, f_tmp) {
      if( f->spec.match_flags & EFX_FILTER_MATCH_LOC_MAC )
        ooft_client_expect_hw_remove(&hw1->client, f);
    }
    /* Remaining items are IP-proto filters — put back as live */
    ci_dllist_join(&hw1->client.hw_filters_added, &ns1_hw1_filters);
  }

  current = proc1;
  rc = oof_tproxy_free(fm1, thr1, NULL, idx1->id);
  cmp_ok(rc, "==", 0, "D: ns1 tproxy free");

  ok(check_hw_filters_all(hw0, hw1, hw2),
     "D: HW filters correct (hw1 IP-proto survives)");

  cmp_ok(ofnm->ofnm_tproxy_filters[0].otf_filter_refs[hw0->id], "==", 0,
         "D: refcount[hw0]=0 (cleared)");
  cmp_ok(ofnm->ofnm_tproxy_filters[0].otf_filter_refs[hw1->id], "==", 1,
         "D: refcount[hw1]=1 (ns2 remains)");
  ok(ofnm->ofnm_tproxy_filters[0].otf_filter.filter_id[hw0->id] < 0,
     "D: filter_id[hw0] cleared");
  ok(ofnm->ofnm_tproxy_filters[0].otf_filter.filter_id[hw1->id] >= 0,
     "D: filter_id[hw1] still installed");
  /* --- Scenario E (BR-9.19 complete): ns2 frees, all cleared --- */
  diag("Scenario E: ns2 frees tproxy, all global filters cleared");

  /* hwport 1: IP-proto from hw_filters_added + ns2's MAC+ARP */
  ooft_client_expect_hw_remove_all(&hw1->client);
  ooft_hw_filter_expect_remove_list(&ns2_hw1_filters);
  /* hwport 2: all filters */
  ooft_hw_filter_expect_remove_list(&ns2_hw2_filters);

  current = proc2;
  rc = oof_tproxy_free(fm2, thr2, NULL, idx2->id);
  cmp_ok(rc, "==", 0, "E: ns2 tproxy free");

  ok(check_hw_filters_all(hw0, hw1, hw2),
     "E: all HW filters cleared");

  cmp_ok(ofnm->ofnm_tproxy_filters[0].otf_filter_refs[hw1->id], "==", 0,
         "E: refcount[hw1]=0 (cleared)");
  cmp_ok(ofnm->ofnm_tproxy_filters[0].otf_filter_refs[hw2->id], "==", 0,
         "E: refcount[hw2]=0 (cleared)");
  ok(tproxy_global_filters_cleared(fm2),
     "E: last tproxy free clears all global filter masks");

  efrm_filter_insert_fail_proto_mac = 0;

  ooft_free_stack(thr1);
  ooft_free_stack(thr2);
  test_cleanup();
  context_free(proc1);
  ooft_free_namespace(ns1);

  done_testing();
}
