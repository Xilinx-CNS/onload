/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include "../onload_kernel_compat.h"
#include "../stack.h"
#include "../../tap/tap.h"
#include "../oof_test.h"
#include "../cplane.h"
#include "../oo_hw_filter.h"
#include "../oof_impl.h"
#include "../utils.h"
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>


static struct oof_local_port_addr*
skf_lpa(struct oof_socket* skf)
{
  return &skf->sf_local_port->lp_addr[skf->sf_la_i];
}


static void check_filters(tcp_helper_resource_t* thr)
{
  int rc;
  rc = ooft_stack_check_sw_filters(thr);
  cmp_ok(rc, "==", 0, "check sw filters");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "check hw filters");
}


/* BR-3.04: Adding a new local address while wild sockets exist causes
 * SW and HW filters to be installed for those sockets on the new address.
 *
 * BR-3.07: Removing an address clears all HW filters and wild/semi-wild
 * SW filters using it, sets OOF_LPA_FLAG_REMOVED, and resets
 * lpa_n_full_sharers.  Full-match (passive) SW filters persist until the
 * socket is deleted.
 *
 * BR-3.08: While an LPA is flagged removed, new sockets may bind/share on
 * it but must not install SW/HW filters or share the wild HW filter.
 */
int test_addr_lifecycle(void)
{
  tcp_helper_resource_t* thr;
  struct ooft_endpoint* wild;
  struct ooft_endpoint* semi;
  struct ooft_endpoint* listener;
  struct ooft_endpoint* passive;
  struct ooft_endpoint* passive_removed;
  struct ooft_endpoint* full_own;
  ci_dllist hw_filters;
  int rc;
  struct oof_manager* fm;
  struct ooft_ifindex* idx0;
  struct ooft_addr* addr2;

  new_test();
  plan(41);

  test_alloc(32);
  thr = ooft_alloc_stack(16);
  fm = thr->ofn->ofn_filter_manager;
  TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X2_FF));

  ci_dllist_init(&hw_filters);
  idx0 = ooft_idx_from_id(1);
  ci_assert(idx0);

  /* --- Scenario A (BR-3.04): Add address after wild socket exists --- */
  diag("Scenario A: add address with existing wild socket");

  wild = ooft_alloc_endpoint(thr, IPPROTO_UDP, INADDR_ANY, htons(2000), INADDR_ANY, 0);

  /* Add wild — SW + HW for both existing addresses */
  ooft_endpoint_expect_unicast_filters(wild, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(wild, 0);
  cmp_ok(rc, "==", 0, "add wild");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_filters);

  /* Add a third address to ifindex 0 */
  ooft_endpoint_expect_sw_add(wild, IPPROTO_UDP,
                              inet_addr("1.0.0.2"), htons(2000), 0, 0);
  ooft_endpoint_expect_hw_unicast(wild, inet_addr("1.0.0.2"), 0);
  addr2 = ooft_alloc_addr(current_ns(), idx0, inet_addr("1.0.0.2"));
  check_filters(thr);

  /* Cleanup: remove new address, then socket */
  ooft_endpoint_expect_sw_remove_addr(wild, inet_addr("1.0.0.2"));
  ooft_cplane_expect_hw_remove_all(cp);
  ooft_del_addr(current_ns(), idx0, addr2);
  check_filters(thr);

  ooft_endpoint_expect_sw_remove_all(wild);
  ooft_hw_filter_expect_remove_list(&hw_filters);
  oof_socket_del(fm, &wild->skf);
  check_filters(thr);

  /* --- Scenario B (BR-3.07): Remove address with active semi-wild --- */
  diag("Scenario B: remove address with active semi-wild socket");

  semi = ooft_alloc_endpoint(thr, IPPROTO_UDP, inet_addr("1.0.0.0"), htons(3000), INADDR_ANY, 0);

  ooft_endpoint_expect_unicast_filters(semi, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(semi, 0);
  cmp_ok(rc, "==", 0, "add semi-wild");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_filters);

  /* Remove the address this socket is bound to */
  ooft_endpoint_expect_sw_remove_all(semi);
  ooft_hw_filter_expect_remove_list(&hw_filters);
  ooft_del_addr(current_ns(), idx0,
                CI_CONTAINER(struct ooft_addr, idx_link,
                             ci_dllist_start(&idx0->addrs)));
  ok(skf_lpa(&semi->skf)->lpa_flags & OOF_LPA_FLAG_REMOVED,
     "B: LPA flagged REMOVED after addr removal");
  check_filters(thr);

  /* Socket still bound but no filters — delete it */
  oof_socket_del(fm, &semi->skf);
  check_filters(thr);

  /* --- Scenario C (BR-3.07): addr removal with listener + passive --- */
  diag("Scenario C: addr removal with active listener and passive");

  /* Re-add the address for this scenario */
  ooft_alloc_addr(current_ns(), idx0, inet_addr("1.0.0.0"));

  listener = ooft_alloc_endpoint(thr, IPPROTO_TCP, inet_addr("1.0.0.0"), htons(4000), INADDR_ANY, 0);
  passive = ooft_alloc_endpoint(thr, IPPROTO_TCP, inet_addr("1.0.0.0"), htons(4000),
                                inet_addr("2.0.0.0"), htons(5000));

  /* Add listener */
  ooft_endpoint_expect_unicast_filters(listener, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(listener, 0);
  cmp_ok(rc, "==", 0, "add listener");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_filters);

  /* Add passive via oof_socket_share */
  {
    ci_addr_t laddr = CI_ADDR_FROM_IP4(passive->laddr_be);
    ci_addr_t raddr = CI_ADDR_FROM_IP4(passive->raddr_be);
    ooft_endpoint_expect_unicast_filters(passive, 0);
    rc = oof_socket_share(fm, &passive->skf, &listener->skf,
                          AF_SPACE_FLAG_IP4, laddr, raddr,
                          passive->lport_be, passive->rport_be);
    cmp_ok(rc, "==", 0, "share passive");
    check_filters(thr);
  }

  /* Remove the address — HW filters and wild/semi-wild SW filters cleared.
   * Full-match (passive) SW filters persist until socket deletion. */
  ooft_endpoint_expect_sw_remove_all(listener);
  ooft_hw_filter_expect_remove_list(&hw_filters);
  ooft_del_addr(current_ns(), idx0,
                CI_CONTAINER(struct ooft_addr, idx_link,
                             ci_dllist_start(&idx0->addrs)));
  ok(skf_lpa(&listener->skf)->lpa_flags & OOF_LPA_FLAG_REMOVED,
     "C: LPA flagged REMOVED after addr removal");
  cmp_ok(skf_lpa(&listener->skf)->lpa_n_full_sharers, "==", 0,
         "C: lpa_n_full_sharers reset to 0 after addr removal");
  check_filters(thr);

  /* BR-3.08: Adding a new semi-wild socket while the LPA is removed binds
   * the socket but does not install a new SW filter or HW filter. */
  passive_removed = ooft_alloc_endpoint(thr, IPPROTO_UDP, inet_addr("1.0.0.0"), htons(4500),
                                        INADDR_ANY, 0);
  rc = ooft_endpoint_add(passive_removed, 0);
  cmp_ok(rc, "==", 0, "add semi-wild while address removed");
  ok(passive_removed->skf.sf_local_port != NULL,
     "removed-address semi-wild is still bound");
  cmp_ok(oo_hw_filter_hwports(&skf_lpa(&passive_removed->skf)->lpa_filter),
         "==", 0, "removed-address LPA has no wild HW filter");
  check_filters(thr);

  /* Cleanup: passives still have their SW filters (not cleared by addr_del).
   * The removed-address passive never had a SW filter, so no SW remove is
   * expected for it. */
  oof_socket_del(fm, &passive_removed->skf);
  ooft_endpoint_expect_sw_remove_all(passive);
  oof_socket_del(fm, &passive->skf);
  oof_socket_del(fm, &listener->skf);
  check_filters(thr);

  /* --- Scenario D (BR-3.07): addr removal clears a full-match socket's own
   *     HW filter while preserving its SW filter until socket deletion. --- */
  diag("Scenario D: addr removal clears full-match own HW");

  ooft_alloc_addr(current_ns(), idx0, inet_addr("1.0.0.0"));
  full_own = ooft_alloc_endpoint(thr, IPPROTO_UDP, inet_addr("1.0.0.0"), htons(5000),
                                 inet_addr("2.0.0.0"), htons(6000));
  ooft_endpoint_expect_unicast_filters(full_own, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(full_own, 0);
  cmp_ok(rc, "==", 0, "add full-match with own HW");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_filters);

  ooft_hw_filter_expect_remove_list(&hw_filters);
  ooft_del_addr(current_ns(), idx0,
                CI_CONTAINER(struct ooft_addr, idx_link,
                             ci_dllist_start(&idx0->addrs)));
  check_filters(thr);

  ooft_endpoint_expect_sw_remove_all(full_own);
  oof_socket_del(fm, &full_own->skf);
  check_filters(thr);

  ooft_free_stack(thr);
  test_cleanup();
  done_testing();
}
