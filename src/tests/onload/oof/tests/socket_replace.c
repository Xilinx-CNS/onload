/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include "../onload_kernel_compat.h"
#include "../stack.h"
#include "../stack_interface.h"
#include "../../tap/tap.h"
#include "../oof_test.h"
#include "../cplane.h"
#include "../efrm.h"
#include "../oo_hw_filter.h"
#include "../utils.h"
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>


static void check_filters(tcp_helper_resource_t* thr)
{
  int rc;
  rc = ooft_stack_check_sw_filters(thr);
  cmp_ok(rc, "==", 0, "check sw filters");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "check hw filters");
}


/* BR-7.06 (dummy-to-real swap), BR-7.07 (preconditions),
 * BR-7.08 (update sharer details).
 *
 * Scenario A: Replace a stackless dummy socket with a real socket,
 *   then arm it. Verifies state transfer, flag clearing, and that
 *   the two-phase add (dummy → arm) installs filters correctly.
 *
 * Scenario B: Update sharer details on a full-match socket that shares a
 *   listener's wild HW filter. Verifies sf_raddr and sf_rport are updated
 *   with no filter side effects.
 */
int test_socket_replace(void)
{
  tcp_helper_resource_t* thr;
  tcp_helper_resource_t* thr_nc;
  tcp_helper_cluster_t* thc;
  struct ooft_endpoint* old_ep;
  struct ooft_endpoint* new_ep;
  struct ooft_endpoint* ep;
  struct ooft_endpoint* passive;
  struct oof_manager* fm;
  ci_addr_t new_raddr;
  int rc;

  new_test();
  plan(29);

  test_alloc(32);
  thr = ooft_alloc_stack(8);
  thr_nc = ooft_alloc_stack(8);
  thc = ooft_alloc_cluster("test_cluster");
  ooft_stack_set_cluster(thr, thc);
  fm = thr->ofn->ofn_filter_manager;
  TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X2_FF));

  /* --- Scenario A (BR-7.06, BR-7.07): replace stackless dummy --- */
  diag("Scenario A: replace stackless dummy with real socket");

  old_ep = ooft_alloc_endpoint(thr, IPPROTO_UDP, inet_addr("1.0.0.0"),
                               htons(2000), INADDR_ANY, 0);

  rc = ooft_endpoint_add(old_ep,
                         OOF_SOCKET_ADD_FLAG_CLUSTERED |
                         OOF_SOCKET_ADD_FLAG_DUMMY |
                         OOF_SOCKET_ADD_FLAG_NO_STACK);
  cmp_ok(rc, "==", 0, "add dummy stackless socket");
  ok(old_ep->skf.sf_local_port != NULL, "dummy is bound");
  ok((old_ep->skf.sf_flags & (OOF_SOCKET_DUMMY | OOF_SOCKET_NO_STACK)) ==
     (OOF_SOCKET_DUMMY | OOF_SOCKET_NO_STACK),
     "dummy has DUMMY|NO_STACK flags");

  /* Replace dummy with real socket */
  new_ep = ooft_alloc_endpoint(thr, IPPROTO_UDP, inet_addr("1.0.0.0"),
                               htons(2000), INADDR_ANY, 0);
  ok(new_ep->skf.sf_local_port == NULL, "new socket not yet bound");

  rc = oof_socket_replace(fm, &old_ep->skf, &new_ep->skf);
  cmp_ok(rc, "==", 0, "replace dummy with real socket");

  /* Verify state transfer (BR-7.06) */
  ok(new_ep->skf.sf_local_port != NULL, "new socket inherited binding");
  ok((new_ep->skf.sf_flags & OOF_SOCKET_DUMMY) != 0,
     "new socket has DUMMY flag");
  ok((new_ep->skf.sf_flags & OOF_SOCKET_NO_STACK) == 0,
     "new socket NO_STACK cleared");

  /* Verify old socket cleared (BR-7.06) */
  ok(old_ep->skf.sf_local_port == NULL, "old socket unbound");
  ok(old_ep->skf.sf_flags == 0, "old socket flags cleared");

  /* Arm the replaced socket — two-phase add (in oof_socket_add).
   * This installs SW+HW filters for the semi-wild binding. */
  ooft_endpoint_expect_unicast_filters(new_ep,
                                       OOFT_EXPECT_FLAG_WILD |
                                       OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(new_ep, OOF_SOCKET_ADD_FLAG_CLUSTERED);
  cmp_ok(rc, "==", 0, "arm replaced socket");
  check_filters(thr);

  /* Clean up armed socket */
  ooft_endpoint_expect_sw_remove_all(new_ep);
  ooft_cplane_expect_hw_remove_all(cp);
  oof_socket_del(fm, &new_ep->skf);
  check_filters(thr);

  /* --- Scenario B (BR-7.08): update sharer details --- */
  diag("Scenario B: update sharer details");

  ep = ooft_alloc_endpoint(thr_nc, IPPROTO_TCP, inet_addr("1.0.0.0"),
                           htons(3000), INADDR_ANY, 0);
  passive = ooft_alloc_endpoint(thr_nc, IPPROTO_TCP, inet_addr("1.0.0.0"),
                                htons(3000), inet_addr("2.0.0.0"),
                                htons(4000));

  ooft_endpoint_expect_unicast_filters(ep, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(ep, 0);
  cmp_ok(rc, "==", 0, "add listener for sharer test");
  check_filters(thr_nc);

  {
    ci_addr_t laddr = CI_ADDR_FROM_IP4(passive->laddr_be);
    ci_addr_t raddr = CI_ADDR_FROM_IP4(passive->raddr_be);
    ooft_endpoint_expect_unicast_filters(passive, 0);
    rc = oof_socket_share(fm, &passive->skf, &ep->skf,
                          AF_SPACE_FLAG_IP4, laddr, raddr,
                          passive->lport_be, passive->rport_be);
  }
  cmp_ok(rc, "==", 0, "share passive for update test");
  check_filters(thr_nc);

  /* Update remote address and port — no filter changes expected */
  new_raddr = CI_ADDR_FROM_IP4(inet_addr("3.0.0.0"));
  oof_socket_update_sharer_details(fm, &passive->skf, new_raddr,
                                   htons(5000));

  ok(CI_IPX_ADDR_EQ(passive->skf.sf_raddr, new_raddr),
     "sf_raddr updated");
  cmp_ok(passive->skf.sf_rport, "==", htons(5000), "sf_rport updated");
  passive->raddr_be = inet_addr("3.0.0.0");
  passive->rport_be = htons(5000);
  ok(ci_dllist_not_empty(&passive->sw_filters_added),
     "passive has an added SW filter");
  if( ci_dllist_not_empty(&passive->sw_filters_added) ) {
    struct ooft_sw_filter* filter;
    filter = CI_CONTAINER(struct ooft_sw_filter, socket_link,
                          ci_dllist_start(&passive->sw_filters_added));
    filter->raddr_be = passive->raddr_be;
    filter->rport_be = passive->rport_be;
  }
  cmp_ok(oo_hw_filter_hwports(&passive->skf.sf_full_match_filter), "==", 0,
         "passive still shares listener HW filter");
  check_filters(thr_nc);

  /* Clean up */
  ooft_endpoint_expect_sw_remove_all(passive);
  oof_socket_del(fm, &passive->skf);
  ooft_endpoint_expect_sw_remove_all(ep);
  ooft_cplane_expect_hw_remove_all(cp);
  oof_socket_del(fm, &ep->skf);
  check_filters(thr_nc);

  ooft_free_stack(thr);
  ooft_free_stack(thr_nc);
  ooft_free_cluster(thc);
  test_cleanup();
  done_testing();
}
