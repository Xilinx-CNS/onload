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


static void check_filters(tcp_helper_resource_t* thr)
{
  int rc;
  rc = ooft_stack_check_sw_filters(thr);
  cmp_ok(rc, "==", 0, "check sw filters");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "check hw filters");
}


/* BR-11.01 (input validation), BR-11.02 (pre-conditions),
 * BR-11.03 (connect from semi-wild), BR-11.04 (connect from wild),
 * BR-11.05 (delete after connect).
 *
 * Scenario A: Connect a semi-wild UDP socket to a full-match.
 *   - Old semi-wild SW+HW filters removed.
 *   - New full-match SW+HW filters installed.
 *
 * Scenario B: Connect a wild UDP socket to a full-match.
 *   - All per-address wild SW+HW filters removed.
 *   - New full-match SW+HW filters installed.
 *
 * Scenario C: Input validation errors.
 *   - laddr=ANY, raddr=ANY, rport=0, TCP socket, unbound UDP socket, and
 *     already-connected UDP socket all return -EINVAL without filter changes.
 */
int test_udp_connect(void)
{
  tcp_helper_resource_t* thr;
  struct ooft_endpoint* ep;
  struct ooft_endpoint* unbound_ep;
  struct ooft_endpoint* tcp_ep;
  ci_dllist hw_filters;
  ci_dllist hw_error_ep;
  struct oof_manager* fm;
  int rc;

  new_test();
  plan(45);

  test_alloc(32);
  thr = ooft_alloc_stack(8);
  fm = thr->ofn->ofn_filter_manager;
  TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X2_FF));

  ci_dllist_init(&hw_filters);
  ci_dllist_init(&hw_error_ep);

  /* --- Scenario A (BR-11.03): connect from semi-wild --- */
  diag("Scenario A: connect from semi-wild");

  ep = ooft_alloc_endpoint(thr, IPPROTO_UDP, inet_addr("1.0.0.0"),
                           htons(2000), INADDR_ANY, 0);

  ooft_endpoint_expect_unicast_filters(ep,
                                       OOFT_EXPECT_FLAG_WILD |
                                       OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add_wild(ep, 0);
  cmp_ok(rc, "==", 0, "add UDP semi-wild");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_filters);

  ep->raddr_be = inet_addr("2.0.0.0");
  ep->rport_be = htons(3000);

  /* Connect: expect old semi-wild SW+HW removed, new full-match added */
  ooft_endpoint_expect_sw_remove_all(ep);
  ooft_hw_filter_expect_remove_list(&hw_filters);
  ooft_endpoint_expect_unicast_filters(ep, OOFT_EXPECT_FLAG_HW);

  rc = ooft_endpoint_udp_connect(ep, 0);
  cmp_ok(rc, "==", 0, "connect from semi-wild");
  check_filters(thr);

  /* Delete connected socket */
  ci_dllist_init(&hw_filters);
  ooft_cplane_claim_added_hw_filters(cp, &hw_filters);
  ooft_endpoint_expect_sw_remove_all(ep);
  ooft_hw_filter_expect_remove_list(&hw_filters);
  oof_socket_del(fm, &ep->skf);
  check_filters(thr);

  /* --- Scenario B (BR-11.04): connect from wild --- */
  diag("Scenario B: connect from wild");

  ep = ooft_alloc_endpoint(thr, IPPROTO_UDP, INADDR_ANY, htons(4000),
                           inet_addr("2.0.0.0"), htons(5000));

  ooft_endpoint_expect_unicast_filters(ep,
                                       OOFT_EXPECT_FLAG_WILD |
                                       OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add_wild(ep, 0);
  cmp_ok(rc, "==", 0, "add UDP wild");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_filters);

  /* The kernel resolves the source address during connect.
   * Set laddr to the resolved address before calling the wrapper. */
  ep->laddr_be = inet_addr("1.0.0.0");

  /* Connect from wild: all per-address wild SW+HW filters removed,
   * new full-match SW+HW filters added, then fixup_wild clears the
   * remaining LPA wild HW filters (no more wild sockets on this port). */
  ooft_endpoint_expect_sw_remove_all(ep);
  ooft_hw_filter_expect_remove_list(&hw_filters);
  ooft_endpoint_expect_unicast_filters(ep, OOFT_EXPECT_FLAG_HW);

  rc = ooft_endpoint_udp_connect(ep, 0);
  cmp_ok(rc, "==", 0, "connect from wild");
  check_filters(thr);

  /* Delete connected socket */
  ci_dllist_init(&hw_filters);
  ooft_cplane_claim_added_hw_filters(cp, &hw_filters);
  ooft_endpoint_expect_sw_remove_all(ep);
  ooft_hw_filter_expect_remove_list(&hw_filters);
  oof_socket_del(fm, &ep->skf);
  check_filters(thr);

  /* --- Scenario C (BR-11.01, BR-11.02): input validation errors --- */
  diag("Scenario C: input validation errors");

  ep = ooft_alloc_endpoint(thr, IPPROTO_UDP, inet_addr("1.0.0.0"),
                           htons(6000), inet_addr("2.0.0.0"), htons(7000));
  ooft_endpoint_expect_unicast_filters(ep,
                                       OOFT_EXPECT_FLAG_WILD |
                                       OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add_wild(ep, 0);
  cmp_ok(rc, "==", 0, "add UDP for error tests");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_error_ep);

  /* BR-11.01: laddr=ANY */
  {
    ci_addr_t laddr_any = {};
    ci_addr_t raddr = CI_ADDR_FROM_IP4(ep->raddr_be);
    rc = oof_udp_connect(fm, &ep->skf, AF_SPACE_FLAG_IP4,
                         laddr_any, raddr, htons(7000));
  }
  cmp_ok(rc, "==", -EINVAL, "connect with laddr=ANY rejected");
  check_filters(thr);

  /* BR-11.01: raddr=ANY */
  {
    ci_addr_t laddr = CI_ADDR_FROM_IP4(ep->laddr_be);
    ci_addr_t raddr_any = {};
    rc = oof_udp_connect(fm, &ep->skf, AF_SPACE_FLAG_IP4,
                         laddr, raddr_any, htons(7000));
  }
  cmp_ok(rc, "==", -EINVAL, "connect with raddr=ANY rejected");
  check_filters(thr);

  /* BR-11.01: rport=0 */
  {
    ci_addr_t laddr = CI_ADDR_FROM_IP4(ep->laddr_be);
    ci_addr_t raddr = CI_ADDR_FROM_IP4(ep->raddr_be);
    rc = oof_udp_connect(fm, &ep->skf, AF_SPACE_FLAG_IP4,
                         laddr, raddr, 0);
  }
  cmp_ok(rc, "==", -EINVAL, "connect with rport=0 rejected");
  check_filters(thr);

  /* BR-11.02: UDP socket has no local port. */
  unbound_ep = ooft_alloc_endpoint(thr, IPPROTO_UDP, inet_addr("1.0.0.0"),
                                   htons(7000), inet_addr("2.0.0.0"),
                                   htons(8000));
  {
    ci_addr_t laddr = CI_ADDR_FROM_IP4(unbound_ep->laddr_be);
    ci_addr_t raddr = CI_ADDR_FROM_IP4(unbound_ep->raddr_be);
    rc = oof_udp_connect(fm, &unbound_ep->skf, AF_SPACE_FLAG_IP4,
                         laddr, raddr, unbound_ep->rport_be);
  }
  cmp_ok(rc, "==", -EINVAL, "connect on unbound UDP socket rejected");
  check_filters(thr);

  /* BR-11.02: TCP socket */
  tcp_ep = ooft_alloc_endpoint(thr, IPPROTO_TCP, inet_addr("1.0.0.0"),
                               htons(8000), INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(tcp_ep, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(tcp_ep, 0);
  cmp_ok(rc, "==", 0, "add TCP for error test");
  check_filters(thr);

  {
    ci_addr_t laddr = CI_ADDR_FROM_IP4(tcp_ep->laddr_be);
    ci_addr_t raddr = CI_ADDR_FROM_IP4(inet_addr("2.0.0.0"));
    rc = oof_udp_connect(fm, &tcp_ep->skf, AF_SPACE_FLAG_IP4,
                         laddr, raddr, htons(9000));
  }
  cmp_ok(rc, "==", -EINVAL, "connect on TCP socket rejected");
  check_filters(thr);

  /* BR-11.02: UDP socket already connected. */
  ooft_endpoint_expect_sw_remove_all(ep);
  ooft_hw_filter_expect_remove_list(&hw_error_ep);
  ooft_endpoint_expect_unicast_filters(ep, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_udp_connect(ep, 0);
  cmp_ok(rc, "==", 0, "connect UDP for already-connected validation");
  check_filters(thr);

  {
    ci_addr_t laddr = CI_ADDR_FROM_IP4(ep->laddr_be);
    ci_addr_t raddr = CI_ADDR_FROM_IP4(inet_addr("3.0.0.0"));
    rc = oof_udp_connect(fm, &ep->skf, AF_SPACE_FLAG_IP4,
                         laddr, raddr, htons(9001));
  }
  cmp_ok(rc, "==", -EINVAL, "connect on already-connected UDP socket rejected");
  check_filters(thr);

  /* Clean up remaining sockets */
  ooft_endpoint_expect_sw_remove_all(tcp_ep);
  ooft_endpoint_expect_sw_remove_all(ep);
  ooft_cplane_expect_hw_remove_all(cp);
  oof_socket_del(fm, &tcp_ep->skf);
  oof_socket_del(fm, &ep->skf);
  check_filters(thr);
  ooft_free_endpoint(unbound_ep);

  ooft_free_stack(thr);
  test_cleanup();
  done_testing();
}
