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


static void check_all_filters(tcp_helper_resource_t* thr)
{
  int rc;

  rc = ooft_stack_check_sw_filters(thr);
  cmp_ok(rc, "==", 0, "check sw filters");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "check hw filters");
}


static void expect_hw_unicast_on_hwport(struct ooft_endpoint* ep,
                                        int hwport, unsigned laddr_be)
{
  ooft_client_expect_hw_add_ip(oo_nics[hwport].efrm_client,
                               tcp_helper_rx_vi_id(ep->thr, hwport),
                               tcp_helper_vi_hw_stack_id(ep->thr, hwport),
                               EFX_FILTER_VID_UNSPEC, ep->proto, laddr_be,
                               ep->lport_be, ep->raddr_be, ep->rport_be);
}


/* Add enterprise-only X2 interfaces to a live X4 setup.
 *
 * An existing BOTH-mode wild socket initially uses CT ports 2,3.  As the new
 * addresses arrive, they receive filters on those already-active ports.  As
 * each enterprise FF port comes up, it must receive filters for every local
 * address, without reactivating the X4 shadow FF ports 0,1.
 */
int test_mixed_interface_add(void)
{
  tcp_helper_resource_t* thr;
  struct ooft_endpoint* wild;
  struct ooft_hwport* hw4;
  struct ooft_hwport* hw5;
  struct ooft_ifindex* idx2;
  struct ooft_ifindex* idx3;
  ci_dllist hw_initial;
  ci_dllist hw_added;
  struct oof_manager* fm;
  unsigned char mac2[6] = { 0,1,0,0,0,2 };
  unsigned char mac3[6] = { 0,1,0,0,0,3 };
  static const char* addrs[4] = {
    "1.0.0.0", "1.0.0.1", "1.0.0.2", "1.0.0.3"
  };
  int rc;
  int i;

  new_test();
  plan(NO_PLAN);

  test_alloc(32);
  thr = ooft_alloc_stack_mode(8, OOFT_RX_BOTH);
  fm = thr->ofn->ofn_filter_manager;
  TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X4_FF));

  ci_dllist_init(&hw_initial);
  ci_dllist_init(&hw_added);

  wild = ooft_alloc_endpoint(thr, IPPROTO_UDP, INADDR_ANY, htons(2000),
                             INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(wild, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(wild, 0);
  cmp_ok(rc, "==", 0, "add wild socket on initial X4 interfaces");
  check_all_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_initial);

  /* This is the X2 portion of ooft_cplane_add_nic(), expanded so the
   * expected filter updates can be registered at each state transition. */
  hw4 = ooft_alloc_hwport(cp, current_ns(), OOFT_HWPORT_EF10_FF);
  hw5 = ooft_alloc_hwport(cp, current_ns(), OOFT_HWPORT_EF10_FF);

  idx2 = ooft_alloc_ifindex(cp, current_ns(), EFX_FILTER_VID_UNSPEC, mac2);
  ooft_add_hwport_to_ifindex(idx2, hw4, current_ns());
  ooft_endpoint_expect_sw_add(wild, IPPROTO_UDP, inet_addr("1.0.0.2"),
                              htons(2000), INADDR_ANY, 0);
  expect_hw_unicast_on_hwport(wild, 2, inet_addr("1.0.0.2"));
  expect_hw_unicast_on_hwport(wild, 3, inet_addr("1.0.0.2"));
  ooft_alloc_addr(current_ns(), idx2, inet_addr("1.0.0.2"));
  idx2->up = 1;
  check_all_filters(thr);

  idx3 = ooft_alloc_ifindex(cp, current_ns(), EFX_FILTER_VID_UNSPEC, mac3);
  ooft_add_hwport_to_ifindex(idx3, hw5, current_ns());
  ooft_endpoint_expect_sw_add(wild, IPPROTO_UDP, inet_addr("1.0.0.3"),
                              htons(2000), INADDR_ANY, 0);
  expect_hw_unicast_on_hwport(wild, 2, inet_addr("1.0.0.3"));
  expect_hw_unicast_on_hwport(wild, 3, inet_addr("1.0.0.3"));
  ooft_alloc_addr(current_ns(), idx3, inet_addr("1.0.0.3"));
  idx3->up = 1;
  check_all_filters(thr);

  /* Bringing up an enterprise port installs the wild filter for every
   * address, including the two addresses that pre-date this interface. */
  for( i = 0; i < 4; i++ )
    expect_hw_unicast_on_hwport(wild, hw4->id, inet_addr(addrs[i]));
  ooft_hwport_up_down(hw4, 1);
  check_all_filters(thr);

  for( i = 0; i < 4; i++ )
    expect_hw_unicast_on_hwport(wild, hw5->id, inet_addr(addrs[i]));
  ooft_hwport_up_down(hw5, 1);
  check_all_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_added);

  ooft_endpoint_expect_sw_remove_all(wild);
  ooft_hw_filter_expect_remove_list(&hw_initial);
  ooft_hw_filter_expect_remove_list(&hw_added);
  oof_socket_del(fm, &wild->skf);
  check_all_filters(thr);

  ooft_free_stack(thr);
  test_cleanup();
  done_testing();
}
