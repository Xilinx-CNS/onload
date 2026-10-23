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


static void check_all_filters(tcp_helper_resource_t* thr)
{
  int rc;

  rc = ooft_stack_check_sw_filters(thr);
  cmp_ok(rc, "==", 0, "check sw filters");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "check hw filters");
}


static struct ooft_addr* find_addr(struct ooft_ifindex* idx,
                                   unsigned laddr_be)
{
  struct ooft_addr* addr;

  CI_DLLIST_FOR_EACH2(struct ooft_addr, addr, idx_link, &idx->addrs)
    if( addr->laddr_be == laddr_be )
      return addr;

  return NULL;
}


static void take_hw_filters_for_laddr(ci_dllist* in, ci_dllist* out,
                                      unsigned laddr_be)
{
  struct ooft_hw_filter* filter;
  struct ooft_hw_filter* filter_tmp;

  CI_DLLIST_FOR_EACH3(struct ooft_hw_filter, filter, client_link, in,
                      filter_tmp) {
    if( filter->spec.loc_host[0] == laddr_be ) {
      ci_dllist_remove_safe(&filter->client_link);
      ci_dllist_push_tail(out, &filter->client_link);
    }
  }
}


/* Remove enterprise-only X2 interfaces from a live mixed setup.
 *
 * A BOTH-mode wild socket initially has filters for four addresses on CT
 * ports 2,3 and enterprise FF ports 4,5.  Deleting the X2 addresses must
 * remove only their filters.  Removing each X2 hwport must then clear only
 * its remaining filters, leaving CT coverage for the original X4 addresses.
 */
int test_mixed_interface_remove(void)
{
  tcp_helper_resource_t* thr;
  struct ooft_endpoint* wild;
  struct ooft_ifindex* idx2;
  struct ooft_ifindex* idx3;
  struct ooft_addr* addr2;
  struct ooft_addr* addr3;
  struct ooft_hwport* hw4;
  struct ooft_hwport* hw5;
  ci_dllist hw_remaining;
  ci_dllist hw_addr2;
  ci_dllist hw_addr3;
  ci_dllist hw4_filters;
  ci_dllist hw5_filters;
  struct oof_manager* fm;
  unsigned addr2_be = inet_addr("1.0.0.2");
  unsigned addr3_be = inet_addr("1.0.0.3");
  int rc;

  new_test();
  plan(NO_PLAN);

  test_alloc(32);
  thr = ooft_alloc_stack_mode(8, OOFT_RX_BOTH);
  fm = thr->ofn->ofn_filter_manager;
  TRY(ooft_cplane_init(current_ns(), OOFT_NIC_X4_FF));
  TRY(ooft_cplane_add_nic(current_ns(), OOFT_NIC_X2_FF,
                          (unsigned char[6]){ 0,1,0,0,0,2 }, addr2_be,
                          (unsigned char[6]){ 0,1,0,0,0,3 }, addr3_be));

  idx2 = ooft_idx_from_id(3);
  idx3 = ooft_idx_from_id(4);
  addr2 = find_addr(idx2, addr2_be);
  addr3 = find_addr(idx3, addr3_be);
  hw4 = ooft_hwport_from_id(4);
  hw5 = ooft_hwport_from_id(5);
  TEST(idx2);
  TEST(idx3);
  TEST(addr2);
  TEST(addr3);
  TEST(hw4);
  TEST(hw5);

  ci_dllist_init(&hw_remaining);
  ci_dllist_init(&hw_addr2);
  ci_dllist_init(&hw_addr3);
  ci_dllist_init(&hw4_filters);
  ci_dllist_init(&hw5_filters);

  wild = ooft_alloc_endpoint(thr, IPPROTO_UDP, INADDR_ANY, htons(2000),
                             INADDR_ANY, 0);
  ooft_endpoint_expect_unicast_filters(wild, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(wild, 0);
  cmp_ok(rc, "==", 0, "add wild socket on mixed interfaces");
  check_all_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_remaining);
  take_hw_filters_for_laddr(&hw_remaining, &hw_addr2, addr2_be);
  take_hw_filters_for_laddr(&hw_remaining, &hw_addr3, addr3_be);

  /* Address deletion removes the X2 address from every active selected
   * datapath, but leaves all filters for the two X4 addresses intact. */
  ooft_endpoint_expect_sw_remove_addr(wild, addr2_be);
  ooft_hw_filter_expect_remove_list(&hw_addr2);
  ooft_del_addr(current_ns(), idx2, addr2);
  check_all_filters(thr);

  ooft_endpoint_expect_sw_remove_addr(wild, addr3_be);
  ooft_hw_filter_expect_remove_list(&hw_addr3);
  ooft_del_addr(current_ns(), idx3, addr3);
  check_all_filters(thr);

  /* Removing an interface from the control-plane view immediately withdraws
   * its hwport's unicast filters.  The later hwport-removed notification is
   * therefore a no-op for these already-cleared UDP filters. */
  ooft_client_hw_filter_matches_hwport(&hw_remaining, &hw4_filters, hw4);
  ooft_client_hw_filter_matches_hwport(&hw_remaining, &hw5_filters, hw5);

  idx2->up = 0;
  ooft_hw_filter_expect_remove_list(&hw4_filters);
  oof_onload_mcast_update_interface(idx2->id, 0, 0, idx2->vlan_id,
                                    idx2->mac, current_ns(),
                                    &efab_tcp_driver);
  oof_onload_mcast_update_filters(idx2->id, current_ns(),
                                  &efab_tcp_driver);
  check_all_filters(thr);
  ooft_hwport_removed(hw4);
  check_all_filters(thr);

  idx3->up = 0;
  ooft_hw_filter_expect_remove_list(&hw5_filters);
  oof_onload_mcast_update_interface(idx3->id, 0, 0, idx3->vlan_id,
                                    idx3->mac, current_ns(),
                                    &efab_tcp_driver);
  oof_onload_mcast_update_filters(idx3->id, current_ns(),
                                  &efab_tcp_driver);
  check_all_filters(thr);
  ooft_hwport_removed(hw5);
  check_all_filters(thr);

  ooft_endpoint_expect_sw_remove_all(wild);
  ooft_hw_filter_expect_remove_list(&hw_remaining);
  oof_socket_del(fm, &wild->skf);
  check_all_filters(thr);

  ooft_free_stack(thr);
  test_cleanup();
  done_testing();
}
