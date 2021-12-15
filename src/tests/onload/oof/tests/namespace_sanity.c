/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */

#include "../onload_kernel_compat.h"
#include "../stack.h"
#include "../../tap/tap.h"
#include "../oof_test.h"
#include "../cplane.h"
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>


/* Adds 4 test points, checking each stack's sw filters, and all hw filters */
static void check_all_filters(tcp_helper_resource_t* thr1,
                              tcp_helper_resource_t* thr2)
{
  int rc;

  /* The check filters function ensures that all expected filters have been
   * added or removed, and that nothing unexpected has been added or
   * removed.
   */
  rc = ooft_stack_check_sw_filters(thr1);
  cmp_ok(rc, "==", 0, "check sw filters stack 1");
  rc = ooft_stack_check_sw_filters(thr2);
  cmp_ok(rc, "==", 0, "check sw filters stack 2");
  rc = ooft_ns_check_hw_filters(thr1->ns);
  cmp_ok(rc, "==", 0, "check hw filters stack 1");
  rc = ooft_ns_check_hw_filters(thr2->ns);
  cmp_ok(rc, "==", 0, "check hw filters stack 2");
}


static void second_namespace_init(struct net* net_ns)
{
  struct ooft_hwport* hw0 = ooft_alloc_hwport(cp, net_ns, 1, 1, 0);
  struct ooft_hwport* hw1 = ooft_alloc_hwport(cp, net_ns, 1, 1, 0);

  unsigned char mac0[6] = { 0,1,0,0,0,2 };
  struct ooft_ifindex* idx0 = ooft_alloc_ifindex(cp, hw0, net_ns,
                                                 EFX_FILTER_VID_UNSPEC, mac0);
  ooft_alloc_addr(net_ns, idx0, inet_addr("1.0.0.2"));
  idx0->up = 1;

  unsigned char mac1[6] = { 0,1,0,0,0,3 };
  struct ooft_ifindex* idx1 = ooft_alloc_ifindex(cp, hw1, net_ns,
                                                 EFX_FILTER_VID_UNSPEC, mac1);
  ooft_alloc_addr(net_ns, idx1, inet_addr("1.0.0.3"));
  idx1->up = 1;

  /* Now bring up both hwports */
  ooft_hwport_up_down(hw0, 1);
  ooft_hwport_up_down(hw1, 1);
}

/* This test covers adding the different types of sockets to a basic cplane
 * environment.
 */
int test_namespace_sanity()
{
  tcp_helper_resource_t* thr1;
  struct ooft_endpoint* udp_wild;
  ci_dllist hw_wild;
  struct ooft_endpoint* udp_semi_wild;
  ci_dllist hw_semi_wild;
  struct ooft_endpoint* udp_connected;
  ci_dllist hw_connected;

  tcp_helper_resource_t* thr2;
  struct ooft_endpoint* tcp_active;
  ci_dllist hw_active;
  struct ooft_endpoint* tcp_listen;
  ci_dllist hw_listen;
  struct ooft_endpoint* tcp_passive1;
  struct ooft_endpoint* tcp_passive2;
  ci_dllist hw_passive2;
  int rc;

  struct ooft_task* proc1;
  struct ooft_task* proc2;
  struct net* ns1;
  struct net* ns2;

  new_test();
  plan(63);

  /* Allocates the filter manager and cplane structures that are used
   * throughout the test.
   */
  test_alloc(32);

  /* Allocate the first stack - we're currently set to proc1, so this stack
   * and future endpoints created it in will be in ns1.
   */
  thr1 = ooft_alloc_stack(4);

  /* test_alloc() create a default process context and namespace for us.
   * Keep track of them so that we can use them later in the test.
   */
  proc1 = current;
  ns1 = current_ns();

  /* And set up ns1 with the default cplane setup (two hwports, each with
   * one configured IP address).
   */
  ooft_default_cplane_init(ns1);

  /* Now add another namespace, with the same setup.  We don't switch to 
   * it yet.
   */
  ns2 = ooft_alloc_namespace(cp);
  proc2 = context_alloc(ns2);

  /* HW filters are associated with an efrm_client rather than a socket.
   * We use these lists to keep track of which filters are associated with
   * which sockets.
   */
  ci_dllist_init(&hw_wild);
  ci_dllist_init(&hw_semi_wild);
  ci_dllist_init(&hw_connected);
  ci_dllist_init(&hw_active);
  ci_dllist_init(&hw_listen);
  ci_dllist_init(&hw_passive2);

  /* Now switch to our second process context, which is also using a
   * different namespace, and allocate another stack.
   */
  current = proc2;
  thr2 = ooft_alloc_stack(4);

  /* We don't currently propogate cplane address information, so can't
   * set up the second namespace until after we know that the filter manager
   * has been created.
   */
  second_namespace_init(ns2);

  TEST_DEBUG(oof_onload_manager_dump(&efab_tcp_driver, dump, "\n"));

  /* Allocating the endpoints sets up the details that will be needed when
   * we pass these to oof, ie the local and remove port and addr info.
   */
  udp_wild = ooft_alloc_endpoint(thr1, IPPROTO_UDP, 0, htons(2000), 0, 0);
  udp_semi_wild = ooft_alloc_endpoint(thr1, IPPROTO_UDP, 1, htons(3000), 0, 0);
  udp_connected = ooft_alloc_endpoint(thr1, IPPROTO_UDP, 1, htons(4000),
                                      4, htons(5000));

  tcp_active = ooft_alloc_endpoint(thr2, IPPROTO_TCP,
                                   inet_addr("1.0.0.2"), htons(2000),
                                   inet_addr("2.0.0.0"), htons(3000));
  tcp_listen = ooft_alloc_endpoint(thr2, IPPROTO_TCP,
                                   inet_addr("1.0.0.2"), htons(4000), 0, 0);
  tcp_passive1 = ooft_alloc_endpoint(thr2, IPPROTO_TCP,
                                     inet_addr("1.0.0.2"), htons(4000),
                                     inet_addr("2.0.0.1"), htons(5000));
  tcp_passive2 = ooft_alloc_endpoint(thr2, IPPROTO_TCP,
                                     inet_addr("1.0.0.2"), htons(4000),
                                     inet_addr("2.0.0.2"), htons(6000));

  /* We can use the utility function to set up our expected filters here
   * rather than setting up for each filter individually.  This will set up to
   * expect SW filters for all local addresses configured in this namespace,
   * and HW filters for each of those addresses on each HW port used by this
   * namespace.  It determines what addresses to install filters for based
   * on the local address of the endpoint.
   *
   * We set the HW filters flag here as we would like to set up for HW
   * filters as well as SW filters.
   */
  ooft_endpoint_expect_unicast_filters(udp_wild, 1);
  /* This is a simple wrapper around oof_socket_add which fills in the
   * function parameters from the endpoint data structure.
   */
  rc = ooft_endpoint_add(udp_wild, 0);
  cmp_ok(rc, "==", 0, "add UDP wild endpoint");
  check_all_filters(thr1, thr2);
  /* When filters are added they are moved onto an "added" list in the
   * endpoint for SW filters and in the efrm_client for HW filters.  As each
   * set of HW filters are installed we grab the contents of the added list
   * onto a local list that associates filters that will be removed together.
   * In more complex tests it could be necessary to further split this list,
   * but here we are just doing one thing at a time, so this is sufficient.
   */
  ooft_cplane_claim_added_hw_filters(cp, &hw_wild);

  ooft_endpoint_expect_unicast_filters(udp_semi_wild, 1);
  rc = ooft_endpoint_add(udp_semi_wild, 0);
  cmp_ok(rc, "==", 0, "add UDP semi-wild endpoint");
  check_all_filters(thr1, thr2);
  ooft_cplane_claim_added_hw_filters(cp, &hw_semi_wild);

  ooft_endpoint_expect_unicast_filters(udp_connected, 1);
  rc = ooft_endpoint_add(udp_connected, 0);
  cmp_ok(rc, "==", 0, "add UDP connected endpoint");
  check_all_filters(thr1, thr2);
  ooft_cplane_claim_added_hw_filters(cp, &hw_connected);

  ooft_endpoint_expect_unicast_filters(tcp_active, 1);
  rc = ooft_endpoint_add(tcp_active, 0);
  cmp_ok(rc, "==", 0, "add TCP active endpoint");
  check_all_filters(thr1, thr2);
  ooft_cplane_claim_added_hw_filters(cp, &hw_active);

  ooft_endpoint_expect_unicast_filters(tcp_listen, 1);
  rc = ooft_endpoint_add(tcp_listen, 0);
  cmp_ok(rc, "==", 0, "add TCP listen endpoint");
  check_all_filters(thr1, thr2);
  ooft_cplane_claim_added_hw_filters(cp, &hw_listen);

  /* For a TCP passive socket we don't want HW filters to be installed as it
   * will share the listener's HW filter, so the HW flag here is 0.  All using
   * the utility function gains us here over calling
   * ooft_endpoint_expect_sw_add directly is avoiding having to fill in the
   * relevant address fields, which the utility function will do automatically
   * for us based on the endpoint state.
   */
  ooft_endpoint_expect_unicast_filters(tcp_passive1, 0);
  rc = ooft_endpoint_add(tcp_passive1, 0);
  cmp_ok(rc, "==", 0, "add TCP passive1 endpoint");
  check_all_filters(thr1, thr2);

  ooft_endpoint_expect_unicast_filters(tcp_passive2, 0);
  rc = ooft_endpoint_add(tcp_passive2, 0);
  cmp_ok(rc, "==", 0, "add TCP passive2 endpoint");
  check_all_filters(thr1, thr2);

  TEST_DEBUG(oof_onload_manager_dump(&efab_tcp_driver, dump, "\n"));

  /* As SW filters are associated with an endpoint we can just expect that
   * the relevant endpoint's filters will be removed.
   *
   * For HW filters we saved a list of the HW filters that were associated
   * with this endpoint when we added it.  We know that in this test it's
   * not shared, so we can just expect removal of all the added HW filters
   * when we remove the endpoint.
   */
  ooft_endpoint_expect_sw_remove_all(udp_wild);
  ooft_hw_filter_expect_remove_list(&hw_wild);
  oof_socket_del(thr1->ofn->ofn_filter_manager, &udp_wild->skf);
  check_all_filters(thr1, thr2);

  ooft_endpoint_expect_sw_remove_all(udp_semi_wild);
  ooft_hw_filter_expect_remove_list(&hw_semi_wild);
  oof_socket_del(thr1->ofn->ofn_filter_manager, &udp_semi_wild->skf);
  check_all_filters(thr1, thr2);

  ooft_endpoint_expect_sw_remove_all(udp_connected);
  ooft_hw_filter_expect_remove_list(&hw_connected);
  oof_socket_del(thr1->ofn->ofn_filter_manager, &udp_connected->skf);
  check_all_filters(thr1, thr2);

  ooft_endpoint_expect_sw_remove_all(tcp_active);
  ooft_hw_filter_expect_remove_list(&hw_active);
  oof_socket_del(thr2->ofn->ofn_filter_manager, &tcp_active->skf);
  check_all_filters(thr1, thr2);

  ooft_endpoint_expect_sw_remove_all(tcp_passive1);
  oof_socket_del(thr2->ofn->ofn_filter_manager, &tcp_passive1->skf);
  check_all_filters(thr1, thr2);

  /* Removing the listener will add new hw filter for passive2, unless the
   * threshold is too small */
  bool expect_unshare = oof_shared_keep_thresh >= 1;
  if( expect_unshare ) {
    ooft_endpoint_expect_hw_unicast(tcp_passive2, tcp_passive2->laddr_be);
    ooft_hw_filter_expect_remove_list(&hw_listen);
  }
  ooft_endpoint_expect_sw_remove_all(tcp_listen);
  oof_socket_del(thr2->ofn->ofn_filter_manager, &tcp_listen->skf);
  if( expect_unshare )
    ooft_cplane_claim_added_hw_filters(cp, &hw_passive2);
  check_all_filters(thr1, thr2);

  ooft_endpoint_expect_sw_remove_all(tcp_passive2);
  if( expect_unshare )
    ooft_hw_filter_expect_remove_list(&hw_passive2);
  else
    ooft_hw_filter_expect_remove_list(&hw_listen);
  oof_socket_del(thr2->ofn->ofn_filter_manager, &tcp_passive2->skf);
  check_all_filters(thr1, thr2);

  ooft_free_stack(thr1);
  ooft_free_stack(thr2);

  /* test_cleanup() will free the current context in use, but we need to
   * explicitly release other any other contexts.
   */
  test_cleanup();
  context_free(proc1);
  ooft_free_namespace(ns1);
  done_testing();
}
