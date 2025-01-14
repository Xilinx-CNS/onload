/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017 Xilinx, Inc. */

#include "../onload_kernel_compat.h"
#include "../stack.h"
#include "../../tap/tap.h"
#include "../oof_test.h"
#include "../cplane.h"
#include "../utils.h"
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>


/* Adds 3 test points, checking each stack's sw filters, and all hw filters */
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

  ci_assert_equal(thr1->ns, thr2->ns);
  rc = ooft_ns_check_hw_filters(thr1->ns);
  cmp_ok(rc, "==", 0, "check hw filters");
}

/* This test covers adding the different types of sockets to a basic cplane
 * environment.
 */
int __test_sanity(enum ooft_nic_type nic_type, enum ooft_rx_mode mode)
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
  struct oof_manager* fm;
  bool no5tuple;
  struct ooft_hwport* hwport;

  new_test();
  plan(60);

  /* Allocates the ns manager and cplane structures that are used
   * throughout the test.
   *
   * It also provides a default process context and namespace.
   */
  test_alloc(32);

  /* Allocating the endpoints sets up the details that will be needed when
   * we pass these to oof, ie the local and remove port and addr info.
   */
  thr1 = ooft_alloc_stack_mode(4, mode);

  /* Allocating a stack results in the stack being associated with a filter
   * manager for the namespace of the created stack.  In this test both our
   * stacks are in the same namespace, and have the same lifetime, so we
   * just grab a pointer to the filter manager from the first stack for
   * convenience.
   */
  fm = thr1->ofn->ofn_filter_manager;

  /* This sets up the cplane in a default configuration of two HW ports,
   * each with one ifindex with one address, all in the same namespace.  The
   * HW ports support VLANs and multicast replication.  The filter manager
   * is notified of the addresses, and the Hw ports are brought up.
   *
   * For a more complex setup each of the components can be added individually
   * using the functions in cplane.h.
   */
  TRY(ooft_cplane_init(current_ns(), nic_type));

  /* This sanity test uses only one NIC, and we assume that 5tuple filter
   * support is consistent accross all hwports, so just check the first */
  hwport = ooft_hwport_from_id(1);
  no5tuple = hwport->flags & OOF_HWPORT_FLAG_NO_5TUPLE;

  TEST_DEBUG(oof_onload_manager_dump(&efab_tcp_driver, dump, "\n"));

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

  udp_wild = ooft_alloc_endpoint(thr1, IPPROTO_UDP, 0, htons(2000), 0, 0);
  udp_semi_wild = ooft_alloc_endpoint(thr1, IPPROTO_UDP, 1, htons(3000), 0, 0);
  udp_connected = ooft_alloc_endpoint(thr1, IPPROTO_UDP, 1, htons(4000),
                                      2, htons(5000));

  thr2 = ooft_alloc_stack_mode(4, mode);
  tcp_active = ooft_alloc_endpoint(thr2, IPPROTO_TCP, 1, htons(2000),
                                   2, htons(3000));
  tcp_listen = ooft_alloc_endpoint(thr2, IPPROTO_TCP, 1, htons(4000), 0, 0);
  tcp_passive1 = ooft_alloc_endpoint(thr2, IPPROTO_TCP, 1, htons(4000),
                                     3, htons(5000));
  tcp_passive2 = ooft_alloc_endpoint(thr2, IPPROTO_TCP, 1, htons(4000),
                                     3, htons(6000));

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
  ci_dllist_init(&hw_wild);
  ooft_cplane_claim_added_hw_filters(cp, &hw_wild);

  ooft_endpoint_expect_unicast_filters(udp_semi_wild, 1);
  rc = ooft_endpoint_add(udp_semi_wild, 0);
  cmp_ok(rc, "==", 0, "add UDP semi-wild endpoint");
  check_all_filters(thr1, thr2);
  ooft_cplane_claim_added_hw_filters(cp, &hw_semi_wild);

  /* for no5tuple not expecting a change in HW filters */
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
  oof_socket_del(fm, &udp_wild->skf);
  check_all_filters(thr1, thr2);

  ooft_endpoint_expect_sw_remove_all(udp_semi_wild);
  ooft_hw_filter_expect_remove_list(&hw_semi_wild);
  oof_socket_del(fm, &udp_semi_wild->skf);
  check_all_filters(thr1, thr2);

  ooft_endpoint_expect_sw_remove_all(udp_connected);
  ooft_hw_filter_expect_remove_list(&hw_connected);
  oof_socket_del(fm, &udp_connected->skf);
  check_all_filters(thr1, thr2);

  ooft_endpoint_expect_sw_remove_all(tcp_active);
  ooft_hw_filter_expect_remove_list(&hw_active);
  oof_socket_del(fm, &tcp_active->skf);
  check_all_filters(thr1, thr2);

  ooft_endpoint_expect_sw_remove_all(tcp_passive1);
  oof_socket_del(fm, &tcp_passive1->skf);
  check_all_filters(thr1, thr2);

  /* Removing the listener will add new hw filter for passive2, unless the
   * threshold is too small or 3tuple sharing is forced by lack of 5tuple filters. */
  bool expect_unshare = oof_shared_keep_thresh >= 1 && !no5tuple;
  ooft_endpoint_expect_sw_remove_all(tcp_listen);
  if( expect_unshare ) {
    ooft_endpoint_expect_hw_unicast(tcp_passive2, tcp_passive2->laddr_be, 0);
    ooft_hw_filter_expect_remove_list(&hw_listen);
  }
  oof_socket_del(fm, &tcp_listen->skf);
  if( expect_unshare )
    ooft_cplane_claim_added_hw_filters(cp, &hw_passive2);
  check_all_filters(thr1, thr2);

  ooft_endpoint_expect_sw_remove_all(tcp_passive2);
  if( expect_unshare )
    ooft_hw_filter_expect_remove_list(&hw_passive2);
  else
    ooft_hw_filter_expect_remove_list(&hw_listen);
  oof_socket_del(fm, &tcp_passive2->skf);
  check_all_filters(thr1, thr2);

  {
    /* udp connect test */
    diag("Create semi wild socket");
    ooft_endpoint_expect_unicast_filters(udp_connected, OOFT_EXPECT_FLAG_WILD | OOFT_EXPECT_FLAG_HW);
    rc = ooft_endpoint_add_wild(udp_connected, 0);

    cmp_ok(rc, "==", 0, "add UDP semi-wild endpoint");

    check_all_filters(thr1, thr2);

    diag("Connect the semi wild socket");
    /* we expect removal of all previously installed SW and HW filters */
    /* TODO check the HW filter replacement is in correct order */

    ooft_cplane_claim_added_hw_filters(cp, &hw_wild);
    if( no5tuple )
      ooft_endpoint_expect_unicast_filters(udp_connected, 0);
    else {
      ooft_endpoint_expect_unicast_filters(udp_connected, OOFT_EXPECT_FLAG_HW);
      ooft_hw_filter_expect_remove_list(&hw_wild);
    }
    ooft_endpoint_expect_sw_remove_all(udp_connected);

    rc = ooft_endpoint_udp_connect (udp_connected, 0);

    cmp_ok(rc, "==", 0, "connected UDP");

    check_all_filters(thr1, thr2);

    /* remove socket */
    if( ! no5tuple ) {
      ci_dllist_init(&hw_wild);
      ooft_cplane_claim_added_hw_filters(cp, &hw_wild);
    }


    diag("Closing the connected socket");
    ooft_hw_filter_expect_remove_list(&hw_wild);
    ooft_endpoint_expect_sw_remove_all(udp_connected);

    oof_socket_del(fm, &udp_connected->skf);
    check_all_filters(thr1, thr2);
  }

  ooft_free_stack(thr1);
  ooft_free_stack(thr2);
  test_cleanup();
  done_testing();
}

int test_sanity() {
  return __test_sanity(OOFT_NIC_X2_FF, OOFT_RX_FF);
}
