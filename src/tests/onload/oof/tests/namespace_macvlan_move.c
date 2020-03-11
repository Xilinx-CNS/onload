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
  struct ooft_hwport* hw0 = ooft_alloc_hwport(cp, net_ns, 1, 1);
  struct ooft_hwport* hw1 = ooft_alloc_hwport(cp, net_ns, 1, 1);

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


/* This test covers creating a wild UDP socket in a namespace with two
 * base interfaces.  A macvlan interface is then created on top of one of
 * these and moved to a different namespace.
 */
int test_namespace_macvlan_move(void)
{
  tcp_helper_resource_t* thr1;
  tcp_helper_resource_t* thr2;
  struct ooft_endpoint* udp_wild;
  struct ooft_endpoint* udp_wild2;
  ci_dllist hw_wild;
  ci_dllist hw_wild2;

  int rc;

  struct ooft_task* proc1;
  struct ooft_task* proc2;
  struct net* ns1;
  struct net* ns2;

  new_test();
  plan(40);

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

  /* Now add another interface.  This is using the same hwport as the first
   * base interface (ie it's effectively a macvlan interface).  We don't
   * configure an address here - we're about to move it to another namespace.
   *
   * We know that the default cplane init will number intefaces from 1, so
   * use that knowledge to just grab the interface we want.
   */
  struct ooft_ifindex* idx1 = ooft_idx_from_id(1);
  ci_assert(idx1);
  struct ooft_hwport* hw = ooft_hwport_from_idx(idx1);

  unsigned char mac[6] = { 0,1,0,0,2,0 };
  struct ooft_ifindex* macvlan = ooft_alloc_ifindex(cp, hw, ns1,
                                                    EFX_FILTER_VID_UNSPEC,
                                                    mac);

  /* Now create another namespace, process and stack */
  ns2 = ooft_alloc_namespace(cp);
  proc2 = context_alloc(ns2);
  current = proc2;
  thr2 = ooft_alloc_stack(4);
  second_namespace_init(ns2);

  TEST_DEBUG(oof_onload_manager_dump(&efab_tcp_driver, dump, "\n"));

  /* Create a socket in the first stack.  We will expect a filter for each
   * of the two up interface IP addresses on each hwport.
   */
  diag("Creating socket in stack 1");
  udp_wild = ooft_alloc_endpoint(thr1, IPPROTO_UDP, 0, htons(2000), 0, 0);
  ooft_endpoint_expect_unicast_filters(udp_wild, 1);
  rc = ooft_endpoint_add(udp_wild, 0);
  cmp_ok(rc, "==", 0, "add UDP wild endpoint");
  check_all_filters(thr1, thr2);
  ci_dllist_init(&hw_wild);
  ooft_cplane_claim_added_hw_filters(cp, &hw_wild);

  TEST_DEBUG(oof_onload_manager_dump(&efab_tcp_driver, dump, "\n"));

  diag("Moving macvlan interface");
  ooft_move_ifindex(cp, macvlan, ns1, ns2);
  ooft_alloc_addr(ns2, macvlan, inet_addr("1.0.2.0"));

  /* Create a socket in the second stack.  We will expect a filter for
   * the macvlan interface address on the hwport it's using, as well as the
   * default interfaces we configure in that namespace.
   */
  diag("Creating socket in stack 2");
  udp_wild2 = ooft_alloc_endpoint(thr2, IPPROTO_UDP, 0, htons(2000), 0, 0);
  ooft_endpoint_expect_unicast_filters(udp_wild2, 1);
  rc = ooft_endpoint_add(udp_wild2, 0);
  cmp_ok(rc, "==", 0, "add UDP wild2 endpoint");
  check_all_filters(thr1, thr2);
  ci_dllist_init(&hw_wild2);
  ooft_cplane_claim_added_hw_filters(cp, &hw_wild2);

  /* Now tidy up, expecting all our added filters to be removed */
  diag("Releasing sockets");
  ooft_endpoint_expect_sw_remove_all(udp_wild);
  ooft_hw_filter_expect_remove_list(&hw_wild);
  oof_socket_del(thr1->ofn->ofn_filter_manager, &udp_wild->skf);
  check_all_filters(thr1, thr2);;
  ooft_free_endpoint(udp_wild);

  ooft_endpoint_expect_sw_remove_all(udp_wild2);
  ooft_hw_filter_expect_remove_list(&hw_wild2);
  oof_socket_del(thr2->ofn->ofn_filter_manager, &udp_wild2->skf);
  check_all_filters(thr1, thr2);
  ooft_free_endpoint(udp_wild2);

  /* Next, we'll create some new sockets, then move the macvlan interface
   * back to the original namespace to check that a) we correctly update the
   * filters in ns2 to remove filters for the address of macvlan, and b)
   * that we install new filters correctly on an existing socket in ns1 when
   * the new interface appears.
   */
  diag("Creating second set of sockets");
  udp_wild = ooft_alloc_endpoint(thr1, IPPROTO_UDP, 0, htons(2000), 0, 0);
  ooft_endpoint_expect_unicast_filters(udp_wild, 1);
  rc = ooft_endpoint_add(udp_wild, 0);
  cmp_ok(rc, "==", 0, "add UDP wild endpoint");
  check_all_filters(thr1, thr2);
  ci_dllist_init(&hw_wild);
  ooft_cplane_claim_added_hw_filters(cp, &hw_wild);

  udp_wild2 = ooft_alloc_endpoint(thr2, IPPROTO_UDP, 0, htons(2000), 0, 0);
  ooft_endpoint_expect_unicast_filters(udp_wild2, 1);
  rc = ooft_endpoint_add(udp_wild2, 0);
  cmp_ok(rc, "==", 0, "add UDP wild2 endpoint");
  check_all_filters(thr1, thr2);
  ci_dllist_init(&hw_wild2);
  ooft_cplane_claim_added_hw_filters(cp, &hw_wild2);

  /* When we move the macvlan interface we will expect SW and HW filter
   * referring to that address to be removed from udp_wild2, and then added
   * to udp_wild.
   */
  ooft_endpoint_expect_sw_remove_addr(udp_wild2, inet_addr("1.0.2.0"));

  /* Split the HW filters for the address we're removing out from the list
   * of claimed filters, then use that to expect removal.
   */
  struct efx_filter_spec match_spec;
  ci_dllist macvlan_filters;
  ci_dllist_init(&macvlan_filters);
  efx_filter_set_ipv4_local(&match_spec, IPPROTO_UDP, inet_addr("1.0.2.0"), 0);
  ooft_client_hw_filter_matches(&hw_wild2, &macvlan_filters, &match_spec,
                                EFX_FILTER_MATCH_LOC_HOST);

  /* And expect removal of all filters on the hwport of the interface we're
   * removing.
   */
  ooft_client_hw_filter_matches_hwport(&hw_wild2, &macvlan_filters, hw);
  ooft_hw_filter_expect_remove_list(&macvlan_filters);

  ooft_endpoint_expect_sw_add(udp_wild, IPPROTO_UDP,
                              inet_addr("1.0.2.0"), htons(2000), 0, 0);
  ooft_endpoint_expect_hw_unicast(udp_wild, inet_addr("1.0.2.0"));

  TEST_DEBUG(oof_onload_manager_dump(&efab_tcp_driver, dump, "\n"));

  ooft_move_ifindex(cp, macvlan, ns2, ns1);
  ooft_alloc_addr(ns1, macvlan, inet_addr("1.0.2.0"));
  diag("Moved macvlan back to ns1");

  TEST_DEBUG(oof_onload_manager_dump(&efab_tcp_driver, dump, "\n"));

  ooft_cplane_claim_added_hw_filters(cp, &hw_wild);
  check_all_filters(thr1, thr2);

  /* Now tidy up, expecting all our added filters to be removed */
  diag("Releasing sockets");
  ooft_endpoint_expect_sw_remove_all(udp_wild);
  ooft_hw_filter_expect_remove_list(&hw_wild);
  oof_socket_del(thr1->ofn->ofn_filter_manager, &udp_wild->skf);
  check_all_filters(thr1, thr2);;
  ooft_free_endpoint(udp_wild);

  ooft_endpoint_expect_sw_remove_all(udp_wild2);
  ooft_hw_filter_expect_remove_list(&hw_wild2);
  oof_socket_del(thr2->ofn->ofn_filter_manager, &udp_wild2->skf);
  check_all_filters(thr1, thr2);
  ooft_free_endpoint(udp_wild2);

  diag("Releasing stacks");
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

