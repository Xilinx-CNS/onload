/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include "../onload_kernel_compat.h"
#include "../include/onload/tcp_driver.h"
#include "../stack.h"
#include "../stack_interface.h"
#include "../../tap/tap.h"
#include "../oof_test.h"
#include "../cplane.h"
#include "../utils.h"
#include "../efrm.h"
#include "../efrm_interface.h"
#include "../oof_onload_types.h"
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>
#include <onload/oof_nat.h>
#include "../oof_impl.h"


static struct oof_nat_table* get_nat_table(void)
{
  return efab_tcp_driver.filter_ns_manager->ofnm_nat_table;
}


static void check_filters(tcp_helper_resource_t* thr)
{
  int rc;

  rc = ooft_stack_check_sw_filters(thr);
  cmp_ok(rc, "==", 0, "check sw filters");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "check hw filters");
}


static void split_hw_filters_for_endpoint(ci_dllist* filters,
                                          ci_dllist* endpoint_filters,
                                          struct ooft_endpoint* ep)
{
  struct efx_filter_spec match_spec = { 0 };

  match_spec.rem_host[0] = ep->raddr_be;
  match_spec.rem_port = ep->rport_be;
  ooft_client_hw_filter_matches(filters, endpoint_filters, &match_spec,
                                EFX_FILTER_MATCH_REM_HOST |
                                EFX_FILTER_MATCH_REM_PORT);
}


static int nat_results_contain(struct oof_nat_lookup_result* results,
                               ci_addr_t orig_addr, uint16_t orig_port)
{
  int i;

  for( i = 0; i < results->n_results; i++ )
    if( CI_IPX_ADDR_EQ(results->results[i].orig_addr, orig_addr) &&
        results->results[i].orig_port == orig_port )
      return 1;

  return 0;
}


static struct oof_local_port*
find_local_port(struct oof_manager* fm, int proto, uint16_t lport)
{
  int hash;

  for( hash = 0; hash < OOF_LOCAL_PORT_TBL_SIZE; hash++ ) {
    struct oof_local_port* lp;
    CI_DLLIST_FOR_EACH2(struct oof_local_port, lp, lp_manager_link,
                        &fm->fm_local_ports[hash])
      if( lp->lp_protocol == proto && lp->lp_lport == lport )
        return lp;
  }

  return NULL;
}


static int count_local_port_nat_filters(struct oof_manager* fm, int proto,
                                        uint16_t lport)
{
  struct oof_local_port* lp = find_local_port(fm, proto, lport);
  int i;
  int count = 0;

  if( lp == NULL )
    return 0;

  for( i = 0; i < fm->fm_local_addr_n; i++ )
    count += ci_dllist_count(&lp->lp_addr[i].lpa_nat_filters);

  return count;
}


static void expect_nat_hw_filters(tcp_helper_resource_t* thr,
                                  unsigned orig_addr_be,
                                  uint16_t orig_port_be)
{
  int i;
  unsigned hwport_mask = thr->ns->hwport_mask;

  for( i = 0; i < CI_CFG_MAX_HWPORTS; i++ ) {
    if( !((1 << i) & hwport_mask) )
      continue;
    if( !oo_nics[i].efrm_client )
      continue;
    ooft_client_expect_hw_add_ip(oo_nics[i].efrm_client,
                                 tcp_helper_rx_vi_id(thr, i),
                                 tcp_helper_vi_hw_stack_id(thr, i),
                                 EFX_FILTER_VID_UNSPEC,
                                 IPPROTO_TCP, orig_addr_be, orig_port_be,
                                 0, 0);
  }
}


static void expect_nat_hw_filters_remove(tcp_helper_resource_t* thr,
                                         unsigned orig_addr_be,
                                         uint16_t orig_port_be)
{
  int i;
  unsigned hwport_mask = thr->ns->hwport_mask;

  for( i = 0; i < CI_CFG_MAX_HWPORTS; i++ ) {
    if( !((1 << i) & hwport_mask) )
      continue;
    if( !oo_nics[i].efrm_client )
      continue;
    ooft_client_expect_hw_remove_ip(oo_nics[i].efrm_client,
                                    tcp_helper_rx_vi_id(thr, i),
                                    tcp_helper_vi_hw_stack_id(thr, i),
                                    EFX_FILTER_VID_UNSPEC,
                                    IPPROTO_TCP, orig_addr_be, orig_port_be,
                                    0, 0);
  }
}


/* BR-10.01 (table init), BR-10.02 (dual hash entries),
 * BR-10.05 (lookup), BR-10.07 (del removes both entries),
 * BR-10.09 (reset), BR-10.10 (filter pool get/put),
 * BR-10.11 (dnat_add installs NAT filter),
 * BR-10.14 (dnat_del removes NAT filter),
 * BR-10.15 (dnat_reset removes all NAT filters),
 * BR-10.16 (__oof_nat_filter_delete clears HW and returns to pool),
 * BR-10.17 (TCP NAT lookup, UDP skipped),
 * BR-10.19 (each NAT result gets own filter),
 * BR-10.21 (wild filter clear removes NAT filters).
 */
int test_nat_table(void)
{
  tcp_helper_resource_t *thr;
  tcp_helper_resource_t *thr2;
  struct ooft_endpoint *ep;
  struct ooft_endpoint *ep2;
  struct oof_manager* fm;
  struct oof_nat_table* nat_table;
  struct oof_nat_lookup_result results;
  struct oof_nat_filter* nat_filter;
  struct ooft_addr* addr0;
  struct ooft_ifindex* idx0;
  struct ooft_task* proc1;
  struct ooft_task* proc2;
  struct net* ns1;
  struct net* ns2;
  ci_addr_t orig_addr, orig_addr2, xlated_addr;
  uint16_t orig_port, orig_port2, lport;
  int rc;

  new_test();
  plan(93);

  orig_addr = CI_ADDR_FROM_IP4(inet_addr("192.168.1.100"));
  orig_port = htons(9000);
  orig_addr2 = CI_ADDR_FROM_IP4(inet_addr("192.168.1.101"));
  orig_port2 = htons(9001);

  test_alloc(32);
  thr = ooft_alloc_stack(64);
  TRY(ooft_default_cplane_init(current_ns()));
  fm = thr->ofn->ofn_filter_manager;
  nat_table = get_nat_table();
  idx0 = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));
  addr0 = CI_CONTAINER(struct ooft_addr, idx_link,
                        ci_dllist_head(&idx0->addrs));
  xlated_addr = CI_ADDR_FROM_IP4(addr0->laddr_be);


  /* Part A: NAT table add, lookup, del, reset. */
  diag("Part A: NAT table add/lookup/del/reset");

  lport = htons(8000);

  rc = oof_nat_table_add(nat_table, orig_addr, orig_port,
                         xlated_addr, lport);
  cmp_ok(rc, "==", 0, "A: add first mapping");

  rc = oof_nat_table_lookup(nat_table, xlated_addr, lport, &results);
  cmp_ok(rc, "==", 0, "A: lookup succeeds");
  cmp_ok(results.n_results, "==", 1, "A: one result");
  ok(nat_results_contain(&results, orig_addr, orig_port),
     "A: lookup returns first original address");
  oof_nat_table_lookup_free(&results);

  rc = oof_nat_table_add(nat_table, orig_addr2, orig_port2,
                         xlated_addr, lport);
  cmp_ok(rc, "==", 0, "A: add second mapping");

  rc = oof_nat_table_lookup(nat_table, xlated_addr, lport, &results);
  cmp_ok(rc, "==", 0, "A: lookup after second add");
  cmp_ok(results.n_results, "==", 2, "A: two results");
  ok(nat_results_contain(&results, orig_addr, orig_port),
     "A: lookup returns first original address after second add");
  ok(nat_results_contain(&results, orig_addr2, orig_port2),
     "A: lookup returns second original address");
  oof_nat_table_lookup_free(&results);

  rc = oof_nat_table_del(nat_table, orig_addr, orig_port);
  cmp_ok(rc, "==", 0, "A: del first mapping");

  rc = oof_nat_table_lookup(nat_table, xlated_addr, lport, &results);
  cmp_ok(rc, "==", 0, "A: lookup after del");
  cmp_ok(results.n_results, "==", 1, "A: one result after del");
  ok(!nat_results_contain(&results, orig_addr, orig_port),
     "A: deleted original address absent from lookup");
  ok(nat_results_contain(&results, orig_addr2, orig_port2),
     "A: remaining original address still present");
  oof_nat_table_lookup_free(&results);

  rc = oof_nat_table_del(nat_table, orig_addr2, orig_port2);
  cmp_ok(rc, "==", 0, "A: del second mapping");

  rc = oof_nat_table_lookup(nat_table, xlated_addr, lport, &results);
  cmp_ok(rc, "==", 0, "A: lookup after both dels");
  cmp_ok(results.n_results, "==", 0, "A: zero results after both dels");
  oof_nat_table_lookup_free(&results);

  rc = oof_nat_table_reset(nat_table);
  cmp_ok(rc, "==", 0, "A: reset");

  rc = oof_nat_table_lookup(nat_table, xlated_addr, lport, &results);
  cmp_ok(rc, "==", 0, "A: lookup after reset");
  cmp_ok(results.n_results, "==", 0, "A: zero results after reset");
  oof_nat_table_lookup_free(&results);


  /* Part B: NAT filter pool get/put. */
  diag("Part B: filter pool get/put");

  lport = htons(8001);

  rc = oof_nat_table_add(nat_table, orig_addr, orig_port,
                         xlated_addr, lport);
  cmp_ok(rc, "==", 0, "B: add mapping to grow pool");

  nat_filter = oof_nat_table_filter_get(nat_table);
  ok(nat_filter != NULL, "B: filter_get returns non-NULL");
  oof_nat_table_filter_put(nat_table, nat_filter);

  TRY(oof_nat_table_reset(nat_table));

  nat_filter = oof_nat_table_filter_get(nat_table);
  ok(nat_filter != NULL, "B: filter_get after reset still works");
  oof_nat_table_filter_put(nat_table, nat_filter);



  /* Part C: Wild TCP socket with NAT mapping installs filters for both
   * the real and original addresses.  Deletion clears all NAT filters. */
  diag("Part C: TCP wild socket with NAT");

  lport = htons(8002);

  rc = oof_nat_table_add(nat_table, orig_addr, orig_port,
                         xlated_addr, lport);
  cmp_ok(rc, "==", 0, "C: add NAT mapping");

  ep = ooft_alloc_endpoint(thr, IPPROTO_TCP, 0, lport, 0, 0);
  ooft_endpoint_expect_unicast_filters(ep, OOFT_EXPECT_FLAG_HW);
  ooft_endpoint_expect_sw_add(ep, IPPROTO_TCP,
                              orig_addr.ip4, orig_port, 0, 0);
  expect_nat_hw_filters(thr, orig_addr.ip4, orig_port);

  rc = ooft_endpoint_add(ep, 0);
  cmp_ok(rc, "==", 0, "C: add TCP wild with NAT");

  check_filters(thr);
  cmp_ok(count_local_port_nat_filters(fm, IPPROTO_TCP, lport), "==", 1,
         "C: one NAT filter installed for first HW owner");

  ooft_endpoint_expect_sw_remove_all(ep);
  ooft_hw_filter_expect_remove_all(thr->ns);
  oof_socket_del(fm, &ep->skf);

  check_filters(thr);

  TRY(oof_nat_table_reset(nat_table));
  ooft_free_endpoint(ep);


  /* Part D: UDP wild socket does NOT install NAT filters. */
  diag("Part D: UDP wild socket skips NAT");

  lport = htons(8003);

  TRY(oof_nat_table_add(nat_table, orig_addr, orig_port,
                        xlated_addr, lport));

  ep = ooft_alloc_endpoint(thr, IPPROTO_UDP, 0, lport, 0, 0);
  ooft_endpoint_expect_unicast_filters(ep, OOFT_EXPECT_FLAG_HW);

  rc = ooft_endpoint_add(ep, 0);
  cmp_ok(rc, "==", 0, "D: add UDP wild with NAT mapping");

  check_filters(thr);

  ooft_endpoint_expect_sw_remove_all(ep);
  ooft_hw_filter_expect_remove_all(thr->ns);
  oof_socket_del(fm, &ep->skf);
  check_filters(thr);

  TRY(oof_nat_table_reset(nat_table));
  ooft_free_endpoint(ep);



  /* Part E: oof_manager_dnat_add installs a NAT filter on an existing
   * wild socket.  oof_manager_dnat_del removes the HW filter. */
  diag("Part E: dnat_add/del with existing wild socket");

  lport = htons(8004);

  TRY(oof_nat_table_add(nat_table, orig_addr, orig_port,
                        xlated_addr, lport));

  ep = ooft_alloc_endpoint(thr, IPPROTO_TCP, 0, lport, 0, 0);
  ooft_endpoint_expect_unicast_filters(ep, OOFT_EXPECT_FLAG_HW);
  ooft_endpoint_expect_sw_add(ep, IPPROTO_TCP,
                              orig_addr.ip4, orig_port, 0, 0);
  expect_nat_hw_filters(thr, orig_addr.ip4, orig_port);
  rc = ooft_endpoint_add(ep, 0);
  cmp_ok(rc, "==", 0, "E: add TCP wild");
  check_filters(thr);

  TRY(oof_nat_table_add(nat_table, orig_addr2, orig_port2,
                        xlated_addr, lport));
  ooft_endpoint_expect_sw_add(ep, IPPROTO_TCP,
                              orig_addr2.ip4, orig_port2, 0, 0);
  expect_nat_hw_filters(thr, orig_addr2.ip4, orig_port2);
  rc = oof_manager_dnat_add(fm, AF_INET, IPPROTO_TCP,
                            orig_addr2, orig_port2, xlated_addr, lport);
  cmp_ok(rc, "==", 0, "E: dnat_add");
  check_filters(thr);
  cmp_ok(count_local_port_nat_filters(fm, IPPROTO_TCP, lport), "==", 2,
         "E: two NAT filters linked before dnat_del");

  expect_nat_hw_filters_remove(thr, orig_addr2.ip4, orig_port2);
  oof_manager_dnat_del(fm, IPPROTO_TCP, orig_addr2, orig_port2);
  check_filters(thr);
  cmp_ok(count_local_port_nat_filters(fm, IPPROTO_TCP, lport), "==", 1,
         "E: dnat_del unlinked the matching NAT filter");

  /* dnat_del removes the HW filter and the nat_filter from
   * lpa_nat_filters, but does NOT remove the SW filter.  When
   * oof_socket_del cleans up, oof_socket_del_wild_sw iterates only
   * the remaining lpa_nat_filters entries.  So orig_addr2's SW
   * filter is orphaned and won't be removed by oof_socket_del. */
  {
    ci_dllink* link;
    CI_DLLIST_FOR_EACH(link, &cp->idxs) {
      struct ooft_ifindex* idx = IDX_FROM_CP_LINK(link);
      ci_dllink* al;
      CI_DLLIST_FOR_EACH(al, &idx->addrs) {
        struct ooft_addr* a = CI_CONTAINER(struct ooft_addr, idx_link, al);
        ooft_endpoint_expect_sw_remove_addr(ep, a->laddr_be);
      }
    }
  }
  ooft_endpoint_expect_sw_remove_addr(ep, orig_addr.ip4);
  ooft_hw_filter_expect_remove_all(thr->ns);
  oof_socket_del(fm, &ep->skf);
  check_filters(thr);

  TRY(oof_nat_table_reset(nat_table));
  ooft_free_endpoint(ep);



  /* Part F: oof_manager_dnat_reset removes all NAT filters at once. */
  diag("Part F: dnat_reset removes all NAT filters");

  lport = htons(8005);

  TRY(oof_nat_table_add(nat_table, orig_addr, orig_port,
                        xlated_addr, lport));
  TRY(oof_nat_table_add(nat_table, orig_addr2, orig_port2,
                        xlated_addr, lport));

  ep = ooft_alloc_endpoint(thr, IPPROTO_TCP, 0, lport, 0, 0);
  ooft_endpoint_expect_unicast_filters(ep, OOFT_EXPECT_FLAG_HW);
  ooft_endpoint_expect_sw_add(ep, IPPROTO_TCP,
                              orig_addr.ip4, orig_port, 0, 0);
  ooft_endpoint_expect_sw_add(ep, IPPROTO_TCP,
                              orig_addr2.ip4, orig_port2, 0, 0);
  expect_nat_hw_filters(thr, orig_addr.ip4, orig_port);
  expect_nat_hw_filters(thr, orig_addr2.ip4, orig_port2);
  rc = ooft_endpoint_add(ep, 0);
  cmp_ok(rc, "==", 0, "F: add TCP wild with 2 NAT mappings");
  check_filters(thr);
  cmp_ok(count_local_port_nat_filters(fm, IPPROTO_TCP, lport), "==", 2,
         "F: two NAT filters linked before reset");

  expect_nat_hw_filters_remove(thr, orig_addr.ip4, orig_port);
  expect_nat_hw_filters_remove(thr, orig_addr2.ip4, orig_port2);
  oof_manager_dnat_reset(fm, IPPROTO_TCP);
  check_filters(thr);
  cmp_ok(count_local_port_nat_filters(fm, IPPROTO_TCP, lport), "==", 0,
         "F: dnat_reset unlinked all NAT filters");

  /* As in Part E, dnat_reset removes nat_filters from lpa_nat_filters
   * but not the SW filters.  Only expect real-address SW removal. */
  {
    ci_dllink* link;
    CI_DLLIST_FOR_EACH(link, &cp->idxs) {
      struct ooft_ifindex* idx = IDX_FROM_CP_LINK(link);
      ci_dllink* al;
      CI_DLLIST_FOR_EACH(al, &idx->addrs) {
        struct ooft_addr* a = CI_CONTAINER(struct ooft_addr, idx_link, al);
        ooft_endpoint_expect_sw_remove_addr(ep, a->laddr_be);
      }
    }
  }
  ooft_hw_filter_expect_remove_all(thr->ns);
  oof_socket_del(fm, &ep->skf);
  check_filters(thr);

  TRY(oof_nat_table_reset(nat_table));
  ooft_free_endpoint(ep);



  /* Part G: oof_onload_dnat_add/del/reset orchestrate NAT operations across
   * multiple namespaces.  Verify that NAT filters are installed and removed
   * in both namespaces. */
  diag("Part G: multi-namespace DNAT orchestration");

  lport = htons(8006);
  proc1 = current;
  ns1 = current_ns();

  ns2 = ooft_alloc_namespace(cp);
  proc2 = context_alloc(ns2);
  current = proc2;
  thr2 = ooft_alloc_stack(64);
  TRY(ooft_default_cplane_init(ns2));

  /* Create wild TCP endpoint in ns1. */
  current = proc1;
  ep = ooft_alloc_endpoint(thr, IPPROTO_TCP, 0, lport, 0, 0);
  ooft_endpoint_expect_unicast_filters(ep, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(ep, 0);
  cmp_ok(rc, "==", 0, "G: add TCP wild in ns1");
  check_filters(thr);

  /* Create wild TCP endpoint in ns2. */
  current = proc2;
  ep2 = ooft_alloc_endpoint(thr2, IPPROTO_TCP, 0, lport, 0, 0);
  ooft_endpoint_expect_unicast_filters(ep2, OOFT_EXPECT_FLAG_HW);
  rc = ooft_endpoint_add(ep2, 0);
  cmp_ok(rc, "==", 0, "G: add TCP wild in ns2");
  check_filters(thr2);

  /* BR-10.28: oof_onload_dnat_add adds to global table then installs
   * NAT filters in every namespace. */
  ooft_endpoint_expect_sw_add(ep, IPPROTO_TCP,
                              orig_addr.ip4, orig_port, 0, 0);
  expect_nat_hw_filters(thr, orig_addr.ip4, orig_port);
  ooft_endpoint_expect_sw_add(ep2, IPPROTO_TCP,
                              orig_addr.ip4, orig_port, 0, 0);
  expect_nat_hw_filters(thr2, orig_addr.ip4, orig_port);

  rc = oof_onload_dnat_add(&efab_tcp_driver,
                            orig_addr, orig_port, xlated_addr, lport);
  cmp_ok(rc, "==", 0, "G: oof_onload_dnat_add");
  rc = oof_nat_table_lookup(nat_table, xlated_addr, lport, &results);
  cmp_ok(rc, "==", 0, "G: global lookup after onload dnat_add");
  cmp_ok(results.n_results, "==", 1, "G: global table has one mapping");
  ok(nat_results_contain(&results, orig_addr, orig_port),
     "G: global table contains added mapping");
  oof_nat_table_lookup_free(&results);
  check_filters(thr);
  check_filters(thr2);

  /* BR-10.29: oof_onload_dnat_del removes from global table then
   * removes NAT filters from every namespace. */
  expect_nat_hw_filters_remove(thr, orig_addr.ip4, orig_port);
  expect_nat_hw_filters_remove(thr2, orig_addr.ip4, orig_port);
  oof_onload_dnat_del(&efab_tcp_driver, orig_addr, orig_port);
  rc = oof_nat_table_lookup(nat_table, xlated_addr, lport, &results);
  cmp_ok(rc, "==", 0, "G: global lookup after onload dnat_del");
  cmp_ok(results.n_results, "==", 0, "G: global table mapping removed");
  oof_nat_table_lookup_free(&results);
  check_filters(thr);
  check_filters(thr2);

  /* BR-10.30: oof_onload_dnat_reset resets global table then removes
   * all NAT filters from every namespace. */
  ooft_endpoint_expect_sw_add(ep, IPPROTO_TCP,
                              orig_addr2.ip4, orig_port2, 0, 0);
  expect_nat_hw_filters(thr, orig_addr2.ip4, orig_port2);
  ooft_endpoint_expect_sw_add(ep2, IPPROTO_TCP,
                              orig_addr2.ip4, orig_port2, 0, 0);
  expect_nat_hw_filters(thr2, orig_addr2.ip4, orig_port2);

  rc = oof_onload_dnat_add(&efab_tcp_driver,
                            orig_addr2, orig_port2, xlated_addr, lport);
  cmp_ok(rc, "==", 0, "G: oof_onload_dnat_add for reset test");
  check_filters(thr);
  check_filters(thr2);
  rc = oof_nat_table_lookup(nat_table, xlated_addr, lport, &results);
  cmp_ok(rc, "==", 0, "G: global lookup before onload dnat_reset");
  cmp_ok(results.n_results, "==", 1, "G: global table populated before reset");
  oof_nat_table_lookup_free(&results);

  expect_nat_hw_filters_remove(thr, orig_addr2.ip4, orig_port2);
  expect_nat_hw_filters_remove(thr2, orig_addr2.ip4, orig_port2);
  oof_onload_dnat_reset(&efab_tcp_driver);
  rc = oof_nat_table_lookup(nat_table, xlated_addr, lport, &results);
  cmp_ok(rc, "==", 0, "G: global lookup after onload dnat_reset");
  cmp_ok(results.n_results, "==", 0, "G: global table reset");
  oof_nat_table_lookup_free(&results);
  check_filters(thr);
  check_filters(thr2);

  /* Cleanup: delete sockets.  SW filters for NAT addresses are orphaned
   * (same as Parts E-F), so only expect real-address SW removal. */
  current = proc1;
  {
    ci_dllink* link;
    CI_DLLIST_FOR_EACH(link, &ns1->idxs) {
      struct ooft_ifindex* idx =
          CI_CONTAINER(struct ooft_ifindex, ns_link, link);
      ci_dllink* al;
      CI_DLLIST_FOR_EACH(al, &idx->addrs) {
        struct ooft_addr* a = CI_CONTAINER(struct ooft_addr, idx_link, al);
        ooft_endpoint_expect_sw_remove_addr(ep, a->laddr_be);
      }
    }
  }
  ooft_hw_filter_expect_remove_all(thr->ns);
  oof_socket_del(fm, &ep->skf);
  check_filters(thr);
  ooft_free_endpoint(ep);

  current = proc2;
  {
    struct oof_manager* fm2 = thr2->ofn->ofn_filter_manager;
    ci_dllink* link;
    CI_DLLIST_FOR_EACH(link, &ns2->idxs) {
      struct ooft_ifindex* idx =
          CI_CONTAINER(struct ooft_ifindex, ns_link, link);
      ci_dllink* al;
      CI_DLLIST_FOR_EACH(al, &idx->addrs) {
        struct ooft_addr* a = CI_CONTAINER(struct ooft_addr, idx_link, al);
        ooft_endpoint_expect_sw_remove_addr(ep2, a->laddr_be);
      }
    }
    ooft_hw_filter_expect_remove_all(thr2->ns);
    oof_socket_del(fm2, &ep2->skf);
  }
  check_filters(thr2);
  ooft_free_endpoint(ep2);


  ooft_free_stack(thr);
  ooft_free_stack(thr2);
  test_cleanup();
  context_free(proc1);
  ooft_free_namespace(ns1);
  done_testing();
}


extern int oof_shared_keep_thresh;


/* BR-10.22 (wild SW removal removes NAT SW filters),
 * BR-10.23 (sf_lport_prenat set on port mismatch during share),
 * BR-10.24 (sf_lport_prenat initialized to 0),
 * BR-10.25 (full-match SW filter uses sf_lport_prenat),
 * BR-10.26 (HW filter unsharing uses sf_lport_prenat),
 * BR-10.27 (oof_manager_lport_addr_find searches NAT addresses).
 *
 * Tests socket share (oof_socket_share) with NAT port translation,
 * wild socket deletion with NAT SW filter cleanup, and HW filter
 * unsharing with sf_lport_prenat.
 */
int test_nat_socket(void)
{
  tcp_helper_resource_t* thr;
  struct ooft_endpoint* listener;
  struct ooft_endpoint* nat_passive;
  struct ooft_endpoint* passive;
  struct oof_manager* fm;
  struct oof_nat_table* nat_table;
  struct ooft_ifindex* idx0;
  struct ooft_addr* addr0;
  ci_addr_t orig_addr, xlated_addr;
  ci_addr_t raddr;
  uint16_t orig_port, rport, xlated_port;
  ci_dllist hw_listener;
  ci_dllist hw_nat_passive;
  ci_dllist hw_passive;
  int rc;
  int saved_keep;

  new_test();
  plan(36);

  orig_addr = CI_ADDR_FROM_IP4(inet_addr("192.168.1.100"));
  orig_port = htons(9000);

  test_alloc(32);
  thr = ooft_alloc_stack(64);
  TRY(ooft_default_cplane_init(current_ns()));
  fm = thr->ofn->ofn_filter_manager;
  nat_table = get_nat_table();
  idx0 = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));
  addr0 = CI_CONTAINER(struct ooft_addr, idx_link,
                        ci_dllist_head(&idx0->addrs));
  xlated_addr = CI_ADDR_FROM_IP4(addr0->laddr_be);

  ci_dllist_init(&hw_listener);
  ci_dllist_init(&hw_nat_passive);
  ci_dllist_init(&hw_passive);

  saved_keep = oof_shared_keep_thresh;

  /* --- Scenario A (BR-10.23, BR-10.24, BR-10.25, BR-10.27):
   *     socket share with NAT port translation --- */
  diag("Scenario A: socket share with NAT");

  xlated_port = htons(4000);

  TRY(oof_nat_table_add(nat_table, orig_addr, orig_port,
                        xlated_addr, xlated_port));

  listener = ooft_alloc_endpoint(thr, IPPROTO_TCP, 0, xlated_port, 0, 0);
  ooft_endpoint_expect_unicast_filters(listener, OOFT_EXPECT_FLAG_HW);
  ooft_endpoint_expect_sw_add(listener, IPPROTO_TCP,
                              orig_addr.ip4, orig_port, 0, 0);
  expect_nat_hw_filters(thr, orig_addr.ip4, orig_port);
  rc = ooft_endpoint_add(listener, 0);
  cmp_ok(rc, "==", 0, "A: add listener");
  cmp_ok(listener->skf.sf_lport_prenat, "==", 0,
         "A: listener sf_lport_prenat zero after socket add (BR-10.24)");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_listener);

  /* NAT passive: client connected to orig_addr:orig_port, translated
   * to xlated_addr:xlated_port.  The lport parameter to oof_socket_share
   * is the pre-NAT port (orig_port). */
  raddr = CI_ADDR_FROM_IP4(inet_addr("2.0.0.0"));
  rport = htons(5000);
  nat_passive = ooft_alloc_endpoint(thr, IPPROTO_TCP,
                                    orig_addr.ip4, orig_port,
                                    raddr.ip4, rport);
  ooft_endpoint_expect_sw_add(nat_passive, IPPROTO_TCP,
                              orig_addr.ip4, orig_port,
                              raddr.ip4, rport);
  rc = oof_socket_share(fm, &nat_passive->skf, &listener->skf,
                        AF_SPACE_FLAG_IP4,
                        CI_ADDR_FROM_IP4(orig_addr.ip4),
                        raddr, orig_port, rport);
  cmp_ok(rc, "==", 0, "A: share NAT passive (BR-10.27 lookup)");
  cmp_ok(nat_passive->skf.sf_lport_prenat, "==", orig_port,
         "A: sf_lport_prenat set (BR-10.23)");
  check_filters(thr);

  /* Non-NAT passive: lport matches listener, sf_lport_prenat stays 0. */
  raddr = CI_ADDR_FROM_IP4(inet_addr("3.0.0.0"));
  rport = htons(6000);
  passive = ooft_alloc_endpoint(thr, IPPROTO_TCP,
                                addr0->laddr_be, xlated_port,
                                raddr.ip4, rport);
  ooft_endpoint_expect_sw_add(passive, IPPROTO_TCP,
                              addr0->laddr_be, xlated_port,
                              raddr.ip4, rport);
  rc = oof_socket_share(fm, &passive->skf, &listener->skf,
                        AF_SPACE_FLAG_IP4,
                        CI_ADDR_FROM_IP4(addr0->laddr_be),
                        raddr, xlated_port, rport);
  cmp_ok(rc, "==", 0, "A: share non-NAT passive");
  cmp_ok(passive->skf.sf_lport_prenat, "==", 0,
         "A: sf_lport_prenat zero (BR-10.24)");
  check_filters(thr);


  /* --- Scenario B (BR-10.22): wild SW deletion removes NAT SW filters.
   *     Delete passives first, then listener (wild, no passives left).
   *     oof_socket_del_wild_sw iterates lpa_nat_filters and removes
   *     the NAT SW filter for orig_addr:orig_port. --- */
  diag("Scenario B: wild SW deletion removes NAT SW filters");

  ooft_endpoint_expect_sw_remove_all(nat_passive);
  oof_socket_del(fm, &nat_passive->skf);
  check_filters(thr);
  ooft_endpoint_expect_sw_remove_all(passive);
  oof_socket_del(fm, &passive->skf);
  check_filters(thr);

  /* Delete listener: wild socket deletion removes primary + NAT SW. */
  ooft_endpoint_expect_sw_remove_all(listener);
  ooft_hw_filter_expect_remove_list(&hw_listener);
  oof_socket_del(fm, &listener->skf);
  check_filters(thr);

  TRY(oof_nat_table_reset(nat_table));
  ooft_free_endpoint(nat_passive);
  ooft_free_endpoint(passive);
  ooft_free_endpoint(listener);


  /* --- Scenario C (BR-10.26): HW unsharing uses sf_lport_prenat.
   *     Delete listener while passives exist; oof_local_port_fixup_wild
   *     finds no wild socket, sharers <= keep_thresh, and calls
   *     oof_full_socks_add_hw_filters which uses sf_lport_prenat for
   *     the 5-tuple HW filter port. --- */
  diag("Scenario C: HW unsharing uses sf_lport_prenat");

  oof_shared_keep_thresh = 5;
  xlated_port = htons(4001);

  TRY(oof_nat_table_add(nat_table, orig_addr, orig_port,
                        xlated_addr, xlated_port));

  listener = ooft_alloc_endpoint(thr, IPPROTO_TCP, 0, xlated_port, 0, 0);
  ooft_endpoint_expect_unicast_filters(listener, OOFT_EXPECT_FLAG_HW);
  ooft_endpoint_expect_sw_add(listener, IPPROTO_TCP,
                              orig_addr.ip4, orig_port, 0, 0);
  expect_nat_hw_filters(thr, orig_addr.ip4, orig_port);
  rc = ooft_endpoint_add(listener, 0);
  cmp_ok(rc, "==", 0, "C: add listener");
  cmp_ok(listener->skf.sf_lport_prenat, "==", 0,
         "C: listener sf_lport_prenat zero after socket add (BR-10.24)");
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_listener);

  raddr = CI_ADDR_FROM_IP4(inet_addr("4.0.0.0"));
  rport = htons(7000);
  nat_passive = ooft_alloc_endpoint(thr, IPPROTO_TCP,
                                    orig_addr.ip4, orig_port,
                                    raddr.ip4, rport);
  ooft_endpoint_expect_sw_add(nat_passive, IPPROTO_TCP,
                              orig_addr.ip4, orig_port,
                              raddr.ip4, rport);
  rc = oof_socket_share(fm, &nat_passive->skf, &listener->skf,
                        AF_SPACE_FLAG_IP4,
                        CI_ADDR_FROM_IP4(orig_addr.ip4),
                        raddr, orig_port, rport);
  cmp_ok(rc, "==", 0, "C: share NAT passive");
  cmp_ok(nat_passive->skf.sf_lport_prenat, "==", orig_port,
         "C: NAT passive sf_lport_prenat set");
  check_filters(thr);

  raddr = CI_ADDR_FROM_IP4(inet_addr("5.0.0.0"));
  rport = htons(8000);
  passive = ooft_alloc_endpoint(thr, IPPROTO_TCP,
                                addr0->laddr_be, xlated_port,
                                raddr.ip4, rport);
  ooft_endpoint_expect_sw_add(passive, IPPROTO_TCP,
                              addr0->laddr_be, xlated_port,
                              raddr.ip4, rport);
  rc = oof_socket_share(fm, &passive->skf, &listener->skf,
                        AF_SPACE_FLAG_IP4,
                        CI_ADDR_FROM_IP4(addr0->laddr_be),
                        raddr, xlated_port, rport);
  cmp_ok(rc, "==", 0, "C: share non-NAT passive");
  cmp_ok(passive->skf.sf_lport_prenat, "==", 0,
         "C: non-NAT passive sf_lport_prenat zero");
  check_filters(thr);

  /* Delete listener: wild SW removed (primary + NAT), then fixup_wild
   * finds sharers=2 <= keep_thresh=5 → unshare.  Each passive gets
   * its own 5-tuple HW filter. */
  ooft_endpoint_expect_sw_remove_all(listener);
  ooft_hw_filter_expect_remove_list(&hw_listener);
  ooft_endpoint_expect_hw_unicast(nat_passive, nat_passive->laddr_be, 0);
  ooft_endpoint_expect_hw_unicast(passive, passive->laddr_be, 0);
  oof_socket_del(fm, &listener->skf);
  check_filters(thr);
  ooft_cplane_claim_added_hw_filters(cp, &hw_passive);
  split_hw_filters_for_endpoint(&hw_passive, &hw_nat_passive, nat_passive);

  /* Clean up passives (each now has own HW filter). */
  ooft_hw_filter_expect_remove_list(&hw_nat_passive);
  ooft_endpoint_expect_sw_remove_all(nat_passive);
  oof_socket_del(fm, &nat_passive->skf);
  check_filters(thr);
  ooft_hw_filter_expect_remove_list(&hw_passive);
  ooft_endpoint_expect_sw_remove_all(passive);
  oof_socket_del(fm, &passive->skf);
  check_filters(thr);

  oof_shared_keep_thresh = saved_keep;
  TRY(oof_nat_table_reset(nat_table));
  ooft_free_endpoint(nat_passive);
  ooft_free_endpoint(passive);
  ooft_free_endpoint(listener);

  ooft_free_stack(thr);
  test_cleanup();
  done_testing();
}
