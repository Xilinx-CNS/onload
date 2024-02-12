/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

/* This test checks interactions between control plane servers in different
 * namespaces.  Currently support for this is limited to the cases where a
 * server in one namespace pulls in state from the server for init_net. */

#include "cplane_unit.h"
#include <cplane/server.h>

#include "../../tap/tap.h"


static void init_sessions(struct cp_session *s_local,
                          struct cp_session *s_main,
                          int *next_ifindex)
{
  cp_unit_init_session(s_local);
  cp_unit_init_session(s_main);
  cp_unit_set_main_cp_handle(s_local, s_main);

  /* Add two base interfaces in main namespace.  Second interface opens up
   * some extra possibilities for getting the hwport-mapping wrong even on
   * tests that don't directly use it. */
  const char mac1[] = {0x00, 0x0f, 0x53, 0x00, 0x00, 0x00};
  const char mac2[] = {0x00, 0x0f, 0x53, 0x00, 0x00, 0x01};
  *next_ifindex = 1;
  cp_unit_nl_handle_link_msg(s_main, RTM_NEWLINK, (*next_ifindex)++, "ethO0",
                             mac1);
  cp_unit_nl_handle_link_msg(s_main, RTM_NEWLINK, (*next_ifindex)++, "ethO1",
                             mac2);
}


static cicp_hwport_mask_t get_all_rxports_mask(struct cp_session *s)
{
  unsigned i;
  cicp_hwport_mask_t mask = 0;
  for( i = 0; i < s->mib[0].dim->llap_max; i++ ) {
    cicp_llap_row_t* row = &s->mib[0].llap[i];
    if( cicp_llap_row_is_free(row) )
      continue;
    mask |= row->rx_hwports;
  }
  return mask;
}


#define MACVLAN_TEST_COUNT 4
void test_macvlan_interface(void)
{
  struct cp_session s_local, s_main;
  int next_ifindex = 1;
  int macvlan_ifindex;
  init_sessions(&s_local, &s_main, &next_ifindex);

  /* Add a macvlan interface in the other namespace. */
  /* Bug70993: the control plane assumes that ifindices are unique across namespaces. */
  cicp_llap_row_t* base_llap_row = &s_main.mib[0].llap[0];
  const char macvlan_mac[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00};
  cp_unit_nl_handle_macvlan_link_msg(&s_local, RTM_NEWLINK, next_ifindex,
                                     "macvlan0", macvlan_mac,
                                     base_llap_row->ifindex);
  macvlan_ifindex = next_ifindex++;

  /* Check hwports.  The macvlan interface should be built on top of the
   * first base interface. */
  cicp_llap_row_t* macvlan_llap_row = &s_local.mib[0].llap[0];
  cmp_ok(macvlan_llap_row->rx_hwports, "==", base_llap_row->rx_hwports,
         "Macvlan RX hwports");
  cmp_ok(macvlan_llap_row->tx_hwports, "==", base_llap_row->tx_hwports,
         "Macvlan TX hwports");

  /* Check if we can resolve the ifindex by hwport ID.  We should not be
   * able to cross the namespaces and should return macvlan where possible. */
  ci_ifid_t ifindex = cp_get_hwport_ifindex(&s_local.mib[0], 0);
  cmp_ok(ifindex, "==", macvlan_ifindex,
         "Get macvlan interface by one hwport");
  ifindex = cp_get_hwport_ifindex(&s_local.mib[0], 1);
  cmp_ok(ifindex, "==", CI_IFID_BAD,
         "Get macvlan interface by another hwport");

  cp_unit_destroy_session(&s_local);
  cp_unit_destroy_session(&s_main);
}


#define VETH_TEST_COUNT 5
void test_veth_interface(void)
{
  struct cp_session s_local, s_main;
  int next_ifindex = 1;
  unsigned i;
  init_sessions(&s_local, &s_main, &next_ifindex);

  /* Add a veth interface in the other namespace.  In the real world there
   * would be an additional peer interface for this veth, but onload doesn't
   * use it so we don't create it here. */
  /* Bug70993: the control plane assumes that ifindices are unique across namespaces. */
  const char veth_mac[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00};
  cp_unit_nl_handle_veth_link_msg(&s_local, RTM_NEWLINK, next_ifindex++,
                                  "veth0", veth_mac);

  cicp_llap_row_t* veth_llap_row = &s_local.mib[0].llap[0];
  cicp_llap_type_t type = veth_llap_row->encap.type;
  cmp_ok(type, "&",
         CICP_LLAP_TYPE_ROUTE_ACROSS_NS,
         "Route-across-NS flag %sset", "");

  /* Check hwports.  RX traffic can be from either base interfaces, TX traffic
   * is routed inside the main namespace and has no directly associated base
   * interface. */
  cmp_ok(veth_llap_row->rx_hwports, "==",
         get_all_rxports_mask(&s_main),
         "Veth RX hwports");
  cmp_ok(veth_llap_row->tx_hwports, "==", 0, "Veth TX hwports");

  /* Check if we can resolve the ifindex by hwport ID.  All hwports should
   * point at the same interface. */
  for( i = 0; i < 2; i++) {
    ci_ifid_t ifindex = cp_get_hwport_ifindex(&s_local.mib[0], i);
    cmp_ok(ifindex, "==", CI_IFID_BAD,
           "Get veth interface");
  }

  cp_unit_destroy_session(&s_local);
  cp_unit_destroy_session(&s_main);
}


int main(void)
{
  cp_unit_init();
  plan(MACVLAN_TEST_COUNT + VETH_TEST_COUNT);

  test_macvlan_interface();
  test_veth_interface();

  done_testing();
}
