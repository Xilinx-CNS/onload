/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2019 Xilinx, Inc. */

#include "onload_kernel_compat.h"
#include "cplane.h"
#include "utils.h"
#include "oof_test.h"

#include <onload/oof_onload.h>
#include <arpa/inet.h>

bool cplane_use_prefsrc_as_local = false;

struct ooft_hwport* ooft_alloc_hwport(struct ooft_cplane* cp, struct net* ns,
                                      int vlans, int mcast_replication,
                                      int no5tuple)
{
  struct ooft_hwport* hw = calloc(1, sizeof(struct ooft_hwport));
  TEST(hw);

  hw->id = cp->hwport_ids++;
  hw->vlans = vlans;
  hw->mcast_replication = mcast_replication;
  hw->no5tuple = no5tuple;
  ci_dllist_init(&hw->idxs);
  ci_dllist_push_tail(&cp->hwports, &hw->cplane_link);

  ooft_init_efrm_client(&hw->client, hw->id);

  return hw;
}


static void ooft_ns_update_hwport_mask(struct net* ns)
{
  struct ooft_ifindex* idx;
  ci_dllink* link;

  ns->hwport_mask = 0;

  CI_DLLIST_FOR_EACH(link, &ns->idxs) {
    idx = CI_CONTAINER(struct ooft_ifindex, ns_link, link);
    ns->hwport_mask |= idx->hwport_mask;
  }
}


int ooft_ns_check_hw_filters(struct net* ns)
{
  int i;
  int rc = 0;

  for( i = 0; i < CI_CFG_MAX_HWPORTS; i++ ) {
    if( (1 << i) & ns->hwport_mask )
      rc |= ooft_client_check_hw_filters(oo_nics[i].efrm_client);
  }

  return rc;
}

void ooft_cplane_expect_hw_remove_all(struct ooft_cplane* cp)
{
  int i;
  ci_dllink* link;

  CI_DLLIST_FOR_EACH(link, &cp->namespaces) {
    struct net* ns = CI_CONTAINER(struct net, cplane_link, link);
    for( i = 0; i < CI_CFG_MAX_HWPORTS; i++ ) {
      if( (1 << i) & ns->hwport_mask )
        ooft_client_expect_hw_remove_all(oo_nics[i].efrm_client);
    }
  }
}


void ooft_cplane_claim_added_hw_filters(struct ooft_cplane* cp,
                                        ci_dllist* list)
{
  int i;
  ci_dllink* link;

  CI_DLLIST_FOR_EACH(link, &cp->namespaces) {
    struct net* ns = CI_CONTAINER(struct net, cplane_link, link);
    for( i = 0; i < CI_CFG_MAX_HWPORTS; i++ ) {
      if( (1 << i) & ns->hwport_mask )
        ooft_client_claim_added_hw_filters(oo_nics[i].efrm_client, list);
    }
  }
}


struct net* ooft_alloc_namespace(struct ooft_cplane* cp)
{
  struct net* ns = calloc(1, sizeof(struct net));
  TEST(ns);

  ns->id = cp->namespace_ids++;
  ci_dllist_init(&ns->idxs);
  ci_dllist_push_tail(&cp->namespaces, &ns->cplane_link);

  return ns;
}


void ooft_free_namespace(struct net* ns)
{
  TEST(ns->refcount == 0);

  ci_dllist_remove(&ns->cplane_link);
  free(ns);
}


void ooft_namespace_put(struct net* ns)
{
  ns->refcount--;
}


void ooft_namespace_get(struct net* ns)
{
  ns->refcount++;
}


void put_net(struct net* net)
{
  ooft_namespace_put(net);
}


struct net* get_net(struct net* net)
{
  ooft_namespace_get(net);
  return net;
}


struct ooft_ifindex* ooft_alloc_ifindex(struct ooft_cplane* cp,
                                        struct ooft_hwport* hw,
                                        struct net* ns, int vlan_id,
                                        unsigned char mac[6])
{
  struct ooft_ifindex* idx = calloc(1, sizeof(struct ooft_ifindex));
  TEST(idx);

  idx->id = cp->idx_ids++;
  idx->vlan_id = vlan_id;
  memcpy(idx->mac, mac, 6);
  idx->hwport_mask |= 1 << hw->id;
  ci_dllist_init(&idx->addrs);
  ci_dllist_push_tail(&cp->idxs, &idx->cplane_link);
  ci_dllist_push_tail(&hw->idxs, &idx->hwport_link);
  ci_dllist_push_tail(&ns->idxs, &idx->ns_link);
  ooft_ns_update_hwport_mask(ns);

  oof_onload_mcast_update_interface(idx->id,  0 /* down for now */,
                                    idx->hwport_mask, idx->vlan_id,
                                    idx->mac, ns, &efab_tcp_driver);
  oof_onload_mcast_update_filters(idx->id, ns, &efab_tcp_driver);

  return idx;
}


void ooft_move_ifindex(struct ooft_cplane* cp, struct ooft_ifindex* idx,
                       struct net* old_ns, struct net* new_ns)
{
  struct ooft_addr* addr;
  struct ooft_addr* addr_tmp;

  /* Update our internal state - move the ifindex between the namespaces */
  ci_dllist_remove(&idx->ns_link);
  ci_dllist_push_tail(&new_ns->idxs, &idx->ns_link);
  ooft_ns_update_hwport_mask(old_ns);
  ooft_ns_update_hwport_mask(new_ns);

  /* Remove any addresses currently configured on this interface */
  CI_DLLIST_FOR_EACH3(struct ooft_addr, addr, idx_link, &idx->addrs,
                      addr_tmp) {
    ooft_del_addr(old_ns, idx, addr);
  }

  /* Now update oof by notifying removal to the old namespace, and addition
   * to the new namespace.
   */
  idx->up = 0;
  oof_onload_mcast_update_interface(idx->id, idx->up, 0, idx->vlan_id,
                                    idx->mac, old_ns, &efab_tcp_driver);
  oof_onload_mcast_update_filters(idx->id, old_ns, &efab_tcp_driver);

  oof_onload_mcast_update_interface(idx->id, idx->up,
                                    idx->hwport_mask, idx->vlan_id,
                                    idx->mac, new_ns, &efab_tcp_driver);
  oof_onload_mcast_update_filters(idx->id, new_ns, &efab_tcp_driver);
}


struct ooft_addr* ooft_alloc_addr(struct net* net_ns,
                                  struct ooft_ifindex* idx, unsigned laddr_be)
{
  struct ooft_addr* addr = malloc(sizeof(struct ooft_addr));
  ci_addr_t laddr;
  TEST(addr);

  addr->laddr_be = laddr_be;
  ci_dllist_push_tail(&idx->addrs, &addr->idx_link);

  laddr = CI_ADDR_FROM_IP4(laddr_be);
  oof_onload_on_cplane_ipadd(AF_INET, laddr, idx->id, net_ns,
                             &efab_tcp_driver);

  return addr;
}


void ooft_del_addr(struct net* net_ns, struct ooft_ifindex* idx,
                   struct ooft_addr* addr)
{
  ci_addr_t laddr;
  TEST(addr);
  TEST(ci_dllist_is_member(&idx->addrs, &addr->idx_link));

  ci_dllist_remove_safe(&addr->idx_link);

  laddr = CI_ADDR_FROM_IP4(addr->laddr_be);
  oof_onload_on_cplane_ipdel(AF_INET, laddr, idx->id, net_ns,
                             &efab_tcp_driver);

  free(addr);
}


struct ooft_cplane* ooft_alloc_cplane(void)
{
  struct ooft_cplane* cp = malloc(sizeof(struct ooft_cplane));
  TEST(cp);

  ci_dllist_init(&cp->hwports);
  ci_dllist_init(&cp->idxs);
  ci_dllist_init(&cp->namespaces);

  cp->hwport_ids = 0;
  cp->idx_ids = 1;
  cp->namespace_ids = 0;

  return cp;
}

int ooft_cplane_init(struct net* net_ns, int no5tuple)
{
  struct ooft_hwport* hw0 = ooft_alloc_hwport(cp, net_ns, 1, 1, no5tuple);
  struct ooft_hwport* hw1 = ooft_alloc_hwport(cp, net_ns, 1, 1, no5tuple);

  unsigned char mac0[6] = { 0,1,0,0,0,0 };
  struct ooft_ifindex* idx0 = ooft_alloc_ifindex(cp, hw0, net_ns,
                                                 EFX_FILTER_VID_UNSPEC, mac0);
  ooft_alloc_addr(net_ns, idx0, inet_addr("1.0.0.0"));
  idx0->up = 1;

  unsigned char mac1[6] = { 0,1,0,0,0,1 };
  struct ooft_ifindex* idx1 = ooft_alloc_ifindex(cp, hw1, net_ns,
                                                 EFX_FILTER_VID_UNSPEC, mac1);
  ooft_alloc_addr(net_ns, idx1, inet_addr("1.0.0.1"));
  idx1->up = 1;

  /* Now bring up both hwports */
  ooft_hwport_up_down(hw0, 1);
  ooft_hwport_up_down(hw1, 1);

  return 0;
}

int ooft_default_cplane_init(struct net* net_ns)
{
  return ooft_cplane_init(net_ns, 0);
}

void ooft_free_cplane(struct ooft_cplane* cp)
{
}


void ooft_hwport_up_down(struct ooft_hwport* hw, int up)
{
  oof_onload_hwport_up_down(&efab_tcp_driver, hw->id, up,
                            hw->mcast_replication, hw->vlans, hw->no5tuple, 1);
}


struct ooft_ifindex* ooft_idx_from_id(int id)
{
  struct ooft_ifindex* idx = NULL;
  ci_dllink* link;

  CI_DLLIST_FOR_EACH(link, &cp->idxs)
    if (IDX_FROM_CP_LINK(link)->id == id ) {
      idx = IDX_FROM_CP_LINK(link);
      break;
    }

  return idx;
}

struct ooft_hwport* ooft_hwport_from_idx(struct ooft_ifindex* idx)
{
  struct ooft_hwport* hw = NULL;
  int port_id = -1;
  ci_dllink* link;

  /* First get the id of the hwport in use.  This function assumes that this
   * is a simple interface, with just one base hwport (ie not a bond).
   */
  int i;
  for( i = 0; i < CI_CFG_MAX_HWPORTS; i++ ) {
    if( idx->hwport_mask & (1 << i) ) {
      /* make sure this is really the only port */
      ci_assert_equal(idx->hwport_mask & ~(1 << i), 0);
      port_id = i;
      break;
    }
  }

  CI_DLLIST_FOR_EACH(link, &cp->hwports)
    if (HWPORT_FROM_CP_LINK(link)->id == port_id ) {
      hw = HWPORT_FROM_CP_LINK(link);
      break;
    }

  return hw;
}
 

