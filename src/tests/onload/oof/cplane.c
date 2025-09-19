/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2019 Xilinx, Inc. */

#include "onload_kernel_compat.h"
#include "cplane.h"
#include "utils.h"
#include "oof_test.h"

#include <onload/oof_onload.h>
#include <arpa/inet.h>

bool cplane_use_prefsrc_as_local = false;

enum ooft_hwport_type ooft_nic_primary_hwport_type(enum ooft_nic_type type)
{
  switch(type) {
  case OOFT_NIC_X2_FF:
    return OOFT_HWPORT_EF10_FF;
  case OOFT_NIC_X2_LL:
    return OOFT_HWPORT_EF10_LL;
  case OOFT_NIC_X4_FF:
    return OOFT_HWPORT_EF10_FF;
  case OOFT_NIC_X4_LL:
    return OOFT_HWPORT_EF10_LL;
  case OOFT_NIC_AFXDP:
    return OOFT_HWPORT_AFXDP;
  };

  ci_assert(false);
  return OOFT_HWPORT_NONE;
}

enum ooft_hwport_type ooft_nic_secondary_hwport_type(enum ooft_nic_type type)
{
  if( type == OOFT_NIC_X4_FF || type == OOFT_NIC_X4_LL )
    return OOFT_HWPORT_EF10CT;
  else
    return OOFT_HWPORT_NONE;
}

unsigned ooft_hwport_type_to_flags(enum ooft_hwport_type type)
{
  switch(type) {
  case OOFT_HWPORT_EF10_FF:
    return OOF_HWPORT_FLAG_MCAST_REPLICATE | OOF_HWPORT_FLAG_VLAN_FILTERS;
  case OOFT_HWPORT_EF10_LL:
    return OOF_HWPORT_FLAG_MCAST_REPLICATE;
  case OOFT_HWPORT_EF10CT:
    return OOF_HWPORT_FLAG_MCAST_REPLICATE | OOF_HWPORT_FLAG_VLAN_FILTERS |
           OOF_HWPORT_FLAG_RX_SHARED;
  case OOFT_HWPORT_AFXDP:
    return OOF_HWPORT_FLAG_NO_5TUPLE;
  default:
    /* Unknown NIC type */
    ci_assert(false);
  };

  return 0;
}

struct ooft_hwport* ooft_alloc_hwport(struct ooft_cplane* cp, struct net* ns,
                                      enum ooft_hwport_type type)
{
  struct ooft_hwport* hw = calloc(1, sizeof(struct ooft_hwport));
  TEST(hw);

  hw->id = cp->hwport_ids++;
  hw->flags = ooft_hwport_type_to_flags(type);
  hw->type = type;
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

void ooft_add_hwport_to_ifindex(struct ooft_ifindex* idx,
                                struct ooft_hwport* hw, struct net* ns)
{
  idx->hwport_mask |= 1 << hw->id;

  if( hw->type == OOFT_HWPORT_EF10CT ) {
    idx->hwport_mask_ll |= 1 << hw->id;
    oo_nics[hw->id].oo_nic_flags |= OO_NIC_LL;

    if( idx->hwport_mask_ff ) {
      int port = ffs(idx->hwport_mask_ff) - 1;

      /* TODO currently bonds are not handled by these tests */
      ci_assert_equal(idx->hwport_mask_ff & ~(1 << port), 0);

      struct ooft_hwport* ff_hw = ooft_hwport_from_id(port);
      ff_hw->hidden_by_ll = true;
      oo_nics[ff_hw->id].oo_nic_flags |= OO_NIC_FALLBACK;
      oo_nics[ff_hw->id].alternate_hwport = hw->id;
      oo_nics[hw->id].alternate_hwport = ff_hw->id;
    }
  }
  else {
    idx->hwport_mask_ff |= 1 << hw->id;
    if( idx->hwport_mask_ll ) {
      int port = ffs(idx->hwport_mask_ll) - 1;

      /* TODO currently bonds are not handled by these tests */
      ci_assert_equal(idx->hwport_mask_ff & ~(1 << port), 0);

      struct ooft_hwport* ll_hw = ooft_hwport_from_id(port);
      hw->hidden_by_ll = true;
      oo_nics[hw->id].oo_nic_flags |= OO_NIC_FALLBACK;
      oo_nics[hw->id].alternate_hwport = ll_hw->id;
      oo_nics[ll_hw->id].alternate_hwport = hw->id;
    }
  }

  ci_assert_equal(idx->hwport_mask, idx->hwport_mask_ll^idx->hwport_mask_ff);

  ooft_ns_update_hwport_mask(ns);
  oof_onload_mcast_update_interface(idx->id,  0 /* down for now */,
                                    idx->hwport_mask, idx->vlan_id,
                                    idx->mac, ns, &efab_tcp_driver);
  oof_onload_mcast_update_filters(idx->id, ns, &efab_tcp_driver);
}


struct ooft_ifindex* ooft_alloc_ifindex(struct ooft_cplane* cp,
                                        struct net* ns, int vlan_id,
                                        unsigned char mac[6])
{
  struct ooft_ifindex* idx = calloc(1, sizeof(struct ooft_ifindex));
  TEST(idx);

  idx->id = cp->idx_ids++;
  idx->vlan_id = vlan_id;
  memcpy(idx->mac, mac, 6);
  ci_dllist_init(&idx->addrs);
  ci_dllist_push_tail(&cp->idxs, &idx->cplane_link);
  ci_dllist_push_tail(&ns->idxs, &idx->ns_link);

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

int ooft_cplane_init(struct net* net_ns, enum ooft_nic_type type)
{
  enum ooft_hwport_type hw_type = ooft_nic_primary_hwport_type(type);
  struct ooft_hwport* hw0 = ooft_alloc_hwport(cp, net_ns, hw_type);
  struct ooft_hwport* hw1 = ooft_alloc_hwport(cp, net_ns, hw_type);
  struct ooft_hwport* hw0_ll = NULL;
  struct ooft_hwport* hw1_ll = NULL;

  hw_type = ooft_nic_secondary_hwport_type(type);
  if( hw_type != OOFT_HWPORT_NONE ) {
    hw0_ll = ooft_alloc_hwport(cp, net_ns, hw_type);
    hw1_ll = ooft_alloc_hwport(cp, net_ns, hw_type);
  }

  unsigned char mac0[6] = { 0,1,0,0,0,0 };
  struct ooft_ifindex* idx0 = ooft_alloc_ifindex(cp, net_ns,
                                                 EFX_FILTER_VID_UNSPEC, mac0);
  ooft_add_hwport_to_ifindex(idx0, hw0, net_ns);
  if( hw0_ll )
    ooft_add_hwport_to_ifindex(idx0, hw0_ll, net_ns);
  ooft_alloc_addr(net_ns, idx0, inet_addr("1.0.0.0"));
  idx0->up = 1;

  unsigned char mac1[6] = { 0,1,0,0,0,1 };
  struct ooft_ifindex* idx1 = ooft_alloc_ifindex(cp, net_ns,
                                                 EFX_FILTER_VID_UNSPEC, mac1);
  ooft_add_hwport_to_ifindex(idx1, hw1, net_ns);
  ooft_alloc_addr(net_ns, idx1, inet_addr("1.0.0.1"));
  if( hw1_ll )
    ooft_add_hwport_to_ifindex(idx1, hw1_ll, net_ns);
  idx1->up = 1;

  /* Now bring up all hwports */
  ooft_hwport_up_down(hw0, 1);
  ooft_hwport_up_down(hw1, 1);
  if( hw0_ll )
    ooft_hwport_up_down(hw0_ll, 1);
  if( hw1_ll )
    ooft_hwport_up_down(hw1_ll, 1);

  return 0;
}

int ooft_default_cplane_init(struct net* net_ns)
{
  return ooft_cplane_init(net_ns, OOFT_NIC_X2_FF);
}

void ooft_free_cplane(struct ooft_cplane* cp)
{
}


void ooft_hwport_up_down(struct ooft_hwport* hw, int up)
{
  oof_onload_hwport_up_down(&efab_tcp_driver, hw->id, up, hw->flags, 1);
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

struct ooft_hwport* ooft_hwport_from_id(int id)
{
  struct ooft_hwport* hw = NULL;
  ci_dllink* link;

  CI_DLLIST_FOR_EACH(link, &cp->hwports)
    if (HWPORT_FROM_CP_LINK(link)->id == id ) {
      hw = HWPORT_FROM_CP_LINK(link);
      break;
    }

  return hw;
}

struct ooft_hwport* ooft_hwport_from_idx(struct ooft_ifindex* idx)
{
  int port_id = -1;

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

  return ooft_hwport_from_id(port_id);
}
 

