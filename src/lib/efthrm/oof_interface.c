/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <ci/internal/ip.h>
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>
#include <onload/tcp_helper.h>
#include <onload/tcp_driver.h>
#include <onload/debug.h>
#include "tcp_filters_internal.h"
#include <onload/driverlink_filter.h>
#include <onload/tcp_helper_fns.h>

#include "oof_onload_types.h"

#define skf_to_ep(skf)  CI_CONTAINER(tcp_helper_endpoint_t, oofilter, (skf))
#define skf_to_ni(skf)  (&skf_to_ep(skf)->thr->netif)


/**********************************************************************
 * Callbacks from oof to onload.
 */

struct tcp_helper_resource_s*
oof_cb_socket_stack(struct oof_socket* skf)
{
  ci_assert_nflags(skf->sf_flags, OOF_SOCKET_NO_STACK);
  return skf_to_ep(skf)->thr;
}


struct tcp_helper_cluster_s*
oof_cb_stack_thc(struct tcp_helper_resource_s* skf_stack)
{
  return skf_stack->thc;
}


void
oof_cb_thc_ref(struct tcp_helper_cluster_s* thc)
{
  tcp_helper_cluster_ref(thc);
}


const char*
oof_cb_thc_name(struct tcp_helper_cluster_s* thc)
{
  return thc->thc_name;
}


int
oof_cb_socket_id(struct oof_socket* skf)
{
  return (skf->sf_flags & OOF_SOCKET_NO_STACK) == 0 ?
         OO_SP_FMT(skf_to_ep(skf)->id) : -1;
}


int
oof_cb_stack_id(struct tcp_helper_resource_s* stack)
{
  return stack ? NI_ID(&stack->netif) : -1;
}


void
oof_cb_callback_set_filter(struct oof_socket* skf)
{
  SP_TO_SOCK_CMN(&oof_cb_socket_stack(skf)->netif,
                 oof_cb_socket_id(skf))->s_flags |= CI_SOCK_FLAG_FILTER;
}



struct oof_cb_sw_filter_op {
  struct oof_cb_sw_filter_op *next;
  oo_sp sock_id;
  int af_space;
  ci_addr_t laddr;
  ci_addr_t raddr;
  int lport;
  int rport;
  int protocol;
  enum {
    OOF_CB_SW_FILTER_OP_ADD,
    OOF_CB_SW_FILTER_OP_REMOVE
  } op;
};


void
oof_cb_sw_filter_apply(ci_netif* ni)
{
  struct oof_cb_sw_filter_op* op;

  ci_assert(ci_netif_is_locked(ni));

  spin_lock_bh(&ni->swf_update_lock);
  for( op = ni->swf_update_first; op != NULL; op = ni->swf_update_first) {
    ni->swf_update_first = op->next;
    if( op->next == NULL )
      ni->swf_update_last = NULL;
    spin_unlock_bh(&ni->swf_update_lock);

    if( op->op == OOF_CB_SW_FILTER_OP_ADD ) {
      ci_netif_filter_insert(ni, op->sock_id, op->af_space, op->laddr,
                             op->lport, op->raddr, op->rport, op->protocol);
    }
    else {
      ci_netif_filter_remove(ni, op->sock_id, op->af_space, op->laddr,
                             op->lport, op->raddr, op->rport, op->protocol);
    }

    ci_free(op);
    spin_lock_bh(&ni->swf_update_lock);
  }
  spin_unlock_bh(&ni->swf_update_lock);
}

static void
oof_cb_sw_filter_postpone(struct oof_socket* skf, int af_space,
                          ci_addr_t laddr, int lport,
                          ci_addr_t raddr, int rport, int protocol, int op_op)
{
  ci_netif* ni = skf_to_ni(skf);
  struct tcp_helper_resource_s *trs = netif2tcp_helper_resource(ni);
  struct oof_cb_sw_filter_op* op = CI_ALLOC_OBJ(struct oof_cb_sw_filter_op);
  
  if( op == NULL ) {
    /* Linux complains about failed allocations */
    return;
  }

  op->sock_id = OO_SP_FROM_INT(ni, skf_to_ep(skf)->id);
  op->af_space = af_space;
  op->laddr = laddr;
  op->raddr = raddr;
  op->lport = lport;
  op->rport = rport;
  op->protocol = protocol;
  op->op = op_op;

  op->next = NULL;

  spin_lock_bh(&ni->swf_update_lock);
  if( ni->swf_update_last == NULL )
    ni->swf_update_first = op;
  else
    ni->swf_update_last->next = op;
  ni->swf_update_last = op;
  spin_unlock_bh(&ni->swf_update_lock);

  /* We are holding a spinlock, so claim to be in driverlink context here */
  if( efab_tcp_helper_netif_lock_or_set_flags(trs, OO_TRUSTED_LOCK_SWF_UPDATE,
                                              CI_EPLOCK_NETIF_SWF_UPDATE, 1) ) {
    ef_eplock_holder_set_flag(&ni->state->lock, CI_EPLOCK_NETIF_SWF_UPDATE);
    efab_tcp_helper_netif_unlock(trs, 1);
  }
}

static int
oof_cb_sw_filter_update(struct oof_socket* skf, int af_space,
                        const ci_addr_t laddr, int lport,
                        const ci_addr_t raddr, int rport,
                        int protocol, int stack_locked, bool insert)
{
  ci_netif* ni = skf_to_ni(skf);
  struct tcp_helper_resource_s *trs = netif2tcp_helper_resource(ni);
  int rc = 0;

  /* We are holding a spinlock, so claim to be in driverlink context here */
  if( stack_locked || efab_tcp_helper_netif_try_lock(trs, 1) ) {
    if( ni->swf_update_first != NULL )
      oof_cb_sw_filter_apply(ni);
    if( insert ) {
        rc = ci_netif_filter_insert(ni, OO_SP_FROM_INT(ni, skf_to_ep(skf)->id),
                                    af_space, laddr, lport, raddr, rport, protocol);
    }
    else
    {
      ci_netif_filter_remove(ni, OO_SP_FROM_INT(ni, skf_to_ep(skf)->id),
                             af_space, laddr, lport, raddr, rport, protocol);
    }
    if( ! stack_locked )
      efab_tcp_helper_netif_unlock(trs, 1);
  } else {
    oof_cb_sw_filter_postpone(skf, af_space, laddr, lport, raddr, rport,
                              protocol, insert ? OOF_CB_SW_FILTER_OP_ADD :
                              OOF_CB_SW_FILTER_OP_REMOVE);
  }
  return rc;
}

/* Fixme: most callers of oof_cb_sw_filter_insert do not check rc. */
int
oof_cb_sw_filter_insert(struct oof_socket* skf, int af_space,
                        const ci_addr_t laddr, int lport,
                        const ci_addr_t raddr, int rport,
                        int protocol, int stack_locked)
{
#ifndef NDEBUG
  ci_netif* ni = skf_to_ni(skf);
#endif

  ci_assert(!stack_locked || ci_netif_is_locked(ni));

  return oof_cb_sw_filter_update(skf, af_space, laddr, lport, raddr, rport,
                                 protocol, stack_locked, true);
}


void
oof_cb_sw_filter_remove(struct oof_socket* skf, int af_space,
                        const ci_addr_t laddr, int lport,
                        const ci_addr_t raddr, int rport,
                        int protocol, int stack_locked)
{
  ci_netif* ni = skf_to_ni(skf);

  if( skf->sf_flags & OOF_SOCKET_SW_FILTER_WAS_REMOVED )
    return;

  /* Do not bother to remove sw filters from wedged stack */
  if( ni->flags & CI_NETIF_FLAG_WEDGED )
    return;

  /* We MAY call this function with incorrect stack_locked flag
   * if OOF_SOCKET_SW_FILTER_WAS_REMOVED or CI_NETIF_FLAG_WEDGED flags
   * are set. */
  ci_assert(!stack_locked || ci_netif_is_locked(ni));

  oof_cb_sw_filter_update(skf, af_space, laddr, lport, raddr, rport, protocol,
                          stack_locked, false);

}


/* dlfilter callbacks are called from oof code to keep hw and dl filters
 * synchronized. */
void
oof_dl_filter_set(struct oo_hw_filter* filter, int stack_id, int protocol,
                  ci_addr_t saddr, int sport, ci_addr_t daddr, int dport)
{
  if( filter->dlfilter_handle != EFX_DLFILTER_HANDLE_BAD )
    efx_dlfilter_remove(efab_tcp_driver.dlfilter, filter->dlfilter_handle);
  efx_dlfilter_add(efab_tcp_driver.dlfilter, protocol,
                   daddr, dport, saddr, sport,
                   stack_id, &filter->dlfilter_handle);
}


void
oof_dl_filter_del(struct oo_hw_filter* filter)
{
  if( filter->dlfilter_handle != EFX_DLFILTER_HANDLE_BAD ) {
    efx_dlfilter_remove(efab_tcp_driver.dlfilter, filter->dlfilter_handle);
    filter->dlfilter_handle = EFX_DLFILTER_HANDLE_BAD;
  }
}


/* Fixme: pass namespace as an argument */
int 
oof_cb_get_hwport_mask(int ifindex, cicp_hwport_mask_t *hwport_mask,
                       void* owner_priv)
{
  int rc;
  struct oo_filter_ns* fns = owner_priv;
  struct oo_cplane_handle* cp;

  /* We should only be installing filters for a stack that exists, which
   * implies the existence of a cplane instance in this namespace.  We use
   * the _if_exists variant and assert we get one as the plain acquire
   * function is not safe to call in this context in case it actually
   * ends up allocating.
   */
  cp = cp_acquire_from_netns_if_exists(fns->ofn_netns);
  ci_assert(cp);

  rc = oo_cp_get_active_hwport_mask(cp, ifindex, hwport_mask);
  cp_release(cp);

  return rc;
}


int
oof_cb_get_vlan_id(int ifindex, unsigned short *vlan_id, void* owner_priv)
{
  struct oo_filter_ns* fns = owner_priv;
  cicp_encap_t encap = {CICP_LLAP_TYPE_NONE, 0}; /* appease gcc */
  int rc;
  struct oo_cplane_handle* cp;

  cp = cp_acquire_from_netns_if_exists(fns->ofn_netns);
  ci_assert(cp);

  if( cp == NULL )
    return -ENODEV;

  rc = oo_cp_find_llap(cp, ifindex, NULL/*mtu*/, NULL/*hwports*/,
                       NULL/*rxhwports*/, NULL/*mac*/, &encap);
  cp_release(cp);
  if( rc == 0 )
    *vlan_id = encap.vlan_id;

  return rc;
}


int
oof_cb_get_mac(int ifindex, unsigned char out_mac[6], void* owner_priv)
{
  struct oo_filter_ns* fns = owner_priv;
  ci_mac_addr_t mac;
  int rc;
  struct oo_cplane_handle* cp;

  cp = cp_acquire_from_netns_if_exists(fns->ofn_netns);
  ci_assert(cp);

  if( cp == NULL )
    return -ENODEV;

  rc = oo_cp_find_llap(cp, ifindex, NULL/*mtu*/, NULL/*hwport*/,
                       NULL/*rxhwports*/, &mac, NULL/*encap*/);
  cp_release(cp);
  if( rc == 0 )
    memcpy(out_mac, mac, sizeof(mac));
  return rc;
}

void
oof_cb_defer_work(void* owner_private)
{
  struct oo_filter_ns* fns = owner_private;
  /* Take a reference to [fns] for the workitem if it wasn't already enqueued.
   * We can't call oo_filter_ns_put() here, because our caller might already
   * hold [ofnm_lock], so we can't do _get(); if( ! queue_work() ) _put();,
   * but taking the reference after the fact is not racy, as our caller must
   * itself hold a reference, so [fns] is not going to go away in the meantime.
   */
  if( queue_work(CI_GLOBAL_WORKQUEUE, &fns->ofn_filter_work_item) )
    __oo_filter_ns_get(&efab_tcp_driver, fns);
}

#ifdef EFRM_NET_HAS_USER_NS
struct user_namespace*
oof_cb_user_ns(void* owner_private)
{
  struct oo_filter_ns* fns = owner_private;
  return fns->ofn_netns->user_ns;
}
#endif

int
oof_cb_add_global_tproxy_filter(struct oo_hw_filter_spec* filter, int proto,
                                unsigned hwport_mask,
                                unsigned* installed_hwport_mask,
                                void* owner_priv)
{
  struct oo_filter_ns* fns = owner_priv;
  return oo_filter_ns_add_global_tproxy_filter(fns, filter, proto, hwport_mask,
                                               installed_hwport_mask);
}

int oof_cb_remove_global_tproxy_filter(int proto, unsigned hwport_mask,
                                       unsigned* installed_hwport_mask,
                                       void* owner_priv)
{
  struct oo_filter_ns* fns = owner_priv;
  return oo_filter_ns_remove_global_tproxy_filter(fns, proto, hwport_mask,
                                                  installed_hwport_mask);
}
