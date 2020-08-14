/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2018 Xilinx, Inc. */

##include "onload_kernel_compat.h"

#include <stdlib.h>
#include <ci/tools.h>
#include <ci/net/ipv4.h>
#include <onload/oof_interface.h>
#include <onload/oof_hw_filter.h>
#include <onload/oof_socket.h>

#include "oof_test.h"
#include "stack.h"
#include "cplane.h"
#include "utils.h"
#include "tcp_filters_internal.h"
#include "../../tap/tap.h"


struct tcp_helper_resource_s* oof_cb_socket_stack(struct oof_socket* skf)
{
  struct ooft_endpoint* ep = CI_CONTAINER(struct ooft_endpoint, skf, skf);
  return ep->thr;
}

struct tcp_helper_cluster_s* oof_cb_stack_thc(struct tcp_helper_resource_s*
                                              skf_stack)
{
  return skf_stack->thc;
}

void oof_cb_thc_ref(struct tcp_helper_cluster_s* thc)
{
  /* TODO should really be atomic if we want to do multi-threaded cluster
   * testing.
   */
  thc->thc_refs++;
}

const char* oof_cb_thc_name(struct tcp_helper_cluster_s* thc)
{
  return thc->thc_name;
}

int oof_cb_socket_id(struct oof_socket* skf)
{
  return ooft_endpoint_id(CI_CONTAINER(struct ooft_endpoint, skf, skf));
}

int oof_cb_stack_id(struct tcp_helper_resource_s* thr)
{
  return thr->stack_id;
}

void oof_cb_callback_set_filter(struct oof_socket* skf)
{
}


int
oof_cb_sw_filter_insert(struct oof_socket* s, int af,
                        const ci_addr_t laddr, int lport,
                        const ci_addr_t raddr, int rport,
                        int protocol, int stack_locked)
{
  struct ooft_endpoint* ep = CI_CONTAINER(struct ooft_endpoint, skf, s);
  struct ooft_sw_filter* filter;
  ci_dllink* link;
  int rc = 0;

  CI_DLLIST_FOR_EACH(link, &ep->sw_filters_to_add) {
    filter = CI_CONTAINER(struct ooft_sw_filter, socket_link, link);
    if( ooft_sw_filter_match(filter, laddr.ip4, lport,
                             raddr.ip4, rport, protocol) ) {
      ci_dllist_remove_safe(link);
      ci_dllist_push_tail(&ep->sw_filters_added, &filter->socket_link);
      break;
    }
  }

  if( !link ) {
    filter = ooft_endpoint_add_sw_filter(&ep->sw_filters_bad_add, protocol,
                                         laddr.ip4, lport,
                                         raddr.ip4, rport);
    rc = -EINVAL;
  }

  LOG_FILTER_OP(ooft_log_sw_filter_op(ep, filter, 0, "INSERT"));
  return rc;
}

void
oof_cb_sw_filter_remove(struct oof_socket* s, int af,
                        const ci_addr_t laddr, int lport,
                        const ci_addr_t raddr, int rport,
                        int protocol, int stack_locked)
{
  struct ooft_endpoint* ep = CI_CONTAINER(struct ooft_endpoint, skf, s);
  struct ooft_sw_filter* filter;
  ci_dllink* link;

  CI_DLLIST_FOR_EACH(link, &ep->sw_filters_to_remove) {
    filter = CI_CONTAINER(struct ooft_sw_filter, socket_link, link);
    if( ooft_sw_filter_match(filter, laddr.ip4, lport,
                             raddr.ip4, rport, protocol) ) {
      ci_dllist_remove_safe(link);
      ci_dllist_push_tail(&ep->sw_filters_removed, &filter->socket_link);
      break;
    }
  }

  if( !link ) {
    filter = ooft_endpoint_add_sw_filter(&ep->sw_filters_bad_remove, protocol,
                                         laddr.ip4, lport,
                                         raddr.ip4, rport);
  }

  LOG_FILTER_OP(ooft_log_sw_filter_op(ep, filter, 0, "REMOVE"));
}

void oof_dl_filter_set(struct oo_hw_filter* filter, int stack_id, int protocol,
                       ci_addr_t saddr, int sport, ci_addr_t daddr, int dport)
{
}

void oof_dl_filter_del(struct oo_hw_filter* filter)
{
}

int oof_cb_get_hwport_mask(int ifindex, cicp_hwport_mask_t *hwport_mask,
                           void* priv)
{
  struct ooft_ifindex* idx = ooft_idx_from_id(ifindex);
  TEST(idx);
  *hwport_mask = idx->hwport_mask;
  return 0;
}

int oof_cb_get_vlan_id(int ifindex, unsigned short *vlan_id, void* priv)
{
  struct ooft_ifindex* idx = ooft_idx_from_id(ifindex);
  TEST(idx);
  *vlan_id = idx->vlan_id;
  return 0;
}

int oof_cb_get_mac(int ifindex, unsigned char mac[6], void* priv)
{
  struct ooft_ifindex* idx = ooft_idx_from_id(ifindex);
  TEST(idx);
  memcpy(mac, idx->mac, 6);
  return 0;
}

void oof_cb_defer_work(void* owner_private)
{
}

struct user_namespace*
oof_cb_user_ns(void* owner_private)
{
  return NULL;
}

int
oof_cb_add_global_tproxy_filter(struct oo_hw_filter_spec* filter, int proto,
                                unsigned hwport_mask,
                                unsigned* installed_hwport_mask,
                                void* owner_priv)
{
  /* Not yet implemented */
  assert(0);
  return -EINVAL;
}

int
oof_cb_remove_global_tproxy_filter(int proto, unsigned hwport_mask,
                                   unsigned* installed_hwport_mask,
                                   void* owner_priv)
{
  /* Not yet implemented */
  assert(0);
  return -EINVAL;
}

