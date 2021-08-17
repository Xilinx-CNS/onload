/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2011-2020 Xilinx, Inc. */
#include <ci/efrm/resource.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/efrm_filter.h>
#include <ci/efrm/pd.h>
#include <ci/efrm/vi_resource.h>
#include <ci/efhw/nic.h>
#include <ci/net/ethernet.h>
#include "efch.h"
#include <ci/efch/op_types.h>
#include "filter_list.h"
#include <ci/driver/driverlink_api.h>


struct filter {
  ci_dllink  link;
  uint64_t   efrm_filter_id;
  /* Special value for filter_id that marks this entry as a
   * block-kernel (and nothing else) filter,
   * This is only for legacy CI_RSOP_FILTER_BLOCK_KERNEL op, which does not
   * carry filter_id.
   */
#define FILTER_ID_INDEPENDENT_BLOCK (-1)
#define FILTER_ID_WRAP INT_MAX
  int        filter_id;
#define FILTER_FLAGS_BLOCK_UNICAST       0x1
#define FILTER_FLAGS_BLOCK_MULTICAST     0x2
#define FILTER_FLAGS_BLOCK_MASK \
        (FILTER_FLAGS_BLOCK_UNICAST | FILTER_FLAGS_BLOCK_MULTICAST)
#define FILTER_FLAGS_BLOCK_ALL \
        (FILTER_FLAGS_BLOCK_UNICAST | FILTER_FLAGS_BLOCK_MULTICAST)
#define FILTER_FLAGS_USES_EFRM_FILTER    0x4

  unsigned   flags;
  int        rxq;
};


void efch_filter_list_init(struct efch_filter_list *fl)
{
  spin_lock_init(&fl->lock);
  ci_dllist_init(&fl->filters);
  fl->next_id = 1;
  fl->wrapped = 0;
}


static int efch_filter_flags_to_efrm(int flags)
{
  return
    ((flags & FILTER_FLAGS_BLOCK_UNICAST) ? EFRM_FILTER_BLOCK_UNICAST : 0) |
    ((flags & FILTER_FLAGS_BLOCK_MULTICAST) ? EFRM_FILTER_BLOCK_MULTICAST : 0);
}


static void efch_filter_destruct(struct efrm_resource *rs,
                                 struct efrm_pd *pd, struct filter *f)
{
  if( f->flags & FILTER_FLAGS_USES_EFRM_FILTER ) {
    efrm_filter_remove(rs->rs_client, f->efrm_filter_id);
  }
  if( f->flags & FILTER_FLAGS_BLOCK_MASK )
    efrm_filter_block_kernel(rs->rs_client,
                             efch_filter_flags_to_efrm(f->flags), false);
}


static void efch_filter_delete(struct efrm_resource *rs, struct efrm_pd *pd,
                               struct filter *f)
{
  efch_filter_destruct(rs, pd, f);
  ci_free(f);
}


void efch_filter_list_free(struct efrm_resource *rs, struct efrm_pd *pd,
                           struct efch_filter_list *fl)
{
  struct filter *f;

  /* Can't call efrm_filter_remove with spinlock held. */
  ci_assert( ! spin_is_locked(&fl->lock) );

  while (ci_dllist_not_empty(&fl->filters)) {
    f = container_of(ci_dllist_head(&fl->filters), struct filter, link);
    ci_dllist_remove(&f->link);
    efch_filter_delete(rs, pd, f);
  }
}


static int efch_filter_list_add_block(struct efrm_resource *rs,
                                      struct efrm_pd *pd,
                                      struct efch_filter_list *fl)
{
  struct filter* f;
  int rc;
  if( (f = ci_alloc(sizeof(*f))) == NULL )
    return -ENOMEM;

  rc = efrm_filter_block_kernel(rs->rs_client, EFRM_FILTER_BLOCK_ALL, true);
  if( rc < 0 ) {
    efch_filter_delete(rs, pd, f);
    return rc;
  }
  f->flags = EFRM_FILTER_BLOCK_ALL;
  f->filter_id = FILTER_ID_INDEPENDENT_BLOCK;

  spin_lock(&fl->lock);
  ci_dllist_put(&fl->filters, &f->link);
  spin_unlock(&fl->lock);

  return 0;
}


static int is_op_block_kernel_only(int op)
{
  return op == CI_RSOP_FILTER_ADD_BLOCK_KERNEL ||
         op == CI_RSOP_FILTER_ADD_BLOCK_KERNEL_UNICAST ||
         op == CI_RSOP_FILTER_ADD_BLOCK_KERNEL_MULTICAST;
}


int efch_filter_list_gen_id(struct efch_filter_list *fl)
{
  int filter_id;
  int initial_id;
  if( fl->next_id == FILTER_ID_WRAP ) {
    fl->next_id = 1;
    fl->wrapped = 1;
  }
  initial_id = filter_id = fl->next_id++;
  while( fl->wrapped ) {
    /* filter_id have once wrapped, 
     * and now every new id needs to be checked against collision */
    int is_id_free = 1;
    struct filter* f;
    CI_DLLIST_FOR_EACH2(struct filter, f, link, &fl->filters)
      if( filter_id == f->filter_id ) {
        is_id_free = 0;
        break;
      }
    if( is_id_free )
      break;
    if( fl->next_id == FILTER_ID_WRAP )
      fl->next_id = 1;
    filter_id = fl->next_id++;
    if( filter_id == initial_id )
      return -ENOENT;
  }
  return filter_id;
}


static int efch_filter_insert(struct efrm_resource *rs, struct efrm_pd *pd,
                              struct efx_filter_spec *spec, struct filter *f,
                              bool replace)
{
  int rxq = -1;
  int rc = efrm_filter_insert(rs->rs_client, spec, &rxq, NULL,
                              replace ? EFHW_FILTER_F_REPLACE : 0);
  if( rc < 0 )
    return rc;

  f->efrm_filter_id = rc;
  f->flags |= FILTER_FLAGS_USES_EFRM_FILTER;
  f->rxq = rxq;

  return rc;
}


static int efch_filter_list_rsops_add(struct efrm_resource *rs,
                                      struct efrm_pd *pd,
                                      struct efch_filter_list *fl,
                                      struct efx_filter_spec *spec,
                                      ci_resource_op_t* op, bool replace)
{
  struct filter* f;
  int rc;
  int block_flags = 0;

  if( (f = ci_alloc(sizeof(*f))) == NULL )
    return -ENOMEM;

  f->flags = 0;
  f->rxq = -1;

  if( op->op == CI_RSOP_FILTER_ADD_BLOCK_KERNEL )
    block_flags = FILTER_FLAGS_BLOCK_ALL;
  else if( op->op == CI_RSOP_FILTER_ADD_ALL_UNICAST ||
           op->op == CI_RSOP_FILTER_ADD_BLOCK_KERNEL_UNICAST )
    block_flags = FILTER_FLAGS_BLOCK_UNICAST;
  else if( op->op == CI_RSOP_FILTER_ADD_ALL_MULTICAST ||
           op->op == CI_RSOP_FILTER_ADD_BLOCK_KERNEL_MULTICAST )
    block_flags = FILTER_FLAGS_BLOCK_MULTICAST;

  if( block_flags ) {
    rc = efrm_filter_block_kernel(rs->rs_client,
                                  efch_filter_flags_to_efrm(block_flags),
                                  true);
    /* EOPNOTSUPP is OK because that means we're on a driver version
     * that doesn't need block feature to get correct unicast-all
     * multicast-all semantics */
    if( rc >= 0 )
        f->flags |= block_flags;
    else if( rc != -EOPNOTSUPP ) {
      efch_filter_delete(rs, pd, f);
      return rc;
    }
  }

  if( ! is_op_block_kernel_only(op->op) ) {
    rc = efch_filter_insert(rs, pd, spec, f, replace);
    if( rc < 0 ) {
      efch_filter_delete(rs, pd, f);
      return rc;
    }
  }

  spin_lock(&fl->lock);
  rc = efch_filter_list_gen_id(fl);
  if( rc >= 0 ) {
    f->filter_id = rc;
    ci_dllist_put(&fl->filters, &f->link);
  }
  spin_unlock(&fl->lock);

  if( rc < 0 ) {
    efch_filter_delete(rs, pd, f);
    return rc;
  }

  op->u.filter_add.u.out.filter_id = f->filter_id;
  op->u.filter_add.u.out.rxq = f->rxq;
  return 0;
}


int efch_filter_list_set_ip4(struct efx_filter_spec* spec,
                             ci_resource_op_t* op, int* replace_out)
{
  int rc;
  *replace_out = false;

  if( op->u.filter_add.ip4.rhost_be32 )
    rc = efx_filter_set_ipv4_full(spec, op->u.filter_add.ip4.protocol,
                                  op->u.filter_add.ip4.host_be32,
                                  op->u.filter_add.ip4.port_be16,
                                  op->u.filter_add.ip4.rhost_be32,
                                  op->u.filter_add.ip4.rport_be16);
  else
    rc = efx_filter_set_ipv4_local(spec, op->u.filter_add.ip4.protocol,
                                   op->u.filter_add.ip4.host_be32,
                                   op->u.filter_add.ip4.port_be16);
  return rc;
}


int efch_filter_list_set_ip4_vlan(struct efx_filter_spec* spec,
				  ci_resource_op_t* op, int* replace_out)
{
  int rc = efch_filter_list_set_ip4(spec, op, replace_out);
  if( rc < 0 )
    return rc;

  return efx_filter_set_eth_local(spec, op->u.filter_add.mac.vlan_id, NULL);
}


int efch_filter_list_set_ip6(struct efx_filter_spec* spec,
                             ci_filter_add_t* filter, int* replace_out)
{
  int rc;
  *replace_out = false;

  if( filter->in.spec.l4.ports.source )
    rc = efx_filter_set_ipv6_full(spec, filter->in.spec.l3.protocol,
                                  filter->in.spec.l3.u.ipv6.daddr,
                                  filter->in.spec.l4.ports.dest,
                                  filter->in.spec.l3.u.ipv6.saddr,
                                  filter->in.spec.l4.ports.source);
  else
    rc = efx_filter_set_ipv6_local(spec, filter->in.spec.l3.protocol,
                                   filter->in.spec.l3.u.ipv6.daddr,
                                   filter->in.spec.l4.ports.dest);
  return rc;
}


int efch_filter_list_set_ip6_vlan(struct efx_filter_spec* spec,
                                  ci_filter_add_t* filter, int* replace_out)
{
  int rc = efch_filter_list_set_ip6(spec, filter, replace_out);
  if( rc < 0 )
    return rc;

  return efx_filter_set_eth_local(spec, filter->in.spec.l2.vid, NULL);
}


int efch_filter_list_set_mac(struct efx_filter_spec* spec,
                             ci_resource_op_t* op, int *replace_out)
{
  int vlan = op->u.filter_add.mac.vlan_id;
  *replace_out = false;

  if( vlan < 0 )
    vlan = EFX_FILTER_VID_UNSPEC;
  return efx_filter_set_eth_local(spec, vlan, op->u.filter_add.mac.mac);
}


int efch_filter_list_set_ip_proto(struct efx_filter_spec* spec,
                                  ci_resource_op_t* op, int *replace_out)
{
  *replace_out = false;
  if( ! capable(CAP_NET_ADMIN) )
    return -EPERM;
  /* The net driver doesn't have an explicit API for setting IP-proto filter-
   * state, so we have to do it by hand. */
  spec->match_flags |= EFX_FILTER_MATCH_ETHER_TYPE |
                       EFX_FILTER_MATCH_IP_PROTO;
  spec->ether_type = CI_ETHERTYPE_IP;
  spec->ip_proto = op->u.filter_add.ip4.protocol;
  return 0;
}


int efch_filter_list_set_ether_type(struct efx_filter_spec* spec,
                                    ci_resource_op_t* op, int *replace_out)
{
  *replace_out = false;
  if( ! capable(CAP_NET_ADMIN) )
    return -EPERM;
  /* The net driver doesn't have an explicit API for setting ethertype filter-
   * state, so we have to do it by hand. */
  spec->match_flags |= EFX_FILTER_MATCH_ETHER_TYPE;
  spec->ether_type = op->u.filter_add.u.in.ether_type_be16;
  return 0;
}


/* Marks [spec] as having a type abstracted by [set_fn] by calling the latter
 * on the former.  Also sets a VLAN on the filter if [vlan_opt] is
 * non-negative. [set_fn] may be NULL in the case that only this VLAN-setting
 * behaviour is required. */
int efch_filter_list_set_misc(struct efx_filter_spec* spec,
                              ci_resource_op_t* op,
                              int (*set_fn)(struct efx_filter_spec*),
                              int vlan_opt, int *replace_out)
{
  int rc = 0;

  *replace_out = false;
  if( ! capable(CAP_NET_ADMIN) )
    return -EPERM;
  if( set_fn != NULL && (rc = set_fn(spec)) < 0 )
    return rc;
  if( vlan_opt >= 0 )
    rc = efx_filter_set_eth_local(spec, vlan_opt, NULL);
  return rc;
}


int efch_filter_list_del(struct efrm_resource *rs, struct efrm_pd *pd,
                         struct efch_filter_list *fl,
                         int filter_id)
{
  struct filter* f;
  int rc = -EINVAL;

  /* Need spinlock to manipulate filter list */
  spin_lock(&fl->lock);
  CI_DLLIST_FOR_EACH2(struct filter, f, link, &fl->filters)
    if( f->filter_id == filter_id ) {
      ci_dllist_remove(&f->link);
      rc = 0;
      break;
    }
  spin_unlock(&fl->lock);

  /* Now spinlock is released can call potentially blocking filter remove */
  if( rc == 0 )
    efch_filter_delete(rs, pd, f);

  return rc;
}


int efch_filter_list_op_add(struct efrm_resource *rs, struct efrm_pd *pd,
                            struct efch_filter_list *fl, ci_resource_op_t *op,
                            int *copy_out, unsigned efx_filter_flags,
                            int rss_context)
{
  int rc;
  int replace;
  struct efx_filter_spec spec;
  int need_spec = ! is_op_block_kernel_only(op->op);
  unsigned stack_id;

  if( op->u.filter_add.u.in.flags & CI_RSOP_FILTER_ADD_FLAG_MCAST_LOOP_RECEIVE )
    efx_filter_flags |= EFX_FILTER_FLAG_TX;

  if( need_spec ) {
    efx_filter_init_rx(&spec, EFX_FILTER_PRI_REQUIRED,
                       EFX_FILTER_FLAG_RX_SCATTER | efx_filter_flags,
                       rs->rs_instance);

    if( efx_filter_flags & EFX_FILTER_FLAG_RX_RSS )
      spec.rss_context = rss_context;
  }

  *copy_out = 1;

  if( efrm_pd_has_vport(pd) )
    efx_filter_set_vport_id(&spec, efrm_pd_get_vport_id(pd));

  stack_id = efrm_pd_stack_id_get(pd);
  ci_assert( stack_id >= 0 );
  efx_filter_set_stack_id(&spec, stack_id);

  switch(op->op) {
  case CI_RSOP_FILTER_ADD_IP4:
    rc = efch_filter_list_set_ip4(&spec, op, &replace);
    break;
  case CI_RSOP_FILTER_ADD_IP4_VLAN:
    rc = efch_filter_list_set_ip4_vlan(&spec, op, &replace);
    break;
  case CI_RSOP_FILTER_ADD_MAC:
    rc = efch_filter_list_set_mac(&spec, op, &replace);
    break;
  case CI_RSOP_FILTER_ADD_MAC_IP_PROTO:
    rc = efch_filter_list_set_mac(&spec, op, &replace);
    if( rc >= 0 )
      rc = efch_filter_list_set_ip_proto(&spec, op, &replace);
    break;
  case CI_RSOP_FILTER_ADD_MAC_ETHER_TYPE:
    rc = efch_filter_list_set_mac(&spec, op, &replace);
    if( rc >= 0 )
      rc = efch_filter_list_set_ether_type(&spec, op, &replace);
    break;
  case CI_RSOP_FILTER_ADD_IP_PROTO_VLAN:
    rc = efch_filter_list_set_ip_proto(&spec, op, &replace);
    if( rc >= 0 )
      rc = efch_filter_list_set_misc(&spec, op, NULL,
                                     op->u.filter_add.mac.vlan_id, &replace);
    break;
  case CI_RSOP_FILTER_ADD_ETHER_TYPE_VLAN:
    rc = efch_filter_list_set_ether_type(&spec, op, &replace);
    if( rc >= 0 )
      rc = efch_filter_list_set_misc(&spec, op, NULL,
                                     op->u.filter_add.mac.vlan_id, &replace);
    break;
  case CI_RSOP_FILTER_ADD_IP_PROTO:
    rc = efch_filter_list_set_ip_proto(&spec, op, &replace);
    break;
  case CI_RSOP_FILTER_ADD_ETHER_TYPE:
    rc = efch_filter_list_set_ether_type(&spec, op, &replace);
    break;
  case CI_RSOP_FILTER_ADD_ALL_UNICAST:
    rc = efch_filter_list_set_misc(&spec, op, efx_filter_set_uc_def, -1,
                                   &replace);
    break;
  case CI_RSOP_FILTER_ADD_ALL_MULTICAST:
    rc = efch_filter_list_set_misc(&spec, op, efx_filter_set_mc_def, -1,
                                   &replace);
    break;
  case CI_RSOP_FILTER_ADD_MISMATCH_UNICAST:
    rc = efch_filter_list_set_misc(&spec, op, efx_filter_set_uc_def, -1,
                                   &replace);
    break;
  case CI_RSOP_FILTER_ADD_MISMATCH_UNICAST_VLAN:
    rc = efch_filter_list_set_misc(&spec, op, efx_filter_set_uc_def,
                                   op->u.filter_add.mac.vlan_id, &replace);
    break;
  case CI_RSOP_FILTER_ADD_MISMATCH_MULTICAST:
    rc = efch_filter_list_set_misc(&spec, op, efx_filter_set_mc_def, -1,
                                   &replace);
    break;
  case CI_RSOP_FILTER_ADD_MISMATCH_MULTICAST_VLAN:
    rc = efch_filter_list_set_misc(&spec, op, efx_filter_set_mc_def,
                                   op->u.filter_add.mac.vlan_id, &replace);
    break;
  case CI_RSOP_FILTER_ADD_BLOCK_KERNEL:
  case CI_RSOP_FILTER_ADD_BLOCK_KERNEL_UNICAST:
  case CI_RSOP_FILTER_ADD_BLOCK_KERNEL_MULTICAST:
    if( ! capable(CAP_NET_ADMIN) )
      rc = -EPERM;
    else
      rc = 0;
    break;
  default:
    rc = -EOPNOTSUPP;
    break;
  }

  if( rc >= 0 )
    rc = efch_filter_list_rsops_add(rs, pd, fl, &spec, op, replace);

  return rc;
}

int efch_filter_list_op_del(struct efrm_resource *rs, struct efrm_pd *pd,
                            struct efch_filter_list *fl, ci_resource_op_t *op)
{
  return efch_filter_list_del(rs, pd, fl, op->u.filter_del.filter_id);
}


int efch_filter_list_op_block(struct efrm_resource *rs, struct efrm_pd *pd,
                              struct efch_filter_list *fl,
                              ci_resource_op_t *op)
{
  if( ! capable(CAP_NET_ADMIN) )
    return -EPERM;
  if( op->u.block_kernel.block)
    return efch_filter_list_add_block(rs, pd, fl);
  else
    return efch_filter_list_del(rs, pd, fl, FILTER_ID_INDEPENDENT_BLOCK);
}

int efch_filter_list_add(struct efrm_resource *rs, struct efrm_pd *pd,
                         struct efch_filter_list *fl,
                         ci_filter_add_t *filter_add, int *copy_out)
{
  struct efx_filter_spec spec;
  struct filter *f;
  int replace;
  int rc;
  unsigned stack_id;

  efx_filter_init_rx(&spec, EFX_FILTER_PRI_REQUIRED, EFX_FILTER_FLAG_RX_SCATTER,
                     rs->rs_instance);

  *copy_out = 1;

  stack_id = efrm_pd_stack_id_get(pd);
  ci_assert( stack_id >= 0 );
  efx_filter_set_stack_id(&spec, stack_id);

  if( filter_add->in.spec.l2.vid != 0xffff )
    rc = efch_filter_list_set_ip6_vlan(&spec, filter_add, &replace);
  else
    rc = efch_filter_list_set_ip6(&spec, filter_add, &replace);
  if( rc < 0 )
    return rc;

  if( (f = ci_alloc(sizeof(*f))) == NULL )
    return -ENOMEM;

  f->flags = 0;
  f->rxq = -1;

  rc = efch_filter_insert(rs, pd, &spec, f, replace);
  if( rc < 0 ) {
    efch_filter_delete(rs, pd, f);
    return rc;
  }

  spin_lock(&fl->lock);
  rc = efch_filter_list_gen_id(fl);
  if( rc >= 0 ) {
    f->filter_id = rc;
    ci_dllist_put(&fl->filters, &f->link);
  }
  spin_unlock(&fl->lock);

  if( rc < 0 ) {
    efch_filter_delete(rs, pd, f);
    return rc;
  }

  filter_add->out.out_len = sizeof(filter_add->out);
  filter_add->out.filter_id = f->filter_id;
  filter_add->out.rxq = f->rxq;
  return 0;
}
