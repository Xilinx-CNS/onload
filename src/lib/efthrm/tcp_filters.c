/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2020 Xilinx, Inc. */
/*
** Copyright 2005-2012  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This program is free software; you can redistribute it and/or modify it
** under the terms of version 2 of the GNU General Public License as
** published by the Free Software Foundation.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author Martin Porter
**  \brief Filter handling code for TCP stack
**   \date Sept 2004
**    \cop (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include "tcp_filters_internal.h"

/* All header dependencies are included via this private header to allow us
 * to allow us to easily replace them with something useable in the user
 * level unit tests.
 */
#include "tcp_filters_deps.h"

#define KERNEL_REDIRECT_VI_ID 0

/*
 * Module option to control whether getting an error (EBUSY) on some
 * ports when adding a filter is fatal or not.
 *
 * We need this to support the case where we have >1 PF on a physical
 * port
 */
int oof_all_ports_required = 1;


static struct efrm_client* get_client(int hwport)
{
  ci_assert((unsigned) hwport < CI_CFG_MAX_HWPORTS);
  return oo_nics[hwport].efrm_client;
}


void oo_hw_filter_init2(struct oo_hw_filter* oofilter,
                        struct tcp_helper_resource_s* trs,
                        struct tcp_helper_cluster_s* thc)
{
  int i;
#if CI_CFG_HANDLE_ICMP
  oofilter->dlfilter_handle = EFX_DLFILTER_HANDLE_BAD;
#endif
  oofilter->trs = trs;
  oofilter->thc = thc;
  for( i = 0; i < CI_CFG_MAX_HWPORTS; ++i )
    oofilter->filter_id[i] = -1;
}


void oo_hw_filter_init(struct oo_hw_filter* oofilter)
{
  oo_hw_filter_init2(oofilter, NULL, NULL);
}


static void oo_hw_filter_clear_hwport(struct oo_hw_filter* oofilter,
                                      int hwport)
{
  ci_assert((unsigned) hwport < CI_CFG_MAX_HWPORTS);
  if( oofilter->filter_id[hwport] >= 0 ) {
    efrm_filter_remove(get_client(hwport), oofilter->filter_id[hwport]);
    oofilter->filter_id[hwport] = -1;
  }
}


void oo_hw_filter_clear(struct oo_hw_filter* oofilter)
{
  int hwport;

  if( oofilter->trs != NULL || oofilter->thc != NULL ) {
    for( hwport = 0; hwport < CI_CFG_MAX_HWPORTS; ++hwport )
      oo_hw_filter_clear_hwport(oofilter, hwport);
    oofilter->trs = NULL;
    oofilter->thc = NULL;
  }
  else {
    for( hwport = 0; hwport < CI_CFG_MAX_HWPORTS; ++hwport )
      ci_assert(oofilter->filter_id[hwport] < 0);
  }
}


void oo_hw_filter_clear_hwports(struct oo_hw_filter* oofilter,
                                unsigned hwport_mask, int kernel_redirect)
{
  int hwport;

  if( kernel_redirect || oofilter->trs != NULL || oofilter->thc != NULL )
    for( hwport = 0; hwport < CI_CFG_MAX_HWPORTS; ++hwport )
      if( hwport_mask & (1 << hwport) )
        oo_hw_filter_clear_hwport(oofilter, hwport);
}


static int
oo_hw_filter_set_hwport(struct oo_hw_filter* oofilter, int hwport,
                        const struct oo_hw_filter_spec* oo_filter_spec,
                        unsigned src_flags)
{
  struct efx_filter_spec spec;
  int rc = 0;
  int rxq = -1;
  int vi_id = -1;
  const u8* mac_ptr = NULL;
  int replace = false;
  int kernel_redirect = src_flags & OO_HW_SRC_FLAG_KERNEL_REDIRECT;
  int redirect = src_flags & OO_HW_SRC_FLAG_REDIRECT;
  int cluster = (oofilter->thc != NULL) && ! kernel_redirect;
  int drop = (src_flags & OO_HW_SRC_FLAG_DROP) &&
             ! cluster; /* drop not supported for RSS - use proper filter */
  unsigned insert_flags = 0;
  unsigned exclusive_rxq_token = EFHW_PD_NON_EXC_TOKEN;

  if( ! kernel_redirect )
    ci_assert_nequal(oofilter->trs == NULL, oofilter->thc == NULL);
  ci_assert_equal(!!redirect, oofilter->filter_id[hwport] >= 0);

  if( kernel_redirect )
    vi_id = KERNEL_REDIRECT_VI_ID;
  else if( cluster )
    vi_id = tcp_helper_cluster_vi_base(oofilter->thc, hwport);
  else
    tcp_helper_get_filter_params(oofilter->trs, hwport, &vi_id, &rxq,
                                 &insert_flags, &exclusive_rxq_token);

  if( vi_id  >= 0 ) {
    int flags = EFX_FILTER_FLAG_RX_SCATTER;
    /* FIXME: enable loopback when installing drop filter */
    int hw_rx_loopback_supported = (cluster || kernel_redirect || drop) ?
      0 : tcp_helper_vi_hw_rx_loopback_supported(oofilter->trs, hwport);

    if( drop && tcp_helper_vi_hw_drop_filter_supported(oofilter->trs, hwport) )
      vi_id = EFX_FILTER_RX_DMAQ_ID_DROP;

    ci_assert( hw_rx_loopback_supported >= 0 );
    if( hw_rx_loopback_supported && (src_flags & OO_HW_SRC_FLAG_LOOPBACK) ) {
      flags |= EFX_FILTER_FLAG_TX;
    }

    if( cluster && ! drop && oofilter->thc->thc_cluster_size > 1 )
      flags |= EFX_FILTER_FLAG_RX_RSS;

    efx_filter_init_rx(&spec, EFX_FILTER_PRI_REQUIRED, flags, vi_id);

    if( flags & EFX_FILTER_FLAG_RX_RSS ) {
      int rss_context = -1;
      if( src_flags & OO_HW_SRC_FLAG_RSS_DST )
        rss_context = efrm_vi_set_get_rss_context
            (oofilter->thc->thc_vi_set[hwport], EFRM_RSS_MODE_ID_DST);
      if( rss_context == -1 )
        /* fallback to default RSS context */
        rss_context = efrm_vi_set_get_rss_context
            (oofilter->thc->thc_vi_set[hwport], EFRM_RSS_MODE_ID_DEFAULT);
      if( rss_context == -1 )
        rss_context = EFX_FILTER_RSS_CONTEXT_DEFAULT;
      spec.rss_context = rss_context;
    }

    if( ! kernel_redirect ) {
      unsigned stack_id = cluster ?
        tcp_helper_cluster_vi_hw_stack_id(oofilter->thc, hwport) :
        tcp_helper_vi_hw_stack_id(oofilter->trs, hwport);
      ci_assert( stack_id >= 0 );
      efx_filter_set_stack_id(&spec, stack_id);
    }

    switch( oo_filter_spec->type ) {
    case OO_HW_FILTER_TYPE_MAC:
      mac_ptr = oo_filter_spec->addr.mac.mac;
      replace = true;
      break;

    case OO_HW_FILTER_TYPE_ETHERTYPE:
      /* Ethertype filter is not MAC-qualified. There are no primitives in the
       * net driver, so we need to set filter flags manually. */
      spec.ether_type = oo_filter_spec->addr.ethertype.t;
      mac_ptr = oo_filter_spec->addr.ethertype.mac;
      spec.match_flags |= EFX_FILTER_MATCH_ETHER_TYPE;
      replace = true;
      break;

    case OO_HW_FILTER_TYPE_IP_PROTO_MAC:
      mac_ptr = oo_filter_spec->addr.ipproto.mac;
      ci_fallthrough;
    case OO_HW_FILTER_TYPE_IP_PROTO:
      /* As in the case of the ethertype filter above, we have to populate
       * [spec] ourselves. */
      spec.ip_proto = oo_filter_spec->addr.ipproto.p;
      spec.ether_type = oo_filter_spec->addr.ipproto.ethertype;
      spec.match_flags |= EFX_FILTER_MATCH_ETHER_TYPE |
                          EFX_FILTER_MATCH_IP_PROTO;
      replace = true;
      break;

    case OO_HW_FILTER_TYPE_IP:
#if CI_CFG_IPV6
      if( IS_AF_INET6(oo_filter_spec->addr.ip.af) ) {
        struct in6_addr saddr;
        struct in6_addr daddr;

        memcpy(&saddr, oo_filter_spec->addr.ip.saddr, sizeof(saddr));
        memcpy(&daddr, oo_filter_spec->addr.ip.daddr, sizeof(daddr));

        if( oo_filter_spec->addr.ip.sport != 0 )
          rc = efx_filter_set_ipv6_full(&spec,
                                        oo_filter_spec->addr.ip.protocol,
                                        daddr,
                                        oo_filter_spec->addr.ip.dport,
                                        saddr,
                                        oo_filter_spec->addr.ip.sport);
        else
          rc = efx_filter_set_ipv6_local(&spec,
                                         oo_filter_spec->addr.ip.protocol,
                                         &daddr,
                                         oo_filter_spec->addr.ip.dport);
      }
      else
#endif
      {
        if( oo_filter_spec->addr.ip.sport != 0 )
          rc = efx_filter_set_ipv4_full(&spec,
                                        oo_filter_spec->addr.ip.protocol,
                                        oo_filter_spec->addr.ip.daddr[0],
                                        oo_filter_spec->addr.ip.dport,
                                        oo_filter_spec->addr.ip.saddr[0],
                                        oo_filter_spec->addr.ip.sport);
        else
          rc = efx_filter_set_ipv4_local(&spec,
                                         oo_filter_spec->addr.ip.protocol,
                                         oo_filter_spec->addr.ip.daddr[0],
                                         oo_filter_spec->addr.ip.dport);
      }
      ci_assert_equal(rc, 0);
      break;

    default:
      /* Invalid filter type. */
      ci_assert(0);
      return -EINVAL;
    }

    /* note: bug 42561 affecting loopback on VLAN 0 with fw <= v4_0_6_6688 */
    if( oo_filter_spec->vlan_id != OO_HW_VLAN_UNSPEC || mac_ptr != NULL ) {
      u16 efx_vlan_id = (oo_filter_spec->vlan_id == OO_HW_VLAN_UNSPEC) ?
                        EFX_FILTER_VID_UNSPEC : (u16) oo_filter_spec->vlan_id;
      rc = efx_filter_set_eth_local(&spec, efx_vlan_id, mac_ptr);
      ci_assert_equal(rc, 0);
    }
    if( redirect ) {
      ci_assert_ge(oofilter->filter_id[hwport], 0);
      rc = efrm_filter_redirect(get_client(hwport), oofilter->filter_id[hwport], &spec);
      if( rc == -ENOENT || rc == -ENODEV ) {
        /* net driver either:
         *  * does not know about our filter, let's better
         *    remove reference to it and try to add new instance
         *  * does not support move the move operation - we cannot leak the filter
         */
        oofilter->filter_id[hwport] = rc;
      }
      else {
        /* Moving filter either:
         *  * succeeded, or
         *  * failed
         *  Regardless keep existing filter anyway and pretend all went fine */
        return 0;
      }
    }
    if( replace )
      insert_flags |= EFHW_FILTER_F_REPLACE;
    rc = efrm_filter_insert(get_client(hwport), &spec, &rxq,
                            exclusive_rxq_token,
                            cluster || kernel_redirect ? NULL :
                                              &oofilter->trs->filter_irqmask,
                            insert_flags);
    /* ENETDOWN indicates that the hardware has gone away. This is not a
     * failure condition at this layer as we can attempt to restore filters
     * when the hardware comes back. A negative filter ID signifies that there
     * is no filter from the net driver's point of view, so we are justified in
     * storing [rc] in the [filter_id] array. */
    if( rc >= 0 || rc == -ENETDOWN ) {
      oofilter->filter_id[hwport] = rc;
      rc = 0;
    }
    if( rc == 0 && oofilter->filter_id[hwport] >= 0 ) {
      /* post_filter_add only has an effect for NICs which share queues between
       * stacks, therefore is fundamentally at odds with RSS. This could (like
       * everything) change in the future, but it's difficult to predict in
       * what way. */
      if( ! kernel_redirect ) {
#if ! CI_CFG_ENDPOINT_MOVE
        ci_assert_equal(cluster, 0);
#else
        if( cluster )
          rc = tcp_helper_cluster_post_filter_add(oofilter->thc, hwport, &spec,
                                                  rxq, replace);
        else
#endif
          rc = tcp_helper_post_filter_add(oofilter->trs, hwport, &spec, rxq,
                                          replace);
        if( rc < 0 ) {
          if( ! replace )
            efrm_filter_remove(get_client(hwport), oofilter->filter_id[hwport]);
          /* We ideally want to restore replaced filters too, but we're not
           * keeping enough info to know how. In any case, we currently have no
           * hardware on which this matters (no hardware uses both a non-trivial
           * tcp_helper_post_filter_add() and the replace option), so it'd be
           * untested code. If/when that hardware comes, there are many possible
           * locations for the solution. */
        }
      }
    }
  }
  else {
    /* Return a recognisable error code to indicate that we didn't try and
     * install a filter here. */
    return -ELNRNG;
  }
  return rc;
}


static int oo_hw_filter_update_error(int rc_old, int rc_new)
{
  /* Preserve the most severe error seen - other errors are more severe
   * then firewall denial, and it is more severe than no error. -ELNRG
   * is not an error - it just indicates this hwport is not in use for
   * the stack this filter directs to. */

  /* Normalise -ELNRNG to 0, as it's not an error */
  if( rc_old == -ELNRNG )
    rc_old = 0;
  if( rc_new == -ELNRNG )
    rc_new = 0;

  /* New succeeded, so old is still good */
  if( rc_new == 0 )
    return rc_old;

  /* Old succeeded, new failed, so keep new rc */
  if( rc_old == 0 )
    return rc_new;

  /* Old failed with a boring error, and new failed, so must be at least
   * as severe as boring, so go with the new error. */
  if( (rc_old == -EACCES) || (rc_old == -EBUSY && !oof_all_ports_required) )
    return rc_new;

  /* Both failed with an interesting error, so just keep the old one */
  return rc_old;
}


static int
__oo_hw_filter_add_hwports(struct oo_hw_filter* oofilter,
                           const struct oo_hw_filter_spec* oo_filter_spec,
                           unsigned set_vlan_mask, unsigned hwport_mask,
                           unsigned redirect_mask,
                           unsigned drop_hwport_mask, unsigned src_flags,
                           bool *ok_seen, unsigned *failed_ports)
{
  int rc1, rc = 0, hwport;

  /* We will change this copy of the filter spec according to [set_vlan_mask]
   * as we iterate over the hwports. */
  struct oo_hw_filter_spec masked_spec = *oo_filter_spec;

  for( hwport = 0; hwport < CI_CFG_MAX_HWPORTS; ++hwport )
    if( ((hwport_mask & (1u << hwport)) && oofilter->filter_id[hwport] < 0) ||
        (redirect_mask & (1u << hwport)) ) {
      /* If we've been told to set the vlan when installing the filter on this
       * port then use provided vlan_id, otherwise use OO_HW_VLAN_UNSPEC.
       */
      masked_spec.vlan_id = (set_vlan_mask & (1u << hwport)) ?
        oo_filter_spec->vlan_id : OO_HW_VLAN_UNSPEC;
      rc1 = oo_hw_filter_set_hwport(oofilter, hwport, &masked_spec,
            src_flags |
            ((drop_hwport_mask & (1u << hwport)) ? OO_HW_SRC_FLAG_DROP : 0) |
            ((redirect_mask & (1u << hwport)) ? OO_HW_SRC_FLAG_REDIRECT : 0));
      /* Track any failing interfaces */
      if( rc1 ) {
        /* Track any ports where we couldn't install a filter. We can try
         * again for any of them that have a fallback option. */
        *failed_ports |= (1u << hwport);

        /* Preserve the most severe error seen */
        rc = oo_hw_filter_update_error(rc, rc1);
      }
      else {
        *ok_seen = true;
      }
    }

  return rc;
}

static unsigned oo_hw_filter_primary_ports(unsigned hwport_mask)
{
  int hwport;
  unsigned primary_mask = hwport_mask;

  for( hwport = 0; hwport < CI_CFG_MAX_HWPORTS; ++hwport ) {
    struct oo_nic *nic = &oo_nics[hwport];
    if( (hwport_mask & (1u << hwport)) &&
        (nic->oo_nic_flags & OO_NIC_FALLBACK) &&
        (nic->alternate_hwport >= 0) &&
        (hwport_mask & (1u << nic->alternate_hwport)) )
      primary_mask &= ~(1u << hwport);
  }

  return primary_mask;
}

static unsigned oo_hw_filter_fallback_ports(unsigned hwport_mask,
                                            unsigned *no_fallback_mask)
{
  int hwport;
  int alternate;
  unsigned fallback_mask = 0;
  *no_fallback_mask = 0;

  while(hwport_mask) {
    hwport = ffs(hwport_mask) - 1;
    alternate = oo_nics[hwport].alternate_hwport;
    if( alternate >= 0 && !(oo_nics[hwport].oo_nic_flags & OO_NIC_FALLBACK) )
      fallback_mask |= 1u << alternate;
    else
      *no_fallback_mask |= 1u << hwport;
    hwport_mask &= ~(1u << hwport);
  }

  return fallback_mask;
}

int oo_hw_filter_add_hwports(struct oo_hw_filter* oofilter,
                             const struct oo_hw_filter_spec* oo_filter_spec,
                             unsigned set_vlan_mask, unsigned hwport_mask,
                             unsigned redirect_mask,
                             unsigned drop_hwport_mask,
                             unsigned src_flags)
{
  int rc, rc1 = 0;
  bool ok_seen = false;
  unsigned install_ports = oo_hw_filter_primary_ports(hwport_mask);
  unsigned failed_ports = 0;
  unsigned failed_without_fallback = 0;

  if( (src_flags & OO_HW_SRC_FLAG_KERNEL_REDIRECT) == 0 )
    ci_assert_nequal(oofilter->trs != NULL, oofilter->thc != NULL);

  /* Firstly mask out the fallback interfaces and install what we can */
  rc = __oo_hw_filter_add_hwports(oofilter, oo_filter_spec, set_vlan_mask,
                                  install_ports, redirect_mask,
                                  drop_hwport_mask, src_flags,
                                  &ok_seen, &failed_ports);
  /* For any port that failed see if we have a fallback available. Try again
   * with any fallback ports. */
  if( failed_ports ) {
    install_ports = oo_hw_filter_fallback_ports(failed_ports,
                                                &failed_without_fallback);
    failed_ports = 0;
    if( hwport_mask ) {
      rc1 = __oo_hw_filter_add_hwports(oofilter, oo_filter_spec,
                                       set_vlan_mask, install_ports,
                                       redirect_mask, drop_hwport_mask,
                                       src_flags, &ok_seen, &failed_ports);
      /* If the first attempt resulted in failure for exactly the set of
       * ports that had a fallback available and that we've now successfully
       * installed a filter for, record that as success. */
      if( (failed_without_fallback == 0) && (failed_ports == 0) )
        rc = 0;
      /* Preserve the most severe error seen over the two attempts */
      rc = oo_hw_filter_update_error(rc, rc1);
    }
  }

  if( ok_seen ) {
    if ( ( rc == -EACCES ) ||
         ( !oof_all_ports_required && ( rc == -EBUSY ) ) ) {
      /* If some interfaces, but not ALL interfaces, have blocked the filter
       *  then consider the filter added.
       */
      rc = 0;
    }
    else if( rc ) {
      rc = -EFILTERSSOME;
    }
  }
  return rc;
}


int oo_hw_filter_set(struct oo_hw_filter* oofilter,
                     const struct oo_hw_filter_spec* oo_filter_spec,
                     unsigned set_vlan_mask, unsigned hwport_mask,
                     unsigned drop_hwport_mask,
                     unsigned src_flags)
{
  int rc;

  rc = oo_hw_filter_add_hwports(oofilter, oo_filter_spec, set_vlan_mask,
                                hwport_mask, 0, drop_hwport_mask, src_flags);
  if( rc < 0 )
    oo_hw_filter_clear(oofilter);
  return rc;
}


/* Returns subset of hwports in mask that are hidden by existing filters */
unsigned oo_hw_filter_hidden_ports(const struct oo_hw_filter* filter,
                                   unsigned mask)
{
  int hwport;
  int alternate;
  unsigned hidden = 0;

  for( hwport = 0; hwport < CI_CFG_MAX_HWPORTS; ++hwport ) {
    /* Not using this port */
    if( !(mask & (1ull << hwport)) )
      continue;

    alternate = oo_nics[hwport].alternate_hwport;
    if( (alternate >= 0) && (filter->filter_id[alternate] >= 0) ) {
      /* When clearing out alternate hwports we assume we are protected by
       * the install phase from having filters on both ports, otherwise we
       * would end up clearing both of them from the mask. */
      ci_assert(filter->filter_id[hwport] < 0);
      hidden |= 1ull << hwport;
    }
  }

  return hidden;
}


int oo_hw_filter_update(struct oo_hw_filter* oofilter,
                        struct tcp_helper_resource_s* new_stack,
                        const struct oo_hw_filter_spec* oo_filter_spec,
                        unsigned set_vlan_mask, unsigned hwport_mask,
                        unsigned drop_hwport_mask,
                        unsigned src_flags)
{
  unsigned add_hwports = 0u;
  unsigned redirect_hwports = 0u;
  int hwport, vi_id;
  int kernel_redirect = src_flags & OO_HW_SRC_FLAG_KERNEL_REDIRECT;

  /* TODO: clustering: This needed for handling NIC resets.
   * For clusters we can only add/remove filters from interfaces.
   */
  if( new_stack != NULL && oofilter->thc != NULL ) {
    ci_log("%s: ERROR: Stack moving not supported on clustered filters",
           __FUNCTION__);
    return -EINVAL;
  }

  oo_hw_filter_clear_hwports(oofilter, ~hwport_mask, kernel_redirect);

  for( hwport = 0; hwport < CI_CFG_MAX_HWPORTS; ++hwport )
    if( hwport_mask & (1 << hwport) ) {
      /* has the target stack got hwport */
      if( (drop_hwport_mask & (1 << hwport) || src_flags & OO_HW_SRC_FLAG_DROP) &&
          tcp_helper_vi_hw_drop_filter_supported(oofilter->trs, hwport) )
        vi_id = EFX_FILTER_RX_DMAQ_ID_DROP;
      else if( new_stack != NULL )
        vi_id = tcp_helper_rx_vi_id(new_stack, hwport);
      else if( oofilter->thc != NULL )
        vi_id = tcp_helper_cluster_vi_base(oofilter->thc, hwport);
      else
        vi_id = kernel_redirect ? 0 : -1;

      /* Remove filter due to lack of hardware? */
      if( vi_id < 0 ) {
        /* if the target stack has no vi on this hwport, we will not install
         * the filter even though with KERNEL_REDIRECT it would be possible
         * This means that KERNEL_REDIRECT filter hwports will match
         * MAC_FILTER's hwport allocation.
         *
         * For KERNEL_REDIRECT filters not to owned by a stack,
         * we install filters on all suggested hwports.
         */
        oo_hw_filter_clear_hwport(oofilter, hwport);
        continue;
      }

      /* Mark for installing new filter? */
      if( oofilter->filter_id[hwport] < 0 ) {
        add_hwports |= 1 << hwport;
        continue;
      }

      /* Move filter between stacks */
      /*
       * Only in non-clustered stack case there is work to do.
       */
      if( kernel_redirect ) {
        /* Always need to point to vi_id 0, so nothing to do */
      }
      else {
        /* Move filter between stacks we attempt this even when new_stack
         * == old_stack in case stack_id or rss gets updated */
        redirect_hwports |= 1 << hwport;
      }
    }

  /* Don't try adding filters for ports that already have a filter on an
   * alternate port. */
  add_hwports &= ~oo_hw_filter_hidden_ports(oofilter, add_hwports);

  /* Insert new filters for any other interfaces in hwport_mask. */
  oofilter->trs = new_stack;
  return oo_hw_filter_add_hwports(oofilter, oo_filter_spec, set_vlan_mask,
                                  add_hwports, redirect_hwports,
                                  drop_hwport_mask, src_flags);
}


void oo_hw_filter_transfer(struct oo_hw_filter* oofilter_old,
                           struct oo_hw_filter* oofilter_new,
                           unsigned hwport_mask)
{
  int hwport;

  ci_assert_equal(oofilter_new->thc, NULL);
  ci_assert_equal(oofilter_old->thc, NULL);
  if( oofilter_old->trs == NULL )
    return;

  ci_assert_equal(oofilter_old->trs, oofilter_new->trs);

  for( hwport = 0; hwport < CI_CFG_MAX_HWPORTS; ++hwport )
    if( (hwport_mask & (1u << hwport)) &&
        oofilter_old->filter_id[hwport] >= 0 ) {
      ci_assert(oofilter_new->filter_id[hwport] < 0);
      oofilter_new->filter_id[hwport] = oofilter_old->filter_id[hwport];
      oofilter_old->filter_id[hwport] = -1;
    }
}


unsigned oo_hw_filter_hwports(struct oo_hw_filter* oofilter)
{
  unsigned hwport_mask = 0;
  int hwport;

  if( oofilter->trs != NULL || oofilter->thc != NULL )
    for( hwport = 0; hwport < CI_CFG_MAX_HWPORTS; ++hwport )
      if( oofilter->filter_id[hwport] >= 0 )
        hwport_mask |= 1 << hwport;
  return hwport_mask;
}
