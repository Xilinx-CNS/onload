/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

/* All header dependencies are included via this private header to allow the
 * unit test to replace them with stubs (see src/tests/onload/oo_nics/). */
#include "oo_nics_deps.h"

#include "oo_nics.h"


static int /* bool */ oo_nic_is_vf(const struct oo_nic* onic)
{
  return efrm_client_get_nic(onic->efrm_client)->devtype.function ==
         EFHW_FUNCTION_VF;
}


ci_inline int oo_dev_get_by_name(tcp_helper_resource_t* trs, const char* name)
{
  struct net_device *nd;
  int ifindex;
#ifdef EFRM_DEV_GET_BY_NAME_TAKES_NS
  nd = dev_get_by_name(trs->netif.cplane->cp_netns, name);
#else
  nd = dev_get_by_name(name);
#endif
  if( nd == NULL )
    return 0;
  ifindex = nd->ifindex;
  dev_put(nd);
  return ifindex;
}

static const char IFACELIST_DELIM[] = " \t\n\v\f\r"; /* inspired by isspace() */
static int oo_get_listed_hwports(tcp_helper_resource_t* trs, const char* list,
                                 cicp_hwport_mask_t* hwports_out, const char* tag)
{
  ci_netif* ni = &trs->netif;
  cicp_hwport_mask_t listed_hwports = 0;
  char *token, *running, *dup;
  int found_iface = 0;

  if( *list == '\0' )
    return 1;
  running = dup = kstrdup(list, GFP_KERNEL);
  if( dup == NULL ) {
    ci_log("%s: WARNING no memory to parse interface %s, assuming empty\n",
           __FUNCTION__, tag);
    return 1;
  }

  while( 1 ) {
    int ifindex;

    token = strsep(&running, IFACELIST_DELIM);
    if( token == NULL )
      break;
    if( *token == '\0' )
      continue;
    found_iface = 1;
    ifindex = oo_dev_get_by_name(trs, token);
    if( ifindex ) {
      cicp_hwport_mask_t hwport_mask = 0;
      int rc;
      rc = oo_cp_find_llap(ni->cplane, ifindex, NULL, NULL,
                           &hwport_mask /* rx_hwports */, NULL, NULL);
      if( rc == 0 && hwport_mask != 0 ) {
        listed_hwports |= hwport_mask;
      }
      else {
        ci_log("%s: WARNING %s contains %s, which is not identified as a "
               "Solarflare interface", __FUNCTION__, tag, token);
      }
    }
    else {
      ci_log("%s: WARNING %s contains %s, which is not known as an interface",
             __FUNCTION__, tag, token);
    }
  }
  *hwports_out = listed_hwports;
  kfree(dup);
  return found_iface ? 0 : 1;
}

/* Find LL hwports of the multiarch NICs within the given hwports mask. */
static cicp_hwport_mask_t oo_get_llct_hwports(cicp_hwport_mask_t hwport_mask)
{
  cicp_hwport_mask_t llct_hwports = 0;

  for( ; hwport_mask != 0; hwport_mask &= (hwport_mask - 1) ) {
    ci_hwport_id_t hwport = cp_hwport_mask_first(hwport_mask);

    if( oo_check_nic_llct(&oo_nics[hwport]) )
      llct_hwports |= cp_hwport_make_mask(hwport);
  }

  return llct_hwports;
}

/* Identify the FF datapath of a multiarch NIC.
 *
 * This is a bit fiddly because the regular/plain SFC NICs look similar to the
 * FF datapaths of the multiarch NICs.  To distinguish, we use the net_device
 * object which is shared between the FF and LL datapaths of the same multiarch
 * NIC.
 */
static bool oo_ff_hwport_match(const struct efhw_nic *nic,
                               const void *opaque_data)
{
  const struct net_device* net_dev = opaque_data;
  return nic->net_dev == net_dev && ! (nic->flags & NIC_FLAG_LLCT);
}

/* Find the genuine multiarch pairs within the given hwport mask.
 *
 * A multiarch pair is an FF hwport and an LLCT hwport that share a net_device
 * and where *both* hwports are present in hwport_mask (i.e. both survived
 * whitelist/blacklist/suitability filtering).  An LLCT hwport whose FF partner
 * is absent (never existed, or was filtered out) is not part of a pair here: it
 * behaves as an LLCT-only interface.  The reverse holds for a lone FF hwport.
 */
static void oo_get_multiarch_pairs(cicp_hwport_mask_t hwport_mask,
                                   cicp_hwport_mask_t llct_hwports,
                                   cicp_hwport_mask_t* paired_ff_out,
                                   cicp_hwport_mask_t* paired_llct_out)
{
  cicp_hwport_mask_t paired_ff = 0;
  cicp_hwport_mask_t paired_llct = 0;

  /* Protect against the oo_nics changes. */
  rtnl_lock();

  /* Iterate over LL hwports and find FF hwports with the same net_device. */
  for( ; llct_hwports != 0; llct_hwports &= (llct_hwports - 1) ) {
    ci_hwport_id_t hwport = cp_hwport_mask_first(llct_hwports);
    struct efhw_nic* nic;
    struct oo_nic* onic;
    cicp_hwport_mask_t ff_mask;

    if( ! oo_nics[hwport].efrm_client )
      continue;

    /* Find the LLCT efhw_nic first. */
    nic = efrm_client_get_nic(oo_nics[hwport].efrm_client);

    /* Then find the matching FF efhw_nic. */
    nic = efhw_nic_find_by_foo(oo_ff_hwport_match, nic->net_dev);
    if( ! nic )
      continue;    /* No FF partner: this is an LLCT-only interface. */

    /* Finally, find the matching oo_nic */
    onic = oo_nic_find(nic);
    if( ! onic ) {
      ci_log("%s: WARNING: Unable to find oo_nic for efhw_nic index=%d",
             __FUNCTION__, nic->index);
      continue;
    }

    /* Only a genuine pair if the FF partner also survived filtering. */
    ff_mask = cp_hwport_make_mask(onic - oo_nics);
    if( ! (ff_mask & hwport_mask) )
      continue;

    paired_ff |= ff_mask;
    paired_llct |= cp_hwport_make_mask(hwport);
  }

  rtnl_unlock();

  *paired_ff_out = paired_ff;
  *paired_llct_out = paired_llct;
}

/* Test whether a single hwport is usable by Onload: it must be registered,
 * pass the module-level acceleration policy (white/blacklist and other
 * suitability checks), and not be a ghost VI on a VF (bug56347 workaround). */
static bool oo_hwport_usable(ci_hwport_id_t hwport)
{
  struct oo_nic* onic = &oo_nics[hwport];

  if( onic->efrm_client == NULL )
    return false;
  /* VIs are created whether the interface is up, down or unplugged.  The latter
   * results in "ghost VIs".  As a temporary workaround for bug56347, we avoid
   * creating ghost VIs on VFs. */
  if( (onic->oo_nic_flags & OO_NIC_UNPLUGGED) && oo_nic_is_vf(onic) )
    return false;
  return oo_check_nic_suitable_for_onload(onic);
}

/* Remove from hwport_mask any hwport that Onload cannot use.  Applying this up
 * front (alongside the interface white/blacklist) means the datapath selection
 * below operates only on hwports that will actually be used. */
static cicp_hwport_mask_t oo_filter_usable_hwports(cicp_hwport_mask_t hwport_mask)
{
  cicp_hwport_mask_t usable = 0;
  cicp_hwport_mask_t m;

  /* Protect against the oo_nics changes. */
  rtnl_lock();

  for( m = hwport_mask; m != 0; m &= (m - 1) ) {
    ci_hwport_id_t hwport = cp_hwport_mask_first(m);
    if( oo_hwport_usable(hwport) )
      usable |= cp_hwport_make_mask(hwport);
  }

  rtnl_unlock();
  return usable;
}

/* User-facing name of a datapath selection, as accepted by
 * EF_TX_DATAPATH/EF_RX_DATAPATH. */
static const char* oo_datapath_name(ci_uint32 datapath)
{
  switch( datapath ) {
  case EF_MULTIARCH_DATAPATH_FF:   return "enterprise";
  case EF_MULTIARCH_DATAPATH_LLCT: return "express";
  case EF_MULTIARCH_DATAPATH_BOTH: return "both";
  case EF_MULTIARCH_DATAPATH_AUTO: return "auto";
  default:                         return "unknown";
  }
}

/* This function is used to retrieve the list of currently active SF
 * interfaces.
 *
 * If ifindices_len > 0, the function is not implemented and returns
 * error.
 *
 * If ifindices_len == 0, then the function performs some
 * initialisation and debug checks.  This is useful for creating
 * stacks without HW (e.g. TCP loopback).
 *
 * If ifindices_len < 0, then the function will autodetect all
 * available SF interfaces based on the cplane information.
 */
int oo_get_nics(tcp_helper_resource_t* trs, int ifindices_len)
{
  ci_netif* ni = &trs->netif;
  struct oo_nic* onic;
  int rc, i, intf_i;
  ci_hwport_id_t hwport;
  cicp_hwport_mask_t hwport_mask, whitelist_mask, llct_hwports;
  cicp_hwport_mask_t multiarch_hwport_mask = 0;
  cicp_hwport_mask_t tx_hwport_mask, rx_hwport_mask;
  bool datapath_unsatisfiable = false;

  efrm_nic_set_clear(&ni->nic_set);
  trs->netif.nic_n = 0;

  if( NI_OPTS(ni).no_hw )
    ifindices_len = 0;

  if( ifindices_len > CI_CFG_MAX_INTERFACES )
    return -E2BIG;

  for( i = 0; i < CI_CFG_MAX_HWPORTS; ++i )
    ni->hwport_to_intf_i[i] = (ci_int8) -1;

  for( i = 0; i < CI_CFG_MAX_INTERFACES; ++i )
    ni->intf_i_to_hwport[i] = (ci_int8) -1;

  hwport_mask = oo_cp_get_hwports(ni->cplane);

  if( oo_get_listed_hwports(trs, NI_OPTS(ni).iface_whitelist,
                            &whitelist_mask, "whitelist") == 0 )
  {
    if( (whitelist_mask & ~hwport_mask) != 0 ) {
      ci_log("%s: WARNING: interface whitelist specifies unlicensed NICs",
             __FUNCTION__);
    }
    /* We only allow whitelist to specify subset of licensed hwports
     * present in current namespace. */
    hwport_mask &= whitelist_mask;
  }

  if( oo_get_listed_hwports(trs, NI_OPTS(ni).iface_blacklist,
                            &whitelist_mask, "blacklist") == 0 )
  {
    if( (whitelist_mask & ~hwport_mask) != 0 ) {
      ci_log("%s: WARNING: interface blacklist specifies unlicensed NICs",
             __FUNCTION__);
    }
    hwport_mask &= ~whitelist_mask;
  }

  /* Drop any hwport that Onload cannot use (module-level black/whitelist and
   * other suitability checks).  Applying this here, alongside the interface
   * white/blacklist above, means the datapath selection below sees only the
   * hwports that will actually be used. */
  hwport_mask = oo_filter_usable_hwports(hwport_mask);

  /* Classify the surviving hwports.  An hwport is either FF or LLCT.  An
   * interface (net_device) is one or two hwports: ff-only, llct-only, or a
   * genuine multiarch pair {FF, LLCT}.  A pair only counts as multiarch if
   * *both* of its hwports survived the filtering above; if only one half
   * survives it behaves as a single-datapath interface. */
  llct_hwports = oo_get_llct_hwports(hwport_mask);
  {
    cicp_hwport_mask_t ff_hwports = hwport_mask & ~llct_hwports;
    cicp_hwport_mask_t paired_ff, paired_llct;
    cicp_hwport_mask_t singleton_ff, singleton_llct;
    bool tx_ok = true, rx_ok = true;

    oo_get_multiarch_pairs(hwport_mask, llct_hwports, &paired_ff, &paired_llct);
    multiarch_hwport_mask = paired_ff | paired_llct;

    /* Single-datapath interfaces: ff-only / llct-only, plus any pair reduced to
     * one surviving hwport.  These cannot serve the other datapath. */
    singleton_ff = ff_hwports & ~paired_ff;
    singleton_llct = llct_hwports & ~paired_llct;

    /* TX selection.  A present interface must be able to serve the requested
     * non-auto datapath, else we fail (tx_ok = false).  Multiarch pairs can
     * serve either; auto prefers LLCT and falls back to FF. */
    switch( NI_OPTS(ni).multiarch_tx_datapath ) {
    case EF_MULTIARCH_DATAPATH_FF:
      tx_hwport_mask = ff_hwports;
      tx_ok = (singleton_llct == 0);
      break;
    case EF_MULTIARCH_DATAPATH_LLCT:
      tx_hwport_mask = llct_hwports;
      tx_ok = (singleton_ff == 0);
      break;
    default: /* auto: prefer LLCT on pairs, singletons use whatever they have */
      tx_hwport_mask = llct_hwports | singleton_ff;
      break;
    }

    /* RX selection, as for TX but with the additional "both" option, which
     * requires an interface to provide both datapaths (i.e. be a pair). */
    switch( NI_OPTS(ni).multiarch_rx_datapath ) {
    case EF_MULTIARCH_DATAPATH_FF:
      rx_hwport_mask = ff_hwports;
      rx_ok = (singleton_llct == 0);
      break;
    case EF_MULTIARCH_DATAPATH_LLCT:
      rx_hwport_mask = llct_hwports;
      rx_ok = (singleton_ff == 0);
      break;
    case EF_MULTIARCH_DATAPATH_BOTH:
      rx_hwport_mask = multiarch_hwport_mask;
      rx_ok = (singleton_ff == 0 && singleton_llct == 0);
      break;
    default: /* auto: pairs use both, singletons use whatever they have */
      rx_hwport_mask = hwport_mask;
      break;
    }

    /* A requested datapath that a present interface cannot serve means we cannot
     * honour the configuration.  An empty selection with no such conflict simply
     * means there are no interfaces, which is reported separately below. */
    if( ! tx_ok || ! rx_ok )
      datapath_unsatisfiable = true;
  }

  /* There are no multiarch hwports if there are no LLCT hwports. */
  ci_assert_impl(!llct_hwports, !multiarch_hwport_mask);

  /* Cannot end up with more hwports than discovered earlier. */
  ci_assert_nflags(tx_hwport_mask, ~hwport_mask);
  ci_assert_nflags(rx_hwport_mask, ~hwport_mask);
  ci_assert_nflags(multiarch_hwport_mask, ~hwport_mask);

  /* The stored masks reflect the selected datapaths regardless of the return
   * code below.  Discovery walks the union of the two directions. */
  ni->tx_hwport_mask = tx_hwport_mask;
  ni->rx_hwport_mask = rx_hwport_mask;
  ni->multiarch_hwport_mask = multiarch_hwport_mask;
  hwport_mask = tx_hwport_mask | rx_hwport_mask;

  if( ifindices_len < 0 ) {
    /* Needed to protect against oo_nics changes */
    rtnl_lock();

    hwport = 0;
    for( intf_i = 0; intf_i < CI_CFG_MAX_INTERFACES; ++intf_i ) {
      for( ; hwport < CI_CFG_MAX_HWPORTS; ++hwport ) {
        if( ~hwport_mask & cp_hwport_make_mask(hwport) )
          continue;
        /* Suitability, the ghost-VI/VF workaround and the module black/white
         * list have already been applied to hwport_mask above, so any selected
         * hwport with a client is usable. */
        onic = &oo_nics[hwport];
        if( onic->efrm_client != NULL )
          break;
      }
      if( hwport >= CI_CFG_MAX_HWPORTS )
        break;
      efrm_nic_set_write(&ni->nic_set, intf_i, CI_TRUE);
      trs->nic[intf_i].thn_intf_i = intf_i;
      trs->nic[intf_i].thn_oo_nic = onic;
      ni->hwport_to_intf_i[onic - oo_nics] = intf_i;
      ni->intf_i_to_hwport[intf_i] = hwport;
      ++trs->netif.nic_n;
      ++hwport;
    }

    rtnl_unlock();
  }
  else if( ifindices_len == 0 ) {
    ci_assert_equal(trs->netif.nic_n, 0);
  }
  else {
    /* This code path is not used yet, but this error message will make it
     * obvious what needs doing if we decide to use it in future...
     */
    ci_log("%s: TODO", __FUNCTION__);
    rc = -EINVAL;
    goto fail;
  }

  if( ifindices_len != 0 ) {
    if( datapath_unsatisfiable ) {
      ci_log("%s: ERROR: The requested TX datapath '%s' and RX datapath '%s' "
             "cannot be provided on all interfaces.  Please check your "
             "configuration.", __FUNCTION__,
             oo_datapath_name(NI_OPTS(ni).multiarch_tx_datapath),
             oo_datapath_name(NI_OPTS(ni).multiarch_rx_datapath));
      return -ENODEV;
    }
    if( trs->netif.nic_n == 0 ) {
      ci_log("%s: ERROR: No Solarflare network interfaces are active/UP,\n"
             "or they are configured with packed stream firmware, disabled,\n"
             "or unlicensed for Onload. Please check your configuration.",
             __FUNCTION__);
      return -ENODEV;
    }
  }
  return 0;

 fail:
  return rc;
}
