/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2008-2020 Xilinx, Inc. */
/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: djr
**     Started: 2008/09/10
** Description: Onload nic management.
** </L5_PRIVATE>
\**************************************************************************/

#include <ci/internal/ip.h>
#include <onload/nic.h>
#include <ci/efhw/efhw_types.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/licensing.h>
#include <ci/efch/op_types.h>
#include <ci/driver/efab/hardware.h>
#include <onload/tcp_driver.h>
#include <onload/tcp_helper_fns.h>
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>

#include <linux/rtnetlink.h>


/* This array can be modified as a result of: 
 * - interfaces up/down via driverlink (rtnl lock already held)
 * - module parameter changes for black/white list
 *
 * It is used from 
 * - tcp_filters.c but always with fm_outer_lock mutex
 * - stack/cluster creation to find interfaces
 * 
 * NIC removal will not interfer with filter code because filter state
 * is removed (with fm_outer_lock mutex) before oo_nic entry removed.
 */

struct oo_nic oo_nics[CI_CFG_MAX_HWPORTS];

static struct oo_nic* oo_nic_find(struct efhw_nic* nic)
{
  int i, max = sizeof(oo_nics) / sizeof(oo_nics[0]);

  CI_DEBUG(ASSERT_RTNL());
  if( ! nic )
    return NULL;

  for( i = 0; i < max; ++i )
    if( oo_nics[i].efrm_client &&
        efrm_client_get_nic(oo_nics[i].efrm_client) == nic )
      return &oo_nics[i];
  return NULL;
}


#if CI_CFG_NIC_RESET_SUPPORT || (CI_CFG_WANT_BPF_NATIVE && CI_HAVE_BPF_NATIVE)
/* Our responses to the pre- and post-reset notifications from the resource
 * driver have much in common with one another.  This function implements the
 * basic pattern. */
static void
oo_efrm_callback_hook_generic(struct efrm_client* client,
                              void impl_fn(ci_netif*, int intf_i))
{
  struct oo_nic* onic;
  ci_netif* ni;
  int hwport, intf_i;
  ci_irqlock_state_t lock_flags;
  ci_dllink *link;

  if( (onic = oo_nic_find(efrm_client_get_nic(client))) != NULL ) {
    hwport = onic - oo_nics;

    /* First of all, handle non-fully-created stacks.
     * Possibly, we'll process them twice: here and later, when they are
     * created and moved to all_stacks list.
     * There is almost no harm except for bug 33496, which is present
     * regardless of our behaviour here.
     */
    ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
    CI_DLLIST_FOR_EACH(link, &THR_TABLE.started_stacks) {
      tcp_helper_resource_t *thr;
      thr = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);
      ni = &thr->netif;
      if( (intf_i = ni->hwport_to_intf_i[hwport]) >= 0 )
        impl_fn(ni, intf_i);
    }
    ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

    ni = NULL;
    while( iterate_netifs_unlocked(&ni, OO_THR_REF_BASE,
                                   OO_THR_REF_INFTY) == 0 )
      if( (intf_i = ni->hwport_to_intf_i[hwport]) >= 0 )
        impl_fn(ni, intf_i);
  }
}
#endif

static void oo_efrm_reset_callback(struct efrm_client* client, void* arg)
{
  /* Schedule the reset work for the stack. */
#if CI_CFG_NIC_RESET_SUPPORT
  oo_efrm_callback_hook_generic(client, tcp_helper_reset_stack);
#endif

  /* The post-reset hook in the resource driver might have changed the
   * efhw_nic's flags, so in principle we should re-announce this hwport to all
   * control plane instances at this point.  However, we don't expect any flags
   * that the control plane cares about to change across a reset, so this is
   * unimplemented. */
}

static void
oo_efrm_reset_suspend_callback(struct efrm_client* client, void* arg)
{
  /* Label each stack as needing reset, but don't schedule that reset yet. */
#if CI_CFG_NIC_RESET_SUPPORT
  oo_efrm_callback_hook_generic(client, tcp_helper_suspend_interface);
#endif
}

static struct efrm_client_callbacks oo_efrm_client_callbacks = {
  oo_efrm_reset_callback,
  oo_efrm_reset_suspend_callback,
};


struct oo_nic* oo_nic_add(const struct net_device* dev)
{
  struct oo_nic* onic;
  int i, max = sizeof(oo_nics) / sizeof(oo_nics[0]);
  struct efrm_client* efrm_client;
  int rc;

  CI_DEBUG(ASSERT_RTNL());

  rc = efrm_client_get_by_dev(dev, &oo_efrm_client_callbacks, NULL,
                              &efrm_client);
  if( rc != 0 )
    /* Resource driver doesn't know about this ifindex. */
    goto fail1;

  for( i = 0; i < max; ++i )
    if( (onic = &oo_nics[i])->efrm_client == NULL )
      break;
  if( i == max ) {
    ci_log("%s: NOT registering ifindex=%d (too many)", __FUNCTION__,
           dev->ifindex);
    goto fail2;
  }

  onic->efrm_client = efrm_client;
  onic->oo_nic_flags = 0;
  onic->crc_id_pools_mask = 0xffff;

  /* Tell cp_server about this hwport */
  rc = cp_announce_hwport(efrm_client_get_nic(efrm_client), i);
  if( rc < 0 && rc != -ENOENT ) {
    /* -ENOENT means there is no cp_server yet; it is OK */
    ci_log("%s: failed to announce ifindex=%d oo_index=%d to cp_server: %d",
           __func__, dev->ifindex, i, rc);
  }

  ci_log("%s: ifindex=%d oo_index=%d", __FUNCTION__, dev->ifindex, i);

  return onic;

 fail2:
  efrm_client_put(efrm_client);
 fail1:
  return NULL;
}


static void oo_nic_remove(struct oo_nic* onic)
{
  int ifindex = efrm_client_get_ifindex(onic->efrm_client);

  CI_DEBUG(ASSERT_RTNL());

  ci_log("%s: ifindex=%d oo_index=%d",
         __FUNCTION__, ifindex, (int) (onic - oo_nics));
  ci_assert(onic->efrm_client != NULL);
  efrm_client_put(onic->efrm_client);
  onic->efrm_client = NULL;
}


struct oo_nic* oo_nic_find_dev(const struct net_device* dev)
{
  return oo_nic_find(efhw_nic_find(dev));
}

int oo_nic_announce(struct oo_cplane_handle* cp, ci_ifid_t ifindex)
{
  int i;
  int rc = -ENOENT;

  CI_DEBUG(ASSERT_RTNL());

  for( i = 0; i < CI_CFG_MAX_HWPORTS; ++i ) {
    struct net_device* dev;
    struct efhw_nic* nic;

    if( oo_nics[i].efrm_client == NULL )
      continue;
    nic = efrm_client_get_nic(oo_nics[i].efrm_client);
    dev = efhw_nic_get_net_dev(nic);
    if( dev == NULL)
      continue;
    if( dev_net(dev) != cp->cp_netns || 
        (ifindex != CI_IFID_BAD && dev->ifindex != ifindex) ) {
      dev_put(dev);
      continue;
    }

    rc = __cp_announce_hwport(cp, dev->ifindex, i, nic->flags);
    dev_put(dev);
    if( rc < 0 ) {
      ci_log("%s: ERROR: failed to announce hwport=%d", __func__, i);
      return rc;
    }
  }

  /* Tell cplane that it's all */
  if( ifindex == CI_IFID_BAD )
    return __cp_announce_hwport(cp, CI_IFID_BAD, CI_HWPORT_ID_BAD, 0);
  else
    return rc;
}

int oo_nic_hwport(struct oo_nic* onic)
{
  int oo_nic_i = onic - oo_nics;

  CI_DEBUG(ASSERT_RTNL());

  return (oo_nic_i);
}


int oo_check_nic_suitable_for_onload(struct oo_nic* onic)
{
  struct efhw_nic *nic = efrm_client_get_nic(onic->efrm_client);

  if( nic->flags & NIC_FLAG_ONLOAD_UNSUPPORTED )
    return 0;

  if( ! efrm_client_accel_allowed(onic->efrm_client) )
    return 0;

  /* Onload does not currently play well with packed stream firmware */
  return !(nic->flags & NIC_FLAG_PACKED_STREAM);
}


/* Tidies up all oo_nic state. Called at module unload. */
void oo_nic_shutdown(void)
{
  struct oo_nic* onic;

  rtnl_lock();

  for( onic = oo_nics;
       onic - oo_nics < sizeof(oo_nics) / sizeof(oo_nics[0]);
       ++onic ) {
    if( onic->efrm_client != NULL )
      oo_nic_remove(onic);
  }

  rtnl_unlock();
}

