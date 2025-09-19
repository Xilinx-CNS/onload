/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file driverlink_ip.c  Inter-driver communications for the IP driver
** <L5_PRIVATE L5_SOURCE>
** \author  gnb
**  \brief  Package - driver/efab	EtherFabric NIC driver
**   \date  2005/10/26
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*/

#include <linux/netfilter.h>
#include <linux/netfilter_arp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_arp.h>

#include <ci/internal/ip.h>
#include <onload/driverlink_filter.h>
#include <onload/linux_onload_internal.h>
#include <onload/tcp_helper_fns.h>
#include <onload/nic.h>
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/nic_notifier.h>
#include "onload_internal.h"
#include "onload_kernel_compat.h"
#include <ci/driver/efab/hardware.h>


static int oo_bond_poll_peak = (HZ/100);
module_param(oo_bond_poll_peak, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(oo_bond_poll_peak,
                 "Period (in jiffies) between peak-rate polls of /sys "
                 "for bonding state synchronisation");

static int oo_bond_peak_polls = 20;
module_param(oo_bond_peak_polls, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(oo_bond_peak_polls,
                 "Number of times to poll /sys at \"peak-rate\" before "
                 "reverting to base rate");


#if CI_CFG_TEAMING
# ifdef IFF_BONDING
#  define NETDEV_IS_BOND_MASTER(_dev)                                   \
  ((_dev->flags & (IFF_MASTER)) && (_dev->priv_flags & IFF_BONDING))
#  define NETDEV_IS_BOND(_dev)                                          \
  ((_dev->flags & (IFF_MASTER | IFF_SLAVE)) && (_dev->priv_flags & IFF_BONDING))
# else
#  define NETDEV_IS_BOND_MASTER(_dev) (_dev->flags & (IFF_MASTER))
#  define NETDEV_IS_BOND(_dev) (_dev->flags & (IFF_MASTER | IFF_SLAVE))
# endif
#else
# define NETDEV_IS_BOND_MASTER(_dev) 0
# define NETDEV_IS_BOND(_dev) 0
#endif


#if CI_CFG_HANDLE_ICMP
/* Check whether device may match software filters for Onload.
 *
 * In the ideal world, we'd like to have a fast check if the device is onloadable.
 * In the reality, there is no fast check for a teaming device, and teaming
 * device may be Onloadable.  So, we just check a device type.
 */
static inline int oo_nf_dev_match(const struct net_device *net_dev)
{
  return net_dev->type == ARPHRD_ETHER;
}

/* Find packet payload (whatever comes after the Ethernet header) */
static int oo_nf_skb_get_payload(struct sk_buff* skb, void** pdata, int* plen)
{
  if( skb_is_nonlinear(skb) ) {
    /* Look in the first page fragment */
    unsigned head_len = skb_headlen(skb);
    skb_frag_t* frag = &skb_shinfo(skb)->frags[0];

    if( skb_shinfo(skb)->frag_list || skb_frag_off(frag) < head_len )
      return 0;
    *pdata = skb_frag_address(frag) - head_len;
    *plen = skb_frag_size(frag) + head_len;
    return 1;
  } else {
    *pdata = skb->data;
    *plen = skb->len;
    return 1;
  }
}

#if defined (RHEL_MAJOR) && defined (RHEL_MINOR)
#if RHEL_MAJOR == 7 && RHEL_MINOR >= 2
/* RHEL 7.2 kernel is crazy and can't be parsed by kernel_compat.sh correctly */
#define EFRM_HAVE_NETFILTER_INDEV_OUTDEV yes
#endif
#endif


#if defined(FUTURE_LINUX_RELEASE)
        /* put future variants here */
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
        /* Linux >= 4.4 : nf_hook_ops were replaced by void;
         * it is too hard to detect this from kernel_compat.sh */
# define NFHOOK_PARAMS \
    void *priv,         \
    struct sk_buff* skb,\
    const struct nf_hook_state *state
# define nfhook_skb skb
# define nfhook_indev state->in
#elif  defined(EFRM_HAVE_NETFILTER_HOOK_STATE) && \
      !defined(EFRM_HAVE_NETFILTER_INDEV_OUTDEV)
        /* linux < 4.4 */
# define NFHOOK_PARAMS \
    const struct nf_hook_ops* ops,  \
    struct sk_buff* skb,            \
    const struct nf_hook_state *state
# define nfhook_skb skb
# define nfhook_indev state->in
#elif defined(EFRM_HAVE_NETFILTER_HOOK_STATE) && \
      defined(EFRM_HAVE_NETFILTER_INDEV_OUTDEV)
        /* RHEL7 3.10 */
# define NFHOOK_PARAMS \
    const struct nf_hook_ops* ops,  \
    struct sk_buff* skb,            \
    const struct net_device* indev, \
    const struct net_device* outdev,\
    const struct nf_hook_state *state
# define nfhook_skb skb
# define nfhook_indev indev
#elif !defined(EFRM_HAVE_NETFILTER_HOOK_STATE) && \
       defined(EFRM_HAVE_NETFILTER_HOOK_OPS)
        /* linux < 4.1 */
# define NFHOOK_PARAMS \
    const struct nf_hook_ops* ops,  \
    struct sk_buff* skb,            \
    const struct net_device* indev, \
    const struct net_device* outdev,\
    int (*okfn)(struct sk_buff*)
# define nfhook_skb skb
# define nfhook_indev indev
#elif !defined(EFRM_HAVE_NETFILTER_HOOK_STATE) && \
      !defined(EFRM_HAVE_NETFILTER_HOOK_OPS) && \
      !defined(EFRM_HAVE_NETFILTER_INDIRECT_SKB)
        /* linux < 3.13 */
# define NFHOOK_PARAMS \
    unsigned int hooknum,           \
    struct sk_buff* skb,            \
    const struct net_device* indev, \
    const struct net_device* outdev,\
    int (*okfn)(struct sk_buff*)
# define nfhook_skb skb
# define nfhook_indev indev
#else
# error "Unsupported kernel version"
#endif



static unsigned int oo_netfilter_ip(NFHOOK_PARAMS)
{
  void* data;
  int len;

  if( oo_nf_dev_match(nfhook_indev) &&
      oo_nf_skb_get_payload(nfhook_skb, &data, &len) &&
      efx_dlfilter_handler(dev_net(nfhook_indev), nfhook_indev->ifindex,
                           efab_tcp_driver.dlfilter,
                           (const ci_ether_hdr*) skb_mac_header(nfhook_skb),
                           data, len) ) {
    kfree_skb(nfhook_skb);
    return NF_STOLEN;
  } else {
    return NF_ACCEPT;
  }
}

static struct nf_hook_ops oo_netfilter_ip_hook = {
  .hook = oo_netfilter_ip,
#ifdef EFRM_HAVE_NETFILTER_OPS_HAVE_OWNER
  .owner = THIS_MODULE,
#endif
#ifdef EFRM_HAVE_NFPROTO_CONSTANTS
  .pf = NFPROTO_IPV4,
#else
  .pf = PF_INET,
#endif
#ifdef NF_IP_PRE_ROUTING
  .hooknum = NF_IP_PRE_ROUTING,
#else
  .hooknum = NF_INET_PRE_ROUTING,
#endif
  .priority = NF_IP_PRI_FIRST,
};

#if CI_CFG_IPV6
static struct nf_hook_ops oo_netfilter_ip6_hook = {
  .hook = oo_netfilter_ip,
#ifdef EFRM_HAVE_NETFILTER_OPS_HAVE_OWNER
  .owner = THIS_MODULE,
#endif
#ifdef EFRM_HAVE_NFPROTO_CONSTANTS
  .pf = NFPROTO_IPV6,
#else
  .pf = PF_INET6,
#endif
#ifdef NF_IP_PRE_ROUTING
  .hooknum = NF_IP_PRE_ROUTING,
#else
  .hooknum = NF_INET_PRE_ROUTING,
#endif
  .priority = NF_IP_PRI_FIRST,
};
#endif
#endif


static void oo_hwport_up(struct oo_nic* onic, int up)
{
  struct efhw_nic* efhw_nic = efrm_client_get_nic(onic->efrm_client);
  unsigned flags = 0;

  if( efhw_nic->flags & NIC_FLAG_HW_MULTICAST_REPLICATION )
    flags |= OOF_HWPORT_FLAG_MCAST_REPLICATE;
  if( (efhw_nic->filter_flags & NIC_FILTER_FLAG_IPX_VLAN_HW) ||
      (efhw_nic->filter_flags & NIC_FILTER_FLAG_IPX_VLAN_SW) )
    flags |= OOF_HWPORT_FLAG_VLAN_FILTERS;
  if( !(efhw_nic->filter_flags & NIC_FILTER_FLAG_RX_TYPE_IP_FULL) &&
      !(efhw_nic->filter_flags & NIC_FILTER_FLAG_IP_FULL_SW) )
    flags |= OOF_HWPORT_FLAG_NO_5TUPLE;
  if( efhw_nic->flags & NIC_FLAG_RX_SHARED )
    flags |= OOF_HWPORT_FLAG_RX_SHARED;

  oof_onload_hwport_up_down(&efab_tcp_driver, oo_nic_hwport(onic), up,
                            flags, 0);
  if( up )
    onic->oo_nic_flags |= OO_NIC_UP;
  else
    onic->oo_nic_flags &= ~OO_NIC_UP;
}


/* This function is called when an interface comes up and handles doing any
 * necessary notifications to the interested parts of onload.
 *
 * It can be called before the NIC has been probed, in which case we will not
 * have an existing oo_nic and so will do nothing. On NIC probe oo_nic_add
 * is responsible for checking if the interface is already up, and triggering
 * a net dev up notification once it's added the NIC if so.
 *
 * Once a device is noticed by onload, it should stay registered in cplane
 * despite going up or being hotplugged.
 */
void oo_nic_notify_up(struct oo_nic *onic, const struct net_device *net_dev)
{
  oo_hwport_up(onic, net_dev->flags & IFF_UP);

  /* Remove OO_NIC_UNPLUGGED regardless of whether the interface is IFF_UP,
   * as we don't want to attempt to create ghost VIs now that the hardware is
   * back.
   */
  if( onic->oo_nic_flags & OO_NIC_UNPLUGGED ) {
    ci_log("%s: Rediscovered %s ifindex %d hwport %d", __func__,
           net_dev->name, net_dev->ifindex, (int)(onic - oo_nics));
    cp_announce_hwport(efrm_client_get_nic(onic->efrm_client), onic - oo_nics);
    onic->oo_nic_flags &= ~OO_NIC_UNPLUGGED;
  }
}

static int oo_nic_probe(const struct efhw_nic* nic,
                        const struct net_device *net_dev)
{
  struct oo_nic* onic = oo_nic_find(nic);

  if( onic != NULL ) {
    if( ! netif_running(net_dev) ) {
      /* We are dealing here with hotplug so we already have relevant NIC
       * structure in place. We just need to block kernel traffic using drop
       * filters to prevent it hitting kernel and causing connection resets.
       * The filters will be redirected towards our RXQ when the interface
       * comes up.  The branch above that deals with the case where the device
       * is up will also insert appropriate filters, although this will be
       * deferred to the workqueue.  TODO: If we add support for hotplug on
       * generic Linux systems, we should also consider the case where [onic]
       * is NULL. */
      OO_DEBUG_VERB(ci_log("%s: Trigger drop filters on if %d", __func__,
                           net_dev->ifindex));

      /* Notify Onload that previous device on that hwport disappeared. */
      oof_onload_hwport_removed(&efab_tcp_driver, oo_nic_hwport(onic));
    }
  }
  else {
    onic = oo_nic_add(nic);
    if( onic == NULL )
      return -1;
  }

  /* If a NIC is already up when it's probed we need to notify now. */
  if( netif_running(net_dev) )
    oo_nic_notify_up(onic, net_dev);

  return 0;
}

void oo_nic_remove(const struct efhw_nic* nic)
{
  /* We need to fini all of the hardware queues immediately. The net driver
   * will tidy up its own queues and *all* VIs, so if we don't free our own
   * queues they will be left dangling and will not be cleared even on an
   * entity reset.
   *   A note on locking: iterate_netifs_unlocked() will give us netif pointers
   * that are guaranteed to remain valid, but the state of the underlying
   * netifs may be unstable. However, we only touch immutable state. We can't
   * defer the work to the lock holders as we need to speak to the hardware
   * right now, before it goes away.
   */
#if CI_CFG_NIC_RESET_SUPPORT
  ci_netif* ni = NULL;
#endif
  struct oo_nic* onic;
  if( (onic = oo_nic_find(nic)) != NULL ) {
    /* Filter status need to be synced as after this function is finished
     * no further operations will be allowed.
     * Also note on polite hotplug oo_nic_remove() is called before
     * oo_netdev_going_down(), which will not have a chance to do its job
     * regarding filters.
     */
    oof_onload_hwport_up_down(&efab_tcp_driver, oo_nic_hwport(onic), 0, 0, 1);

#if CI_CFG_NIC_RESET_SUPPORT
    /* We need to prevent simultaneous resets so that the queues that are to be
     * shut down don't get brought back up again.  We do this by disabling any
     * further scheduling of resets, and then flushing any already scheduled on
     * each stack. */
    efrm_client_disable_post_reset(onic->efrm_client);

    onic->oo_nic_flags |= OO_NIC_UNPLUGGED;
    while( iterate_netifs_unlocked(&ni, OO_THR_REF_BASE,
                                     OO_THR_REF_INFTY) == 0 )
      tcp_helper_flush_resets(ni);
#endif

    /* The actual business of flushing the queues will be handled by the
     * resource driver in its own driverlink removal hook in a moment. */
  }
}


static void oo_fixup_wakeup_breakage(struct oo_nic *onic)
{
  /* This is needed after a hardware interface is brought up, and after an
   * MTU change.  When a netdev goes down, or the MTU is changed, the net
   * driver event queues are destroyed and brought back.  This can cause
   * wakeup events to get lost.
   *
   * NB. This should cease to be necessary once the net driver is changed
   * to keep event queues up when the interface goes down.
   */
  ci_netif* ni = NULL;
  int hwport, intf_i;
  hwport = onic - oo_nics;
  while( iterate_netifs_unlocked(&ni, OO_THR_REF_BASE,
                                 OO_THR_REF_INFTY) == 0 )
    if( (intf_i = ni->hwport_to_intf_i[hwport]) >= 0 )
      ci_bit_clear(&ni->state->evq_primed, intf_i);
}


void oo_netdev_up(const struct net_device* netdev)
{
  struct oo_nic* onic = oo_nic_find_by_net_dev(netdev, 0, NIC_FLAG_LLCT);
  if( onic ) {
    oo_nic_notify_up(onic, netdev);
    oo_fixup_wakeup_breakage(onic);
  }

  /* Check if there's an additional datapath, and update that too if so */
  onic = oo_nic_find_by_net_dev(netdev, NIC_FLAG_LLCT, 0);
  if( onic )
    oo_nic_notify_up(onic, netdev);
}


static void oo_netdev_going_down(struct net_device* netdev)
{
  struct oo_nic* onic = oo_nic_find_by_net_dev(netdev, 0, NIC_FLAG_LLCT);
  if( onic != NULL )
      oo_hwport_up(onic, 0);

  /* Check if there's an additional datapath, and update that too if so */
  onic = oo_nic_find_by_net_dev(netdev, NIC_FLAG_LLCT, 0);
  if( onic != NULL )
      oo_hwport_up(onic, 0);
}


/* Context: rtnl lock held */
static int oo_netdev_event(struct notifier_block *this,
                           unsigned long event, void *ptr)
{
  struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
  struct oo_nic *onic;

  switch( event ) {
  case NETDEV_UP:
    oo_netdev_up(netdev);
    break;

  case NETDEV_GOING_DOWN:
    oo_netdev_going_down(netdev);
    break;

  case NETDEV_CHANGEMTU:
    /* For NICs where we rely on the net driver EVQs for wakeups we need to
     * update our prime state now. */
    if( (onic = oo_nic_find_by_net_dev(netdev, 0, NIC_FLAG_EVQ_IRQ)) != NULL )
      oo_fixup_wakeup_breakage(onic);

#ifdef EFRM_RTMSG_IFINFO_EXPORTED
    /* The control plane has to know about the new MTU value.
     * rtnetlink_event() converts most of NETDEV_* events into RTM_NEWLINK
     * messages, but it ignores NETDEV_CHANGEMTU.
     *
     * For older kernels rtmsg_ifinfo() is not available, so we rely on
     * periodic dump of the OS state in the onload_cp_server.  In many
     * cases (such as MTU change for an SFC NIC) the RTM_NEWLINK message
     * is delivered because of interface flags change; the only known issue
     * is with the bond interface.  See bug 74973 for details.
     */
    rtmsg_ifinfo(RTM_NEWLINK, netdev, 0
#ifdef EFRM_RTMSG_IFINFO_NEEDS_GFP_FLAGS
                 /* linux >= 3.13 require gfp_t argument */
                 , GFP_KERNEL
#endif
                 );
#else
    /* rtmsg_ifinfo() is exported in linux >= 3.9 and in the last
     * RHEL6 updates.  In 4.15 it is no longer exported, but
     * rtnetlink_event() doesn't ignore NETDEV_CHANGEMTU, so we don't
     * need to do anything.
     */
#endif
    break;

  default:
    break;
  }

  return NOTIFY_DONE;
}


static struct notifier_block oo_netdev_notifier = {
  .notifier_call = oo_netdev_event,
};


static struct efrm_nic_notifier oo_nic_notifier = {
  .probe = oo_nic_probe,
  .remove = oo_nic_remove,
};


int oo_hooks_register(void)
{
  int rc;

  rc = register_netdevice_notifier(&oo_netdev_notifier);
  if (rc != 0)
    goto fail1;

  efrm_register_nic_notifier(&oo_nic_notifier);

#if CI_CFG_HANDLE_ICMP && ! defined(EFRM_HAVE_NF_NET_HOOK)
  if( (rc = nf_register_hook(&oo_netfilter_ip_hook)) < 0 )
    goto fail4;
#if CI_CFG_IPV6
  if( (rc = nf_register_hook(&oo_netfilter_ip6_hook)) < 0 )
    goto fail5;
#endif
#endif

  return 0;

#if CI_CFG_HANDLE_ICMP && ! defined(EFRM_HAVE_NF_NET_HOOK)
#if CI_CFG_IPV6
  fail5:
   nf_unregister_hook(&oo_netfilter_ip_hook);
#endif
  fail4:
   efrm_unregister_nic_notifier(&oo_nic_notifier);
#endif
  unregister_netdevice_notifier(&oo_netdev_notifier);
 fail1:
  ci_log("%s: efx_dl_register_driver failed (%d)", __FUNCTION__, rc);
  return rc;
}


void oo_hooks_unregister(void)
{
#if CI_CFG_HANDLE_ICMP && ! defined(EFRM_HAVE_NF_NET_HOOK)
  nf_unregister_hook(&oo_netfilter_ip_hook);
#if CI_CFG_IPV6
  nf_unregister_hook(&oo_netfilter_ip6_hook);
#endif
#endif
  unregister_netdevice_notifier(&oo_netdev_notifier);
  efrm_unregister_nic_notifier(&oo_nic_notifier);
}

#ifdef EFRM_HAVE_NF_NET_HOOK
int oo_register_nfhook(struct net *net)
{
  int rc = 0;
#if CI_CFG_HANDLE_ICMP
  if( (rc = nf_register_net_hook(net, &oo_netfilter_ip_hook)) != 0 )
    return rc;
#if CI_CFG_IPV6
  if( (rc = nf_register_net_hook(net, &oo_netfilter_ip6_hook)) != 0 )
    nf_unregister_net_hook(net, &oo_netfilter_ip_hook);
#endif
#endif
  return rc;
}
void oo_unregister_nfhook(struct net *net)
{
#if CI_CFG_HANDLE_ICMP
  nf_unregister_net_hook(net, &oo_netfilter_ip_hook);
#if CI_CFG_IPV6
  nf_unregister_net_hook(net, &oo_netfilter_ip6_hook);
#endif
#endif
}
#endif

/*! \cidoxg_end */
