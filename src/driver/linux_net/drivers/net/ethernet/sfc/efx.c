/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2005-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/delay.h>
#include <linux/notifier.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/ethtool.h>
#include <linux/topology.h>
#include <linux/gfp.h>
#ifndef EFX_USE_KCOMPAT
#include <linux/aer.h>
#include <linux/interrupt.h>
#endif
#ifdef EFX_NOT_UPSTREAM
#ifdef EFX_USE_LINUX_UACCESS_H
#include <linux/uaccess.h>
#else
#include <asm/uaccess.h>
#endif
#endif
#if defined(CONFIG_EEH)
#include <asm/pci-bridge.h>
#endif
#include "net_driver.h"
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_PCI_AER)
#include <linux/aer.h>
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_ADD_VXLAN_PORT) || defined(EFX_HAVE_NDO_UDP_TUNNEL_ADD)
#include <net/gre.h>
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_UDP_TUNNEL_ADD)
#include <net/udp_tunnel.h>
#endif
#include "debugfs.h"
#ifdef CONFIG_SFC_DUMP
#include "dump.h"
#endif
#include "efx.h"
#include "efx_common.h"
#include "efx_channels.h"
#include "nic.h"
#include "io.h"
#include "rx_common.h"
#include "tx_common.h"
#include "efx_devlink.h"
#include "efx_virtbus.h"
#include "selftest.h"
#include "sriov.h"
#include "xdp.h"
#ifdef EFX_USE_KCOMPAT
#include "efx_ioctl.h"
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_GCOV)
#include "../linux/gcov.h"
#endif


#include "mcdi.h"
#include "mcdi_filters.h"
#include "mcdi_pcol.h"
#include "workarounds.h"

#ifdef CONFIG_SFC_TRACING
#define CREATE_TRACE_POINTS
#include <trace/events/sfc.h>
#endif

#ifdef EFX_NOT_UPSTREAM
/* Allocate resources for XDP transmit and redirect functionality.
 *
 * This allocates a transmit queue per CPU and enough event queues to cover
 * those - multiple transmit queues will share a single event queue.
 */
static bool xdp_alloc_tx_resources;
module_param(xdp_alloc_tx_resources, bool, 0444);
MODULE_PARM_DESC(xdp_alloc_tx_resources,
		 "[EXPERIMENTAL] Allocate resources for XDP TX");
#endif

/**************************************************************************
 *
 * Type name strings
 *
 **************************************************************************
 */

/* UDP tunnel type names */
static const char *efx_udp_tunnel_type_names[] = {
	[TUNNEL_ENCAP_UDP_PORT_ENTRY_VXLAN] = "vxlan",
	[TUNNEL_ENCAP_UDP_PORT_ENTRY_GENEVE] = "geneve",
};

void efx_get_udp_tunnel_type_name(u16 type, char *buf, size_t buflen)
{
	if (type < ARRAY_SIZE(efx_udp_tunnel_type_names) &&
	    efx_udp_tunnel_type_names[type] != NULL)
		snprintf(buf, buflen, "%s", efx_udp_tunnel_type_names[type]);
	else
		snprintf(buf, buflen, "type %d", type);
}

#if defined(EFX_USE_KCOMPAT) && (!defined(EFX_USE_CANCEL_WORK_SYNC) || !defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC))
struct workqueue_struct *efx_workqueue;
#endif

/**************************************************************************
 *
 * Configurable values
 *
 *************************************************************************/

#if defined(EFX_USE_KCOMPAT) && (defined(EFX_USE_GRO) || defined(EFX_USE_SFC_LRO))
/*
 * Enable large receive offload (LRO) aka soft segment reassembly (SSR)
 *
 * This sets the default for new devices.  It can be controlled later
 * using ethtool.
 */
static bool lro = true;
module_param(lro, bool, 0444);
MODULE_PARM_DESC(lro, "Large receive offload acceleration");
#endif

extern bool separate_tx_channels;
module_param(separate_tx_channels, bool, 0444);
MODULE_PARM_DESC(separate_tx_channels,
		 "Use separate channels for TX and RX");

/* Initial interrupt moderation settings.  They can be modified after
 * module load with ethtool.
 *
 * The default for RX should strike a balance between increasing the
 * round-trip latency and reducing overhead.
 */
static unsigned int rx_irq_mod_usec = 60;

/* Initial interrupt moderation settings.  They can be modified after
 * module load with ethtool.
 *
 * This default is chosen to ensure that a 10G link does not go idle
 * while a TX queue is stopped after it has become full.  A queue is
 * restarted when it drops below half full.  The time this takes (assuming
 * worst case 3 descriptors per packet and 1024 descriptors) is
 *   512 / 3 * 1.2 = 205 usec.
 */
static unsigned int tx_irq_mod_usec = 150;

#if !defined(EFX_USE_KCOMPAT) || (defined(topology_core_cpumask))
#define HAVE_EFX_NUM_PACKAGES
#endif
#if !defined(EFX_USE_KCOMPAT) || (defined(topology_sibling_cpumask) && defined(EFX_HAVE_EXPORTED_CPU_SIBLING_MAP))
#define HAVE_EFX_NUM_CORES
#endif

extern unsigned int interrupt_mode;
module_param(interrupt_mode, uint, 0444);
MODULE_PARM_DESC(interrupt_mode,
		 "Interrupt mode (0=>MSIX 1=>MSI)");

static bool irq_adapt_enable = true;
module_param(irq_adapt_enable, bool, 0444);
MODULE_PARM_DESC(irq_adapt_enable,
                 "Enable adaptive interrupt moderation");

static unsigned int rx_ring = EFX_DEFAULT_RX_DMAQ_SIZE;
module_param(rx_ring, uint, 0644);
MODULE_PARM_DESC(rx_ring,
		 "Maximum number of descriptors in a receive ring");

static unsigned int tx_ring = EFX_DEFAULT_TX_DMAQ_SIZE;
module_param(tx_ring, uint, 0644);
MODULE_PARM_DESC(tx_ring,
		 "Maximum number of descriptors in a transmit ring");

#ifdef EFX_NOT_UPSTREAM
int efx_target_num_vis = -1;
module_param_named(num_vis, efx_target_num_vis, int, 0644);
MODULE_PARM_DESC(num_vis, "Set number of VIs");
#endif

#ifdef EFX_NOT_UPSTREAM
static char *performance_profile;
module_param(performance_profile, charp, 0444);
MODULE_PARM_DESC(performance_profile,
		 "Tune settings for different performance profiles: 'throughput', 'latency' or (default) 'auto'");
#endif

/**************************************************************************
 *
 * Port handling
 *
 **************************************************************************/

static void efx_fini_port(struct efx_nic *efx);

static int efx_init_port(struct efx_nic *efx)
{
	int rc;

	netif_dbg(efx, drv, efx->net_dev, "init port\n");

	mutex_lock(&efx->mac_lock);

	efx->port_initialized = true;

	/* Ensure the PHY advertises the correct flow control settings */
	rc = efx_mcdi_port_reconfigure(efx);
	if (rc && rc != -EPERM)
		goto fail;

	mutex_unlock(&efx->mac_lock);
	return 0;

fail:
	efx->port_initialized = false;
	mutex_unlock(&efx->mac_lock);
	return rc;
}

static void efx_fini_port(struct efx_nic *efx)
{
	netif_dbg(efx, drv, efx->net_dev, "shut down port\n");

	if (!efx->port_initialized)
		return;

	efx->port_initialized = false;

	efx->link_state.up = false;
	efx_link_status_changed(efx);
}

/**************************************************************************
 *
 * Interrupt moderation
 *
 **************************************************************************/
unsigned int efx_usecs_to_ticks(struct efx_nic *efx, unsigned int usecs)
{
	if (usecs == 0)
		return 0;
	if (usecs * 1000 < efx->timer_quantum_ns)
		return 1; /* never round down to 0 */
	return usecs * 1000 / efx->timer_quantum_ns;
}

unsigned int efx_ticks_to_usecs(struct efx_nic *efx, unsigned int ticks)
{
	/* We must round up when converting ticks to microseconds
	 * because we round down when converting the other way.
	 */
	return DIV_ROUND_UP(ticks * efx->timer_quantum_ns, 1000);
}

/* Set interrupt moderation parameters */
int efx_init_irq_moderation(struct efx_nic *efx, unsigned int tx_usecs,
			    unsigned int rx_usecs, bool rx_adaptive,
			    bool rx_may_override_tx)
{
	struct efx_channel *channel;
	unsigned int timer_max_us;

	EFX_ASSERT_RESET_SERIALISED(efx);

	timer_max_us = efx->timer_max_ns / 1000;

	if (tx_usecs > timer_max_us || rx_usecs > timer_max_us)
		return -EINVAL;

	if (tx_usecs != rx_usecs && efx->tx_channel_offset == 0 &&
	    !rx_may_override_tx) {
		netif_err(efx, drv, efx->net_dev, "Channels are shared. "
			  "RX and TX IRQ moderation must be equal\n");
		return -EINVAL;
	}

	efx->irq_rx_adaptive = rx_adaptive;
	efx->irq_rx_moderation_us = rx_usecs;
	efx_for_each_channel(channel, efx) {
		if (efx_channel_has_rx_queue(channel))
			channel->irq_moderation_us = rx_usecs;
		else if (efx_channel_has_tx_queues(channel))
			channel->irq_moderation_us = tx_usecs;
		else if (efx_channel_is_xdp_tx(channel))
			channel->irq_moderation_us = tx_usecs;
	}

	return 0;
}

void efx_get_irq_moderation(struct efx_nic *efx, unsigned int *tx_usecs,
			    unsigned int *rx_usecs, bool *rx_adaptive)
{
	*rx_adaptive = efx->irq_rx_adaptive;
	*rx_usecs = efx->irq_rx_moderation_us;

	/* If channels are shared between RX and TX, so is IRQ
	 * moderation.  Otherwise, IRQ moderation is the same for all
	 * TX channels and is not adaptive.
	 */
	if (efx->tx_channel_offset == 0) {
		*tx_usecs = *rx_usecs;
	} else {
		struct efx_channel *tx_channel;

		tx_channel = efx->channel[efx->tx_channel_offset];
		*tx_usecs = tx_channel->irq_moderation_us;
	}
}

/**************************************************************************
 *
 * ioctls
 *
 *************************************************************************/

/* Net device ioctl
 * Context: process, rtnl_lock() held.
 */
int efx_ioctl(struct net_device *net_dev, struct ifreq *ifr, int cmd)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	struct mii_ioctl_data *data = if_mii(ifr);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NET_TSTAMP)
	if (cmd == SIOCSHWTSTAMP)
		return efx_ptp_set_ts_config(efx, ifr);
	if (cmd == SIOCGHWTSTAMP)
		return efx_ptp_get_ts_config(efx, ifr);
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_PRIVATE_IOCTL)
	if (cmd == SIOCEFX) {
		struct efx_sock_ioctl __user *user_data =
			(struct efx_sock_ioctl __user *)ifr->ifr_data;
		u16 efx_cmd;

		if (copy_from_user(&efx_cmd, &user_data->cmd, sizeof(efx_cmd)))
			return -EFAULT;
		return efx_private_ioctl(efx, efx_cmd, &user_data->u);
	}
#endif

	/* Convert phy_id from older PRTAD/DEVAD format */
	if ((cmd == SIOCGMIIREG || cmd == SIOCSMIIREG) &&
	    (data->phy_id & 0xfc00) == 0x0400)
		data->phy_id ^= MDIO_PHY_ID_C45 | 0x0400;

	return mdio_mii_ioctl(&efx->mdio, data, cmd);
}

/**************************************************************************
 *
 * Kernel net device interface
 *
 *************************************************************************/

/* Context: process, rtnl_lock() held. */
int efx_net_open(struct net_device *net_dev)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	unsigned loops = 2;
	int rc;

	netif_dbg(efx, ifup, efx->net_dev, "opening device on CPU %d\n",
		  raw_smp_processor_id());

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	if (efx->open_count++) {
		netif_dbg(efx, drv, efx->net_dev,
			  "already open, now by %hu clients\n", efx->open_count);
		/* inform the kernel about link state again */
		efx_link_status_changed(efx);
		return 0;
	}
#endif
#endif

	rc = efx_check_disabled(efx);
	if (rc)
		goto fail;
	if (efx->phy_mode & PHY_MODE_SPECIAL) {
		rc = -EBUSY;
		goto fail;
	}
	if (efx_mcdi_poll_reboot(efx) && efx_reset(efx, RESET_TYPE_ALL)) {
		rc = -EIO;
		goto fail;
	}
	efx->reset_count = 0;

	efx->stats_initialised = false;

	do {
		if (!efx->max_channels || !efx->max_tx_channels) {
			netif_err(efx, drv, efx->net_dev,
				  "Insufficient resources to allocate any channels\n");
			rc = -ENOSPC;
			goto fail;
		}

		/* Determine the number of channels and queues by trying to hook
		 * in MSI-X interrupts.
		 */
		rc = efx_probe_interrupts(efx);
		if (rc)
			goto fail;

		rc = efx_set_channels(efx);
		if (rc)
			goto fail;

		/* dimension_resources can fail with EAGAIN */
		rc = efx->type->dimension_resources(efx);
		if (rc != 0 && rc != -EAGAIN)
			goto fail;

		if (rc == -EAGAIN) {
			/* try again with new max_channels */
			efx_unset_channels(efx);
			efx_remove_interrupts(efx);
		}
	} while (rc == -EAGAIN && --loops);
	/* rc should be 0 here or we would have jumped to fail: */
	WARN_ON(rc);

	rc = efx_probe_channels(efx);
	if (rc)
		goto fail;

	rc = efx_init_napi(efx);
	if (rc)
		goto fail;

	rc = efx_init_port(efx);
	if (rc)
		goto fail;

	rc = efx_probe_filters(efx);
	if (rc)
		goto fail;

	rc = efx_nic_init_interrupt(efx);
	if (rc)
		goto fail;
	efx_set_interrupt_affinity(efx, true);
#ifdef EFX_USE_IRQ_NOTIFIERS
	efx_register_irq_notifiers(efx);
#endif

	down_write(&efx->filter_sem);
	rc = efx->type->init(efx);
	up_write(&efx->filter_sem);
	if (rc)
		goto fail;

	rc = efx_enable_interrupts(efx);
	if (rc)
		goto fail;

	/* Notify the kernel of the link state polled during driver load,
	 * before the monitor starts running */
	efx_link_status_changed(efx);

	rc = efx_start_all(efx);
	if (rc)
		goto fail;

	if (efx->state == STATE_DISABLED || efx->reset_pending) {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
		if (efx->type->detach_reps)
			efx->type->detach_reps(efx);
#endif
		netif_device_detach(efx->net_dev);
	} else {
		efx->state = STATE_NET_UP;
	}

	efx_selftest_async_start(efx);

	return 0;

fail:
	efx_net_stop(net_dev);
	return rc;
}

/* Context: process, rtnl_lock() held.
 * Note that the kernel will ignore our return code; this method
 * should really be a void.
 */
int efx_net_stop(struct net_device *net_dev)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	netif_dbg(efx, ifdown, efx->net_dev, "closing on CPU %d\n",
			raw_smp_processor_id());

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	if (efx->open_count && --efx->open_count) {
		netif_dbg(efx, drv, efx->net_dev, "still open by %hu clients\n",
			  efx->open_count);
		return 0;
	}
#endif
#endif

	if (efx->state == STATE_DISABLED)
		return 0;

	netif_stop_queue(efx->net_dev);
	efx_stop_all(efx);

	efx_disable_interrupts(efx);
	if (efx->type->fini)
		efx->type->fini(efx);
	efx_clear_interrupt_affinity(efx);
#ifdef EFX_USE_IRQ_NOTIFIERS
	efx_unregister_irq_notifiers(efx);
#endif
	efx_nic_fini_interrupt(efx);
	efx_remove_filters(efx);
	efx_fini_port(efx);
	efx_fini_napi(efx);
	efx_remove_channels(efx);
	if (efx->type->free_resources)
		efx->type->free_resources(efx);
	efx_unset_channels(efx);
	efx_remove_interrupts(efx);

	efx->state = STATE_NET_DOWN;

	return 0;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_VLAN_RX_ADD_VID_PROTO)
static int efx_vlan_rx_add_vid(struct net_device *net_dev, __be16 proto, u16 vid)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx->type->vlan_rx_add_vid)
		return efx->type->vlan_rx_add_vid(efx, proto, vid);
	else
		return -EOPNOTSUPP;
}

static int efx_vlan_rx_kill_vid(struct net_device *net_dev, __be16 proto, u16 vid)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx->type->vlan_rx_kill_vid)
		return efx->type->vlan_rx_kill_vid(efx, proto, vid);
	else
		return -EOPNOTSUPP;
}
#elif defined(EFX_HAVE_NDO_VLAN_RX_ADD_VID_RC)
static int efx_vlan_rx_add_vid(struct net_device *net_dev, u16 vid)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx->type->vlan_rx_add_vid)
		return efx->type->vlan_rx_add_vid(efx, htons(ETH_P_8021Q), vid);
	else
		return -EOPNOTSUPP;
}

static int efx_vlan_rx_kill_vid(struct net_device *net_dev, u16 vid)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx->type->vlan_rx_kill_vid)
		return efx->type->vlan_rx_kill_vid(efx, htons(ETH_P_8021Q), vid);
	else
		return -EOPNOTSUPP;
}
#elif defined(EFX_HAVE_NDO_VLAN_RX_ADD_VID)
static void efx_vlan_rx_add_vid(struct net_device *net_dev, unsigned short vid)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx->type->vlan_rx_add_vid)
		efx->type->vlan_rx_add_vid(efx, htons(ETH_P_8021Q), vid);
}

static void efx_vlan_rx_kill_vid(struct net_device *net_dev, unsigned short vid)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx->type->vlan_rx_kill_vid)
		efx->type->vlan_rx_kill_vid(efx, htons(ETH_P_8021Q), vid);
}
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_HAVE_VLAN_RX_PATH)
void efx_vlan_rx_register(struct net_device *dev, struct vlan_group *vlan_group)
{
	struct efx_nic *efx = efx_netdev_priv(dev);
	struct efx_channel *channel;

	/* Before changing efx_nic::vlan_group to null, we must flush
	 * out all VLAN-tagged skbs currently in the software RX
	 * pipeline.  Changing it to non-null might be safe, but we
	 * conservatively pause the RX path in both cases.
	 */
	efx_for_each_channel(channel, efx)
		if (efx_channel_has_rx_queue(channel))
			efx_stop_eventq(channel);

	efx->vlan_group = vlan_group;

	efx_for_each_channel(channel, efx)
		if (efx_channel_has_rx_queue(channel))
			efx_start_eventq(channel);
}

#endif /* EFX_NOT_UPSTREAM */

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_UDP_TUNNEL_ADD)
static int efx_udp_tunnel_type_map(enum udp_parsable_tunnel_type in)
{
	switch (in) {
	case UDP_TUNNEL_TYPE_VXLAN:
		return TUNNEL_ENCAP_UDP_PORT_ENTRY_VXLAN;
	case UDP_TUNNEL_TYPE_GENEVE:
		return TUNNEL_ENCAP_UDP_PORT_ENTRY_GENEVE;
	default:
		return -1;
	}
}

static void efx_udp_tunnel_add(struct net_device *dev, struct udp_tunnel_info *ti)
{
	struct efx_nic *efx = efx_netdev_priv(dev);
	struct efx_udp_tunnel tnl;
	int efx_tunnel_type;

	efx_tunnel_type = efx_udp_tunnel_type_map(ti->type);
	if (efx_tunnel_type < 0)
		return;

	tnl.type = (u16)efx_tunnel_type;
	tnl.port = ti->port;

	if (efx->type->udp_tnl_add_port)
		efx->type->udp_tnl_add_port(efx, tnl);
}

static void efx_udp_tunnel_del(struct net_device *dev, struct udp_tunnel_info *ti)
{
	struct efx_nic *efx = efx_netdev_priv(dev);
	struct efx_udp_tunnel tnl;
	int efx_tunnel_type;

	efx_tunnel_type = efx_udp_tunnel_type_map(ti->type);
	if (efx_tunnel_type < 0)
		return;

	tnl.type = (u16)efx_tunnel_type;
	tnl.port = ti->port;

	if (efx->type->udp_tnl_del_port)
		efx->type->udp_tnl_del_port(efx, tnl);
}
#else
#if defined(EFX_HAVE_NDO_ADD_VXLAN_PORT)
void efx_vxlan_add_port(struct net_device *dev, sa_family_t sa_family,
			__be16 port)
{
	struct efx_udp_tunnel tnl = {.port = port,
				     .type = TUNNEL_ENCAP_UDP_PORT_ENTRY_VXLAN};
	struct efx_nic *efx = efx_netdev_priv(dev);

	if (efx->type->udp_tnl_add_port)
		efx->type->udp_tnl_add_port(efx, tnl);
}

void efx_vxlan_del_port(struct net_device *dev, sa_family_t sa_family,
			__be16 port)
{
	struct efx_udp_tunnel tnl = {.port = port,
				     .type = TUNNEL_ENCAP_UDP_PORT_ENTRY_VXLAN};
	struct efx_nic *efx = efx_netdev_priv(dev);

	if (efx->type->udp_tnl_del_port)
		efx->type->udp_tnl_del_port(efx, tnl);
}
#endif
#if defined(EFX_HAVE_NDO_ADD_GENEVE_PORT)
void efx_geneve_add_port(struct net_device *dev, sa_family_t sa_family,
			__be16 port)
{
	struct efx_udp_tunnel tnl = {.port = port,
				     .type = TUNNEL_ENCAP_UDP_PORT_ENTRY_GENEVE};
	struct efx_nic *efx = efx_netdev_priv(dev);

	if (efx->type->udp_tnl_add_port)
		efx->type->udp_tnl_add_port(efx, tnl);
}

void efx_geneve_del_port(struct net_device *dev, sa_family_t sa_family,
			__be16 port)
{
	struct efx_udp_tunnel tnl = {.port = port,
				     .type = TUNNEL_ENCAP_UDP_PORT_ENTRY_GENEVE};
	struct efx_nic *efx = efx_netdev_priv(dev);

	if (efx->type->udp_tnl_del_port)
		efx->type->udp_tnl_del_port(efx, tnl);
}
#endif
#endif

extern const struct net_device_ops efx_netdev_ops;

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NET_DEVICE_OPS_EXT)
extern const struct net_device_ops_ext efx_net_device_ops_ext;
#endif

static void efx_update_name(struct efx_nic *efx)
{
	strcpy(efx->name, efx->net_dev->name);

#if defined(CONFIG_SFC_MTD) && !defined(EFX_WORKAROUND_87308)
	efx_mtd_rename(efx);
#endif

	efx_set_channel_names(efx);
#ifdef CONFIG_SFC_DEBUGFS
	mutex_lock(&efx->debugfs_symlink_mutex);
	if (efx->debug_symlink)
		efx_fini_debugfs_netdev(efx->net_dev);
	efx_init_debugfs_netdev(efx->net_dev);
	mutex_unlock(&efx->debugfs_symlink_mutex);
#endif
}

static int efx_netdev_event(struct notifier_block *this,
			    unsigned long event, void *ptr)
{
	struct efx_nic *efx = container_of(this, struct efx_nic, netdev_notifier);
	struct net_device *net_dev = netdev_notifier_info_to_dev(ptr);

	if (efx->net_dev == net_dev &&
	    (event == NETDEV_CHANGENAME || event == NETDEV_REGISTER)) {
		efx_update_name(efx);

#if defined(CONFIG_SFC_MTD) && defined(EFX_WORKAROUND_87308)
		if (atomic_xchg(&efx->mtd_struct->probed_flag, 1) == 0)
			(void)efx_mtd_probe(efx);
#endif
	}

	return NOTIFY_DONE;
}

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
static ssize_t show_lro(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
	return sprintf(buf, "%d\n", efx_ssr_enabled(efx));
}
static ssize_t set_lro(struct device *dev, struct device_attribute *attr,
		       const char *buf, size_t count)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
	bool enable = count > 0 && *buf != '0';
	ssize_t rc;

	rtnl_lock();
	if (!efx->lro_available && enable) {
		rc = -EINVAL;
		goto out;
	}
#ifdef NETIF_F_LRO
	if (enable != !!(efx->net_dev->features & NETIF_F_LRO)) {
		efx->net_dev->features ^= NETIF_F_LRO;
		netdev_features_change(efx->net_dev);
	}
#else
	efx->lro_enabled = enable;
#endif
	rc = count;
out:
	rtnl_unlock();
	return rc;
}
static DEVICE_ATTR(lro, 0644, show_lro, set_lro);
#endif

static ssize_t
show_phy_type(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
	return sprintf(buf, "%d\n", efx->phy_type);
}
static DEVICE_ATTR(phy_type, 0444, show_phy_type, NULL);

static void efx_init_features(struct efx_nic *efx)
{
	struct net_device *net_dev = efx->net_dev;

	efx->fixed_features |= NETIF_F_HIGHDMA;
	net_dev->features |= (efx->type->offload_features | NETIF_F_SG |
			      NETIF_F_TSO | NETIF_F_TSO_ECN |
			      NETIF_F_RXCSUM | NETIF_F_RXALL);
#if !defined(EFX_USE_KCOMPAT) || defined(NETIF_F_IPV6_CSUM)
	if (efx->type->offload_features & (NETIF_F_IPV6_CSUM | NETIF_F_HW_CSUM))
		net_dev->features |= NETIF_F_TSO6;
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_GRO)
	if (lro)
		net_dev->features |= NETIF_F_GRO;
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	if (lro) {
#if defined(NETIF_F_LRO)
		net_dev->features |= NETIF_F_LRO;
#endif
	}
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	/* soft VLAN acceleration cannot be disabled at runtime */
	efx->fixed_features |= NETIF_F_HW_VLAN_CTAG_RX;
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_TX_ACCEL)
	efx->fixed_features |= NETIF_F_HW_VLAN_CTAG_TX;
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_VLAN_FEATURES)
	/* Mask for features that also apply to VLAN devices */
	net_dev->vlan_features |= (NETIF_F_CSUM_MASK | NETIF_F_SG |
				   NETIF_F_HIGHDMA | NETIF_F_ALL_TSO |
				   NETIF_F_RXCSUM);
#else
	/* Alternative to vlan_features in RHEL 5.5+.  These all
	 * depend on NETIF_F_HW_CSUM or NETIF_F_HW_VLAN_TX because
	 * inline VLAN tags break the Ethertype check for IPv4-only
	 * checksum offload in dev_queue_xmit().
	 */
	if ((net_dev->features | efx->fixed_features) &
	    (NETIF_F_HW_CSUM | NETIF_F_HW_VLAN_TX)) {
#if defined(NETIF_F_VLAN_CSUM)
		net_dev->features |= NETIF_F_VLAN_CSUM;
#endif
#if defined(NETIF_F_VLAN_SG)
		net_dev->features |= NETIF_F_VLAN_SG;
#endif
#if defined(NETIF_F_VLAN_TSO)
		net_dev->features |= NETIF_F_VLAN_TSO;
#endif
#if defined(NETIF_F_VLAN_HIGHDMA)
		net_dev->features |= NETIF_F_VLAN_HIGHDMA;
#endif
	}
#endif

	efx_add_hw_features(efx, net_dev->features & ~efx->fixed_features);

	/* Disable receiving frames with bad FCS, by default. */
	net_dev->features &= ~NETIF_F_RXALL;

	/* Disable VLAN filtering by default.  It may be enforced if
	 * the feature is fixed (i.e. VLAN filters are required to
	 * receive VLAN tagged packets due to vPort restrictions).
	 */
	net_dev->features &= ~NETIF_F_HW_VLAN_CTAG_FILTER;
	net_dev->features |= efx->fixed_features;
}

static int efx_register_netdev(struct efx_nic *efx)
{
	struct net_device *net_dev = efx->net_dev;
	int rc;

	net_dev->watchdog_timeo = 5 * HZ;
	net_dev->irq = efx->pci_dev->irq;
	net_dev->netdev_ops = &efx_netdev_ops;
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_NDO_SET_MULTICAST_LIST)
	if (efx_nic_rev(efx) >= EFX_REV_HUNT_A0)
		net_dev->priv_flags |= IFF_UNICAST_FLT;
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NETDEV_RFS_INFO)
#ifdef CONFIG_RFS_ACCEL
	netdev_extended(net_dev)->rfs_data.ndo_rx_flow_steer = efx_filter_rfs;
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || !defined(SET_ETHTOOL_OPS)
	net_dev->ethtool_ops = &efx_ethtool_ops;
#else
	SET_ETHTOOL_OPS(net_dev, &efx_ethtool_ops);
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_ETHTOOL_OPS_EXT)
	set_ethtool_ops_ext(net_dev, &efx_ethtool_ops_ext);
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_GSO_MAX_SEGS)
	net_dev->gso_max_segs = EFX_TSO_MAX_SEGS;
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NETDEV_MTU_LIMITS)
	net_dev->min_mtu = EFX_MIN_MTU;
	net_dev->max_mtu = EFX_MAX_MTU;
#elif defined(EFX_HAVE_NETDEV_EXT_MTU_LIMITS)
	net_dev->extended->min_mtu = EFX_MIN_MTU;
	net_dev->extended->max_mtu = EFX_MAX_MTU;
#endif

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NDO_EXT_BUSY_POLL)
#ifdef CONFIG_NET_RX_BUSY_POLL
	netdev_extended(net_dev)->ndo_busy_poll = efx_busy_poll;
#endif
#endif

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NET_DEVICE_OPS_EXT)
	set_netdev_ops_ext(net_dev, &efx_net_device_ops_ext);
#endif

	rtnl_lock();

	/* If there was a scheduled reset during probe, the NIC is
	 * probably hosed anyway.  We must do this in the same locked
	 * section as we set state = READY.
	 */
	if (efx->reset_pending) {
		netif_err(efx, probe, efx->net_dev,
			  "aborting probe due to scheduled reset\n");
		rc = -EIO;
		goto fail_locked;
	}

	rc = dev_alloc_name(net_dev, net_dev->name);
	if (rc < 0)
		goto fail_locked;
	efx_update_name(efx);

	rc = register_netdevice(net_dev);
	if (rc)
		goto fail_locked;

	/* Always start with carrier off; PHY events will detect the link */
	netif_carrier_off(net_dev);

	efx->state = STATE_NET_DOWN;

	rtnl_unlock();

	efx_init_mcdi_logging(efx);
	efx_probe_devlink(efx);

	return 0;

fail_locked:
	rtnl_unlock();
	netif_err(efx, drv, efx->net_dev, "could not register net dev\n");
	return rc;
}

static void efx_unregister_netdev(struct efx_nic *efx)
{
	if (WARN_ON(efx_netdev_priv(efx->net_dev) != efx))
		return;

#if defined(EFX_NOT_UPSTREAM)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
	/* bug11519: This has only been seen on fc4, but the bug has never
	 * been fully understood - so this workaround is applied to a range
	 * of kernels. The issue is that if dev_close() is run too close
	 * to a driver unload, then netlink can allow userspace to leak a
	 * reference count. Sleeping here for a bit lowers the probability
	 * of seeing this failure. */
	schedule_timeout_uninterruptible(HZ * 2);

#endif
#endif
	if (efx_dev_registered(efx)) {
		strlcpy(efx->name, pci_name(efx->pci_dev), sizeof(efx->name));
		efx_fini_devlink(efx);
		efx_fini_mcdi_logging(efx);
		rtnl_lock();
		unregister_netdevice(efx->net_dev);
		efx->state = STATE_UNINIT;
		rtnl_unlock();
	}
}

/**************************************************************************
 *
 * List of NICs we support
 *
 **************************************************************************/

/* PCI device ID table */
static const struct pci_device_id efx_pci_table[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x0803),	/* SFC9020 */
	 .driver_data = (unsigned long) &siena_a0_nic_type},
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x0813),	/* SFL9021 */
	 .driver_data = (unsigned long) &siena_a0_nic_type},
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x0903),  /* SFC9120 PF */
	 .driver_data = (unsigned long) &efx_hunt_a0_nic_type},
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x1903),  /* SFC9120 VF */
	 .driver_data = (unsigned long) &efx_hunt_a0_vf_nic_type},
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x0923),  /* SFC9140 PF */
	 .driver_data = (unsigned long) &efx_hunt_a0_nic_type},
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x1923),  /* SFC9140 VF */
	 .driver_data = (unsigned long) &efx_hunt_a0_vf_nic_type},
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x0a03),  /* SFC9220 PF */
	 .driver_data = (unsigned long) &efx_hunt_a0_nic_type},
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x1a03),  /* SFC9220 VF */
	 .driver_data = (unsigned long) &efx_hunt_a0_vf_nic_type},
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x0b03),  /* SFC9250 PF */
	 .driver_data = (unsigned long) &efx_hunt_a0_nic_type},
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x1b03),  /* SFC9250 VF */
	 .driver_data = (unsigned long) &efx_hunt_a0_vf_nic_type},
	{0}			/* end of list */
};

void efx_update_sw_stats(struct efx_nic *efx, u64 *stats)
{
	u64 n_rx_nodesc_trunc = 0;
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx)
		n_rx_nodesc_trunc += channel->n_rx_nodesc_trunc;
	stats[GENERIC_STAT_rx_nodesc_trunc] = n_rx_nodesc_trunc;
	stats[GENERIC_STAT_rx_noskb_drops] = atomic_read(&efx->n_rx_noskb_drops);
}

/**************************************************************************
 *
 * PCI interface
 *
 **************************************************************************/

void efx_pci_remove_post_io(struct efx_nic *efx,
			    void (*nic_remove)(struct efx_nic *efx))
{
	efx_unregister_netdev(efx);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP)
	rtnl_lock();
	efx_xdp_setup_prog(efx, NULL);
	rtnl_unlock();
#endif
	if (efx->type->sriov_fini)
		efx->type->sriov_fini(efx);
	if (efx->type->vswitching_remove)
		efx->type->vswitching_remove(efx);
	efx_fini_channels(efx);
	efx->type->remove_port(efx);
	nic_remove(efx);
	efx_remove_common(efx);
#ifdef CONFIG_SFC_DEBUGFS
	mutex_lock(&efx->debugfs_symlink_mutex);
	efx_fini_debugfs_netdev(efx->net_dev);
	mutex_unlock(&efx->debugfs_symlink_mutex);
#endif
}

int efx_pci_probe_post_io(struct efx_nic *efx,
			  int (*nic_probe)(struct efx_nic *efx))
{
	int rc;

#ifdef EFX_NOT_UPSTREAM
	if (!performance_profile)
		efx->performance_profile = EFX_PERFORMANCE_PROFILE_AUTO;
	else if (strcmp(performance_profile, "throughput") == 0)
		efx->performance_profile = EFX_PERFORMANCE_PROFILE_THROUGHPUT;
	else if (strcmp(performance_profile, "latency") == 0)
		efx->performance_profile = EFX_PERFORMANCE_PROFILE_LATENCY;
	else
		efx->performance_profile = EFX_PERFORMANCE_PROFILE_AUTO;
#endif

	rc = efx_probe_common(efx);
	if (rc)
		return rc;
#ifdef EFX_NOT_UPSTREAM
	if (efx->mcdi->fn_flags &
	    (1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_NO_ACTIVE_PORT))
		return 0;
#endif

	netif_dbg(efx, probe, efx->net_dev, "creating NIC\n");

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	/* Initialise NIC resource information */
	efx->farch_resources = efx->type->farch_resources;
	efx->farch_resources.biu_lock = &efx->biu_lock;
	efx->ef10_resources = efx->type->ef10_resources;
#endif
#endif

	/* Carry out hardware-type specific initialisation */
	rc = nic_probe(efx);
	if (rc)
		return rc;

	efx->txq_min_entries =
		roundup_pow_of_two(2 * efx->type->tx_max_skb_descs(efx));

	/* Initialise the interrupt moderation settings */
	efx->irq_mod_step_us = DIV_ROUND_UP(efx->timer_quantum_ns, 1000);
	efx_init_irq_moderation(efx, tx_irq_mod_usec, rx_irq_mod_usec,
				irq_adapt_enable, true);

	netif_dbg(efx, probe, efx->net_dev, "create port\n");

	/* Connect up MAC/PHY operations table */
	rc = efx->type->probe_port(efx);
	if (rc)
		return rc;

	/* Initialise MAC address to permanent address */
	ether_addr_copy(efx->net_dev->dev_addr, efx->net_dev->perm_addr);

	rc = efx_check_queue_size(efx, &rx_ring,
				  EFX_RXQ_MIN_ENT, EFX_MAX_DMAQ_SIZE, true);
	if (rc == -ERANGE)
		netif_warn(efx, probe, efx->net_dev,
			   "rx_ring parameter must be between %u and %lu; clamped to %u\n",
			   EFX_RXQ_MIN_ENT, EFX_MAX_DMAQ_SIZE, rx_ring);
	else if (rc == -EINVAL)
		netif_warn(efx, probe, efx->net_dev,
			   "rx_ring parameter must be a power of two; rounded to %u\n",
			   rx_ring);
	efx->rxq_entries = rx_ring;

	rc = efx_check_queue_size(efx, &tx_ring,
				  efx->txq_min_entries, EFX_TXQ_MAX_ENT(efx),
				  true);
	if (rc == -ERANGE)
		netif_warn(efx, probe, efx->net_dev,
			   "tx_ring parameter must be between %u and %lu; clamped to %u\n",
			   efx->txq_min_entries, EFX_TXQ_MAX_ENT(efx), tx_ring);
	else if (rc == -EINVAL)
		netif_warn(efx, probe, efx->net_dev,
			   "tx_ring parameter must be a power of two; rounded to %u\n",
			   tx_ring);
	efx->txq_entries = tx_ring;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NET_TSTAMP)
	efx_ptp_get_attributes(efx);
	if (efx_ptp_uses_separate_channel(efx) ||
	    efx_ptp_use_mac_tx_timestamps(efx))
#endif
	efx_ptp_defer_probe_with_channel(efx);

	rc = efx_init_channels(efx);
	if (rc)
		return rc;

	rc = efx->type->vswitching_probe(efx);
	if (rc) /* not fatal; the PF will still work fine */
		netif_warn(efx, probe, efx->net_dev,
			   "failed to setup vswitching rc=%d, VFs may not function\n",
			   rc);

	if (efx->type->sriov_init) {
		rc = efx->type->sriov_init(efx);
		if (rc)
			netif_err(efx, probe, efx->net_dev,
				  "SR-IOV can't be enabled rc %d\n", rc);
	}

	return efx_register_netdev(efx);
}

/* Final NIC shutdown
 * This is called only at module unload (or hotplug removal).  A PF can call
 * this on its VFs to ensure they are unbound first.
 */
static void efx_pci_remove(struct pci_dev *pci_dev)
{
	struct efx_probe_data *probe_data;
	struct efx_nic *efx;

	efx = pci_get_drvdata(pci_dev);
	if (!efx)
		return;

	/* Mark the NIC as fini, then stop the interface */
	rtnl_lock();
	dev_close(efx->net_dev);

	if (!efx_nic_hw_unavailable(efx))
		efx->state = STATE_UNINIT;

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	if (efx_dl_supported(efx))
		efx_dl_unregister_nic(&efx->dl_nic);
#endif
#endif

	/* Allow any queued efx_resets() to complete */
	rtnl_unlock();
	efx_flush_reset_workqueue(efx);

#if defined(CONFIG_SFC_MTD) && defined(EFX_WORKAROUND_87308)
	(void)cancel_delayed_work_sync(&efx->mtd_struct->creation_work);
#endif

	efx_virtbus_unregister(efx);
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	device_remove_file(&efx->pci_dev->dev, &dev_attr_lro);
#endif
	device_remove_file(&efx->pci_dev->dev, &dev_attr_phy_type);

	efx->type->remove(efx);

#ifdef CONFIG_SFC_MTD
#ifdef EFX_WORKAROUND_87308
	if (atomic_read(&efx->mtd_struct->probed_flag) == 1)
		efx_mtd_remove(efx);
#else
	efx_mtd_remove(efx);
#endif
#endif

#ifdef CONFIG_SFC_DUMP
	efx_dump_fini(efx);
#endif

	unregister_netdevice_notifier(&efx->netdev_notifier);

	efx_fini_io(efx);
	pci_dbg(efx->pci_dev, "shutdown successful\n");

	efx_fini_struct(efx);
	pci_set_drvdata(pci_dev, NULL);
	free_netdev(efx->net_dev);
	probe_data = container_of(efx, struct efx_probe_data, efx);
	kfree(probe_data);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_AER)
	pci_disable_pcie_error_reporting(pci_dev);
#endif
};

/* NIC initialisation
 *
 * This is called at module load (or hotplug insertion,
 * theoretically).  It sets up PCI mappings, resets the NIC,
 * sets up and registers the network devices with the kernel and hooks
 * the interrupt service routine.  It does not prepare the device for
 * transmission; this is left to the first time one of the network
 * interfaces is brought up (i.e. efx_net_open).
 */
static int efx_pci_probe(struct pci_dev *pci_dev,
			 const struct pci_device_id *entry)
{
	struct efx_probe_data *probe_data, **probe_ptr;
	struct net_device *net_dev;
	struct efx_nic *efx;
	int rc;

	/* Allocate probe data and struct efx_nic */
	probe_data = kzalloc(sizeof(*probe_data), GFP_KERNEL);
	if (!probe_data)
		return -ENOMEM;
	probe_data->pci_dev = pci_dev;
	efx = &probe_data->efx;

	/* Allocate and initialise a struct net_device */
	net_dev = alloc_etherdev_mq(sizeof(probe_data), EFX_MAX_CORE_TX_QUEUES);
	if (!net_dev)
		return -ENOMEM;
	probe_ptr = netdev_priv(net_dev);
	*probe_ptr = probe_data;
	efx->net_dev = net_dev;
	efx->type = (const struct efx_nic_type *) entry->driver_data;

	efx_init_features(efx);

	pci_set_drvdata(pci_dev, efx);
	SET_NETDEV_DEV(net_dev, &pci_dev->dev);
	rc = efx_init_struct(efx, pci_dev);
	if (rc)
		goto fail;
	efx->mdio.dev = net_dev;
#ifdef CONFIG_SFC_MTD
	if (efx_mtd_init(efx) < 0)
		goto fail;
#endif

	netif_info(efx, probe, efx->net_dev,
		   "Solarflare NIC detected: device %04x:%04x subsys %04x:%04x\n",
		   efx->pci_dev->vendor, efx->pci_dev->device,
		   efx->pci_dev->subsystem_vendor,
		   efx->pci_dev->subsystem_device);

#ifdef EFX_NOT_UPSTREAM
	efx->xdp_tx = xdp_alloc_tx_resources;
#else
	efx->xdp_tx = true;
#endif

	/* Set up basic I/O (BAR mappings etc) */
	rc = efx_init_io(efx, efx->type->mem_bar(efx), efx->type->max_dma_mask,
			 efx->type->mem_map_size(efx));
	if (rc)
		goto fail;

	efx->netdev_notifier.notifier_call = efx_netdev_event;
	rc = register_netdevice_notifier(&efx->netdev_notifier);
	if (rc)
		goto fail;

#ifdef CONFIG_SFC_DUMP
	rc = efx_dump_init(efx);
	if (rc)
		goto fail;
#endif

	rc = efx->type->probe(efx);
	if (rc)
		goto fail;

	rc = efx_virtbus_register(efx);
	if (rc)
		pci_warn(efx->pci_dev,
			 "Unable to register virtual bus driver (%d)\n", rc);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
	efx->tx_queues_per_channel++;
#endif
#ifdef EFX_NOT_UPSTREAM
	if (efx->mcdi->fn_flags &
	    (1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_NO_ACTIVE_PORT)) {
		netif_dbg(efx, probe, efx->net_dev,
			  "initialisation successful (no active port)\n");
		return 0;
	}
#endif

	rc = device_create_file(&efx->pci_dev->dev, &dev_attr_phy_type);
	if (rc) {
		netif_err(efx, drv, efx->net_dev,
			  "failed to init net dev attributes\n");
		goto fail;
	}
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	rc = device_create_file(&efx->pci_dev->dev, &dev_attr_lro);
	if (rc) {
		netif_err(efx, drv, efx->net_dev,
			  "failed to init net dev attributes\n");
		goto fail;
	}
#endif

	netif_dbg(efx, probe, efx->net_dev, "initialisation successful\n");
	if (PCI_FUNC(pci_dev->devfn) == 0)
		efx_mcdi_log_puts(efx, "probe");

#ifdef CONFIG_SFC_MTD
#ifdef EFX_WORKAROUND_87308
	schedule_delayed_work(&efx->mtd_struct->creation_work, 5 * HZ);
#else
	/* Try to create MTDs, but allow this to fail */
	rtnl_lock();
	rc = efx_mtd_probe(efx);
	rtnl_unlock();
#endif
#endif

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_MTD_TABLE)
	if (rc == -EBUSY)
		netif_warn(efx, probe, efx->net_dev,
			   "kernel MTD table is full; flash will not be "
			   "accessible\n");
	else
#endif
	if (rc && rc != -EPERM)
		netif_warn(efx, probe, efx->net_dev,
			   "failed to create MTDs (%d)\n", rc);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_AER)
	(void)pci_enable_pcie_error_reporting(pci_dev);
#endif

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	efx_dl_probe(efx);
	if (efx_dl_supported(efx)) {
		rtnl_lock();
		efx_dl_register_nic(&efx->dl_nic);
		rtnl_unlock();
	}
#endif
#endif

	if (efx->type->udp_tnl_push_ports)
		efx->type->udp_tnl_push_ports(efx);

	return 0;

fail:
	efx_pci_remove(pci_dev);
	return rc;
}

/* efx_pci_sriov_configure returns the actual number of Virtual Functions enabled
   on success*/

#ifdef CONFIG_SFC_SRIOV
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SRIOV_CONFIGURE) || defined(EFX_HAVE_PCI_DRIVER_RH)

static int efx_pci_sriov_configure(struct pci_dev *dev,
				   int num_vfs)
{
	int rc;
	struct efx_nic *efx = pci_get_drvdata(dev);

	if (efx->type->sriov_configure) {
		rc = efx->type->sriov_configure(efx, num_vfs);
		if (rc)
			return rc;
		else
			return num_vfs;
	}
	else
		return -ENOSYS;
}
#endif
#endif

static int efx_pm_freeze(struct device *dev)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));

	rtnl_lock();

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	efx_dl_reset_suspend(&efx->dl_nic);
#endif
#endif

	if (efx->state == STATE_NET_UP) {
		efx_device_detach_sync(efx);

		efx_stop_all(efx);
		efx_disable_interrupts(efx);
	}

	if (efx_net_active(efx->state)) {
		efx->state = efx_freeze(efx->state);

		efx_mcdi_port_reconfigure(efx);
	}

	rtnl_unlock();

	return 0;
}

static void efx_pci_shutdown(struct pci_dev *pci_dev)
{
	struct efx_nic *efx = pci_get_drvdata(pci_dev);

	if (!efx)
		return;

	efx_pm_freeze(&pci_dev->dev);
	pci_disable_device(pci_dev);
}

static int efx_pm_thaw(struct device *dev)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
	int rc;

	rtnl_lock();

	if (efx->state == (STATE_NET_UP | STATE_FROZEN)) {
		rc = efx_enable_interrupts(efx);
		if (rc)
			goto fail;

		mutex_lock(&efx->mac_lock);
		efx_mcdi_port_reconfigure(efx);
		mutex_unlock(&efx->mac_lock);

		efx_start_all(efx);

		efx_device_attach_if_not_resetting(efx);
	}

	if (efx_frozen(efx->state)) {
		efx->state = efx_thaw(efx->state);

		efx_mcdi_port_reconfigure(efx);

		efx->type->resume_wol(efx);
	}

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	efx_dl_reset_resume(&efx->dl_nic, efx->state != STATE_DISABLED);
#endif
#endif

	rtnl_unlock();

	/* Reschedule any quenched resets scheduled during efx_pm_freeze() */
	efx_queue_reset_work(efx);

	return 0;

fail:
#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	efx_dl_reset_resume(&efx->dl_nic, false);
#endif
#endif

	rtnl_unlock();

	return rc;
}

static int efx_pm_poweroff(struct device *dev)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct efx_nic *efx = pci_get_drvdata(pci_dev);

	if (efx->type->fini)
		efx->type->fini(efx);

	efx->reset_pending = 0;

	pci_save_state(pci_dev);
	return pci_set_power_state(pci_dev, PCI_D3hot);
}

/* Used for both resume and restore */
static int efx_pm_resume(struct device *dev)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct efx_nic *efx = pci_get_drvdata(pci_dev);
	int rc;

	rc = pci_set_power_state(pci_dev, PCI_D0);
	if (rc)
		goto fail;
	pci_restore_state(pci_dev);
	rc = pci_enable_device(pci_dev);
	if (rc)
		goto fail;
	pci_set_master(efx->pci_dev);
	rc = efx->type->reset(efx, RESET_TYPE_ALL);
	if (rc)
		goto fail;
	down_write(&efx->filter_sem);
	rc = efx->type->init(efx);
	up_write(&efx->filter_sem);
	if (rc)
		goto fail;
	rc = efx_pm_thaw(dev);
	return rc;

fail:
#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	efx_dl_reset_resume(&efx->dl_nic, false);
#endif
#endif
	return rc;
}

static int efx_pm_suspend(struct device *dev)
{
	int rc;

	efx_pm_freeze(dev);
	rc = efx_pm_poweroff(dev);
	if (rc)
		efx_pm_resume(dev);
	return rc;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_DEV_PM_OPS)

static const struct dev_pm_ops efx_pm_ops = {
	.suspend	= efx_pm_suspend,
	.resume		= efx_pm_resume,
	.freeze		= efx_pm_freeze,
	.thaw		= efx_pm_thaw,
	.poweroff	= efx_pm_poweroff,
	.restore	= efx_pm_resume,
};

#elif defined(EFX_USE_PM_EXT_OPS)

static struct pm_ext_ops efx_pm_ops = {
	.base = {
		.suspend	= efx_pm_suspend,
		.resume		= efx_pm_resume,
		.freeze		= efx_pm_freeze,
		.thaw		= efx_pm_thaw,
		.poweroff	= efx_pm_poweroff,
		.restore	= efx_pm_resume,
	}
};

#else /* !EFX_USE_DEV_PM_OPS && !EFX_USE_PM_EXT_OPS */

static int efx_pm_old_suspend(struct pci_dev *dev, pm_message_t state)
{
	switch (state.event) {
	case PM_EVENT_FREEZE:
#if defined(PM_EVENT_QUIESCE)
	case PM_EVENT_QUIESCE:
#elif defined(PM_EVENT_PRETHAW)
	case PM_EVENT_PRETHAW:
#endif
		return efx_pm_freeze(&dev->dev);
	default:
		return efx_pm_suspend(&dev->dev);
	}
}

static int efx_pm_old_resume(struct pci_dev *dev)
{
	return efx_pm_resume(&dev->dev);
}

#endif /* EFX_USE_PM_EXT_OPS */

#if defined(CONFIG_SFC_SRIOV) && defined(EFX_HAVE_PCI_DRIVER_RH) && !defined(EFX_HAVE_SRIOV_CONFIGURE)
static struct pci_driver_rh efx_pci_driver_rh = {
	.sriov_configure = efx_pci_sriov_configure,
};
#endif

static struct pci_driver efx_pci_driver = {
	.name		= KBUILD_MODNAME,
	.id_table	= efx_pci_table,
	.probe		= efx_pci_probe,
	.remove		= efx_pci_remove,
#if !defined(EFX_USE_KCOMPAT)
	.driver.pm	= &efx_pm_ops,
#elif defined(EFX_USE_DEV_PM_OPS)
	/* May need to cast away const */
	.driver.pm	= (struct dev_pm_ops *)&efx_pm_ops,
#elif defined(EFX_USE_PM_EXT_OPS)
	.pm		= &efx_pm_ops,
#else
	.suspend	= efx_pm_old_suspend,
	.resume		= efx_pm_old_resume,
#endif
	.shutdown	= efx_pci_shutdown,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_AER)
	.err_handler	= &efx_err_handlers,
#endif
#ifdef CONFIG_SFC_SRIOV
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SRIOV_CONFIGURE)
	.sriov_configure = efx_pci_sriov_configure,
#elif defined(EFX_HAVE_PCI_DRIVER_RH)
	.rh_reserved    = &efx_pci_driver_rh,
#endif
#endif
};

const struct net_device_ops efx_netdev_ops = {
	.ndo_open		= efx_net_open,
	.ndo_stop		= efx_net_stop,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_STATS64)
	.ndo_get_stats64	= efx_net_stats,
#else
	.ndo_get_stats		= efx_net_stats,
#endif
	.ndo_tx_timeout		= efx_watchdog,
	.ndo_start_xmit		= efx_hard_start_xmit,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_do_ioctl		= efx_ioctl,
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NDO_EXT_CHANGE_MTU)
	.extended.ndo_change_mtu = efx_change_mtu,
#else
	.ndo_change_mtu		= efx_change_mtu,
#endif
	.ndo_set_mac_address	= efx_set_mac_address,
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_NDO_SET_MULTICAST_LIST)
	.ndo_set_rx_mode	= efx_set_rx_mode, /* Lookout */
#else
	/* On older kernel versions, set_rx_mode is expected to
	 * support multiple unicast addresses and set_multicast_list
	 * is expected to support only one.  On newer versions the
	 * IFF_UNICAST_FLT flag distinguishes these.
	 */
	.ndo_set_multicast_list	= efx_set_rx_mode,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_FEATURES)
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	.ndo_fix_features	= efx_fix_features,
#endif
	.ndo_set_features	= efx_set_features,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_FEATURES_CHECK)
	.ndo_features_check	= efx_features_check,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_VLAN_RX_ADD_VID)
	.ndo_vlan_rx_add_vid	= efx_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= efx_vlan_rx_kill_vid,
#endif
#ifdef CONFIG_SFC_SRIOV
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_VF_MAC)
	.ndo_set_vf_mac         = efx_sriov_set_vf_mac,
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NDO_EXT_SET_VF_VLAN_PROTO)
	.extended.ndo_set_vf_vlan = efx_sriov_set_vf_vlan,
#else
	.ndo_set_vf_vlan        = efx_sriov_set_vf_vlan,
#endif
	.ndo_get_vf_config      = efx_sriov_get_vf_config,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VF_LINK_STATE)
	.ndo_set_vf_link_state  = efx_sriov_set_vf_link_state,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_VF_SPOOFCHK)
	.ndo_set_vf_spoofchk	= efx_sriov_set_vf_spoofchk,
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PHYS_PORT_ID)
	.ndo_get_phys_port_id	= efx_get_phys_port_id,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PHYS_PORT_NAME)
#ifndef CONFIG_NET_DEVLINK
	.ndo_get_phys_port_name	= efx_get_phys_port_name,
#endif
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_HAVE_VLAN_RX_PATH)
	.ndo_vlan_rx_register	= efx_vlan_rx_register,
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_NDO_POLL_CONTROLLER)
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= efx_netpoll,
#endif
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NDO_BUSY_POLL)
#ifdef CONFIG_NET_RX_BUSY_POLL
	.ndo_busy_poll		= efx_busy_poll,
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_NETDEV_RFS_INFO)
#ifdef CONFIG_RFS_ACCEL
	.ndo_rx_flow_steer	= efx_filter_rfs,
#endif
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_UDP_TUNNEL_ADD)
	.ndo_udp_tunnel_add	= efx_udp_tunnel_add,
	.ndo_udp_tunnel_del	= efx_udp_tunnel_del,
#else
#if defined(EFX_HAVE_NDO_ADD_VXLAN_PORT)
	.ndo_add_vxlan_port	= efx_vxlan_add_port,
	.ndo_del_vxlan_port	= efx_vxlan_del_port,
#endif
#if defined(EFX_HAVE_NDO_ADD_GENEVE_PORT)
	.ndo_add_geneve_port	= efx_geneve_add_port,
	.ndo_del_geneve_port	= efx_geneve_del_port,
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP)
	.ndo_bpf		= efx_xdp,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_NEED_WAKEUP)
	.ndo_xsk_wakeup		= efx_xsk_wakeup,
#else
	.ndo_xsk_async_xmit	= efx_xsk_async_xmit,
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_REDIR)
	.ndo_xdp_xmit		= efx_xdp_xmit,
#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_XDP_FLUSH)
	.ndo_xdp_flush		= efx_xdp_flush,
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_DEVLINK)
#ifdef CONFIG_NET_DEVLINK
	.ndo_get_devlink_port	= efx_get_devlink_port,
#endif
#endif

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NDO_SIZE)
	.ndo_size		= sizeof(struct net_device_ops),
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NDO_SIZE_RH)
	.ndo_size_rh		= sizeof(struct net_device_ops),
#endif
};

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NET_DEVICE_OPS_EXT)
const struct net_device_ops_ext efx_net_device_ops_ext = {
#ifdef EFX_HAVE_EXT_NDO_SET_FEATURES
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	.ndo_fix_features      = efx_fix_features,
#endif
	.ndo_set_features      = efx_set_features,
#endif

#ifdef EFX_HAVE_NET_DEVICE_OPS_EXT_GET_PHYS_PORT_ID
	.ndo_get_phys_port_id	= efx_get_phys_port_id,
#endif
#ifdef CONFIG_SFC_SRIOV
#ifdef EFX_HAVE_NET_DEVICE_OPS_EXT_SET_VF_SPOOFCHK
	.ndo_set_vf_spoofchk	= efx_sriov_set_vf_spoofchk,
#endif
#ifdef EFX_HAVE_NET_DEVICE_OPS_EXT_SET_VF_LINK_STATE
	.ndo_set_vf_link_state	= efx_sriov_set_vf_link_state,
#endif
#endif /* CONFIG_SFC_SRIOV */
};
#endif
/**************************************************************************
 *
 * Kernel module interface
 *
 *************************************************************************/

#ifdef EFX_NOT_UPSTREAM

module_param(rx_irq_mod_usec, uint, 0444);
MODULE_PARM_DESC(rx_irq_mod_usec,
		 "Receive interrupt moderation (microseconds)");

module_param(tx_irq_mod_usec, uint, 0444);
MODULE_PARM_DESC(tx_irq_mod_usec,
		 "Transmit interrupt moderation (microseconds)");

#endif /* EFX_NOT_UPSTREAM */

static int __init efx_init_module(void)
{
	int rc;

	printk(KERN_INFO "Solarflare NET driver v" EFX_DRIVER_VERSION "\n");

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_GCOV)
	gcov_provider_init(THIS_MODULE);
#endif

	rc = efx_init_debugfs("sfc");
	if (rc)
		goto err_debugfs;

#if defined(EFX_USE_KCOMPAT) && (!defined(EFX_USE_CANCEL_WORK_SYNC) || !defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC))
	efx_workqueue = create_singlethread_workqueue("sfc_wq");
	if (!efx_workqueue) {
		printk(KERN_ERR "Failed to create workqueue\n");
		rc = -ENOMEM;
		goto err_wq;
	}
#endif

	rc = efx_create_reset_workqueue();
	if (rc)
		goto err_reset;

	rc = efx_channels_init_module();
	if (rc)
		goto err_channels_init;

	rc = pci_register_driver(&efx_pci_driver);
	if (rc < 0) {
		printk(KERN_ERR "pci_register_driver failed, rc=%d\n", rc);
		goto err_pci;
	}

	return 0;

 err_pci:
	efx_channels_fini_module();
 err_channels_init:
	efx_destroy_reset_workqueue();
 err_reset:
#if defined(EFX_USE_KCOMPAT) && (!defined(EFX_USE_CANCEL_WORK_SYNC) || !defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC))
	destroy_workqueue(efx_workqueue);
 err_wq:
#endif
	efx_fini_debugfs();
 err_debugfs:
	return rc;
}

static void __exit efx_exit_module(void)
{
	printk(KERN_INFO "Solarflare NET driver unloading\n");

	pci_unregister_driver(&efx_pci_driver);
	efx_channels_fini_module();
	efx_destroy_reset_workqueue();
#if defined(EFX_USE_KCOMPAT) && (!defined(EFX_USE_CANCEL_WORK_SYNC) || !defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC))
	destroy_workqueue(efx_workqueue);
#endif
	efx_fini_debugfs();

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_GCOV)
	gcov_provider_fini(THIS_MODULE);
#endif
}

module_init(efx_init_module);
module_exit(efx_exit_module);

MODULE_AUTHOR("Solarflare Communications and "
	      "Michael Brown <mbrown@fensystems.co.uk>");
MODULE_DESCRIPTION("Solarflare network driver");
MODULE_LICENSE("GPL");
MODULE_DEVICE_TABLE(pci, efx_pci_table);
MODULE_VERSION(EFX_DRIVER_VERSION);
