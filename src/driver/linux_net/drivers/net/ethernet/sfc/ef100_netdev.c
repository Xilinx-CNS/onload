/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2018 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#include <linux/module.h>
#include "net_driver.h"
#include "mcdi_port_common.h"
#include "mcdi_functions.h"
#include "efx_common.h"
#include "efx_channels.h"
#include "tx_common.h"
#include "debugfs.h"
#include "ef100_netdev.h"
#include "ef100_ethtool.h"
#include "efx_common.h"
#include "nic.h"
#include "ef100_nic.h"
#include "ef100_tx.h"
#include "ef100_regs.h"
#include "mcdi_filters.h"
#include "rx_common.h"
#include "efx_ioctl.h"
#include "ioctl_common.h"
#ifdef CONFIG_SFC_TRACING
#include <trace/events/sfc.h>
#endif
#include "mae.h"
#include "tc.h"
#include "efx_devlink.h"
#include "ef100_sriov.h"
#include "ef100_rep.h"
#include "xdp.h"

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
#include "io.h"
#endif
#endif

static void ef100_update_name(struct efx_nic *efx)
{
	strcpy(efx->name, efx->net_dev->name);
#ifdef CONFIG_SFC_DEBUGFS
	mutex_lock(&efx->debugfs_symlink_mutex);
	if (efx->debug_symlink)
		efx_fini_debugfs_netdev(efx->net_dev);
	efx_init_debugfs_netdev(efx->net_dev);
	mutex_unlock(&efx->debugfs_symlink_mutex);
#endif
}

static int ef100_alloc_vis(struct efx_nic *efx, unsigned int *allocated_vis)
{
	unsigned int rx_vis = efx_rx_channels(efx);
	unsigned int tx_vis = efx_tx_channels(efx) * efx->tx_queues_per_channel;
	unsigned int min_vis, max_vis;
	int rc;

	tx_vis += efx_xdp_channels(efx) * efx->xdp_tx_per_channel;

	max_vis = max(rx_vis, tx_vis);
	min_vis = efx->tx_queues_per_channel;
#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	/* We will consume all VIs with IDs less than the current value of
	 * max_vis, so report that as the ID of the first VI available to the
	 * driverlink client, and then bump the requested number of VIs by the
	 * number that the client would like. */
	efx->ef10_resources.vi_min = max_vis;
	max_vis += EF100_ONLOAD_VIS;
#endif
#endif
	rc = efx_mcdi_alloc_vis(efx, min_vis, max_vis,
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_DRIVERLINK)
				&efx->ef10_resources.vi_base,
				&efx->ef10_resources.vi_shift,
#else
				NULL, NULL,
#endif
				allocated_vis);
	if ((*allocated_vis >= min_vis) && (*allocated_vis < max_vis))
		rc = -EAGAIN;

	return rc;
}

static int ef100_remap_bar(struct efx_nic *efx, int max_vis)
{
	unsigned int uc_mem_map_size;
	void __iomem *membase;

	efx->max_vis = max_vis;
	uc_mem_map_size = PAGE_ALIGN(max_vis * efx->vi_stride);

	/* Extend the original UC mapping of the memory BAR */
#if defined(EFX_USE_KCOMPAT)
	membase = efx_ioremap(efx->membase_phys, uc_mem_map_size);
#else
	membase = ioremap(efx->membase_phys, uc_mem_map_size);
#endif
	if (!membase) {
		netif_err(efx, probe, efx->net_dev,
			  "could not extend memory BAR to %x\n",
			  uc_mem_map_size);
		return -ENOMEM;
	}
	iounmap(efx->membase);
	efx->membase = membase;
	return 0;
}

/* Context: process, rtnl_lock() held.
 * Note that the kernel will ignore our return code; this method
 * should really be a void.
 */
static int ef100_net_stop(struct net_device *net_dev)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	netif_dbg(efx, ifdown, efx->net_dev, "closing on CPU %d\n",
		  raw_smp_processor_id());

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
	if (efx->type->detach_reps)
		efx->type->detach_reps(efx);
#endif
	netif_stop_queue(net_dev);
	efx_stop_all(efx);

	efx->state = STATE_NET_ALLOCATED;

	efx_net_dealloc(efx);

	return 0;
}

void ef100_net_dealloc(struct efx_nic *efx)
{
	struct ef100_nic_data *nic_data;

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	if (--efx->open_count) {
		netif_dbg(efx, drv, efx->net_dev, "still open\n");
		return;
	}
#endif
#endif

	efx_disable_interrupts(efx);
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_BUSYPOLL)
	if (efx->interrupt_mode != EFX_INT_MODE_POLLED) {
		efx_clear_interrupt_affinity(efx);
		efx_nic_fini_interrupt(efx);
	}
#else
	efx_clear_interrupt_affinity(efx);
	efx_nic_fini_interrupt(efx);
#endif
	efx_fini_filters(efx);
	efx_fini_napi(efx);

	nic_data = efx->nic_data;
	if (nic_data->evq_phases)
		bitmap_free(nic_data->evq_phases);
	nic_data->evq_phases = NULL;

	efx_remove_channels(efx);
	efx_mcdi_free_vis(efx);
	efx_unset_channels(efx);
	efx_remove_interrupts(efx);
	efx_fini_channels(efx);

	efx->state = STATE_NET_DOWN;
}

/* Context: process, rtnl_lock() held. */
static int ef100_net_open(struct net_device *net_dev)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	struct ef100_nic_data *nic_data;
	int rc;

	ef100_update_name(efx);
	netif_dbg(efx, ifup, net_dev, "opening device on CPU %d\n",
		  raw_smp_processor_id());

	rc = ef100_net_alloc(efx);
	if (rc)
		goto fail;

	rc = efx_start_all(efx);
	if (rc)
		goto fail;

	/* Link state detection is normally event-driven; we have
	 * to poll now because we could have missed a change
	 */
	mutex_lock(&efx->mac_lock);
	if (efx_mcdi_phy_poll(efx))
		efx_link_status_changed(efx);
	mutex_unlock(&efx->mac_lock);

	efx->state = STATE_NET_UP;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
	if (netif_running(efx->net_dev) && efx->type->attach_reps)
		efx->type->attach_reps(efx);
#endif
	/* Mport changes are normally event-driven. Check now because
	 * we could have missed a change.
	 */
	nic_data = efx->nic_data;
	if (nic_data->grp_mae)
		schedule_work(&efx->mae->mport_work);
	return 0;

fail:
	ef100_net_stop(net_dev);
	return rc;
}

/* This function tries to distribute allocated VIs based on the channel
 * priority from the total pool of available VIs
 */
static void ef100_adjust_channels(struct efx_nic *efx, unsigned int avail_vis)
{
	unsigned int vi_share;

	/*
	 * - vi_share is initially initialized to the total VIs required for
	 *   the channel type.
	 * - the below logic tries to compute the actual vi_share each channel
	 *   type gets
	 */
	vi_share = min(efx->n_combined_channels * efx->tx_queues_per_channel,
		       avail_vis);
	vi_share -= (vi_share % efx->tx_queues_per_channel);
	avail_vis -= vi_share;
	/* rx_only and tx_only channels are not present in ef100,
	 * the below logic does not have any effect
	 */
	efx->n_combined_channels = (vi_share / efx->tx_queues_per_channel);
	vi_share = min(efx->n_extra_channels * efx->tx_queues_per_channel,
		       avail_vis);
	vi_share -= (vi_share % efx->tx_queues_per_channel);
	avail_vis -= vi_share;
	efx->n_extra_channels = (vi_share / efx->tx_queues_per_channel);
	vi_share = min(efx->n_rx_only_channels, avail_vis);
	avail_vis -= vi_share;
	efx->n_rx_only_channels = vi_share;
	vi_share = min(efx->n_tx_only_channels * efx->tx_queues_per_channel,
		       avail_vis);
	vi_share -= (vi_share % efx->tx_queues_per_channel);
	avail_vis -= vi_share;
	efx->n_tx_only_channels = (vi_share / efx->tx_queues_per_channel);
	vi_share = (efx->n_xdp_channels * efx->xdp_tx_per_channel);
	if (avail_vis < vi_share)
		efx->n_xdp_channels = 0;
	else
		avail_vis -= vi_share;
	/* Recalculate RSS spread based on available RX channels */
	efx->n_rss_channels = efx_rx_channels(efx) - efx->n_extra_channels;
}

int ef100_net_alloc(struct efx_nic *efx)
{
	struct ef100_nic_data *nic_data;
	unsigned int allocated_vis;
	int rc;

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	if (efx->open_count++) {
		netif_dbg(efx, drv, efx->net_dev, "already open\n");
		/* inform the kernel about link state again */
		efx_link_status_changed(efx);
		return 0;
	}
#endif
#endif

	rc = efx_check_disabled(efx);
	if (rc)
		return rc;

	efx->stats_initialised = false;
	allocated_vis = 0;
	do {
		rc = efx_init_channels(efx);
		if (rc)
			return rc;

		rc = efx_probe_interrupts(efx);
		if (rc)
			return rc;

		rc = efx_set_channels(efx);
		if (rc)
			return rc;

		if (!allocated_vis) {
			rc = efx_mcdi_free_vis(efx);
			if (rc)
				return rc;

			rc = ef100_alloc_vis(efx, &allocated_vis);
			if (rc && rc != -EAGAIN)
				return rc;
			if (rc == -EAGAIN) {
				efx_unset_channels(efx);
				efx_remove_interrupts(efx);
				efx_fini_channels(efx);

				ef100_adjust_channels(efx, allocated_vis);
				efx->max_vis = allocated_vis;
			}
		}
	} while (rc == -EAGAIN);

	rc = efx_mcdi_push_default_indir_table(efx, efx->n_rss_channels);
	if (rc)
		return rc;

	rc = efx_probe_channels(efx);
	if (rc)
		return rc;

	rc = ef100_remap_bar(efx, allocated_vis);
	if (rc)
		return rc;

	nic_data = efx->nic_data;
	nic_data->evq_phases = bitmap_zalloc(efx_channels(efx), GFP_KERNEL);
	if (!nic_data->evq_phases)
		return -ENOMEM;

	rc = efx_init_napi(efx);
	if (rc)
		return rc;

	rc = efx_init_filters(efx);
	if (rc)
		return rc;

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_BUSYPOLL)
	if (efx->interrupt_mode != EFX_INT_MODE_POLLED) {
		rc = efx_nic_init_interrupt(efx);
		if (rc)
			return rc;
		efx_set_interrupt_affinity(efx, true);
	}
#else
	rc = efx_nic_init_interrupt(efx);
	if (rc)
		return rc;
	efx_set_interrupt_affinity(efx, true);
#endif

	rc = efx_enable_interrupts(efx);
	if (rc)
		return rc;

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	/* Register with driverlink layer */
	efx->ef10_resources.vi_lim = allocated_vis;
	efx->ef10_resources.timer_quantum_ns = efx->timer_quantum_ns;
	efx->ef10_resources.rss_channel_count = efx->rss_spread;
	efx->ef10_resources.rx_channel_count = efx_rx_channels(efx);
	efx->ef10_resources.flags = EFX_DL_EF10_USE_MSI;
	efx->ef10_resources.vi_stride = efx->vi_stride;
	efx->ef10_resources.mem_bar = efx->mem_bar;

	if (efx->irq_resources)
		efx->irq_resources->int_prime =
			efx_mem(efx, efx_reg(efx, ER_GZ_EVQ_INT_PRIME));
	efx->ef10_resources.hdr.next = efx->irq_resources ?
				       &efx->irq_resources->hdr : NULL;

	efx->dl_nic.dl_info = &efx->ef10_resources.hdr;
#endif
#endif

	/* in case the MC rebooted while we were stopped, consume the change
	 * to the warm reboot count
	 */
	(void) efx_mcdi_poll_reboot(efx);

	return 0;
}

/* Initiate a packet transmission.  We use one channel per CPU
 * (sharing when we have more CPUs than channels).
 *
 * Context: non-blocking.
 * Note that returning anything other than NETDEV_TX_OK will cause the
 * OS to free the skb.
 */
static netdev_tx_t ef100_hard_start_xmit(struct sk_buff *skb,
					 struct net_device *net_dev)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	return __ef100_hard_start_xmit(skb, efx, net_dev, NULL);
}

netdev_tx_t __ef100_hard_start_xmit(struct sk_buff *skb,
				    struct efx_nic *efx,
				    struct net_device *net_dev,
				    struct efx_rep *efv)
{
	struct efx_tx_queue *tx_queue;
	struct efx_channel *channel;
	int rc;

#ifdef CONFIG_SFC_TRACING
	trace_sfc_transmit(skb, net_dev);
#endif
	channel = efx_get_tx_channel(efx, skb_get_queue_mapping(skb));
	netif_vdbg(efx, tx_queued, net_dev,
		   "%s len %d data %d channel %d\n", __FUNCTION__,
		   skb->len, skb->data_len, channel ? channel->channel : -1);
	if (!efx_channels(efx) || !efx_tx_channels(efx) || !channel ||
	    !channel->tx_queue_count) {
		netif_err(efx, tx_err, net_dev,
			  "Bad TX channel (%u; %u; %d), stopping queue\n",
			  efx_channels(efx), efx_tx_channels(efx),
			  channel ? channel->tx_queue_count : -1);
		netif_stop_queue(net_dev);
		goto err;
	}

	tx_queue = &channel->tx_queues[0];
	rc = __ef100_enqueue_skb(tx_queue, skb, efv);
	if (rc == 0)
		return NETDEV_TX_OK;

err:
	net_dev->stats.tx_dropped++;
	return NETDEV_TX_OK;
}

#if defined(EFX_NOT_UPSTREAM)
static int ef100_do_siocefx(struct net_device *net_dev, struct ifreq *ifr,
			    void __user *data)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	struct efx_sock_ioctl __user *user_data = data;
	u16 efx_cmd;
	int rc;

	if (copy_from_user(&efx_cmd, &user_data->cmd, sizeof(efx_cmd)))
		return -EFAULT;
	rc = efx_private_ioctl_common(efx, efx_cmd, &user_data->u);
	if (rc == -EOPNOTSUPP)
		netif_err(efx, drv, efx->net_dev,
			  "unknown private ioctl cmd %x\n", efx_cmd);
	return rc;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SIOCDEVPRIVATE)
static int ef100_siocdevprivate(struct net_device *net_dev, struct ifreq *ifr,
				void __user *data, int cmd)
{
	if (cmd == SIOCEFX)
		return ef100_do_siocefx(net_dev, ifr, data);
	return -EOPNOTSUPP;
}
#else
static int ef100_ioctl(struct net_device *net_dev, struct ifreq *ifr, int cmd)
{
	if (cmd == SIOCEFX)
		return ef100_do_siocefx(net_dev, ifr, ifr->ifr_data);
	return -EOPNOTSUPP;
}
#endif
#endif

#if defined(EFX_USE_KCOMPAT) && defined(EFX_TC_OFFLOAD) && !defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER) && !defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER)
#ifdef EFX_HAVE_NDO_UDP_TUNNEL_ADD
#include "net/udp_tunnel.h"
static int ef100_udp_tunnel_type_map(enum udp_parsable_tunnel_type in)
{
	switch (in) {
	case UDP_TUNNEL_TYPE_VXLAN:
		return EFX_ENCAP_TYPE_VXLAN;
	case UDP_TUNNEL_TYPE_GENEVE:
		return EFX_ENCAP_TYPE_GENEVE;
	default:
		return EFX_ENCAP_TYPE_NONE;
	}
}

static void ef100_udp_tunnel_add(struct net_device *dev, struct udp_tunnel_info *ti)
{
	struct efx_nic *efx = efx_netdev_priv(dev);
	struct ef100_udp_tunnel tnl;

	tnl.type = ef100_udp_tunnel_type_map(ti->type);
	if (tnl.type == EFX_ENCAP_TYPE_NONE)
		return;

	tnl.port = ti->port;

	if (efx->type->udp_tnl_add_port2)
		efx->type->udp_tnl_add_port2(efx, tnl);
}

static void ef100_udp_tunnel_del(struct net_device *dev, struct udp_tunnel_info *ti)
{
	struct efx_nic *efx = efx_netdev_priv(dev);
	struct ef100_udp_tunnel tnl;

	tnl.type = ef100_udp_tunnel_type_map(ti->type);
	if (tnl.type == EFX_ENCAP_TYPE_NONE)
		return;

	tnl.port = ti->port;

	if (efx->type->udp_tnl_del_port2)
		efx->type->udp_tnl_del_port2(efx, tnl);
}
#else
#ifdef EFX_HAVE_NDO_ADD_VXLAN_PORT
void ef100_vxlan_add_port(struct net_device *dev, sa_family_t sa_family,
			  __be16 port)
{
	struct ef100_udp_tunnel tnl = {.port = port,
				       .type = EFX_ENCAP_TYPE_VXLAN};
	struct efx_nic *efx = efx_netdev_priv(dev);

	if (efx->type->udp_tnl_add_port2)
		efx->type->udp_tnl_add_port2(efx, tnl);
}

void ef100_vxlan_del_port(struct net_device *dev, sa_family_t sa_family,
			  __be16 port)
{
	struct ef100_udp_tunnel tnl = {.port = port,
				       .type = EFX_ENCAP_TYPE_VXLAN};
	struct efx_nic *efx = efx_netdev_priv(dev);

	if (efx->type->udp_tnl_del_port2)
		efx->type->udp_tnl_del_port2(efx, tnl);
}
#endif
#ifdef EFX_HAVE_NDO_ADD_GENEVE_PORT
void ef100_geneve_add_port(struct net_device *dev, sa_family_t sa_family,
			   __be16 port)
{
	struct ef100_udp_tunnel tnl = {.port = port,
				       .type = EFX_ENCAP_TYPE_GENEVE};
	struct efx_nic *efx = efx_netdev_priv(dev);

	if (efx->type->udp_tnl_add_port2)
		efx->type->udp_tnl_add_port2(efx, tnl);
}

void ef100_geneve_del_port(struct net_device *dev, sa_family_t sa_family,
			   __be16 port)
{
	struct ef100_udp_tunnel tnl = {.port = port,
				       .type = EFX_ENCAP_TYPE_GENEVE};
	struct efx_nic *efx = efx_netdev_priv(dev);

	if (efx->type->udp_tnl_del_port2)
		efx->type->udp_tnl_del_port2(efx, tnl);
}
#endif
#endif
#endif

static const struct net_device_ops ef100_netdev_ops = {
	.ndo_open               = ef100_net_open,
	.ndo_stop               = ef100_net_stop,
	.ndo_start_xmit         = ef100_hard_start_xmit,
	.ndo_tx_timeout         = efx_watchdog,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_STATS64)
	.ndo_get_stats64        = efx_net_stats,
#else
	.ndo_get_stats		= efx_net_stats,
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NDO_EXT_CHANGE_MTU)
	.extended.ndo_change_mtu = efx_change_mtu,
#else
	.ndo_change_mtu         = efx_change_mtu,
#endif
	.ndo_validate_addr      = eth_validate_addr,
#if defined(EFX_NOT_UPSTREAM)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SIOCDEVPRIVATE)
	.ndo_siocdevprivate     = ef100_siocdevprivate,
#else
	.ndo_do_ioctl           = ef100_ioctl,
#endif
#endif
	.ndo_set_mac_address    = efx_set_mac_address,
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_NDO_SET_MULTICAST_LIST)
	.ndo_set_rx_mode        = efx_set_rx_mode, /* Lookout */
#else
	/* On older kernel versions, set_rx_mode is expected to
	 * support multiple unicast addresses and set_multicast_list
	 * is expected to support only one.  On newer versions the
	 * IFF_UNICAST_FLT flag distinguishes these.
	 */
	.ndo_set_multicast_list = efx_set_rx_mode,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_FEATURES)
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	.ndo_fix_features       = efx_fix_features,
#endif
	.ndo_set_features       = efx_set_features,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_VLAN_RX_ADD_VID)
	.ndo_vlan_rx_add_vid    = efx_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid   = efx_vlan_rx_kill_vid,
#endif
#if 0
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
	.ndo_set_vf_spoofchk    = efx_sriov_set_vf_spoofchk,
#endif
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PHYS_PORT_ID)
	.ndo_get_phys_port_id   = efx_get_phys_port_id,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PHYS_PORT_NAME)
#ifndef CONFIG_NET_DEVLINK
	.ndo_get_phys_port_name = efx_get_phys_port_name,
#endif
#endif
#if 0
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_HAVE_VLAN_RX_PATH)
	.ndo_vlan_rx_register   = efx_vlan_rx_register,
#endif
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_NDO_POLL_CONTROLLER)
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller    = efx_netpoll,
#endif
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NDO_BUSY_POLL)
#ifdef CONFIG_NET_RX_BUSY_POLL
	.ndo_busy_poll          = efx_busy_poll,
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_NETDEV_RFS_INFO)
#ifdef CONFIG_RFS_ACCEL
	.ndo_rx_flow_steer      = efx_filter_rfs,
#endif
#endif

#if defined(EFX_USE_KCOMPAT) && defined(EFX_TC_OFFLOAD) && !defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER) && !defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER)
#ifdef EFX_HAVE_NDO_UDP_TUNNEL_ADD
	.ndo_udp_tunnel_add     = ef100_udp_tunnel_add,
	.ndo_udp_tunnel_del     = ef100_udp_tunnel_del,
#else
#ifdef EFX_HAVE_NDO_ADD_VXLAN_PORT
	.ndo_add_vxlan_port     = ef100_vxlan_add_port,
	.ndo_del_vxlan_port     = ef100_vxlan_del_port,
#endif
#ifdef EFX_HAVE_NDO_ADD_GENEVE_PORT
	.ndo_add_geneve_port    = ef100_geneve_add_port,
	.ndo_del_geneve_port    = ef100_geneve_del_port,
#endif
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP)
	.ndo_bpf                = efx_xdp,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_REDIR)
	.ndo_xdp_xmit           = efx_xdp_xmit,
#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_XDP_FLUSH)
	.ndo_xdp_flush          = efx_xdp_flush,
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
	.ndo_setup_tc		= efx_setup_tc,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_DEVLINK)
#ifdef CONFIG_NET_DEVLINK
	.ndo_get_devlink_port	= efx_get_devlink_port,
#endif
#endif

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NDO_SIZE)
	.ndo_size               = sizeof(struct net_device_ops),
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NDO_SIZE_RH)
	.ndo_size_rh            = sizeof(struct net_device_ops),
#endif
};

/*	Netdev registration
 */
int ef100_netdev_event(struct notifier_block *this,
		       unsigned long event, void *ptr)
{
	struct efx_nic *efx = container_of(this, struct efx_nic, netdev_notifier);
	struct net_device *net_dev = netdev_notifier_info_to_dev(ptr);
	struct ef100_nic_data *nic_data = efx->nic_data;
	int err;

	if (efx->net_dev == net_dev &&
	    (event == NETDEV_CHANGENAME || event == NETDEV_REGISTER))
		ef100_update_name(efx);

	if (!nic_data->grp_mae)
		return NOTIFY_DONE;
	err = efx_tc_netdev_event(efx, event, net_dev);
	if (err & NOTIFY_STOP_MASK)
		return err;

	return NOTIFY_DONE;
}

int ef100_netevent_event(struct notifier_block *this, unsigned long event,
			 void *ptr)
{
	struct efx_nic *efx = container_of(this, struct efx_nic, netevent_notifier);
	struct ef100_nic_data *nic_data = efx->nic_data;
	int err;

	if (!nic_data->grp_mae)
		return NOTIFY_DONE;
	err = efx_tc_netevent_event(efx, event, ptr);
	if (err & NOTIFY_STOP_MASK)
		return err;

	return NOTIFY_DONE;
};

static int ef100_register_netdev(struct efx_nic *efx)
{
	struct net_device *net_dev = efx->net_dev;
	int rc;

	net_dev->watchdog_timeo = 5 * HZ;
	net_dev->irq = efx->pci_dev->irq;
	net_dev->netdev_ops = &ef100_netdev_ops;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NETDEV_MTU_LIMITS)
	net_dev->min_mtu = EFX_MIN_MTU;
	net_dev->max_mtu = EFX_100_MAX_MTU;
#elif defined(EFX_HAVE_NETDEV_EXT_MTU_LIMITS)
	net_dev->extended->min_mtu = EFX_MIN_MTU;
	net_dev->extended->max_mtu = EFX_100_MAX_MTU;
#endif
	net_dev->ethtool_ops = &ef100_ethtool_ops;

	rtnl_lock();

	rc = dev_alloc_name(net_dev, net_dev->name);
	if (rc < 0)
		goto fail_locked;
	ef100_update_name(efx);

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

static void ef100_unregister_netdev(struct efx_nic *efx)
{
	if (efx_dev_registered(efx)) {
		efx_fini_devlink(efx);
		efx_fini_mcdi_logging(efx);
		efx->state = STATE_PROBED;
		unregister_netdev(efx->net_dev);
	}
}

void ef100_remove_netdev(struct efx_probe_data *probe_data)
{
	struct efx_nic *efx = &probe_data->efx;

	if (!efx->net_dev)
		return;

	rtnl_lock();
#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	if (efx_dl_supported(efx))
		efx_dl_unregister_nic(&efx->dl_nic);
#endif
#endif
	dev_close(efx->net_dev);
	rtnl_unlock();

	/* Unregistering our netdev notifier triggers unbinding of TC indirect
	 * blocks, so we have to do it before PCI removal.
	 */
	unregister_netdevice_notifier(&efx->netdev_notifier);
	unregister_netevent_notifier(&efx->netevent_notifier);

	ef100_unregister_netdev(efx);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP)
	rtnl_lock();
	efx_xdp_setup_prog(efx, NULL);
	rtnl_unlock();
#endif

	efx_ef100_fini_reps(efx);
	if (!efx->type->is_vf) {
#if defined(CONFIG_SFC_SRIOV)
		efx_ef100_pci_sriov_disable(efx, true);
#endif
		efx_fini_tc(efx);
		efx_fini_mae(efx);
	}

#ifdef CONFIG_SFC_DEBUGFS
	mutex_lock(&efx->debugfs_symlink_mutex);
	efx_fini_debugfs_netdev(efx->net_dev);
	mutex_unlock(&efx->debugfs_symlink_mutex);
#endif

	efx_mcdi_filter_table_remove(efx);
	efx_fini_interrupts(efx);
	efx_mcdi_mac_fini_stats(efx);
	kfree(efx->phy_data);
	efx->phy_data = NULL;

	efx_mcdi_mon_remove(efx);

	free_netdev(efx->net_dev);
	efx->net_dev = NULL;
	efx->state = STATE_PROBED;
}

int ef100_probe_netdev(struct efx_probe_data *probe_data)
{
	struct efx_nic *efx = &probe_data->efx;
	struct ef100_nic_data *nic_data;
	struct efx_probe_data **probe_ptr;
	struct net_device *net_dev;
	int rc;

#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_TC_OFFLOAD)
	if (efx->mcdi->fn_flags &
	    (1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_NO_ACTIVE_PORT)) {
		return 0;
	}
#endif

	/* Allocate and initialise a struct net_device */
	net_dev = alloc_etherdev_mq(sizeof(probe_data), EFX_MAX_CORE_TX_QUEUES);
	if (!net_dev)
		return -ENOMEM;
	probe_ptr = netdev_priv(net_dev);
	*probe_ptr = probe_data;
	efx->net_dev = net_dev;
	SET_NETDEV_DEV(net_dev, &efx->pci_dev->dev);

	/* enable all supported features except rx-fcs and rx-all */
	net_dev->features |= efx->type->offload_features &
			     ~(NETIF_F_RXFCS | NETIF_F_RXALL);
	efx_add_hw_features(efx, efx->type->offload_features);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_VLAN_FEATURES)
	net_dev->vlan_features |= (NETIF_F_HW_CSUM | NETIF_F_SG |
				   NETIF_F_HIGHDMA | NETIF_F_ALL_TSO);
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_HW_ENC_FEATURES)
	net_dev->hw_enc_features |= efx->type->offload_features;
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_GSO_MAX_SEGS)
	if (!READ_ONCE(net_dev->gso_max_segs))
		netif_set_gso_max_segs(net_dev,
				       ESE_EF100_DP_GZ_TSO_MAX_HDR_NUM_SEGS_DEFAULT);
#endif
	efx->mdio.dev = net_dev;
#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	efx_dl_probe(efx);
	efx->ef10_resources = efx->type->ef10_resources;
	efx->n_dl_irqs = EF100_ONLOAD_IRQS;
#endif
	efx_nic_check_pcie_link(efx, EFX_BW_PCIE_GEN3_X16, NULL, NULL);
#endif

	rc = efx_ef100_init_datapath_caps(efx);
	if (rc < 0)
		goto fail;

	rc = efx_mcdi_mon_probe(efx);
	if (rc && rc != -EPERM)
		netif_warn(efx, drv, efx->net_dev, "could not init sensors\n");

	rc = ef100_phy_probe(efx);
	if (rc)
		goto fail;

	rc = efx_mcdi_mac_init_stats(efx);
	if (rc)
		goto fail;

	nic_data = efx->nic_data;
	if (nic_data->grp_mae) {
		rc = efx_init_struct_tc(efx);
		if (rc)
			goto fail;
	}

	rc = efx_init_interrupts(efx);
	if (rc < 0)
		goto fail;

	/* Update maximum channel count for ethtool */
	efx->max_channels = min_t(u16, efx->max_channels, efx->max_irqs);
	efx->max_tx_channels = efx->max_channels;

	rc = ef100_filter_table_probe(efx);
	if (rc)
		goto fail;

	/* Add unspecified VID to support VLAN filtering being disabled */
	rc = efx_mcdi_filter_add_vlan(efx, EFX_FILTER_VID_UNSPEC);
	if (rc)
		goto fail;

	/* If VLAN filtering is enabled, we need VID 0 to get untagged
	 * traffic.  It is added automatically if 8021q module is loaded,
	 * but we can't rely on it since module may be not loaded.
	 */
	rc = efx_mcdi_filter_add_vlan(efx, 0);
	if (rc)
		goto fail;

	netdev_rss_key_fill(efx->rss_context.rx_hash_key,
			    sizeof(efx->rss_context.rx_hash_key));

	/* Don't fail init if RSS setup doesn't work. */
	efx_mcdi_push_default_indir_table(efx, efx->n_rss_channels);

	rc = ef100_get_mac_address(efx, net_dev->perm_addr, CLIENT_HANDLE_SELF,
				   efx->type->is_vf);
	if (rc)
		return rc;
	/* Assign MAC address */
	eth_hw_addr_set(net_dev, net_dev->perm_addr);
	ether_addr_copy(nic_data->port_id, net_dev->perm_addr);

	if (!efx->type->is_vf) {
		rc = ef100_probe_netdev_pf(efx);
		if (rc)
			goto fail;
	}

	rc = ef100_register_netdev(efx);
	if (rc)
		goto fail;

	efx->netdev_notifier.notifier_call = ef100_netdev_event;
	rc = register_netdevice_notifier(&efx->netdev_notifier);
	if (rc) {
		netif_err(efx, probe, efx->net_dev,
			  "Failed to register netdevice notifier, rc=%d\n", rc);
		goto fail;
	}

	efx->netevent_notifier.notifier_call = ef100_netevent_event;
	rc = register_netevent_notifier(&efx->netevent_notifier);
	if (rc) {
		netif_err(efx, probe, efx->net_dev,
			  "Failed to register netevent notifier, rc=%d\n", rc);
		goto fail;
	}

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	if (efx_dl_supported(efx)) {
		rtnl_lock();
		efx_dl_register_nic(&efx->dl_nic);
		rtnl_unlock();
	}
#endif
#endif

fail:
	return rc;
}
