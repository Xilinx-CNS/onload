/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2018 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "net_driver.h"
#include <linux/filter.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/aer.h>
#include "efx_common.h"
#include "efx_channels.h"
#include "efx.h"
#include "mcdi.h"
#include "debugfs.h"
#include "mcdi_port_common.h"
#include "selftest.h"
#include "rx_common.h"
#include "tx_common.h"
#include "nic.h"
#include "io.h"
#include "tc.h"
#include "dump.h"
#include "mcdi_pcol.h"
#include "tc.h"
#include "xdp.h"
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_ADD_VXLAN_PORT) || defined(EFX_HAVE_NDO_UDP_TUNNEL_ADD) || defined(EFX_HAVE_UDP_TUNNEL_NIC_INFO)
#include <net/gre.h>
#endif
#ifdef EFX_NOT_UPSTREAM
#include "ef100_dump.h"
#endif
#ifdef CONFIG_SFC_VDPA
#include "ef100_vdpa.h"
#endif

static unsigned int debug = (NETIF_MSG_DRV | NETIF_MSG_PROBE |
		NETIF_MSG_LINK | NETIF_MSG_IFDOWN |
		NETIF_MSG_IFUP | NETIF_MSG_RX_ERR |
		NETIF_MSG_TX_ERR | NETIF_MSG_HW);
module_param(debug, uint, 0);
MODULE_PARM_DESC(debug, "Bitmapped debugging message enable value");

/* This is the time (in ms) between invocations of the hardware
 * monitor.
 */
unsigned int monitor_interval_ms = 200;
module_param(monitor_interval_ms, uint, 0644);
MODULE_PARM_DESC(monitor_interval_ms, "Bus state test interval in ms");

#ifdef EFX_NOT_UPSTREAM
static bool phy_power_follows_link;
module_param(phy_power_follows_link, bool, 0444);
MODULE_PARM_DESC(phy_power_follows_link,
		"Power down phy when interface is administratively down");

static bool link_down_on_reset;
module_param(link_down_on_reset, bool, 0444);
MODULE_PARM_DESC(link_down_on_reset,
		 "Signal the link down and up on resets");
#endif

/* How often and how many times to poll for a reset while waiting for a
 * BIST that another function started to complete.
 */
#define BIST_WAIT_DELAY_MS      100
#define BIST_WAIT_DELAY_COUNT   300

/* Default stats update time */
#define STATS_PERIOD_MS_DEFAULT 1000


static const unsigned int efx_reset_type_max = RESET_TYPE_MAX;
static const char *const efx_reset_type_names[] = {
	[RESET_TYPE_INVISIBLE]          = "INVISIBLE",
	[RESET_TYPE_ALL]                = "ALL",
	[RESET_TYPE_RECOVER_OR_ALL]     = "RECOVER_OR_ALL",
	[RESET_TYPE_WORLD]              = "WORLD",
	[RESET_TYPE_DATAPATH]           = "DATAPATH",
	[RESET_TYPE_MC_BIST]            = "MC_BIST",
	[RESET_TYPE_DISABLE]            = "DISABLE",
	[RESET_TYPE_TX_WATCHDOG]        = "TX_WATCHDOG",
	[RESET_TYPE_INT_ERROR]          = "INT_ERROR",
	[RESET_TYPE_DMA_ERROR]          = "DMA_ERROR",
	[RESET_TYPE_TX_SKIP]            = "TX_SKIP",
	[RESET_TYPE_MC_FAILURE]         = "MC_FAILURE",
	[RESET_TYPE_MCDI_TIMEOUT]       = "MCDI_TIMEOUT (FLR)",
};
#define RESET_TYPE(type) \
	STRING_TABLE_LOOKUP(type, efx_reset_type)

/* Loopback mode names (see LOOPBACK_MODE()) */
const unsigned int efx_loopback_mode_max = LOOPBACK_MAX;
const char *const efx_loopback_mode_names[] = {
	[LOOPBACK_NONE]         = "NONE",
	[LOOPBACK_DATA]         = "DATAPATH",
	[LOOPBACK_GMAC]         = "GMAC",
	[LOOPBACK_XGMII]        = "XGMII",
	[LOOPBACK_XGXS]         = "XGXS",
	[LOOPBACK_XAUI]         = "XAUI",
	[LOOPBACK_GMII]         = "GMII",
	[LOOPBACK_SGMII]        = "SGMII",
	[LOOPBACK_XGBR]         = "XGBR",
	[LOOPBACK_XFI]          = "XFI",
	[LOOPBACK_XAUI_FAR]     = "XAUI_FAR",
	[LOOPBACK_GMII_FAR]     = "GMII_FAR",
	[LOOPBACK_SGMII_FAR]    = "SGMII_FAR",
	[LOOPBACK_XFI_FAR]      = "XFI_FAR",
	[LOOPBACK_GPHY]         = "GPHY",
	[LOOPBACK_PHYXS]        = "PHYXS",
	[LOOPBACK_PCS]          = "PCS",
	[LOOPBACK_PMAPMD]       = "PMA/PMD",
	[LOOPBACK_XPORT]        = "XPORT",
	[LOOPBACK_XGMII_WS]     = "XGMII_WS",
	[LOOPBACK_XAUI_WS]      = "XAUI_WS",
	[LOOPBACK_XAUI_WS_FAR]  = "XAUI_WS_FAR",
	[LOOPBACK_XAUI_WS_NEAR] = "XAUI_WS_NEAR",
	[LOOPBACK_GMII_WS]      = "GMII_WS",
	[LOOPBACK_XFI_WS]       = "XFI_WS",
	[LOOPBACK_XFI_WS_FAR]   = "XFI_WS_FAR",
	[LOOPBACK_PHYXS_WS]     = "PHYXS_WS",
};

#ifdef EFX_NOT_UPSTREAM
#if IS_MODULE(CONFIG_SFC_DRIVERLINK)
static struct efx_dl_ops efx_driverlink_ops;
#endif
#endif

/* Reset workqueue. If any NIC has a hardware failure then a reset will be
 * queued onto this work queue. This is not a per-nic work queue, because
 * efx_reset_work() acquires the rtnl lock, so resets are naturally serialised.
 */
static struct workqueue_struct *reset_workqueue;

int efx_create_reset_workqueue(void)
{
	reset_workqueue = create_singlethread_workqueue("sfc_reset");
	if (!reset_workqueue) {
		printk(KERN_ERR "Failed to create reset workqueue\n");
		return -ENOMEM;
	}

	return 0;
}

void efx_queue_reset_work(struct efx_nic *efx)
{
	queue_work(reset_workqueue, &efx->reset_work);
}

void efx_flush_reset_workqueue(struct efx_nic *efx)
{
	cancel_work_sync(&efx->reset_work);
}

void efx_destroy_reset_workqueue(void)
{
	if (reset_workqueue) {
		destroy_workqueue(reset_workqueue);
		reset_workqueue = NULL;
	}
}

/* We assume that efx->type->reconfigure_mac will always try to sync RX
 * filters and therefore needs to read-lock the filter table against freeing
 */
int efx_mac_reconfigure(struct efx_nic *efx, bool mtu_only)
{
	int rc = 0;

	WARN_ON(!mutex_is_locked(&efx->mac_lock));

	if (efx->type->reconfigure_mac) {
		down_read(&efx->filter_sem);
		rc = efx->type->reconfigure_mac(efx, mtu_only);
		up_read(&efx->filter_sem);
	}
	return rc;
}

/* Asynchronous work item for changing MAC promiscuity and multicast
 * hash.  Avoid a drain/rx_ingress enable by reconfiguring the current
 * MAC directly. */
static void efx_mac_work(struct work_struct *data)
{
	struct efx_nic *efx = container_of(data, struct efx_nic, mac_work);

	mutex_lock(&efx->mac_lock);
	if (efx->port_enabled)
		(void)efx_mac_reconfigure(efx, false);
	mutex_unlock(&efx->mac_lock);
}

int efx_set_mac_address(struct net_device *net_dev, void *data)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	struct sockaddr *addr = data;
	const u8 *new_addr = addr->sa_data;
	u8 old_addr[6];
	int rc;

	if (!is_valid_ether_addr(new_addr)) {
		netif_err(efx, drv, efx->net_dev,
			  "invalid ethernet MAC address requested: %pM\n",
			  new_addr);
		return -EADDRNOTAVAIL;
	}

	ether_addr_copy(old_addr, net_dev->dev_addr); /* save old address */
	eth_hw_addr_set(net_dev, new_addr);

	if (efx->type->set_mac_address) {
		rc = efx->type->set_mac_address(efx);
		if (rc) {
			eth_hw_addr_set(net_dev, old_addr);
			return rc;
		}
	}

	/* Reconfigure the MAC */
	mutex_lock(&efx->mac_lock);
	(void)efx_mac_reconfigure(efx, false);
	mutex_unlock(&efx->mac_lock);

	return 0;
}

/* Context: netif_addr_lock held, BHs disabled. */
void efx_set_rx_mode(struct net_device *net_dev)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx->port_enabled)
		schedule_work(&efx->mac_work);

	/* Otherwise efx_start_port() will do this */
}

/* This ensures that the kernel is kept informed (via
 * netif_carrier_on/off) of the link status, and also maintains the
 * link status's stop on the port's TX queue.
 */
void efx_link_status_changed(struct efx_nic *efx)
{
	struct efx_link_state *link_state = &efx->link_state;
	bool kernel_link_up;

	/* SFC Bug 5356: A net_dev notifier is registered, so we must ensure
	 * that no events are triggered between unregister_netdev() and the
	 * driver unloading. A more general condition is that NETDEV_CHANGE
	 * can only be generated between NETDEV_UP and NETDEV_DOWN
	 */
	if ((efx->type->revision != EFX_REV_EF100) &&
	    !netif_running(efx->net_dev))
		return;

	kernel_link_up = netif_carrier_ok(efx->net_dev);

	if (link_state->up != kernel_link_up) {
		efx->n_link_state_changes++;

		if (link_state->up)
			netif_carrier_on(efx->net_dev);
		else
			netif_carrier_off(efx->net_dev);
	}

	/* Status message for kernel log */
	if (!net_ratelimit())
		return;

	if (link_state->up) {
		netif_info(efx, link, efx->net_dev,
			   "link up at %uMbps %s-duplex (MTU %d)%s%s%s\n",
			   link_state->speed, link_state->fd ? "full" : "half",
			   efx->net_dev->mtu,
			   (efx->loopback_mode ? " [" : ""),
			   (efx->loopback_mode ? LOOPBACK_MODE(efx) : ""),
			   (efx->loopback_mode ? " LOOPBACK]" : ""));

		if ((efx->wanted_fc & EFX_FC_AUTO) &&
		    (efx->wanted_fc & EFX_FC_TX) &&
		    (~efx->link_state.fc & EFX_FC_TX))
			/* There is no way to report this state
			 * through ethtool, so print this information
			 * to the kernel log
			 */
			netif_info(efx, link, efx->net_dev,
				   "Flow control autonegotiated tx OFF (wanted ON)\n");
	} else if (kernel_link_up) {
		netif_info(efx, link, efx->net_dev, "link down%s\n",
			   (efx->phy_mode & PHY_MODE_LOW_POWER) ? " [OFF]" : "");
	}

}

/* Context: process, rtnl_lock() held. */
int efx_change_mtu(struct net_device *net_dev, int new_mtu)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	int old_mtu;
	int rc;

	rc = efx_check_disabled(efx);
	if (rc)
		return rc;

#if defined(EFX_USE_KCOMPAT) && !(defined(EFX_HAVE_NETDEV_MTU_LIMITS) || defined(EFX_HAVE_NETDEV_EXT_MTU_LIMITS))
	if (new_mtu > (efx_nic_rev(efx) == EFX_REV_EF100? EFX_100_MAX_MTU: EFX_MAX_MTU)) {
		netif_err(efx, drv, efx->net_dev,
			  "Requested MTU of %d too big (max: %d)\n",
			  new_mtu, EFX_MAX_MTU);
		return -EINVAL;
	}
	if (new_mtu < EFX_MIN_MTU) {
		netif_err(efx, drv, efx->net_dev,
			  "Requested MTU of %d too small (min: %d)\n",
			  new_mtu, EFX_MIN_MTU);
		return -EINVAL;
	}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP)
	if (rtnl_dereference(efx->xdp_prog) &&
	    new_mtu > efx_xdp_max_mtu(efx)) {
		netif_err(efx, drv, efx->net_dev,
			  "Requested MTU of %d too big for XDP (max: %d)\n",
			  new_mtu, efx_xdp_max_mtu(efx));
		return -EINVAL;
	}
#endif

	netif_dbg(efx, drv, efx->net_dev, "changing MTU to %d\n", new_mtu);

	efx_device_detach_sync(efx);
	efx_stop_all(efx);

	mutex_lock(&efx->mac_lock);
	old_mtu = net_dev->mtu;
	net_dev->mtu = new_mtu;
	rc = efx_mac_reconfigure(efx, true);
	if (rc)
		net_dev->mtu = old_mtu;
	mutex_unlock(&efx->mac_lock);

	if (efx->state == STATE_NET_UP)
		efx_start_all(efx);
	efx_device_attach_if_not_resetting(efx);

	/*
	 * Reinsert filters as the previous call to efx_mac_reconfigure, being
	 * called on a detached device, will not have done so.
	 */
	if (!rc && (efx->state != STATE_DISABLED) && !efx->reset_pending) {
		mutex_lock(&efx->mac_lock);
		rc = efx_mac_reconfigure(efx, false);
		mutex_unlock(&efx->mac_lock);
		netif_info(efx, link, net_dev, "MTU changed to %d\n", new_mtu);
	}
	return rc;
}

#ifdef EFX_NOT_UPSTREAM
#if IS_MODULE(CONFIG_SFC_DRIVERLINK)
/* Is Driverlink supported on this device? */
bool efx_dl_supported(struct efx_nic *efx)
{
	if (!efx->mcdi || !efx->dl_nic.ops)
		return false;

	/* VI spreading will confuse driverlink clients, so prevent
	 * registration if it's in use.
	 */
	if (efx->mcdi->fn_flags &
	    (1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_TX_ONLY_VI_SPREADING_ENABLED)) {
		netif_info(efx, drv, efx->net_dev,
			   "Driverlink disabled: VI spreading in use\n");
		return false;
	}

	return true;
}
#endif
#endif

/**************************************************************************
 *
 * Hardware monitor
 *
 **************************************************************************/

/* Run periodically off the general workqueue */
static void efx_monitor(struct work_struct *data)
{
	struct efx_nic *efx = container_of(data, struct efx_nic,
			monitor_work.work);

	netif_vdbg(efx, timer, efx->net_dev,
		   "hardware monitor executing on CPU %d\n",
		   raw_smp_processor_id());
	WARN_ON_ONCE(!efx->type->monitor);

	/* If the mac_lock is already held then it is likely a port
	 * reconfiguration is already in place, which will likely do
	 * most of the work of monitor() anyway.
	 */
	if (mutex_trylock(&efx->mac_lock)) {
		if (efx->port_enabled && efx->type->monitor)
			efx->type->monitor(efx);
		mutex_unlock(&efx->mac_lock);
	}

	efx_start_monitor(efx);
}

void efx_start_monitor(struct efx_nic *efx)
{
	if (efx->type->monitor != NULL)
		schedule_delayed_work(&efx->monitor_work,
				      msecs_to_jiffies(monitor_interval_ms));
}

/**************************************************************************
 *
 * Device reset and suspend
 *
 **************************************************************************/
/* Channels are shutdown and reinitialised whilst the NIC is running
 * to propagate configuration changes (mtu, checksum offload), or
 * to clear hardware error conditions
 */
static int efx_start_datapath(struct efx_nic *efx)
{
	bool old_rx_scatter = efx->rx_scatter;
	size_t rx_page_buf_step;
	int rc = 0;
	netdev_features_t old_features = efx->net_dev->features;
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	bool old_lro_available = efx->lro_available;

	efx->lro_available = true;
#endif

	/* Calculate the rx buffer allocation parameters required to
	 * support the current MTU, including padding for header
	 * alignment and overruns.
	 */
	efx->rx_dma_len = (efx->rx_prefix_size +
			   EFX_MAX_FRAME_LEN(efx->net_dev->mtu) +
			   efx->type->rx_buffer_padding);
	rx_page_buf_step = efx_rx_buffer_step(efx);
	if (rx_page_buf_step <= PAGE_SIZE) {
		efx->rx_scatter = efx->type->always_rx_scatter;
		efx->rx_buffer_order = 0;
	} else if (efx->type->can_rx_scatter) {
		BUILD_BUG_ON(EFX_RX_USR_BUF_SIZE % L1_CACHE_BYTES);
#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
		BUILD_BUG_ON(sizeof(struct efx_rx_page_state) +
			     2 * ALIGN(NET_IP_ALIGN + EFX_RX_USR_BUF_SIZE,
				       EFX_RX_BUF_ALIGNMENT) +
			     XDP_PACKET_HEADROOM > PAGE_SIZE);
#endif
		efx->rx_scatter = true;
		efx->rx_dma_len = EFX_RX_USR_BUF_SIZE;
		efx->rx_buffer_order = 0;
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
		efx->lro_available = false;
#endif
	} else {
		efx->rx_scatter = false;
		efx->rx_buffer_order = get_order(rx_page_buf_step);
	}

	efx_rx_config_page_split(efx);
	if (efx->rx_buffer_order)
		netif_dbg(efx, drv, efx->net_dev,
			  "RX buf len=%u; page order=%u batch=%u\n",
			  efx->rx_dma_len, efx->rx_buffer_order,
			  efx->rx_pages_per_batch);
	else
		netif_dbg(efx, drv, efx->net_dev,
			  "RX buf len=%u step=%u bpp=%u; page batch=%u\n",
			  efx->rx_dma_len, efx->rx_page_buf_step,
			  efx->rx_bufs_per_page, efx->rx_pages_per_batch);

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	/* This will call back into efx_fix_features() */
	if (efx->lro_available != old_lro_available)
		netdev_update_features(efx->net_dev);
#endif

	/* Restore previously fixed features in hw_features and remove
	 * features which are fixed now.
	 */
	efx->net_dev->hw_features |= efx->net_dev->features;
	efx->net_dev->hw_features &= ~efx->fixed_features;
	efx->net_dev->features |= efx->fixed_features;
	if (efx->net_dev->features != old_features)
		netdev_features_change(efx->net_dev);

	/* RX filters may also have scatter-enabled flags */
	if ((efx->rx_scatter != old_rx_scatter) &&
	    efx->type->filter_update_rx_scatter)
		efx->type->filter_update_rx_scatter(efx);

	if (efx->type->filter_table_up)
		rc = efx->type->filter_table_up(efx);
	if (rc)
		goto fail;

	/* We must keep at least one descriptor in a TX ring empty.
	 * We could avoid this when the queue size does not exactly
	 * match the hardware ring size, but it's not that important.
	 * Therefore we stop the queue when one more skb might fill
	 * the ring completely.  We wake it when half way back to
	 * empty.
	 */
	efx->txq_stop_thresh = efx->txq_entries -
			       efx->type->tx_max_skb_descs(efx);
	efx->txq_wake_thresh = efx->txq_stop_thresh / 2;

	rc = efx_start_channels(efx);
	if (rc)
		goto fail;

	efx_ptp_start_datapath(efx);

	efx->datapath_started = true;

	/* trigger MAC reconfiguration again to ensure filters get inserted */
	mutex_lock(&efx->mac_lock);
	efx_mac_reconfigure(efx, false);
	mutex_unlock(&efx->mac_lock);

	if (netif_device_present(efx->net_dev))
		netif_tx_wake_all_queues(efx->net_dev);

	return 0;
fail:
	efx_stop_channels(efx);

	if (efx->type->filter_table_down)
		efx->type->filter_table_down(efx);
	return rc;
}

static void efx_stop_datapath(struct efx_nic *efx)
{
	EFX_ASSERT_RESET_SERIALISED(efx);
	BUG_ON(efx->port_enabled);

	efx->datapath_started = false;

	efx_ptp_stop_datapath(efx);

	efx_stop_channels(efx);

	if (efx->type->filter_table_down)
		efx->type->filter_table_down(efx);
}

static void efx_start_port(struct efx_nic *efx)
{
	netif_dbg(efx, ifup, efx->net_dev, "start port\n");
	BUG_ON(efx->port_enabled);

	mutex_lock(&efx->mac_lock);
	efx->port_enabled = true;
	/* Always come out of low power unless we're forced off */
	if (!efx->phy_power_force_off)
		efx->phy_mode &= ~PHY_MODE_LOW_POWER;
	__efx_reconfigure_port(efx);

	/* Ensure MAC ingress/egress is enabled */
	(void)efx_mac_reconfigure(efx, false);

	mutex_unlock(&efx->mac_lock);
}

/* Cancel work for MAC reconfiguration, periodic hardware monitoring
 * and the async self-test, wait for them to finish and prevent them
 * being scheduled again.  This doesn't cover online resets, which
 * should only be cancelled when removing the device.
 */
static void efx_stop_port(struct efx_nic *efx)
{
	netif_dbg(efx, ifdown, efx->net_dev, "stop port\n");

	EFX_ASSERT_RESET_SERIALISED(efx);

	mutex_lock(&efx->mac_lock);
	efx->port_enabled = false;
	if (efx->phy_power_follows_link)
		efx->phy_mode |= PHY_MODE_LOW_POWER;
	__efx_reconfigure_port(efx);
	mutex_unlock(&efx->mac_lock);

	netif_addr_lock_bh(efx->net_dev);
	netif_addr_unlock_bh(efx->net_dev);

	cancel_delayed_work_sync(&efx->monitor_work);
	efx_selftest_async_cancel(efx);
	cancel_work_sync(&efx->mac_work);
}

/* If the interface is supposed to be running but is not, start
 * the hardware and software data path, regular activity for the port
 * (MAC statistics, link polling, etc.) and schedule the port to be
 * reconfigured.  Interrupts must already be enabled.  This function
 * is safe to call multiple times, so long as the NIC is not disabled.
 * Requires the RTNL lock.
 */
int efx_start_all(struct efx_nic *efx)
{
	int rc;

	EFX_ASSERT_RESET_SERIALISED(efx);

	/* Check that it is appropriate to restart the interface. All
	 * of these flags are safe to read under just the rtnl lock
	 */
	if (efx->state == STATE_DISABLED || efx->port_enabled ||
	    efx->reset_pending)
		return 0;

	efx_start_port(efx);
	rc = efx_start_datapath(efx);
	if (rc) {
		efx_stop_port(efx);
		return rc;
	}

	/* Start the hardware monitor if there is one */
	efx_start_monitor(efx);

	/* Link state detection is normally event-driven; we have
	 * to poll now because we could have missed a change
	 */
	mutex_lock(&efx->mac_lock);
	if (efx_mcdi_phy_poll(efx))
		efx_link_status_changed(efx);
	mutex_unlock(&efx->mac_lock);

	if (efx->type->start_stats)
		efx->type->start_stats(efx);
	else
		efx_mcdi_mac_start_stats(efx);
	efx->type->pull_stats(efx);
	efx->type->update_stats(efx, NULL, NULL);
	/* release stats_lock obtained in update_stats */
	spin_unlock_bh(&efx->stats_lock);

	return rc;
}

/* Quiesce the hardware and software data path, and regular activity
 * for the port without bringing the link down.  Safe to call multiple
 * times with the NIC in almost any state, but interrupts should be
 * enabled.  Requires the RTNL lock.
 */
void efx_stop_all(struct efx_nic *efx)
{
	EFX_ASSERT_RESET_SERIALISED(efx);

	/* port_enabled can be read safely under the rtnl lock */
	if (!efx->port_enabled)
		return;

	/* update stats before we go down so we can accurately count
	 * rx_nodesc_drops
	 */
	efx->type->update_stats(efx, NULL, NULL);
	/* release stats_lock obtained in update_stats */
	spin_unlock_bh(&efx->stats_lock);
	if (efx->type->stop_stats)
		efx->type->stop_stats(efx);
	else
		efx_mcdi_mac_stop_stats(efx);
	efx_stop_port(efx);

	/* Stop the kernel transmit interface.  This is only valid if
	 * the device is stopped or detached; otherwise the watchdog
	 * may fire immediately.
	 */
	WARN_ON(netif_running(efx->net_dev) &&
		netif_device_present(efx->net_dev));
	netif_tx_disable(efx->net_dev);

	efx_stop_datapath(efx);
}

/* Context: process, dev_base_lock or RTNL held, non-blocking. */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NETDEV_STATS64_VOID)
void efx_net_stats(struct net_device *net_dev, struct rtnl_link_stats64 *stats)
#else
struct rtnl_link_stats64 *efx_net_stats(struct net_device *net_dev,
					struct rtnl_link_stats64 *stats)
#endif
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	efx->type->update_stats(efx, NULL, stats);
	/* release stats_lock obtained in update_stats */
	spin_unlock_bh(&efx->stats_lock);
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NETDEV_STATS64_VOID)

	return stats;
#endif
}

void efx_reset_sw_stats(struct efx_nic *efx)
{
	struct efx_channel *channel;
	struct efx_tx_queue *tx_queue;

	efx_for_each_channel(channel, efx) {
		if (efx_channel_has_rx_queue(channel))
			efx_channel_get_rx_queue(channel)->rx_packets = 0;
		efx_for_each_channel_tx_queue(tx_queue, channel) {
			tx_queue->tx_packets = 0;
			tx_queue->pushes = 0;
			tx_queue->pio_packets = 0;
			tx_queue->cb_packets = 0;
		}
	}
}

static int efx_msecs_since(unsigned long event_jiffies)
{
	if (!event_jiffies)
		return -1;
	return jiffies_to_msecs(jiffies - event_jiffies);
}

void efx_print_stopped_queues(struct efx_nic *efx)
{
	struct efx_channel *channel;

	netif_info(efx, tx_err, efx->net_dev,
		   "TX queue timeout: printing stopped queue data\n");

	efx_for_each_channel(channel, efx) {
		struct netdev_queue *core_txq = channel->tx_queues[0].core_txq;
		long unsigned int busy_poll_state = 0xffff;
		struct efx_tx_queue *tx_queue;

		if (!efx_channel_has_tx_queues(channel))
			continue;

		/* The netdev watchdog must have triggered on a queue that had
		 * stopped transmitting, so ignore other queues.
		 */
		if (!netif_xmit_stopped(core_txq))
			continue;

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NDO_BUSY_POLL)
#ifdef CONFIG_NET_RX_BUSY_POLL
		busy_poll_state = channel->busy_poll_state;
#endif
#endif
		netif_info(efx, tx_err, efx->net_dev,
			   "Channel %u: %senabled Busy poll %#lx NAPI state %#lx Doorbell %sheld %scoalescing Xmit state %#lx\n",
			   channel->channel, (channel->enabled ? "" : "NOT "),
			   busy_poll_state, channel->napi_str.state,
			   (channel->holdoff_doorbell ? "" : "not "),
			   (channel->tx_coalesce_doorbell ? "" : "not "),
			   core_txq->state);
		efx_for_each_channel_tx_queue(tx_queue, channel)
			netif_info(efx, tx_err, efx->net_dev,
				   "Tx queue: insert %u, write %u (%dms), read %u (%dms)\n",
				   tx_queue->insert_count,
				   tx_queue->write_count,
				   efx_msecs_since(tx_queue->notify_jiffies),
				   tx_queue->read_count,
				   efx_msecs_since(tx_queue->read_jiffies));
	}
}

/* Push loopback/power/transmit disable settings to the PHY, and reconfigure
 * the MAC appropriately. All other PHY configuration changes are pushed
 * through efx_mcdi_phy_set_settings(), and pushed asynchronously to the MAC
 * through efx_monitor().
 *
 * Callers must hold the mac_lock
 */
int __efx_reconfigure_port(struct efx_nic *efx)
{
	enum efx_phy_mode phy_mode;
	int rc = 0;

	WARN_ON(!mutex_is_locked(&efx->mac_lock));

	/* Disable PHY transmit in mac level loopbacks */
	phy_mode = efx->phy_mode;
	if (LOOPBACK_INTERNAL(efx))
		efx->phy_mode |= PHY_MODE_TX_DISABLED;
	else
		efx->phy_mode &= ~PHY_MODE_TX_DISABLED;

	if (efx->type->reconfigure_port)
		rc = efx->type->reconfigure_port(efx);

	if (rc)
		efx->phy_mode = phy_mode;

	return rc;
}

/* Reinitialise the MAC to pick up new PHY settings, even if the port is
 * disabled.
 */
int efx_reconfigure_port(struct efx_nic *efx)
{
	int rc;

	EFX_ASSERT_RESET_SERIALISED(efx);

	mutex_lock(&efx->mac_lock);
	rc = __efx_reconfigure_port(efx);
	mutex_unlock(&efx->mac_lock);

	return rc;
}

static void efx_wait_for_bist_end(struct efx_nic *efx)
{
	int i;

	for (i = 0; i < BIST_WAIT_DELAY_COUNT; ++i) {
		if (efx->type->mcdi_poll_bist_end(efx))
			goto out;
		msleep(BIST_WAIT_DELAY_MS);
	}

	netif_err(efx, drv, efx->net_dev, "Warning: No MC reboot after BIST mode\n");
out:
	/* Either way unset the BIST flag. If we found no reboot we probably
	 * won't recover, but we should try.
	 */
	efx->mc_bist_for_other_fn = false;
	efx->reset_count = 0;
}

/* Try recovery mechanisms.
 * For now only EEH is supported.
 * Returns 0 if the recovery mechanisms are unsuccessful.
 * Returns a non-zero value otherwise.
 */
int efx_try_recovery(struct efx_nic *efx)
{
#ifdef CONFIG_EEH
	/* A PCI error can occur and not be seen by EEH because nothing
	 * happens on the PCI bus. In this case the driver may fail and
	 * schedule a 'recover or reset', leading to this recovery handler.
	 * Manually call the eeh failure check function.
	 */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_EEH_DEV_CHECK_FAILURE)
	struct eeh_dev *eehdev = pci_dev_to_eeh_dev(efx->pci_dev);

	if (eeh_dev_check_failure(eehdev)) {
#else
	struct pci_dev *pcidev = efx->pci_dev;
	struct device_node *dn = pci_device_to_OF_node(pcidev);

	if (eeh_dn_check_failure(dn, pcidev)) {
#endif
		/* The EEH mechanisms will handle the error and reset
		 * the device if necessary.
		 */
		return 1;
	}
#endif
	return 0;
}

/* Tears down the entire software state and most of the hardware state
 * before reset.
 */
void efx_reset_down(struct efx_nic *efx, enum reset_type method)
{
	EFX_ASSERT_RESET_SERIALISED(efx);

	if (method == RESET_TYPE_MCDI_TIMEOUT)
		efx->type->prepare_flr(efx);

	efx_stop_all(efx);
	efx_disable_interrupts(efx);

	mutex_lock(&efx->mac_lock);
	down_write(&efx->filter_sem);
	mutex_lock(&efx->rss_lock);
	if (efx->type->fini)
		efx->type->fini(efx);
}

/* Context: netif_tx_lock held, BHs disabled. */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_TX_TIMEOUT_TXQUEUE)
void efx_watchdog(struct net_device *net_dev, unsigned int txqueue)
#else
void efx_watchdog(struct net_device *net_dev)
#endif
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	efx_print_stopped_queues(efx);
	netif_err(efx, tx_err, efx->net_dev,
		  "TX stuck with port_enabled=%d: resetting channels\n",
		  efx->port_enabled);

	efx_schedule_reset(efx, RESET_TYPE_TX_WATCHDOG);
}

/* This function will always ensure that the locks acquired in
 * efx_reset_down() are released. A failure return code indicates
 * that we were unable to reinitialise the hardware, and the
 * driver should be disabled. If ok is false, then the rx and tx
 * engines are not restarted, pending a RESET_DISABLE.
 */
int efx_reset_up(struct efx_nic *efx, enum reset_type method, bool ok)
{
	u32 attach_flags;
	int rc = 0;

	EFX_ASSERT_RESET_SERIALISED(efx);

	if (method == RESET_TYPE_MCDI_TIMEOUT)
		efx->type->finish_flr(efx);

	efx_mcdi_post_reset(efx);

	if (efx_net_allocated(efx->state) && efx->type->init)
		rc = efx->type->init(efx);
	if (rc) {
		if (rc != -EAGAIN)
			netif_err(efx, drv, efx->net_dev, "failed to initialise NIC\n");
		goto fail;
	}

	if (!ok)
		goto fail;

	if (efx->port_initialized && method != RESET_TYPE_INVISIBLE &&
	    method != RESET_TYPE_DATAPATH) {
		rc = efx_mcdi_port_reconfigure(efx);
		if (rc && rc != -EPERM)
			netif_err(efx, drv, efx->net_dev,
				  "could not restore PHY settings\n");
	}

	if (efx_net_allocated(efx->state)) {
		rc = efx_enable_interrupts(efx);
		if (rc)
			goto fail;
	}

#ifdef CONFIG_SFC_DUMP
	rc = efx_dump_reset(efx);
	if (rc)
		goto fail;
#endif

	/* If the MC has reset then re-attach the driver to restore the
	 * firmware state. Note that although there are some ways we can get
	 * here that aren't the result of an MC reset, it is still safe to
	 * perform the attach operation.
	 */
	rc = efx_mcdi_drv_attach(efx, MC_CMD_FW_DONT_CARE, &attach_flags, true);
	if (rc) /* not fatal: the PF will still work */
		netif_warn(efx, probe, efx->net_dev,
			   "failed to re-attach driver to MCPU rc=%d, PPS & NCSI may malfunction\n",
			   rc);
	else
		/* Store new attach flags. */
		efx->mcdi->fn_flags = attach_flags;

	if (efx->type->vswitching_restore) {
		rc = efx->type->vswitching_restore(efx);
		if (rc) /* not fatal; the PF will still work fine */
			netif_warn(efx, probe, efx->net_dev,
				   "failed to restore vswitching rc=%d, VFs may not function\n",
				   rc);
	}

	if (efx->type->rx_restore_rss_contexts)
		efx->type->rx_restore_rss_contexts(efx);
	mutex_unlock(&efx->rss_lock);
	if (efx->state == STATE_NET_UP)
		efx->type->filter_table_restore(efx);
	up_write(&efx->filter_sem);
	mutex_unlock(&efx->mac_lock);

	if (efx->state == STATE_NET_UP) {
		rc = efx_start_all(efx);
		if (rc) {
			efx->port_initialized = false;
			return rc;
		}
	} else {
		efx->port_initialized = false;
	}

	if (efx->type->udp_tnl_push_ports)
		efx->type->udp_tnl_push_ports(efx);

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PTP)
	/* If PPS possible re-enable after MC reset */
	if (efx->type->pps_reset)
		if (efx->type->pps_reset(efx))
			netif_warn(efx, drv, efx->net_dev, "failed to reset PPS");
#endif

	return 0;

fail:
	efx->port_initialized = false;

	mutex_unlock(&efx->rss_lock);
	up_write(&efx->filter_sem);
	mutex_unlock(&efx->mac_lock);

	return rc;
}

static int efx_do_reset(struct efx_nic *efx, enum reset_type method)
{
	int rc = efx->type->reset(efx, method);

	if (rc) {
		netif_err(efx, drv, efx->net_dev, "failed to reset hardware\n");
		return rc;
	}

	/* Clear flags for the scopes we covered.  We assume the NIC and
	 * driver are now quiescent so that there is no race here.
	 */
	if (method < RESET_TYPE_MAX_METHOD)
		efx->reset_pending &= -(1 << (method + 1));
	else /* it doesn't fit into the well-ordered scope hierarchy */
		__clear_bit(method, &efx->reset_pending);

	/* Reinitialise bus-mastering, which may have been turned off before
	 * the reset was scheduled. This is still appropriate, even in the
	 * RESET_TYPE_DISABLE since this driver generally assumes the hardware
	 * can respond to requests.
	 */
	pci_set_master(efx->pci_dev);

	return 0;
}

/* Do post-processing after the reset.
 * Returns whether the reset was completed and the device is back up.
 */
static int efx_reset_complete(struct efx_nic *efx, enum reset_type method,
			      bool retry, bool disabled)
{
	if (disabled) {
		netif_err(efx, drv, efx->net_dev, "has been disabled\n");
		efx->state = STATE_DISABLED;
		return false;
	}

	if (retry) {
		netif_info(efx, drv, efx->net_dev, "scheduling retry of reset\n");
		if (method == RESET_TYPE_MC_BIST)
			method = RESET_TYPE_DATAPATH;
		efx_schedule_reset(efx, method);
		return false;
	}

	netif_dbg(efx, drv, efx->net_dev, "reset complete\n");
	return true;
}

/* Reset the NIC using the specified method.  Note that the reset may
 * fail, in which case the card will be left in an unusable state.
 *
 * Caller must hold the rtnl_lock.
 */
int efx_reset(struct efx_nic *efx, enum reset_type method)
{
	int rc, rc2 = 0;
	bool disabled, retry;
	bool link_up = efx->link_state.up;

	ASSERT_RTNL();

#ifdef EFX_NOT_UPSTREAM
#if IS_MODULE(CONFIG_SFC_DRIVERLINK)
	/* Notify driverlink clients of imminent reset then serialise
	 * against other driver operations
	 */
	efx_dl_reset_suspend(&efx->dl_nic);
#endif
#endif

	netif_info(efx, drv, efx->net_dev, "resetting (%s)\n",
		   RESET_TYPE(method));

	efx_device_detach_sync(efx);
	/* efx_reset_down() grabs locks that prevent recovery on EF100.
	 * EF100 reset is handled in the efx_nic_type callback below.
	 */
	if (efx_nic_rev(efx) != EFX_REV_EF100)
		efx_reset_down(efx, method);

	if (efx->link_down_on_reset && link_up) {
		efx->link_state.up = false;
		efx_link_status_changed(efx);
	}

	rc = efx_do_reset(efx, method);

	retry = rc == -EAGAIN;

	/* Leave device stopped if necessary */
	disabled = (rc && !retry) ||
		method == RESET_TYPE_DISABLE;

	if (efx->link_down_on_reset && link_up) {
		efx->link_state.up = true;
		efx_link_status_changed(efx);
	}

	if (efx_nic_rev(efx) != EFX_REV_EF100)
		rc2 = efx_reset_up(efx, method, !disabled && !retry);
	if (rc2) {
		if (rc2 == -EAGAIN)
			retry = true;
		else
			disabled = true;
		if (!rc)
			rc = rc2;
	}

	if (disabled)
		dev_close(efx->net_dev);

	if (efx_reset_complete(efx, method, retry, disabled)) {
		efx_device_attach_if_not_resetting(efx);

		/* Now reset is finished, reconfigure MAC
		 * again to ensure filters that weren't inserted while
		 * resetting are now.
		 */
		mutex_lock(&efx->mac_lock);
		(void)efx_mac_reconfigure(efx, false);
		mutex_unlock(&efx->mac_lock);

		if (PCI_FUNC(efx->pci_dev->devfn) == 0)
			efx_mcdi_log_puts(efx, efx_reset_type_names[method]);
	}
#ifdef EFX_NOT_UPSTREAM
#if IS_MODULE(CONFIG_SFC_DRIVERLINK)
	efx_dl_reset_resume(&efx->dl_nic, !disabled);
#endif

#endif
	return rc;
}

#ifdef CONFIG_SFC_VDPA
static void efx_reset_vdpa(struct efx_nic *efx, enum reset_type method)
{
	bool retry, disabled;
	int rc;

	WARN_ON(method != RESET_TYPE_DISABLE);
	method = RESET_TYPE_DISABLE;

	pr_info("%s: VDPA resetting (%s)\n", __func__, RESET_TYPE(method));

	rc = efx_do_reset(efx, method);

	retry = rc == -EAGAIN;

	/* Leave device stopped if necessary */
	disabled = (rc && !retry) || method == RESET_TYPE_DISABLE;

	if (disabled)
		ef100_vdpa_reset(&efx->vdpa_nic->vdpa_dev);

	efx_reset_complete(efx, method, retry, disabled);
}
#endif

/* The worker thread exists so that code that cannot sleep can
 * schedule a reset for later.
 */
static void efx_reset_work(struct work_struct *data)
{
	struct efx_nic *efx = container_of(data, struct efx_nic, reset_work);
	unsigned long pending;
	enum reset_type method;

	pending = READ_ONCE(efx->reset_pending);
	method = fls(pending) - 1;

#ifdef EFX_NOT_UPSTREAM
	if (method == RESET_TYPE_TX_WATCHDOG &&
	    efx_nic_rev(efx) == EFX_REV_EF100) {
		WARN_ON(efx->state == STATE_VDPA);
		efx_ef100_dump_napi_debug(efx);
		efx_ef100_dump_sss_regs(efx);
	}
#endif

	if (method == RESET_TYPE_MC_BIST)
		efx_wait_for_bist_end(efx);

	if (method == RESET_TYPE_RECOVER_OR_ALL &&
	    efx_try_recovery(efx))
		return;

	if (!pending)
		return;

	rtnl_lock();

	/* We checked the state in efx_schedule_reset() but it may
	 * have changed by now.  Now that we have the RTNL lock,
	 * it cannot change again.
	 */
	if (efx_net_active(efx->state))
		(void)efx_reset(efx, method);
#ifdef CONFIG_SFC_VDPA
	else if (efx->state == STATE_VDPA)
		efx_reset_vdpa(efx, method);
#endif

	rtnl_unlock();
}

void efx_schedule_reset(struct efx_nic *efx, enum reset_type type)
{
	static const unsigned int RESETS_BEFORE_DISABLE = 5;
	unsigned long last_reset = READ_ONCE(efx->last_reset);
	enum reset_type method;

	if (efx_recovering(efx->state)) {
		netif_dbg(efx, drv, efx->net_dev,
			  "recovering: skip scheduling %s reset\n",
			  RESET_TYPE(type));
		return;
	}

	method = efx->type->map_reset_reason(type);

	/* check we're scheduling a new reset and if so check we're
	 * not scheduling resets too often.
	 * this part is not atomically safe, but is also ultimately a
	 * heuristic; if we lose increments due to dirty writes
	 * that's fine and if we falsely increment or reset due to an
	 * inconsistent read of last_reset on 32-bit arch it's also ok.
	 */
	if (time_after(jiffies, last_reset + HZ))
		       efx->reset_count = 0;
	if (!(efx->reset_pending & (1 << method)) &&
	    ++efx->reset_count > RESETS_BEFORE_DISABLE) {
		method = RESET_TYPE_DISABLE;
		netif_err(efx, drv, efx->net_dev,
			  "too many resets, scheduling %s\n",
			  RESET_TYPE(method));
	}

	/* It is not atomic-safe as well, but there is a high chance that
	 * this code will catch the just-set current_reset value.  If we
	 * fail once, we'll get the value next time. */
	if (time_after(efx->current_reset, last_reset) )
		efx->last_reset = efx->current_reset;

	if (method == type)
		netif_dbg(efx, drv, efx->net_dev, "scheduling %s reset\n",
			  RESET_TYPE(method));
	else
		netif_dbg(efx, drv, efx->net_dev,
			  "scheduling %s reset for %s\n",
			  RESET_TYPE(method), RESET_TYPE(type));

	set_bit(method, &efx->reset_pending);

	if (efx->state != STATE_VDPA) {
		/* If we're not READY then just leave the flags set as the cue
		 * to abort probing or reschedule the reset later.
		 */
		if (!efx_net_active(READ_ONCE(efx->state)))
			return;

		/* Stop the periodic statistics monitor to prevent it firing
		 * while we are handling the reset.
		 */
		efx_mac_stats_reset_monitor(efx);

		/* we might be resetting because things are broken, so detach
		 * so we don't get things like the TX watchdog firing while we
		 * wait to reset.
		 */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
		if (efx->type->detach_reps)
			efx->type->detach_reps(efx);
#endif
		netif_device_detach(efx->net_dev);
	}

	efx_queue_reset_work(efx);
}

/**************************************************************************
 *
 * Dummy NIC operations
 *
 * Can be used for some unimplemented operations
 * Needed so all function pointers are valid and do not have to be tested
 * before use
 *
 **************************************************************************/
int efx_port_dummy_op_int(struct efx_nic *efx)
{
	return 0;
}
void efx_port_dummy_op_void(struct efx_nic *efx) {}

/**************************************************************************
 *
 * Data housekeeping
 *
 **************************************************************************/
void efx_fini_struct(struct efx_nic *efx)
{
	efx_filter_clear_ntuple(efx);
#ifdef CONFIG_RFS_ACCEL
	kfree(efx->rps_hash_table);
#endif

#ifdef CONFIG_DEBUG_FS
	mutex_destroy(&efx->debugfs_symlink_mutex);
#endif
#ifdef CONFIG_SFC_MTD
	efx_mtd_free(efx);
#endif
}

bool efx_is_supported_ringsize(struct efx_nic *efx, unsigned long entries)
{
	if (efx->supported_bitmap)
		return !!(efx->supported_bitmap & entries);

	return true;
}

bool efx_is_guaranteed_ringsize(struct efx_nic *efx, unsigned long entries)
{
	/* supported_bitmap!= 0 -- MCDI v10 ring size supported */
	if (efx->supported_bitmap)
		return !!(efx->guaranteed_bitmap & entries);

	return true;
}

/* Tries to get nearest next available guaranteed ring size.
 * Higher ring size is preferred of guranteed ring sizes.
 * If nothing matches, returns the same value.
 * param entries assmued to be pow-of-two
 */
unsigned long
efx_best_guaranteed_ringsize(struct efx_nic *efx, unsigned long entries,
			     bool fallback_to_supported)
{
	unsigned long more_entries = entries << 1;
	unsigned long less_entries = entries >> 1;

	while (1) {
		if ((more_entries & efx->supported_bitmap) &&
		    (more_entries & efx->guaranteed_bitmap))
			return more_entries;
		more_entries <<= 1;
		if ((less_entries & efx->supported_bitmap) &&
		    (less_entries & efx->guaranteed_bitmap))
			return less_entries;
		less_entries >>= 1;
		/* check if next loops are valid anymore */
		if ((more_entries | less_entries) & efx->guaranteed_bitmap)
			continue;
		else if (fallback_to_supported &&
			 (more_entries | less_entries) & efx->supported_bitmap)
			continue;
		else
			break;
	}

	return entries;
}

unsigned long
efx_next_guaranteed_ringsize(struct efx_nic *efx, unsigned long entries,
			     bool fallback_to_supported)
{
	unsigned long more_entries = entries << 1;

	while (1) {
		if ((more_entries & efx->supported_bitmap) &&
		    (more_entries & efx->guaranteed_bitmap))
			return more_entries;
		more_entries <<= 1;
		if (more_entries & efx->guaranteed_bitmap)
			continue;
		else if (fallback_to_supported &&
			 (more_entries & efx->guaranteed_bitmap))
			continue;
		else
			break;
	}

	return entries;
}

/* This zeroes out and then fills in the invariants in a struct
 * efx_nic (including all sub-structures).
 */
int efx_init_struct(struct efx_nic *efx, struct pci_dev *pci_dev)
{
	/* Initialise common structures */
	spin_lock_init(&efx->biu_lock);
	INIT_WORK(&efx->reset_work, efx_reset_work);
	INIT_DELAYED_WORK(&efx->monitor_work, efx_monitor);
	efx_selftest_async_init(efx);
	efx->pci_dev = pci_dev;
	efx->msg_enable = debug;
	efx->state = STATE_UNINIT;
	strscpy(efx->name, pci_name(pci_dev), sizeof(efx->name));

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	efx->lro_available = true;
#ifndef NETIF_F_LRO
	efx->lro_enabled = lro;
#endif
#endif
#ifdef EFX_NOT_UPSTREAM
	efx->phy_power_follows_link = phy_power_follows_link;
	efx->link_down_on_reset = link_down_on_reset;
#endif
#ifdef DEBUG
	efx->log_tc_errs = true;
#endif
	efx->tc_match_ignore_ttl = true;
	INIT_LIST_HEAD(&efx->channel_list);
	efx->rx_prefix_size = efx->type->rx_prefix_size;
	efx->rx_ip_align =
		NET_IP_ALIGN ? (efx->rx_prefix_size + NET_IP_ALIGN) % 4 : 0;
	efx->rx_packet_hash_offset =
		efx->type->rx_hash_offset - efx->type->rx_prefix_size;
	efx->rx_packet_ts_offset =
		efx->type->rx_ts_offset - efx->type->rx_prefix_size;
	INIT_LIST_HEAD(&efx->rss_context.list);
	mutex_init(&efx->rss_lock);
	INIT_LIST_HEAD(&efx->vport.list);
	mutex_init(&efx->vport_lock);
	efx->vport.vport_id = EVB_PORT_ID_ASSIGNED;
	spin_lock_init(&efx->stats_lock);
	efx->num_mac_stats = MC_CMD_MAC_NSTATS;
	BUILD_BUG_ON(MC_CMD_MAC_NSTATS - 1 != MC_CMD_MAC_GENERATION_END);
	efx->stats_period_ms = STATS_PERIOD_MS_DEFAULT;
	INIT_DELAYED_WORK(&efx->stats_monitor_work, efx_mac_stats_monitor);
	efx->stats_monitor_generation = EFX_MC_STATS_GENERATION_INVALID;
	efx->vi_stride = EFX_DEFAULT_VI_STRIDE;
	mutex_init(&efx->mac_lock);
	init_rwsem(&efx->filter_sem);
	INIT_LIST_HEAD(&efx->ntuple_list);
#ifdef CONFIG_RFS_ACCEL
	mutex_init(&efx->rps_mutex);
	spin_lock_init(&efx->rps_hash_lock);
	/* Failure to allocate is not fatal, but may degrade ARFS performance */
	efx->rps_hash_table = kcalloc(EFX_ARFS_HASH_TABLE_SIZE,
				      sizeof(*efx->rps_hash_table), GFP_KERNEL);
#endif
	INIT_WORK(&efx->mac_work, efx_mac_work);
	init_waitqueue_head(&efx->flush_wq);

#ifdef CONFIG_DEBUG_FS
	mutex_init(&efx->debugfs_symlink_mutex);
#endif
	efx->tx_queues_per_channel = 1;
	efx->rxq_entries = EFX_DEFAULT_RX_DMAQ_SIZE;
	efx->txq_entries = EFX_DEFAULT_TX_DMAQ_SIZE;

	efx->rss_context.context_id = EFX_MCDI_RSS_CONTEXT_INVALID;
	efx->vport.vport_id = EVB_PORT_ID_ASSIGNED;

	efx->mem_bar = UINT_MAX;
	efx->reg_base = 0;

	efx->max_channels = EFX_MAX_CHANNELS;
	efx->max_tx_channels = EFX_MAX_CHANNELS;

	mutex_init(&efx->reflash_mutex);

	return 0;
}

/* This configures the PCI device to enable I/O and DMA. */
int efx_init_io(struct efx_nic *efx, int bar, dma_addr_t dma_mask, unsigned int mem_map_size)
{
	struct pci_dev *pci_dev = efx->pci_dev;
	int rc;

	efx->mem_bar = UINT_MAX;
	pci_dbg(pci_dev, "initialising I/O bar=%d\n", bar);

	rc = pci_enable_device(pci_dev);
	if (rc) {
		pci_err(pci_dev, "failed to enable PCI device\n");
		goto fail1;
	}

	pci_set_master(pci_dev);

	rc = dma_set_mask_and_coherent(&pci_dev->dev, dma_mask);
	if (rc) {
		pci_err(pci_dev, "could not find a suitable DMA mask\n");
		goto fail2;
	}
	pci_dbg(pci_dev, "using DMA mask %llx\n", (unsigned long long)dma_mask);

	efx->membase_phys = pci_resource_start(efx->pci_dev, bar);
	if (!efx->membase_phys) {
		pci_err(pci_dev,
			"ERROR: No BAR%d mapping from the BIOS. Try pci=realloc on the kernel command line\n",
			bar);
		rc = -ENODEV;
		goto fail3;
	}
	rc = pci_request_region(pci_dev, bar, "sfc");

	if (rc) {
		pci_err(pci_dev, "request for memory BAR[%d] failed\n", bar);
		rc = -EIO;
		goto fail3;
	}
	efx->mem_bar = bar;
#if defined(EFX_USE_KCOMPAT)
	efx->membase = efx_ioremap(efx->membase_phys, mem_map_size);
#else
	efx->membase = ioremap(efx->membase_phys, mem_map_size);
#endif

	if (!efx->membase) {
		pci_err(pci_dev, "could not map memory BAR[%d] at %llx+%x\n",
			bar, (unsigned long long)efx->membase_phys,
			mem_map_size);
		rc = -ENOMEM;
		goto fail4;
	}
	pci_dbg(pci_dev, "memory BAR[%d] at %llx+%x (virtual %p)\n", bar,
		(unsigned long long)efx->membase_phys, mem_map_size,
		efx->membase);

	return 0;

fail4:
	pci_release_region(efx->pci_dev, bar);
fail3:
	efx->membase_phys = 0;
fail2:
	pci_disable_device(efx->pci_dev);
fail1:
	return rc;
}

void efx_fini_io(struct efx_nic *efx)
{
	pci_dbg(efx->pci_dev, "shutting down I/O\n");

	if (efx->membase) {
		iounmap(efx->membase);
		efx->membase = NULL;
	}

	if (efx->membase_phys) {
		pci_release_region(efx->pci_dev, efx->mem_bar);
		efx->membase_phys = 0;
		efx->mem_bar = UINT_MAX;

		/* Don't disable bus-mastering if VFs are assigned */
		if (!pci_vfs_assigned(efx->pci_dev))
			pci_disable_device(efx->pci_dev);
	}
}

int efx_probe_common(struct efx_nic *efx)
{
	int rc = efx_mcdi_init(efx);

	if (rc)
		return rc;
	if (efx->mcdi->fn_flags &
	    (1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_NO_ACTIVE_PORT)
#if defined(EFX_USE_KCOMPAT) && defined(EFX_TC_OFFLOAD)
	    && efx_nic_rev(efx) != EFX_REV_EF100
#endif
	    )
		return 0;

	/* Reset (most) configuration for this function */
	rc = efx_mcdi_reset(efx, RESET_TYPE_ALL);
	if (rc)
		return rc;
	/* Enable event logging */
	rc = efx_mcdi_log_ctrl(efx, true, false, 0);
	if (rc)
		return rc;

	/* Create debugfs symlinks */
#ifdef CONFIG_DEBUG_FS
	mutex_lock(&efx->debugfs_symlink_mutex);
	rc = efx_init_debugfs_nic(efx);
	mutex_unlock(&efx->debugfs_symlink_mutex);
	if (rc)
		pci_err(efx->pci_dev, "failed to init device debugfs\n");
#endif

	return 0;
}

void efx_remove_common(struct efx_nic *efx)
{
#ifdef CONFIG_DEBUG_FS
	mutex_lock(&efx->debugfs_symlink_mutex);
	efx_fini_debugfs_nic(efx);
	mutex_unlock(&efx->debugfs_symlink_mutex);
#endif

	efx_mcdi_detach(efx);
	efx_mcdi_fini(efx);
}

/** Check queue size for range and rounding.
 *
 *  If #fix is set it will clamp and round as required.
 *  Regardless of #fix this will return an error code if the value is
 *  invalid.
 */
int efx_check_queue_size(struct efx_nic *efx, u32 *entries,
			 u32 min, u32 max, bool fix)
{
	if (*entries < min || *entries > max) {
		if (fix)
			*entries = clamp_t(u32, *entries, min, max);
		return -ERANGE;
	}

	if (!is_power_of_2(*entries)) {
		if (fix)
			*entries = roundup_pow_of_two(*entries);
		return -EINVAL;
	}

	return 0;
}

#ifdef CONFIG_SFC_MCDI_LOGGING
static ssize_t mcdi_logging_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
	struct efx_mcdi_iface *mcdi = efx_mcdi(efx);

	return scnprintf(buf, PAGE_SIZE, "%d\n", mcdi->logging_enabled);
}
static ssize_t mcdi_logging_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
	struct efx_mcdi_iface *mcdi = efx_mcdi(efx);
	bool enable = count > 0 && *buf != '0';

	mcdi->logging_enabled = enable;
	return count;
}
static DEVICE_ATTR_RW(mcdi_logging);

void efx_init_mcdi_logging(struct efx_nic *efx)
{
	int rc = device_create_file(&efx->pci_dev->dev, &dev_attr_mcdi_logging);
	if (rc) {
		netif_warn(efx, drv, efx->net_dev,
			   "failed to init net dev attributes\n");
	}
}

void efx_fini_mcdi_logging(struct efx_nic *efx)
{
	device_remove_file(&efx->pci_dev->dev, &dev_attr_mcdi_logging);
}
#endif

/* VLAN acceleration */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_VLAN_RX_ADD_VID_PROTO)
int efx_vlan_rx_add_vid(struct net_device *net_dev, __be16 proto, u16 vid)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx->type->vlan_rx_add_vid)
		return efx->type->vlan_rx_add_vid(efx, proto, vid);
	else
		return -EOPNOTSUPP;
}

int efx_vlan_rx_kill_vid(struct net_device *net_dev, __be16 proto, u16 vid)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx->type->vlan_rx_kill_vid)
		return efx->type->vlan_rx_kill_vid(efx, proto, vid);
	else
		return -EOPNOTSUPP;
}
#elif defined(EFX_HAVE_NDO_VLAN_RX_ADD_VID_RC)
int efx_vlan_rx_add_vid(struct net_device *net_dev, u16 vid)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx->type->vlan_rx_add_vid)
		return efx->type->vlan_rx_add_vid(efx, htons(ETH_P_8021Q), vid);
	else
		return -EOPNOTSUPP;
}

int efx_vlan_rx_kill_vid(struct net_device *net_dev, u16 vid)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx->type->vlan_rx_kill_vid)
		return efx->type->vlan_rx_kill_vid(efx, htons(ETH_P_8021Q),
						   vid);
	else
		return -EOPNOTSUPP;
}
#else
void efx_vlan_rx_add_vid(struct net_device *net_dev, unsigned short vid)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx->type->vlan_rx_add_vid)
		efx->type->vlan_rx_add_vid(efx, htons(ETH_P_8021Q), vid);
}

void efx_vlan_rx_kill_vid(struct net_device *net_dev, unsigned short vid)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx->type->vlan_rx_kill_vid)
		efx->type->vlan_rx_kill_vid(efx, htons(ETH_P_8021Q), vid);
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_HWTSTAMP_GET)
int efx_hwtstamp_set(struct net_device *net_dev,
		     struct kernel_hwtstamp_config *config,
		     struct netlink_ext_ack *extack)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	return efx_ptp_set_ts_config(efx, config, extack);
}

int efx_hwtstamp_get(struct net_device *net_dev,
		     struct kernel_hwtstamp_config *config)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	return efx_ptp_get_ts_config(efx, config);
}
#endif

/* V-port allocations.  Same algorithms (and justification for them) as RSS
 * contexts, above.
 */
struct efx_vport *efx_alloc_vport_entry(struct efx_nic *efx)
{
	struct list_head *head = &efx->vport.list;
	struct efx_vport *ctx, *new;
	u16 id = 1; /* Don't use zero, that refers to the driver master vport */

	WARN_ON(!mutex_is_locked(&efx->vport_lock));

	/* Search for first gap in the numbering */
	list_for_each_entry(ctx, head, list) {
		if (ctx->user_id != id)
			break;
		id++;
		/* Check for wrap.  If this happens, we have nearly 2^16
		 * allocated vports, which seems unlikely.
		 */
		if (WARN_ON_ONCE(!id))
			return NULL;
	}

	/* Create the new entry */
	new = kzalloc(sizeof(struct efx_vport), GFP_KERNEL);
	if (!new)
		return NULL;

	/* Insert the new entry into the gap */
	new->user_id = id;
	list_add_tail(&new->list, &ctx->list);
	return new;
}

struct efx_vport *efx_find_vport_entry(struct efx_nic *efx, u16 id)
{
	struct list_head *head = &efx->vport.list;
	struct efx_vport *ctx;

	WARN_ON(!mutex_is_locked(&efx->vport_lock));

	list_for_each_entry(ctx, head, list)
		if (ctx->user_id == id)
			return ctx;
	return NULL;
}

void efx_free_vport_entry(struct efx_vport *ctx)
{
	list_del(&ctx->list);
	kfree(ctx);
}

int efx_vport_add(struct efx_nic *efx, u16 vlan, bool vlan_restrict)
{
	struct efx_vport *vpx;
	int rc;

	if (!efx->type->vport_add)
		return -EOPNOTSUPP;

	mutex_lock(&efx->vport_lock);
	vpx = efx_alloc_vport_entry(efx);
	if (!vpx) {
		rc = -ENOMEM;
		goto out_unlock;
	}
	vpx->vlan = vlan;
	vpx->vlan_restrict = vlan_restrict;
	rc = efx->type->vport_add(efx, vpx->vlan, vpx->vlan_restrict,
			&vpx->vport_id);
	if (rc < 0)
		efx_free_vport_entry(vpx);
	else
		rc = vpx->user_id;
out_unlock:
	mutex_unlock(&efx->vport_lock);
	return rc;
}

int efx_vport_del(struct efx_nic *efx, u16 port_user_id)
{
	struct efx_vport *vpx;
	int rc;

	if (!efx->type->vport_del)
		return -EOPNOTSUPP;

	mutex_lock(&efx->vport_lock);
	vpx = efx_find_vport_entry(efx, port_user_id);
	if (!vpx) {
		rc = -ENOENT;
		goto out_unlock;
	}

	rc = efx->type->vport_del(efx, vpx->vport_id);
	if (!rc)
		efx_free_vport_entry(vpx);
out_unlock:
	mutex_unlock(&efx->vport_lock);
	return rc;
}

#if defined(EFX_NOT_UPSTREAM) && defined(DEBUG)
/* Used by load.sh to reliably indicate DEBUG vs RELEASE */
extern int __efx_enable_debug; /* placate sparse */
int __efx_enable_debug __attribute__((unused));
#endif

/**************************************************************************
 *
 * PCI error handling
 *
 **************************************************************************/

/* A PCI error affecting this device was detected.
 * At this point MMIO and DMA may be disabled.
 * Stop the software path and request a slot reset.
 */
static pci_ers_result_t efx_io_error_detected(struct pci_dev *pdev,
					      pci_channel_state_t state)
{
	pci_ers_result_t status = PCI_ERS_RESULT_RECOVERED;
	struct efx_nic *efx = pci_get_drvdata(pdev);

	if (state == pci_channel_io_perm_failure)
		return PCI_ERS_RESULT_DISCONNECT;

	rtnl_lock();

	switch (efx->state) {
#ifdef CONFIG_SFC_VDPA
	case STATE_VDPA:
		WARN_ON(efx_nic_rev(efx) != EFX_REV_EF100);
		efx->state = STATE_DISABLED;
		ef100_vdpa_reset(&efx->vdpa_nic->vdpa_dev);

		status = PCI_ERS_RESULT_DISCONNECT;
		break;
#endif
	case STATE_DISABLED:
		/* If the interface is disabled we don't want to do anything
		 * with it.
		 */
		status = PCI_ERS_RESULT_RECOVERED;
		break;
	default:
		efx->state = efx_begin_recovery(efx->state);
		efx->reset_pending = 0;

		efx_device_detach_sync(efx);

		if (efx_net_active(efx->state)) {
			efx_stop_all(efx);
			efx_disable_interrupts(efx);
		}

		status = PCI_ERS_RESULT_NEED_RESET;
		break;
	}

	rtnl_unlock();

	pci_disable_device(pdev);

	return status;
}

/* Fake a successfull reset, which will be performed later in efx_io_resume. */
static pci_ers_result_t efx_io_slot_reset(struct pci_dev *pdev)
{
	struct efx_nic *efx = pci_get_drvdata(pdev);
	pci_ers_result_t status = PCI_ERS_RESULT_RECOVERED;
	int rc;

	if (pci_enable_device(pdev)) {
		netif_err(efx, hw, efx->net_dev,
			  "Cannot re-enable PCI device after reset.\n");
		status =  PCI_ERS_RESULT_DISCONNECT;
	}

	rc = pci_aer_clear_nonfatal_status(pdev);
	if (rc) {
		netif_err(efx, hw, efx->net_dev,
		"pci_aer_clear_nonfatal_status failed (%d)\n", rc);
		/* Non-fatal error. Continue. */
	}

	return status;
}

/* Perform the actual reset and resume I/O operations. */
static void efx_io_resume(struct pci_dev *pdev)
{
	struct efx_nic *efx = pci_get_drvdata(pdev);
	int rc;

	rtnl_lock();

	if (efx->state == STATE_DISABLED)
		goto out;

	rc = efx_reset(efx, RESET_TYPE_ALL);
	if (rc) {
		netif_err(efx, hw, efx->net_dev,
			  "efx_reset failed after PCI error (%d)\n", rc);
	} else {
		efx->state = efx_end_recovery(efx->state);
		efx->reset_count = 0;
		netif_dbg(efx, hw, efx->net_dev,
			  "Done resetting and resuming IO after PCI error.\n");
	}

out:
	rtnl_unlock();
}

int efx_rx_queue_id_internal(struct efx_nic *efx, int rxq_id)
{
	if (efx_tx_vi_spreading(efx))
		return rxq_id * 2;
	else
		return rxq_id;
}

/* For simplicity and reliability, we always require a slot reset and try to
 * reset the hardware when a pci error affecting the device is detected.
 * We leave both the link_reset and mmio_enabled callback unimplemented:
 * with our request for slot reset the mmio_enabled callback will never be
 * called, and the link_reset callback is not used by AER or EEH mechanisms.
 */
const struct pci_error_handlers efx_err_handlers = {
	.error_detected = efx_io_error_detected,
	.slot_reset	= efx_io_slot_reset,
	.resume		= efx_io_resume,
};

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_FEATURES_CHECK)
/* Determine whether the NIC will be able to handle TX offloads for a given
 * encapsulated packet.
 */
static bool efx_can_encap_offloads(struct efx_nic *efx, struct sk_buff *skb)
{
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NDO_ADD_VXLAN_PORT) && !defined(EFX_HAVE_NDO_UDP_TUNNEL_ADD) && !defined(EFX_HAVE_UDP_TUNNEL_NIC_INFO)
	return false;
#else
	struct gre_base_hdr *greh;
	__be16 dst_port;
	u8 ipproto;

	/* Does the NIC support encap offloads?
	 * If not, we should never get here, because we shouldn't have
	 * advertised encap offload feature flags in the first place.
	 */
	if (WARN_ON_ONCE(!efx->type->udp_tnl_has_port))
		return false;

	/* Determine encapsulation protocol in use */
	switch (skb->protocol) {
	case htons(ETH_P_IP):
		ipproto = ip_hdr(skb)->protocol;
		break;
	case htons(ETH_P_IPV6):
		/* If there are extension headers, this will cause us to
		 * think we can't offload something that we maybe could have.
		 */
		ipproto = ipv6_hdr(skb)->nexthdr;
		break;
	default:
		/* Not IP, so can't offload it */
		return false;
	}
	switch (ipproto) {
	case IPPROTO_GRE:
		/* We support NVGRE but not IP over GRE or random gretaps.
		 * Specifically, the NIC will accept GRE as encapsulated if
		 * the inner protocol is Ethernet, but only handle it
		 * correctly if the GRE header is 8 bytes long.  Moreover,
		 * it will not update the Checksum or Sequence Number fields
		 * if they are present.  (The Routing Present flag,
		 * GRE_ROUTING, cannot be set else the header would be more
		 * than 8 bytes long; so we don't have to worry about it.)
		 */
		if (skb->inner_protocol_type != ENCAP_TYPE_ETHER)
			return false;
		if (ntohs(skb->inner_protocol) != ETH_P_TEB)
			return false;
		if (skb_inner_mac_header(skb) - skb_transport_header(skb) != 8)
			return false;
		greh = (struct gre_base_hdr *)skb_transport_header(skb);
		return !(greh->flags & (GRE_CSUM | GRE_SEQ));
	case IPPROTO_UDP:
		/* If the port is registered for a UDP tunnel, we assume the
		 * packet is for that tunnel, and the NIC will handle it as
		 * such.  If not, the NIC won't know what to do with it.
		 */
		dst_port = udp_hdr(skb)->dest;
		return efx->type->udp_tnl_has_port(efx, dst_port);
	default:
		return false;
	}
#endif
}

netdev_features_t efx_features_check(struct sk_buff *skb,
					    struct net_device *dev,
					    netdev_features_t features)
{
	struct efx_nic *efx = efx_netdev_priv(dev);

	if (skb->encapsulation) {
		if (features & NETIF_F_GSO_MASK)
			/* Hardware can only do TSO with at most 208 bytes
			 * of headers.
			 */
			if (skb_inner_transport_offset(skb) >
			    EFX_TSO2_MAX_HDRLEN)
				features &= ~(NETIF_F_GSO_MASK);
		if (features & (NETIF_F_GSO_MASK | NETIF_F_CSUM_MASK))
			if (!efx_can_encap_offloads(efx, skb))
				features &= ~(NETIF_F_GSO_MASK |
					      NETIF_F_CSUM_MASK);
	}
	return features;
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PHYS_PORT_ID)
int efx_get_phys_port_id(struct net_device *net_dev,
			 struct netdev_phys_item_id *ppid)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx->type->get_phys_port_id)
		return efx->type->get_phys_port_id(efx, ppid);
	else
		return -EOPNOTSUPP;
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PHYS_PORT_NAME)
int efx_get_phys_port_name(struct net_device *net_dev,
			   char *name, size_t len)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (snprintf(name, len, "p%u", efx->port_num) >= len)
		return -EINVAL;
	return 0;
}
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
/* This is called by netdev_update_features() to apply any
 * restrictions on offload features.  We must disable LRO whenever RX
 * scattering is on since our implementation (SSR) does not yet
 * support it.
 */
netdev_features_t efx_fix_features(struct net_device *net_dev,
				   netdev_features_t data)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (!efx->lro_available)
		data &= ~NETIF_F_LRO;

	if (!efx->vlan_filter_available)
		data &= ~NETIF_F_HW_VLAN_CTAG_FILTER;

	return data;
}
#endif

int efx_set_features(struct net_device *net_dev, netdev_features_t data)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	int rc;

	/* If disabling RX n-tuple filtering, clear existing filters */
	if (net_dev->features & ~data & NETIF_F_NTUPLE) {
		rc = efx->type->filter_clear_rx(efx, EFX_FILTER_PRI_MANUAL);
		if (rc)
			return rc;
	}

	/* If Rx VLAN filter is changed, update filters via mac_reconfigure.
	 * If forward-fcs is changed, mac_reconfigure updates that too.
	 */
	if ((net_dev->features ^ data) & (NETIF_F_HW_VLAN_CTAG_FILTER |
				NETIF_F_RXFCS)) {
		/* efx_set_rx_mode() will schedule MAC work to update filters
		 * when a new features are finally set in net_dev.
		 */
		efx_set_rx_mode(net_dev);
	}

	return 0;
}

#ifdef EFX_NOT_UPSTREAM
#if IS_MODULE(CONFIG_SFC_DRIVERLINK)
static struct efx_nic *efx_dl_device_priv(struct efx_dl_device *efx_dev)
{
	return container_of(efx_dev->nic, struct efx_nic, dl_nic);
}

static int __efx_dl_publish(struct efx_dl_device *efx_dev)
{
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);
	int rc = efx_net_alloc(efx);

	if (rc)
		efx_net_dealloc(efx);

	return rc;
}

static void __efx_dl_unpublish(struct efx_dl_device *efx_dev)
{
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);

	efx_net_dealloc(efx);
}

static void __efx_dl_pause(struct efx_dl_device *efx_dev)
{
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);

	efx_pause_napi(efx);
}

static void __efx_dl_resume(struct efx_dl_device *efx_dev)
{
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);

	efx_resume_napi(efx);
}

static void __efx_dl_schedule_reset(struct efx_dl_device *efx_dev)
{
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);

	efx_schedule_reset(efx, RESET_TYPE_ALL);
}

static u32 __efx_dl_rss_flags_default(struct efx_dl_device *efx_dev)
{
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);

	if (efx->type->rx_get_default_rss_flags)
		return efx->type->rx_get_default_rss_flags(efx);
	/* NIC does not support RSS flags, so any value will do */
	return 0;
}

static int __efx_dl_rss_context_new(struct efx_dl_device *efx_dev,
				    const u32 *indir, const u8 *key, u32 flags,
				    u8 num_queues, u32 *rss_context)
{
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);
	struct efx_rss_context *ctx;
	int rc;

	/* num_queues=0 is used internally by the driver to represent
	 * efx->rss_spread, and is not appropriate for driverlink clients
	 */
	if (!num_queues)
		return -EINVAL;

	if (!efx->type->rx_push_rss_context_config)
		return -EOPNOTSUPP;

	if (!efx->type->rx_set_rss_flags)
		return -EOPNOTSUPP;

	mutex_lock(&efx->rss_lock);
	ctx = efx_alloc_rss_context_entry(efx);
	if (!ctx) {
		rc = -ENOMEM;
		goto out_unlock;
	}
	if (!indir) {
		efx_set_default_rx_indir_table(efx, ctx);
		indir = ctx->rx_indir_table;
	}
	if (!key) {
		netdev_rss_key_fill(ctx->rx_hash_key, sizeof(ctx->rx_hash_key));
		key = ctx->rx_hash_key;
	}
	ctx->num_queues = num_queues;
	rc = efx->type->rx_push_rss_context_config(efx, ctx, indir, key);
	if (rc)
		goto out_free;
	*rss_context = ctx->user_id;
	rc = efx->type->rx_set_rss_flags(efx, ctx, flags);
	if (rc)
		goto out_delete;
	ctx->flags = flags;

out_unlock:
	mutex_unlock(&efx->rss_lock);
	return rc;

out_delete:
	efx->type->rx_push_rss_context_config(efx, ctx, NULL, NULL);
out_free:
	efx_free_rss_context_entry(ctx);
	goto out_unlock;
}

static int __efx_dl_rss_context_set(struct efx_dl_device *efx_dev,
				    const u32 *indir, const u8 *key,
				    u32 flags, u32 rss_context)
{
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);
	struct efx_rss_context *ctx;
	u32 old_flags;
	int rc;

	if (!efx->type->rx_push_rss_context_config)
		return -EOPNOTSUPP;

	mutex_lock(&efx->rss_lock);
	ctx = efx_find_rss_context_entry(efx, rss_context);
	if (!ctx) {
		rc = -ENOENT;
		goto out_unlock;
	}

	if (!indir) /* no change */
		indir = ctx->rx_indir_table;
	if (!key) /* no change */
		key = ctx->rx_hash_key;
	old_flags = ctx->flags;
	ctx->flags = flags;
	rc = efx->type->rx_push_rss_context_config(efx, ctx, indir, key);
	if (rc) /* restore old RSS flags on failure */
		ctx->flags = old_flags;
out_unlock:
	mutex_unlock(&efx->rss_lock);
	return rc;
}

static int __efx_dl_rss_context_free(struct efx_dl_device *efx_dev,
				     u32 rss_context)
{
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);
	struct efx_rss_context *ctx;
	int rc;

	if (!efx->type->rx_push_rss_context_config)
		return -EOPNOTSUPP;

	mutex_lock(&efx->rss_lock);
	ctx = efx_find_rss_context_entry(efx, rss_context);
	if (!ctx) {
		rc = -ENOENT;
		goto out_unlock;
	}

	rc = efx->type->rx_push_rss_context_config(efx, ctx, NULL, NULL);
	if (!rc)
		efx_free_rss_context_entry(ctx);
out_unlock:
	mutex_unlock(&efx->rss_lock);
	return rc;
}

/* We additionally include priority in the filter ID so that we
 * can pass it back into efx_filter_remove_id_safe().
 */
#define EFX_FILTER_PRI_SHIFT    28
#define EFX_FILTER_ID_MASK      ((1 << EFX_FILTER_PRI_SHIFT) - 1)

static int __efx_dl_filter_insert(struct efx_dl_device *efx_dev,
				  const struct efx_filter_spec *spec,
				  bool replace_equal)
{
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);
	s32 filter_id = efx_filter_insert_filter(efx,
						 spec, replace_equal);
	if (filter_id >= 0) {
		EFX_WARN_ON_PARANOID(filter_id & ~EFX_FILTER_ID_MASK);
		filter_id |= spec->priority << EFX_FILTER_PRI_SHIFT;
	}
	return filter_id;
}

static int __efx_dl_filter_remove(struct efx_dl_device *efx_dev, int filter_id)
{
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);

	if (filter_id < 0)
		return -EINVAL;
	return efx_filter_remove_id_safe(efx,
					 filter_id >> EFX_FILTER_PRI_SHIFT,
					 filter_id & EFX_FILTER_ID_MASK);
}

static int __efx_dl_filter_redirect(struct efx_dl_device *efx_dev,
				    int filter_id, int rxq_i, u32 *rss_context,
				    int stack_id)
{
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);

	if (WARN_ON(filter_id < 0))
		return -EINVAL;
	return efx->type->filter_redirect(efx, filter_id & EFX_FILTER_ID_MASK,
			rss_context, rxq_i, stack_id);
}

static int __efx_dl_vport_new(struct efx_dl_device *efx_dev, u16 vlan,
			      bool vlan_restrict)
{
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);

	return efx_vport_add(efx, vlan, vlan_restrict);
}

static int __efx_dl_vport_free(struct efx_dl_device *efx_dev, u16 port_id)
{
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);

	return efx_vport_del(efx, port_id);
}

static
int __efx_dl_init_txq(struct efx_dl_device *efx_dev, u32 client_id,
		      dma_addr_t *dma_addrs,
		      int n_dma_addrs, u16 vport_id, u8 stack_id, u32 owner_id,
		      bool timestamp, u8 crc_mode, bool tcp_udp_only,
		      bool tcp_csum_dis, bool ip_csum_dis, bool inner_tcp_csum,
		      bool inner_ip_csum, bool buff_mode, bool pacer_bypass,
		      bool ctpio, bool ctpio_uthresh, bool m2m_d2c, u32 instance,
		      u32 label, u32 target_evq, u32 num_entries)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_INIT_TXQ_EXT_IN_LEN);
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);
	struct efx_vport *vpx;
	u32 port_id;
	int i, rc;

	mutex_lock(&efx->vport_lock);
	/* look up vport, convert to hw ID, and OR in stack_id */
	if (vport_id == 0)
		vpx = &efx->vport;
	else
		vpx = efx_find_vport_entry(efx, vport_id);
	if (!vpx) {
		rc = -ENOENT;
		goto out_unlock;
	}
	if (vpx->vport_id == EVB_PORT_ID_NULL) {
		rc = -EOPNOTSUPP;
		goto out_unlock;
	}
	port_id = vpx->vport_id | EVB_STACK_ID(stack_id);

	MCDI_SET_DWORD(inbuf, INIT_TXQ_EXT_IN_SIZE, num_entries);
	MCDI_SET_DWORD(inbuf, INIT_TXQ_EXT_IN_TARGET_EVQ, target_evq);
	MCDI_SET_DWORD(inbuf, INIT_TXQ_EXT_IN_LABEL, label);
	MCDI_SET_DWORD(inbuf, INIT_TXQ_EXT_IN_INSTANCE, instance);
	MCDI_SET_DWORD(inbuf, INIT_TXQ_EXT_IN_OWNER_ID, owner_id);
	MCDI_SET_DWORD(inbuf, INIT_TXQ_EXT_IN_PORT_ID, port_id);

	MCDI_POPULATE_DWORD_12(inbuf, INIT_TXQ_EXT_IN_FLAGS,
		INIT_TXQ_EXT_IN_FLAG_BUFF_MODE, !!buff_mode,
		INIT_TXQ_EXT_IN_FLAG_IP_CSUM_DIS, !!ip_csum_dis,
		INIT_TXQ_EXT_IN_FLAG_TCP_CSUM_DIS, !!tcp_csum_dis,
		INIT_TXQ_EXT_IN_FLAG_INNER_IP_CSUM_EN, !!inner_ip_csum,
		INIT_TXQ_EXT_IN_FLAG_INNER_TCP_CSUM_EN, !!inner_tcp_csum,
		INIT_TXQ_EXT_IN_FLAG_TCP_UDP_ONLY, !!tcp_udp_only,
		INIT_TXQ_EXT_IN_CRC_MODE, crc_mode,
		INIT_TXQ_EXT_IN_FLAG_TIMESTAMP, !!timestamp,
		INIT_TXQ_EXT_IN_FLAG_CTPIO, !!ctpio,
		INIT_TXQ_EXT_IN_FLAG_CTPIO_UTHRESH, !!ctpio_uthresh,
		INIT_TXQ_EXT_IN_FLAG_PACER_BYPASS, !!pacer_bypass,
		INIT_TXQ_EXT_IN_FLAG_M2M_D2C, !!m2m_d2c);

	for (i = 0; i < n_dma_addrs; ++i)
		MCDI_SET_ARRAY_QWORD(inbuf, INIT_TXQ_EXT_IN_DMA_ADDR, i,
				     dma_addrs[i]);

	rc = efx_mcdi_rpc_client(efx, client_id, MC_CMD_INIT_TXQ, inbuf,
	                         MC_CMD_INIT_TXQ_EXT_IN_LEN, NULL, 0, NULL);
out_unlock:
	mutex_unlock(&efx->vport_lock);
	return rc;
}

static
int __efx_dl_init_rxq(struct efx_dl_device *efx_dev, u32 client_id,
		      dma_addr_t *dma_addrs,
		      int n_dma_addrs, u16 vport_id, u8 stack_id, u32 owner_id,
		      u8 crc_mode, bool timestamp, bool hdr_split,
		      bool buff_mode, bool rx_prefix, u8 dma_mode, u32 instance,
		      u32 label, u32 target_evq, u32 num_entries,
		      u8 ps_buf_size, bool force_rx_merge, int ef100_rx_buffer_size)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_INIT_RXQ_V4_IN_LEN);
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);
	struct efx_vport *vpx;
	u32 port_id;
	int i, rc;

	mutex_lock(&efx->vport_lock);
	/* look up vport, convert to hw ID, and OR in stack_id */
	if (vport_id == 0)
		vpx = &efx->vport;
	else
		vpx = efx_find_vport_entry(efx, vport_id);
	if (!vpx) {
		rc = -ENOENT;
		goto out_unlock;
	}
	if (vpx->vport_id == EVB_PORT_ID_NULL) {
		rc = -EOPNOTSUPP;
		goto out_unlock;
	}
	port_id = vpx->vport_id | EVB_STACK_ID(stack_id);

	MCDI_SET_DWORD(inbuf, INIT_RXQ_EXT_IN_SIZE, num_entries);
	MCDI_SET_DWORD(inbuf, INIT_RXQ_EXT_IN_TARGET_EVQ, target_evq);
	MCDI_SET_DWORD(inbuf, INIT_RXQ_EXT_IN_LABEL, label);
	MCDI_SET_DWORD(inbuf, INIT_RXQ_EXT_IN_INSTANCE, instance);
	MCDI_SET_DWORD(inbuf, INIT_RXQ_EXT_IN_OWNER_ID, owner_id);
	MCDI_SET_DWORD(inbuf, INIT_RXQ_EXT_IN_PORT_ID, port_id);

	MCDI_POPULATE_DWORD_8(inbuf, INIT_RXQ_EXT_IN_FLAGS,
		INIT_RXQ_EXT_IN_FLAG_BUFF_MODE, !!buff_mode,
		INIT_RXQ_EXT_IN_FLAG_HDR_SPLIT, !!hdr_split,
		INIT_RXQ_EXT_IN_FLAG_TIMESTAMP, !!timestamp,
		INIT_RXQ_EXT_IN_FLAG_PREFIX, !!rx_prefix,
		INIT_RXQ_EXT_IN_CRC_MODE, crc_mode,
		INIT_RXQ_EXT_IN_DMA_MODE, dma_mode,
		INIT_RXQ_EXT_IN_PACKED_STREAM_BUFF_SIZE, ps_buf_size,
		INIT_RXQ_EXT_IN_FLAG_FORCE_EV_MERGING, !!force_rx_merge);

	for (i = 0; i < n_dma_addrs; ++i)
		MCDI_SET_ARRAY_QWORD(inbuf, INIT_RXQ_EXT_IN_DMA_ADDR, i,
				     dma_addrs[i]);

	if (efx_nic_rev(efx) == EFX_REV_EF100) {
		if (ef100_rx_buffer_size % L1_CACHE_BYTES) {
			rc = -EINVAL;
			goto out_unlock;
		}
		MCDI_SET_DWORD(inbuf, INIT_RXQ_V4_IN_BUFFER_SIZE_BYTES,
				      ef100_rx_buffer_size);
	}


	rc = efx_mcdi_rpc_client(efx, client_id, MC_CMD_INIT_RXQ, inbuf,
	                         MC_CMD_INIT_RXQ_V4_IN_LEN, NULL, 0, NULL);
out_unlock:
	mutex_unlock(&efx->vport_lock);
	return rc;
}

static
int __efx_dl_set_multicast_loopback_suppression(struct efx_dl_device *efx_dev,
						bool suppress, u16 vport_id,
						u8 stack_id)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_SET_PARSER_DISP_CONFIG_IN_LEN(1));
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);
	struct efx_vport *vpx;
	u32 port_id;
	int rc;

	mutex_lock(&efx->vport_lock);
	/* look up vport, convert to hw ID, and OR in stack_id */
	if (vport_id == 0)
		vpx = &efx->vport;
	else
		vpx = efx_find_vport_entry(efx, vport_id);
	if (!vpx) {
		rc = -ENOENT;
		goto out_unlock;
	}
	if (vpx->vport_id == EVB_PORT_ID_NULL) {
		rc = -EOPNOTSUPP;
		goto out_unlock;
	}
	port_id = vpx->vport_id | EVB_STACK_ID(stack_id);

	MCDI_SET_DWORD(inbuf, SET_PARSER_DISP_CONFIG_IN_TYPE,
		       MC_CMD_SET_PARSER_DISP_CONFIG_IN_VADAPTOR_SUPPRESS_SELF_TX);
	MCDI_SET_DWORD(inbuf, SET_PARSER_DISP_CONFIG_IN_ENTITY, port_id);
	MCDI_SET_DWORD(inbuf, SET_PARSER_DISP_CONFIG_IN_VALUE, !!suppress);
	rc = efx_mcdi_rpc(efx, MC_CMD_SET_PARSER_DISP_CONFIG,
			  inbuf, sizeof(inbuf), NULL, 0, NULL);
out_unlock:
	mutex_unlock(&efx->vport_lock);
	return rc;
}

static int __efx_dl_mcdi_rpc(struct efx_dl_device *efx_dev, unsigned int cmd,
			     size_t inlen, size_t outlen, size_t *outlen_actual,
			     const u8 *inbuf, u8 *outbuf)
{
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);

	/* FIXME: Buffer parameter types should be changed to __le32 *
	 * so we can reasonably assume they are properly padded even
	 * if the lengths are not multiples of 4.
	 */
	if (WARN_ON(inlen & 3 || outlen & 3))
		return -EINVAL;

	return efx_mcdi_rpc_quiet(efx, cmd, (const efx_dword_t *)inbuf,
				  inlen, (efx_dword_t *)outbuf, outlen,
				  outlen_actual);
}

static int __efx_dl_filter_block_kernel(struct efx_dl_device *efx_dev,
					enum efx_dl_filter_block_kernel_type type)
{
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);
	int rc = 0;

	mutex_lock(&efx->dl_block_kernel_mutex);

	if (efx->dl_block_kernel_count[type] == 0) {
		rc = efx->type->filter_block_kernel(efx, type);
		if (rc)
			goto unlock;
	}
	++efx->dl_block_kernel_count[type];

unlock:
	mutex_unlock(&efx->dl_block_kernel_mutex);

	return rc;
}

static void __efx_dl_filter_unblock_kernel(struct efx_dl_device *efx_dev,
					   enum efx_dl_filter_block_kernel_type type)
{
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);

	mutex_lock(&efx->dl_block_kernel_mutex);

	if (--efx->dl_block_kernel_count[type] == 0)
		efx->type->filter_unblock_kernel(efx, type);

	mutex_unlock(&efx->dl_block_kernel_mutex);
}

static long __efx_dl_dma_xlate(struct efx_dl_device *efx_dev,
			       const dma_addr_t *src,
			       dma_addr_t *dst, unsigned int n)
{
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);
	unsigned i;
	long rc = -1;

	if (!efx->type->regionmap_buffer) {
		/* This NIC has 1:1 mappings */
		memmove(dst, src, n * sizeof(src[0]));
		return n;
	}

	for (i = 0; i < n; ++i) {
		dma_addr_t addr = src[i];
		if (efx->type->regionmap_buffer(efx, &addr)) {
			if (rc < 0)
				rc = i;
			addr = (dma_addr_t)-1;
		}
		dst[i] = addr;
	}
	return rc >= 0 ? rc : n;
}

static int __efx_dl_mcdi_rpc_client(struct efx_dl_device *efx_dev,
                                    u32 client_id, unsigned int cmd,
                                    size_t inlen, size_t outlen,
                                    size_t *outlen_actual,
                                    u32 *inbuf, u32 *outbuf)
{
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);

	return efx_mcdi_rpc_client(efx, client_id, cmd, (efx_dword_t *)inbuf,
	                           inlen, (efx_dword_t *)outbuf, outlen,
	                           outlen_actual);
}

static int __efx_dl_client_alloc(struct efx_dl_device *efx_dev, u32 parent,
                                 u32 *id)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_CLIENT_ALLOC_OUT_LEN);
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);
	int rc;

	BUILD_BUG_ON(MC_CMD_CLIENT_ALLOC_IN_LEN != 0);
	rc = efx_mcdi_rpc_client(efx, parent, MC_CMD_CLIENT_ALLOC,
				 NULL, 0, outbuf, sizeof(outbuf), NULL);
	if (rc)
		return rc;
	*id = MCDI_DWORD(outbuf, CLIENT_ALLOC_OUT_CLIENT_ID);
	return 0;
}

static int __efx_dl_client_free(struct efx_dl_device *efx_dev, u32 id)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_CLIENT_FREE_IN_LEN);
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);

	MCDI_SET_DWORD(inbuf, CLIENT_FREE_IN_CLIENT_ID, id);
	return efx_mcdi_rpc(efx, MC_CMD_CLIENT_FREE,
	                    inbuf, sizeof(inbuf), NULL, 0, NULL);
}

static int __efx_dl_vi_set_user(struct efx_dl_device *efx_dev,
                                u32 vi_instance, u32 user)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_SET_VI_USER_IN_LEN);
	struct efx_nic *efx = efx_dl_device_priv(efx_dev);

	MCDI_SET_DWORD(inbuf, SET_VI_USER_IN_INSTANCE, vi_instance);
	MCDI_SET_DWORD(inbuf, SET_VI_USER_IN_CLIENT_ID, user);
	return efx_mcdi_rpc(efx, MC_CMD_SET_VI_USER,
	                    inbuf, sizeof(inbuf), NULL, 0, NULL);
}

static bool efx_dl_hw_unavailable(struct efx_dl_device *efx_dev)
{
	return efx_nic_hw_unavailable(efx_dl_device_priv(efx_dev));
}

static struct efx_dl_ops efx_driverlink_ops = {
	.hw_unavailable = efx_dl_hw_unavailable,
	.pause = __efx_dl_pause,
	.resume = __efx_dl_resume,
	.schedule_reset = __efx_dl_schedule_reset,
	.rss_flags_default = __efx_dl_rss_flags_default,
	.rss_context_new = __efx_dl_rss_context_new,
	.rss_context_set = __efx_dl_rss_context_set,
	.rss_context_free = __efx_dl_rss_context_free,
	.filter_insert = __efx_dl_filter_insert,
	.filter_remove = __efx_dl_filter_remove,
	.filter_redirect = __efx_dl_filter_redirect,
	.vport_new = __efx_dl_vport_new,
	.vport_free = __efx_dl_vport_free,
	.init_txq = __efx_dl_init_txq,
	.init_rxq = __efx_dl_init_rxq,
	.set_multicast_loopback_suppression =
		__efx_dl_set_multicast_loopback_suppression,
	.filter_block_kernel = __efx_dl_filter_block_kernel,
	.filter_unblock_kernel = __efx_dl_filter_unblock_kernel,
	.mcdi_rpc = __efx_dl_mcdi_rpc,
	.publish = __efx_dl_publish,
	.unpublish = __efx_dl_unpublish,
	.dma_xlate = __efx_dl_dma_xlate,
	.mcdi_rpc_client = __efx_dl_mcdi_rpc_client,
	.client_alloc = __efx_dl_client_alloc,
	.client_free = __efx_dl_client_free,
	.vi_set_user = __efx_dl_vi_set_user,
};

void efx_dl_probe(struct efx_nic *efx)
{
	mutex_init(&efx->dl_block_kernel_mutex);
	efx->dl_nic.pci_dev = efx->pci_dev;
	efx->dl_nic.net_dev = efx->net_dev;
	efx->dl_nic.ops = &efx_driverlink_ops;
	efx->dl_nic.msg_enable = efx->msg_enable;
	INIT_LIST_HEAD(&efx->dl_nic.nic_node);
	INIT_LIST_HEAD(&efx->dl_nic.device_list);
}
#endif
#endif

