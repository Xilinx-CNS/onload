/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/in.h>
#include "mcdi_pcol.h"
#include "net_driver.h"
#include "workarounds.h"
#include "selftest.h"
#include "efx.h"
#include "filter.h"
#include "nic.h"
#include "efx_common.h"
#include "mcdi_port_common.h"
#include "efx_channels.h"
#include "tx_common.h"
#include "ethtool_common.h"
#include "efx_reflash.h"
#ifdef CONFIG_SFC_DUMP
#include "dump.h"
#endif

#ifdef EFX_NOT_UPSTREAM
#include "sfctool.h"
#endif
#include "efx_ethtool.h"

#define EFX_ETHTOOL_EEPROM_MAGIC 0xEFAB

/**************************************************************************
 *
 * Ethtool operations
 *
 **************************************************************************
 */

static int efx_ethtool_get_regs_len(struct net_device *net_dev)
{
	return efx_nic_get_regs_len(efx_netdev_priv(net_dev));
}

static void efx_ethtool_get_regs(struct net_device *net_dev,
				 struct ethtool_regs *regs, void *buf)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	regs->version = efx->type->revision;
	efx_nic_get_regs(efx, buf);
}

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_ETHTOOL_GET_SSET_COUNT)
static int efx_ethtool_get_stats_count(struct net_device *net_dev)
{
	return efx_ethtool_get_sset_count(net_dev, ETH_SS_STATS);
}
static int efx_ethtool_self_test_count(struct net_device *net_dev)
{
	return efx_ethtool_get_sset_count(net_dev, ETH_SS_TEST);
}
#endif

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NDO_SET_FEATURES) && !defined(EFX_HAVE_EXT_NDO_SET_FEATURES)

static int efx_ethtool_set_tso(struct net_device *net_dev, u32 enable)
{
	struct efx_nic *efx __attribute__ ((unused)) = efx_netdev_priv(net_dev);
	u32 features;

	features = NETIF_F_TSO;
	if (efx->type->offload_features & (NETIF_F_IPV6_CSUM | NETIF_F_HW_CSUM))
		features |= NETIF_F_TSO6;

	if (enable)
		net_dev->features |= features;
	else
		net_dev->features &= ~features;

	return 0;
}

static int efx_ethtool_set_tx_csum(struct net_device *net_dev, u32 enable)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	u32 features = efx->type->offload_features & NETIF_F_CSUM_MASK;

	if (enable)
		net_dev->features |= features;
	else
		net_dev->features &= ~features;

	return 0;
}

static int efx_ethtool_set_rx_csum(struct net_device *net_dev, u32 enable)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	/* No way to stop the hardware doing the checks; we just
	 * ignore the result.
	 */
	efx->rx_checksum_enabled = !!enable;

	return 0;
}

static u32 efx_ethtool_get_rx_csum(struct net_device *net_dev)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	return efx->rx_checksum_enabled;
}

#if defined(EFX_USE_ETHTOOL_FLAGS)
static int efx_ethtool_set_flags(struct net_device *net_dev, u32 data)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	u32 supported = (efx->type->offload_features &
			 (ETH_FLAG_RXHASH | ETH_FLAG_NTUPLE));
	int rc;

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	if (efx->lro_available)
		supported |= ETH_FLAG_LRO;
#endif

	if (data & ~supported)
		return -EINVAL;

	if (net_dev->features & ~data & ETH_FLAG_NTUPLE) {
		rc = efx->type->filter_clear_rx(efx, EFX_FILTER_PRI_MANUAL);
		if (rc)
			return rc;
	}

	net_dev->features = (net_dev->features & ~supported) | data;
	return 0;
}
#endif

#endif /* EFX_HAVE_NDO_SET_FEATURES && EFX_HAVE_EXT_NDO_SET_FEATURES */

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_ETHTOOL_OP_GET_LINK)
static u32 efx_ethtool_get_link(struct net_device *net_dev)
{
	return netif_running(net_dev) && netif_carrier_ok(net_dev);
}
#endif

/*
 * Each channel has a single IRQ and moderation timer, started by any
 * completion (or other event).  Unless the module parameter
 * separate_tx_channels is set, IRQs and moderation are therefore
 * shared between RX and TX completions.  In this case, when RX IRQ
 * moderation is explicitly changed then TX IRQ moderation is
 * automatically changed too, but otherwise we fail if the two values
 * are requested to be different.
 *
 * The hardware does not support a limit on the number of completions
 * before an IRQ, so we do not use the max_frames fields.  We should
 * report and require that max_frames == (usecs != 0), but this would
 * invalidate existing user documentation.
 *
 * The hardware does not have distinct settings for interrupt
 * moderation while the previous IRQ is being handled, so we should
 * not use the 'irq' fields.  However, an earlier developer
 * misunderstood the meaning of the 'irq' fields and the driver did
 * not support the standard fields.  To avoid invalidating existing
 * user documentation, we report and accept changes through either the
 * standard or 'irq' fields.  If both are changed at the same time, we
 * prefer the standard field.
 *
 * We implement adaptive IRQ moderation, but use a different algorithm
 * from that assumed in the definition of struct ethtool_coalesce.
 * Therefore we do not use any of the adaptive moderation parameters
 * in it.
 */

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_COALESCE_CQE)
static int efx_ethtool_get_coalesce(struct net_device *net_dev,
				    struct ethtool_coalesce *coalesce,
				    struct kernel_ethtool_coalesce *kernel_coal,
				    struct netlink_ext_ack *extack)
#else
static int efx_ethtool_get_coalesce(struct net_device *net_dev,
				    struct ethtool_coalesce *coalesce)
#endif
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	unsigned int tx_usecs, rx_usecs;
	bool rx_adaptive;
	int rc;

	rc = efx_get_irq_moderation(efx, &tx_usecs, &rx_usecs, &rx_adaptive);
	if (rc)
		return rc;

	coalesce->tx_coalesce_usecs = tx_usecs;
	coalesce->tx_coalesce_usecs_irq = tx_usecs;
	coalesce->rx_coalesce_usecs = rx_usecs;
	coalesce->rx_coalesce_usecs_irq = rx_usecs;
	coalesce->use_adaptive_rx_coalesce = rx_adaptive;
	coalesce->stats_block_coalesce_usecs = efx->stats_period_ms * 1000;

	return 0;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_COALESCE_CQE)
static int efx_ethtool_set_coalesce(struct net_device *net_dev,
				    struct ethtool_coalesce *coalesce,
				    struct kernel_ethtool_coalesce *kernel_coal,
				    struct netlink_ext_ack *extack)
#else
static int efx_ethtool_set_coalesce(struct net_device *net_dev,
				    struct ethtool_coalesce *coalesce)
#endif
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	struct efx_channel *channel;
	unsigned int tx_usecs, rx_usecs;
	bool adaptive, rx_may_override_tx;
	unsigned int stats_usecs;
	int rc = 0;

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_COALESCE_PARAMS)
	if (coalesce->use_adaptive_tx_coalesce)
		return -EINVAL;
#endif

	efx_for_each_channel(channel, efx)
		if (channel->enabled) {
			rc = 1;
			break;
        }

	if (!rc)
		return -ENETDOWN;

	rc = efx_get_irq_moderation(efx, &tx_usecs, &rx_usecs, &adaptive);
	if (rc)
		return rc;

	if (coalesce->rx_coalesce_usecs != rx_usecs)
		rx_usecs = coalesce->rx_coalesce_usecs;
	else
		rx_usecs = coalesce->rx_coalesce_usecs_irq;

	adaptive = coalesce->use_adaptive_rx_coalesce;

	/* If channels are shared, TX IRQ moderation can be quietly
	 * overridden unless it is changed from its old value.
	 */
	rx_may_override_tx = (coalesce->tx_coalesce_usecs == tx_usecs &&
			      coalesce->tx_coalesce_usecs_irq == tx_usecs);
	if (coalesce->tx_coalesce_usecs != tx_usecs)
		tx_usecs = coalesce->tx_coalesce_usecs;
	else
		tx_usecs = coalesce->tx_coalesce_usecs_irq;

	rc = efx_init_irq_moderation(efx, tx_usecs, rx_usecs, adaptive,
				     rx_may_override_tx);
	if (rc != 0)
		return rc;

	efx_for_each_channel(channel, efx)
		if (channel->enabled)
			efx->type->push_irq_moderation(channel);

	stats_usecs = coalesce->stats_block_coalesce_usecs;
	if (stats_usecs > 0 && stats_usecs < 1000)
		stats_usecs = 1000;

	efx->stats_period_ms = stats_usecs / 1000;
	if (efx->type->update_stats_period)
		efx->type->update_stats_period(efx);
	else
		efx_mcdi_mac_update_stats_period(efx);

	return 0;
}

static void efx_ethtool_get_ringparam(struct net_device *net_dev,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_GET_RINGPARAM_EXTACK)
				      struct ethtool_ringparam *ring,
				      struct kernel_ethtool_ringparam *kring,
				      struct netlink_ext_ack *ext_ack)
#else
				      struct ethtool_ringparam *ring)
#endif
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	ring->rx_max_pending = efx_max_dmaq_size(efx);
	ring->tx_max_pending = EFX_TXQ_MAX_ENT(efx);
	ring->rx_pending = efx->rxq_entries;
	ring->tx_pending = efx->txq_entries;
}

static int efx_ethtool_set_ringparam(struct net_device *net_dev,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_SET_RINGPARAM_EXTACK)
				     struct ethtool_ringparam *ring,
				     struct kernel_ethtool_ringparam *kring,
				     struct netlink_ext_ack *ext_ack)
#else
				     struct ethtool_ringparam *ring)
#endif
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	bool is_up = !efx_check_disabled(efx) && netif_running(efx->net_dev);
	int rc;

	if (ring->rx_mini_pending || ring->rx_jumbo_pending)
		return -EINVAL;

	if (ring->rx_pending == efx->rxq_entries &&
	    ring->tx_pending == efx->txq_entries)
		/* Nothing to do */
		return 0;

	/* Validate range and rounding of RX queue. */
	rc = efx_check_queue_size(efx, &ring->rx_pending,
				  EFX_RXQ_MIN_ENT, efx_max_dmaq_size(efx),
				  false);
	if (rc == -ERANGE)
		netif_err(efx, drv, efx->net_dev,
			  "Rx queue length must be between %u and %lu\n",
			  EFX_RXQ_MIN_ENT, efx_max_dmaq_size(efx));
	else if (rc == -EINVAL)
		netif_err(efx, drv, efx->net_dev,
			  "Rx queue length must be power of two\n");

	if (rc)
		return rc;

	/* Validate range and rounding of TX queue. */
	rc = efx_check_queue_size(efx, &ring->tx_pending,
				  efx->txq_min_entries, EFX_TXQ_MAX_ENT(efx),
				  false);
	if (rc == -ERANGE)
		netif_err(efx, drv, efx->net_dev,
			  "Tx queue length must be between %u and %lu\n",
			  efx->txq_min_entries, EFX_TXQ_MAX_ENT(efx));
	else if (rc == -EINVAL)
		netif_err(efx, drv, efx->net_dev,
			  "Tx queue length must be power of two\n");
	if (rc)
		return rc;

#ifdef EFX_NOT_UPSTREAM
#if IS_MODULE(CONFIG_SFC_DRIVERLINK)
	if (efx->open_count > is_up) {
		netif_err(efx, drv, efx->net_dev,
			  "unable to set ring sizes. device in use by driverlink stack\n");
		return -EBUSY;
	}
#endif
#endif

	/* Apply the new settings */
	efx->rxq_entries = ring->rx_pending;
	efx->txq_entries = ring->tx_pending;

	/* Update the datapath with the new settings if the interface is up */
	if (is_up) {
		dev_close(net_dev);
		rc = dev_open(net_dev, NULL);
	}

	return rc;
}

static void efx_ethtool_get_wol(struct net_device *net_dev,
				struct ethtool_wolinfo *wol)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	return efx->type->get_wol(efx, wol);
}


static int efx_ethtool_set_wol(struct net_device *net_dev,
			       struct ethtool_wolinfo *wol)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	return efx->type->set_wol(efx, wol->wolopts);
}

#ifdef CONFIG_SFC_DUMP
int efx_ethtool_get_dump_flag(struct net_device *net_dev,
			      struct ethtool_dump *dump)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	return efx_dump_get_flag(efx, dump);
}

int efx_ethtool_get_dump_data(struct net_device *net_dev,
			      struct ethtool_dump *dump, void *buffer)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	return efx_dump_get_data(efx, dump, buffer);
}

int efx_ethtool_set_dump(struct net_device *net_dev, struct ethtool_dump *val)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	return efx_dump_set(efx, val);
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_GET_TS_INFO) || defined(EFX_HAVE_ETHTOOL_EXT_GET_TS_INFO)
static
#endif
int efx_ethtool_get_ts_info(struct net_device *net_dev,
			    struct ethtool_ts_info *ts_info)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	/* Software capabilities */
	ts_info->so_timestamping = (SOF_TIMESTAMPING_RX_SOFTWARE |
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB_TX_TIMESTAMP)
				    SOF_TIMESTAMPING_TX_SOFTWARE |
#endif
				    SOF_TIMESTAMPING_SOFTWARE);
	ts_info->phc_index = -1;

	efx_ptp_get_ts_info(efx, ts_info);
	return 0;
}

#if defined(EFX_USE_KCOMPAT) && (!defined(EFX_USE_DEVLINK) || defined(EFX_NEED_ETHTOOL_FLASH_DEVICE))
int efx_ethtool_flash_device(struct net_device *net_dev,
			     struct ethtool_flash *flash)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	const struct firmware *fw;
	int rc;

	if (flash->region != ETHTOOL_FLASH_ALL_REGIONS) {
		netif_err(efx, drv, efx->net_dev,
			  "Updates to NVRAM region %u are not supported\n",
			  flash->region);
		return -EINVAL;
	}

	rc = request_firmware(&fw, flash->data, &efx->pci_dev->dev);
	if (rc)
		return rc;

	dev_hold(net_dev);
	rtnl_unlock();

	rc = efx_reflash_flash_firmware(efx, fw);

	rtnl_lock();
	dev_put(net_dev);

	release_firmware(fw);
	return rc;
}
#endif

const struct ethtool_ops efx_ethtool_ops = {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_RXFH_PARAM)
	.cap_rss_ctx_supported	= true,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_COALESCE_PARAMS)
	.supported_coalesce_params = (ETHTOOL_COALESCE_USECS |
				      ETHTOOL_COALESCE_USECS_IRQ |
				      ETHTOOL_COALESCE_STATS_BLOCK_USECS |
				      ETHTOOL_COALESCE_USE_ADAPTIVE_RX),
#endif
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_LINKSETTINGS) || defined(EFX_HAVE_ETHTOOL_LEGACY)
	.get_settings		= efx_ethtool_get_settings,
	.set_settings		= efx_ethtool_set_settings,
#endif
	.get_drvinfo		= efx_ethtool_get_drvinfo,
	.get_regs_len		= efx_ethtool_get_regs_len,
	.get_regs		= efx_ethtool_get_regs,
	.get_msglevel		= efx_ethtool_get_msglevel,
	.set_msglevel		= efx_ethtool_set_msglevel,
	.nway_reset		= efx_ethtool_nway_reset,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_ETHTOOL_OP_GET_LINK)
	.get_link		= ethtool_op_get_link,
#else
	.get_link		= efx_ethtool_get_link,
#endif
	.get_coalesce		= efx_ethtool_get_coalesce,
	.set_coalesce		= efx_ethtool_set_coalesce,
	.get_ringparam		= efx_ethtool_get_ringparam,
	.set_ringparam		= efx_ethtool_set_ringparam,
	.get_pauseparam         = efx_ethtool_get_pauseparam,
	.set_pauseparam         = efx_ethtool_set_pauseparam,
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NDO_SET_FEATURES) && !defined(EFX_HAVE_EXT_NDO_SET_FEATURES)
	.get_rx_csum		= efx_ethtool_get_rx_csum,
	.set_rx_csum		= efx_ethtool_set_rx_csum,
	.get_tx_csum		= ethtool_op_get_tx_csum,
	/* Need to enable/disable IPv6 too */
	.set_tx_csum		= efx_ethtool_set_tx_csum,
	.get_sg			= ethtool_op_get_sg,
	.set_sg			= ethtool_op_set_sg,
	.get_tso		= ethtool_op_get_tso,
	/* Need to enable/disable TSO-IPv6 too */
	.set_tso		= efx_ethtool_set_tso,
#if defined(EFX_USE_ETHTOOL_FLAGS)
	.get_flags		= ethtool_op_get_flags,
	.set_flags		= efx_ethtool_set_flags,
#endif
#endif /* EFX_HAVE_NDO_SET_FEATURES */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_ETHTOOL_GET_SSET_COUNT)
	.get_sset_count		= efx_ethtool_get_sset_count,
#else
	.self_test_count	= efx_ethtool_self_test_count,
	.get_stats_count	= efx_ethtool_get_stats_count,
#endif
#if defined(EFX_USE_KCOMPAT) && (!defined(EFX_USE_DEVLINK) || defined(EFX_NEED_ETHTOOL_FLASH_DEVICE))
	.flash_device		= efx_ethtool_flash_device,
#endif
	.get_priv_flags		= efx_ethtool_get_priv_flags,
	.set_priv_flags		= efx_ethtool_set_priv_flags,
	.self_test		= efx_ethtool_self_test,
	.get_strings		= efx_ethtool_get_strings,
#if !defined(EFX_USE_KCOMPAT) || (defined(EFX_HAVE_ETHTOOL_SET_PHYS_ID) && !defined(EFX_USE_ETHTOOL_OPS_EXT))
	.set_phys_id		= efx_ethtool_phys_id,
#elif !defined(EFX_USE_ETHTOOL_OPS_EXT)
	.phys_id		= efx_ethtool_phys_id_loop,
#endif
	.get_ethtool_stats	= efx_ethtool_get_stats,
	.get_wol                = efx_ethtool_get_wol,
	.set_wol                = efx_ethtool_set_wol,
#if !defined(EFX_USE_KCOMPAT) || (defined(EFX_HAVE_ETHTOOL_RESET) && !defined(EFX_USE_ETHTOOL_OPS_EXT))
	.reset			= efx_ethtool_reset,
#endif
#if !defined(EFX_USE_KCOMPAT)
	.get_rxnfc		= efx_ethtool_get_rxnfc,
	.set_rxnfc		= efx_ethtool_set_rxnfc,
#else
	.get_rxnfc		= efx_ethtool_get_rxnfc_wrapper,
	.set_rxnfc		= efx_ethtool_set_rxnfc_wrapper,
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_ETHTOOL_OPS_EXT)
};
const struct ethtool_ops_ext efx_ethtool_ops_ext = {
	.size			= sizeof(struct ethtool_ops_ext),
	.set_phys_id		= efx_ethtool_phys_id,
	/* Do not set ethtool_ops_ext::reset due to RH BZ 1008678 (SF bug 39031) */
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_GET_RXFH_INDIR_SIZE)
	.get_rxfh_indir_size	= efx_ethtool_get_rxfh_indir_size,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_GET_RXFH_KEY_SIZE)
	.get_rxfh_key_size	= efx_ethtool_get_rxfh_key_size,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_CONFIGURABLE_RSS_HASH)
	.get_rxfh		= efx_ethtool_get_rxfh,
	.set_rxfh		= efx_ethtool_set_rxfh,
#elif defined(EFX_HAVE_ETHTOOL_GET_RXFH)
	.get_rxfh		= efx_ethtool_get_rxfh_no_hfunc,
	.set_rxfh		= efx_ethtool_set_rxfh_no_hfunc,
#elif defined(EFX_HAVE_ETHTOOL_GET_RXFH_INDIR)
# if defined(EFX_HAVE_OLD_ETHTOOL_RXFH_INDIR)
	.get_rxfh_indir		= efx_ethtool_old_get_rxfh_indir,
	.set_rxfh_indir		= efx_ethtool_old_set_rxfh_indir,
# else
	.get_rxfh_indir		= efx_ethtool_get_rxfh_indir,
	.set_rxfh_indir		= efx_ethtool_set_rxfh_indir,
# endif
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_ETHTOOL_RXFH_CONTEXT)
	.get_rxfh_context	= efx_ethtool_get_rxfh_context,
	.set_rxfh_context	= efx_ethtool_set_rxfh_context,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_GET_DUMP_FLAG) || defined(EFX_HAVE_ETHTOOL_GET_DUMP_DATA) || defined(EFX_HAVE_ETHTOOL_SET_DUMP)
#ifdef CONFIG_SFC_DUMP
	.get_dump_flag		= efx_ethtool_get_dump_flag,
	.get_dump_data		= efx_ethtool_get_dump_data,
	.set_dump		= efx_ethtool_set_dump,
#endif
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_GET_TS_INFO) || defined(EFX_HAVE_ETHTOOL_EXT_GET_TS_INFO)
	.get_ts_info		= efx_ethtool_get_ts_info,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_GMODULEEEPROM)
	.get_module_info	= efx_ethtool_get_module_info,
	.get_module_eeprom	= efx_ethtool_get_module_eeprom,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_CHANNELS) || defined(EFX_HAVE_ETHTOOL_EXT_CHANNELS)
	.get_channels		= efx_ethtool_get_channels,
	.set_channels		= efx_ethtool_set_channels,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_LINKSETTINGS)
	.get_link_ksettings	= efx_ethtool_get_link_ksettings,
	.set_link_ksettings	= efx_ethtool_set_link_ksettings,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_FECSTATS)
	.get_fec_stats		= efx_ethtool_get_fec_stats,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_FECPARAM)
	.get_fecparam		= efx_ethtool_get_fecparam,
	.set_fecparam		= efx_ethtool_set_fecparam,
#endif
};
