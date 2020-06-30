/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2018 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#include <linux/module.h>
#include <linux/netdevice.h>
#include "net_driver.h"
#include "efx.h"
#include "mcdi_port_common.h"
#include "ethtool_common.h"
#include "ef100_ethtool.h"
#include "mcdi_functions.h"

/* This is the maximum number of descriptor rings supported by the QDMA */
#define EFX_EF100_MAX_DMAQ_SIZE 16384UL

static void ef100_ethtool_get_ringparam(struct net_device *net_dev,
					struct ethtool_ringparam *ring)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	ring->rx_max_pending = EFX_EF100_MAX_DMAQ_SIZE;
	ring->tx_max_pending = EFX_EF100_MAX_DMAQ_SIZE;
	ring->rx_pending = efx->rxq_entries;
	ring->tx_pending = efx->txq_entries;
}

/*	Ethtool options available
 */
const struct ethtool_ops ef100_ethtool_ops = {
	.get_drvinfo		= efx_ethtool_get_drvinfo,
	.get_msglevel		= efx_ethtool_get_msglevel,
	.set_msglevel		= efx_ethtool_set_msglevel,
	.nway_reset		= efx_ethtool_nway_reset,
	.get_pauseparam         = efx_ethtool_get_pauseparam,
	.set_pauseparam         = efx_ethtool_set_pauseparam,
	.get_sset_count		= efx_ethtool_get_sset_count,
	.get_priv_flags		= efx_ethtool_get_priv_flags,
	.set_priv_flags		= efx_ethtool_set_priv_flags,
	.self_test		= efx_ethtool_self_test,
	.get_strings		= efx_ethtool_get_strings,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_LINKSETTINGS)
	.get_link_ksettings	= efx_ethtool_get_link_ksettings,
	.set_link_ksettings	= efx_ethtool_set_link_ksettings,
#else
	.get_settings		= efx_ethtool_get_settings,
	.set_settings		= efx_ethtool_set_settings,
#endif
	.get_link		= ethtool_op_get_link,
	.get_ringparam		= ef100_ethtool_get_ringparam,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_FECPARAM)
	.get_fecparam		= efx_ethtool_get_fecparam,
	.set_fecparam		= efx_ethtool_set_fecparam,
#endif
	.get_ethtool_stats	= efx_ethtool_get_stats,
#if !defined(EFX_USE_KCOMPAT)
	.get_rxnfc              = efx_ethtool_get_rxnfc,
	.set_rxnfc              = efx_ethtool_set_rxnfc,
#elif defined(EFX_HAVE_ETHTOOL_RXNFC)
	.get_rxnfc              = efx_ethtool_get_rxnfc_wrapper,
	.set_rxnfc              = efx_ethtool_set_rxnfc_wrapper,
#endif
#ifdef EFX_FLASH_FIRMWARE
	.flash_device		= efx_mcdi_flash_bundle,
#endif
#if !defined(EFX_USE_KCOMPAT) || (defined(EFX_HAVE_ETHTOOL_RESET) && !defined(EFX_USE_ETHTOOL_OPS_EXT))
	.reset                  = efx_ethtool_reset,
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_ETHTOOL_OPS_EXT)
};

const struct ethtool_ops_ext efx_ethtool_ops_ext = {
	.size			= sizeof(struct ethtool_ops_ext),
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
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_RXFH_CONTEXT)
	.get_rxfh_context	= efx_ethtool_get_rxfh_context,
	.set_rxfh_context	= efx_ethtool_set_rxfh_context,
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_GMODULEEEPROM)
	.get_module_info	= efx_ethtool_get_module_info,
	.get_module_eeprom	= efx_ethtool_get_module_eeprom,
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_CHANNELS) || defined(EFX_HAVE_ETHTOOL_EXT_CHANNELS)
	.get_channels		= efx_ethtool_get_channels,
	.set_channels		= efx_ethtool_set_channels,
#endif
};

