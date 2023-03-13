/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2018 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_ETHTOOL_COMMON_H
#define EFX_ETHTOOL_COMMON_H

int efx_ethtool_phys_id(struct net_device *net_dev,
			enum ethtool_phys_id_state state);
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_SET_PHYS_ID)
int efx_ethtool_phys_id_loop(struct net_device *net_dev, u32 count);
#endif

void efx_ethtool_get_common_drvinfo(struct efx_nic *efx,
				    struct ethtool_drvinfo *info);
void efx_ethtool_get_drvinfo(struct net_device *net_dev,
			     struct ethtool_drvinfo *info);
u32 efx_ethtool_get_msglevel(struct net_device *net_dev);
void efx_ethtool_set_msglevel(struct net_device *net_dev, u32 msg_enable);
void efx_ethtool_self_test(struct net_device *net_dev,
				  struct ethtool_test *test, u64 *data);
int efx_ethtool_nway_reset(struct net_device *net_dev);
void efx_ethtool_get_pauseparam(struct net_device *net_dev,
				struct ethtool_pauseparam *pause);
int efx_ethtool_set_pauseparam(struct net_device *net_dev,
			       struct ethtool_pauseparam *pause);
int efx_ethtool_fill_self_tests(struct efx_nic *efx,
				struct efx_self_tests *tests,
				u8 *strings, u64 *data);
int efx_ethtool_get_sset_count(struct net_device *net_dev, int string_set);
void efx_ethtool_get_strings(struct net_device *net_dev, u32 string_set,
			     u8 *strings);
u32 efx_ethtool_get_priv_flags(struct net_device *net_dev);
int efx_ethtool_set_priv_flags(struct net_device *net_dev, u32 flags);
void efx_ethtool_get_stats(struct net_device *net_dev,
			   struct ethtool_stats *stats __attribute__ ((unused)),
			   u64 *data);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_CHANNELS) || defined(EFX_HAVE_ETHTOOL_EXT_CHANNELS)
void efx_ethtool_get_channels(struct net_device *net_dev,
			      struct ethtool_channels *channels);
int efx_ethtool_set_channels(struct net_device *net_dev,
			     struct ethtool_channels *channels);
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_LINKSETTINGS)
int efx_ethtool_get_link_ksettings(struct net_device *net_dev,
				   struct ethtool_link_ksettings *out);
int efx_ethtool_set_link_ksettings(struct net_device *net_dev,
				const struct ethtool_link_ksettings *settings);
#endif
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_LINKSETTINGS) || defined(EFX_HAVE_ETHTOOL_LEGACY)
int efx_ethtool_get_settings(struct net_device *net_dev,
			     struct ethtool_cmd *ecmd);
int efx_ethtool_set_settings(struct net_device *net_dev,
			     struct ethtool_cmd *ecmd);
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_FECSTATS)
void efx_ethtool_get_fec_stats(struct net_device *net_dev,
			       struct ethtool_fec_stats *fec_stats);
#endif
int efx_ethtool_get_fecparam(struct net_device *net_dev,
			       struct ethtool_fecparam *fecparam);
int efx_ethtool_set_fecparam(struct net_device *net_dev,
			       struct ethtool_fecparam *fecparam);

#ifdef EFX_USE_KCOMPAT
int efx_ethtool_get_rxnfc(struct net_device *net_dev,
			  struct efx_ethtool_rxnfc *info, u32 *rule_locs);
#else
int efx_ethtool_get_rxnfc(struct net_device *net_dev,
			  struct ethtool_rxnfc *info, u32 *rule_locs);
#endif
#ifdef EFX_USE_KCOMPAT
int efx_ethtool_get_rxnfc_wrapper(struct net_device *net_dev,
					 struct ethtool_rxnfc *info,
#ifdef EFX_HAVE_OLD_ETHTOOL_GET_RXNFC
					 void *rules);
#else
					 u32 *rules);
#endif
int efx_ethtool_set_rxnfc_wrapper(struct net_device *net_dev,
					 struct ethtool_rxnfc *info);
#endif
int efx_ethtool_reset(struct net_device *net_dev, u32 *flags);

#define IP4_ADDR_FULL_MASK      ((__force __be32)~0)
#define IP_PROTO_FULL_MASK      0xFF
#define PORT_FULL_MASK	  ((__force __be16)~0)
#define ETHER_TYPE_FULL_MASK    ((__force __be16)~0)

static inline void ip6_fill_mask(__be32 *mask)
{
	mask[0] = mask[1] = mask[2] = mask[3] = ~(__be32)0;
}

u32 efx_ethtool_get_rxfh_indir_size(struct net_device *net_dev);
u32 efx_ethtool_get_rxfh_key_size(struct net_device *net_dev);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_GET_RXFH) || defined(EFX_HAVE_ETHTOOL_GET_RXFH_INDIR) || !defined(EFX_HAVE_ETHTOOL_RXFH_INDIR)
int efx_ethtool_get_rxfh(struct net_device *net_dev, u32 *indir, u8 *key,
			 u8 *hfunc);
int efx_ethtool_set_rxfh(struct net_device *net_dev,
			 const u32 *indir, const u8 *key, const u8 hfunc);
#else
int efx_sfctool_get_rxfh(struct efx_nic *efx, u32 *indir, u8 *key,
			 u8 *hfunc);
int efx_sfctool_set_rxfh(struct efx_nic *efx,
			 const u32 *indir, const u8 *key, const u8 hfunc);
#endif


#if defined(EFX_USE_KCOMPAT)
#if defined(EFX_HAVE_ETHTOOL_GET_RXFH_INDIR) && !defined(EFX_HAVE_ETHTOOL_GET_RXFH) && !defined(EFX_HAVE_OLD_ETHTOOL_RXFH_INDIR)
/* Wrappers that only set the indirection table, not the key. */
int efx_ethtool_get_rxfh_indir(struct net_device *net_dev, u32 *indir);
int efx_ethtool_set_rxfh_indir(struct net_device *net_dev,const u32 *indir);
#endif
#endif
#if defined(EFX_HAVE_OLD_ETHTOOL_RXFH_INDIR) || !defined(EFX_HAVE_ETHTOOL_RXFH_INDIR)
int efx_ethtool_old_get_rxfh_indir(struct net_device *net_dev,
				   struct ethtool_rxfh_indir *indir);
int efx_ethtool_old_set_rxfh_indir(struct net_device *net_dev,
				   const struct ethtool_rxfh_indir *indir);
#endif

#if defined(EFX_HAVE_ETHTOOL_GET_RXFH) && !defined(EFX_HAVE_CONFIGURABLE_RSS_HASH)
/* Wrappers without hash function getting and setting. */
int efx_ethtool_get_rxfh_no_hfunc(struct net_device *net_dev,
				  u32 *indir, u8 *key);
# if defined(EFX_HAVE_ETHTOOL_SET_RXFH_NOCONST)
/* RH backported version doesn't have const for arguments. */
int efx_ethtool_set_rxfh_no_hfunc(struct net_device *net_dev,
				  u32 *indir, u8 *key);
# else
int efx_ethtool_set_rxfh_no_hfunc(struct net_device *net_dev,
				  const u32 *indir, const u8 *key);
# endif
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_RXFH_CONTEXT)
int efx_ethtool_get_rxfh_context(struct net_device *net_dev, u32 *indir,
				 u8 *key, u8 *hfunc, u32 rss_context);
int efx_ethtool_set_rxfh_context(struct net_device *net_dev,
				 const u32 *indir, const u8 *key,
				 const u8 hfunc, u32 *rss_context,
				 bool delete);
#else
int efx_sfctool_get_rxfh_context(struct efx_nic *efx, u32 *indir,
				 u8 *key, u8 *hfunc, u32 rss_context);
int efx_sfctool_set_rxfh_context(struct efx_nic *efx,
				 const u32 *indir, const u8 *key,
				 const u8 hfunc, u32 *rss_context,
				 bool delete);
#endif

#endif

int efx_ethtool_get_module_eeprom(struct net_device *net_dev,
				  struct ethtool_eeprom *ee,
				  u8 *data);
int efx_ethtool_get_module_info(struct net_device *net_dev,
				struct ethtool_modinfo *modinfo);

#if defined(EFX_USE_KCOMPAT) && (!defined(EFX_USE_DEVLINK) || defined(EFX_NEED_ETHTOOL_FLASH_DEVICE))
int efx_ethtool_flash_device(struct net_device *net_dev,
			     struct ethtool_flash *flash);
#endif
