/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_SFCTOOL_H
#define EFX_SFCTOOL_H

#ifdef EFX_USE_KCOMPAT
/* Must come before other headers */
#include "kernel_compat.h"
#endif

/* Forward declaration */
struct efx_nic;

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_FECPARAM)
/**
 * struct ethtool_fecparam - Ethernet forward error correction(fec) parameters
 * @cmd: Command number = %ETHTOOL_GFECPARAM or %ETHTOOL_SFECPARAM
 * @active_fec: FEC mode which is active on porte
 * @fec: Bitmask of supported/configured FEC modes
 * @reserved: Reserved for future extensions. i.e FEC bypass feature.
 *
 * Drivers should reject a non-zero setting of @autoneg when
 * autoneogotiation is disabled (or not supported) for the link.
 *
 */
struct ethtool_fecparam {
	__u32   cmd;
	/* bitmask of FEC modes */
	__u32   active_fec;
	__u32   fec;
	__u32   reserved;
};

/**
 * enum ethtool_fec_config_bits - flags definition of ethtool_fec_configuration
 * @ETHTOOL_FEC_NONE_BIT: FEC mode configuration is not supported
 * @ETHTOOL_FEC_AUTO_BIT: Default/Best FEC mode provided by driver
 * @ETHTOOL_FEC_OFF_BIT: No FEC Mode
 * @ETHTOOL_FEC_RS_BIT: Reed-Solomon Forward Error Detection mode
 * @ETHTOOL_FEC_BASER_BIT: Base-R/Reed-Solomon Forward Error Detection mode
 */
enum ethtool_fec_config_bits {
	ETHTOOL_FEC_NONE_BIT,
	ETHTOOL_FEC_AUTO_BIT,
	ETHTOOL_FEC_OFF_BIT,
	ETHTOOL_FEC_RS_BIT,
	ETHTOOL_FEC_BASER_BIT,
};

#define ETHTOOL_FEC_NONE		(1 << ETHTOOL_FEC_NONE_BIT)
#define ETHTOOL_FEC_AUTO		(1 << ETHTOOL_FEC_AUTO_BIT)
#define ETHTOOL_FEC_OFF			(1 << ETHTOOL_FEC_OFF_BIT)
#define ETHTOOL_FEC_RS			(1 << ETHTOOL_FEC_RS_BIT)
#define ETHTOOL_FEC_BASER		(1 << ETHTOOL_FEC_BASER_BIT)

#define ETHTOOL_GFECPARAM	0x00000050 /* Get FEC settings */
#define ETHTOOL_SFECPARAM	0x00000051 /* Set FEC settings */
#endif /* !EFX_HAVE_ETHTOOL_FECPARAM */

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_RXFH_CONTEXT)
/**
 * struct sfctool_rxfh - command to get/set RX flow hash indir or/and hash key.
 * @cmd: Specific command number - %ETHTOOL_GRSSH or %ETHTOOL_SRSSH
 * @rss_context: RSS context identifier.  Context 0 is the default for normal
 *	traffic; other contexts can be referenced as the destination for RX flow
 *	classification rules.  %ETH_RXFH_CONTEXT_ALLOC is used with command
 *	%ETHTOOL_SRSSH to allocate a new RSS context; on return this field will
 *	contain the ID of the newly allocated context.
 * @indir_size: On entry, the array size of the user buffer for the
 *	indirection table, which may be zero, or (for %ETHTOOL_SRSSH),
 *	%ETH_RXFH_INDIR_NO_CHANGE.  On return from %ETHTOOL_GRSSH,
 *	the array size of the hardware indirection table.
 * @key_size: On entry, the array size of the user buffer for the hash key,
 *	which may be zero.  On return from %ETHTOOL_GRSSH, the size of the
 *	hardware hash key.
 * @hfunc: Defines the current RSS hash function used by HW (or to be set to).
 *	Valid values are one of the %ETH_RSS_HASH_*.
 * @rsvd8:	Reserved for future extensions.
 * @rsvd32:	Reserved for future extensions.
 * @rss_config: RX ring/queue index for each hash value i.e., indirection table
 *	of @indir_size __u32 elements, followed by hash key of @key_size
 *	bytes.
 *
 * For %ETHTOOL_GRSSH, a @indir_size and key_size of zero means that only the
 * size should be returned.  For %ETHTOOL_SRSSH, an @indir_size of
 * %ETH_RXFH_INDIR_NO_CHANGE means that indir table setting is not requested
 * and a @indir_size of zero means the indir table should be reset to default
 * values (if @rss_context == 0) or that the RSS context should be deleted.
 * An hfunc of zero means that hash function setting is not requested.
 */
struct sfctool_rxfh {
	__u32   cmd;
	__u32	rss_context;
	__u32   indir_size;
	__u32   key_size;
	__u8	hfunc;
	__u8	rsvd8[3];
	__u32	rsvd32;
	__u32   rss_config[0];
};
#define ETH_RXFH_CONTEXT_ALLOC		0xffffffff
#ifndef ETH_RXFH_INDIR_NO_CHANGE
#define ETH_RXFH_INDIR_NO_CHANGE	0xffffffff
#endif

#ifndef ETHTOOL_GRSSH
#define ETHTOOL_GRSSH		0x00000046 /* Get RX flow hash configuration */
#define ETHTOOL_SRSSH		0x00000047 /* Set RX flow hash configuration */
#endif
#endif /* !EFX_HAVE_ETHTOOL_RXFH_CONTEXT */

int efx_sfctool(struct efx_nic *efx, u32 cmd, void __user *data);

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_RXFH_CONTEXT)
u32 efx_sfctool_get_rxfh_indir_size(struct efx_nic *efx);
u32 efx_sfctool_get_rxfh_key_size(struct efx_nic *efx);
int efx_sfctool_get_rxnfc(struct efx_nic *efx,
			  struct efx_ethtool_rxnfc *info, u32 *rule_locs);
int efx_sfctool_get_rxfh_context(struct efx_nic *efx, u32 *indir,
				 u8 *key, u8 *hfunc, u32 rss_context);
int efx_sfctool_set_rxfh_context(struct efx_nic *efx,
				 const u32 *indir, const u8 *key,
				 const u8 hfunc, u32 *rss_context,
				 bool delete);
#endif
#endif /* EFX_SFCTOOL_H */
