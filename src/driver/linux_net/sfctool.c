/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "sfctool.h"
#include "net_driver.h"
#include "ethtool_common.h"
#include "efx_ethtool.h"
#include "efx_ioctl.h"
#include "ioctl_common.h"

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_FECPARAM)
int efx_sfctool_get_fecparam(struct efx_nic *efx,
			     struct ethtool_fecparam *fecparam);
int efx_sfctool_set_fecparam(struct efx_nic *efx,
			     struct ethtool_fecparam *fecparam);

static int sfctool_get_fecparam(struct efx_nic *efx, void __user *useraddr)
{
	struct ethtool_fecparam fecparam = { ETHTOOL_GFECPARAM };
	int rc;

	rc = efx_ethtool_get_fecparam(efx->net_dev, &fecparam);
	if (rc)
		return rc;

	if (copy_to_user(useraddr, &fecparam, sizeof(fecparam)))
		return -EFAULT;
	return 0;
}

static int sfctool_set_fecparam(struct efx_nic *efx, void __user *useraddr)
{
	struct ethtool_fecparam fecparam;

	if (copy_from_user(&fecparam, useraddr, sizeof(fecparam)))
		return -EFAULT;

	return efx_ethtool_set_fecparam(efx->net_dev, &fecparam);
}
#endif

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_RXFH_CONTEXT)
#if !defined(EFX_HAVE_ETHTOOL_GET_RXFH) && !defined(EFX_HAVE_ETHTOOL_GET_RXFH_INDIR) && defined(EFX_HAVE_ETHTOOL_RXFH_INDIR)
int efx_sfctool_get_rxfh(struct efx_nic *efx, u32 *indir, u8 *key, u8 *hfunc);
int efx_sfctool_set_rxfh(struct efx_nic *efx,
			 const u32 *indir, const u8 *key, const u8 hfunc);
#endif

static noinline_for_stack int sfctool_get_rxfh(struct efx_nic *efx,
					       void __user *useraddr)
{
	int ret;
	u32 user_indir_size, user_key_size;
	u32 dev_indir_size = 0, dev_key_size = 0;
	struct sfctool_rxfh rxfh;
	u32 total_size;
	u32 indir_bytes;
	u32 *indir = NULL;
	u8 dev_hfunc = 0;
	u8 *hkey = NULL;
	u8 *rss_config;

	dev_indir_size = efx_sfctool_get_rxfh_indir_size(efx);
	dev_key_size = efx_sfctool_get_rxfh_key_size(efx);

	if (copy_from_user(&rxfh, useraddr, sizeof(rxfh)))
		return -EFAULT;
	user_indir_size = rxfh.indir_size;
	user_key_size = rxfh.key_size;

	/* Check that reserved fields are 0 for now */
	if (rxfh.rsvd8[0] || rxfh.rsvd8[1] || rxfh.rsvd8[2] || rxfh.rsvd32)
		return -EINVAL;

	rxfh.indir_size = dev_indir_size;
	rxfh.key_size = dev_key_size;
	/* upstream writes back to user here.  But we delay so as not to corrupt
	 * user's cmd buffer if we encounter errors, as that would prevent them
	 * re-using it for standard ethtool.
	 */

	if ((user_indir_size && (user_indir_size != dev_indir_size)) ||
	    (user_key_size && (user_key_size != dev_key_size)))
		return -EINVAL;

	indir_bytes = user_indir_size * sizeof(indir[0]);
	total_size = indir_bytes + user_key_size;
	rss_config = kzalloc(total_size, GFP_USER);
	if (!rss_config)
		return -ENOMEM;

	if (user_indir_size)
		indir = (u32 *)rss_config;

	if (user_key_size)
		hkey = rss_config + indir_bytes;

	if (rxfh.rss_context)
		ret = efx_sfctool_get_rxfh_context(efx, indir, hkey,
						   &dev_hfunc,
						   rxfh.rss_context);
	else
#if defined(EFX_HAVE_ETHTOOL_GET_RXFH) || defined(EFX_HAVE_ETHTOOL_GET_RXFH_INDIR) || !defined(EFX_HAVE_ETHTOOL_RXFH_INDIR)
		return -EOPNOTSUPP; /* use ethtool instead */
#else
		ret = efx_sfctool_get_rxfh(efx, indir, hkey, &dev_hfunc);
#endif
	if (ret)
		goto out;

	if (copy_to_user(useraddr, &rxfh, sizeof(rxfh))) {
		ret = -EFAULT;
	} else if (copy_to_user(useraddr + offsetof(struct sfctool_rxfh, hfunc),
				&dev_hfunc, sizeof(rxfh.hfunc))) {
		ret = -EFAULT;
	} else if (copy_to_user(useraddr +
			      offsetof(struct sfctool_rxfh, rss_config[0]),
			      rss_config, total_size)) {
		ret = -EFAULT;
	}
out:
	kfree(rss_config);

	return ret;
}

static int ethtool_copy_validate_indir(u32 *indir, void __user *useraddr,
					struct efx_ethtool_rxnfc *rx_rings,
					u32 size)
{
	int i;

	if (copy_from_user(indir, useraddr, size * sizeof(indir[0])))
		return -EFAULT;

	/* Validate ring indices */
	for (i = 0; i < size; i++)
		if (indir[i] >= rx_rings->data)
			return -EINVAL;

	return 0;
}

static noinline_for_stack int sfctool_set_rxfh(struct efx_nic *efx,
					       void __user *useraddr)
{
	int ret;
	struct efx_ethtool_rxnfc rx_rings;
	struct sfctool_rxfh rxfh;
	u32 dev_indir_size = 0, dev_key_size = 0, i;
	u32 *indir = NULL, indir_bytes = 0;
	u8 *hkey = NULL;
	u8 *rss_config;
	u32 rss_cfg_offset = offsetof(struct sfctool_rxfh, rss_config[0]);
	bool delete = false;

	dev_indir_size = efx_sfctool_get_rxfh_indir_size(efx);
	dev_key_size = efx_sfctool_get_rxfh_key_size(efx);

	if (copy_from_user(&rxfh, useraddr, sizeof(rxfh)))
		return -EFAULT;

	/* Check that reserved fields are 0 for now */
	if (rxfh.rsvd8[0] || rxfh.rsvd8[1] || rxfh.rsvd8[2] || rxfh.rsvd32)
		return -EINVAL;

	/* If either indir, hash key or function is valid, proceed further.
	 * Must request at least one change: indir size, hash key or function.
	 */
	if ((rxfh.indir_size &&
	     rxfh.indir_size != ETH_RXFH_INDIR_NO_CHANGE &&
	     rxfh.indir_size != dev_indir_size) ||
	    (rxfh.key_size && (rxfh.key_size != dev_key_size)) ||
	    (rxfh.indir_size == ETH_RXFH_INDIR_NO_CHANGE &&
	     rxfh.key_size == 0 && rxfh.hfunc == ETH_RSS_HASH_NO_CHANGE))
		return -EINVAL;

	if (rxfh.indir_size != ETH_RXFH_INDIR_NO_CHANGE)
		indir_bytes = dev_indir_size * sizeof(indir[0]);

	rss_config = kzalloc(indir_bytes + rxfh.key_size, GFP_USER);
	if (!rss_config)
		return -ENOMEM;

	rx_rings.cmd = ETHTOOL_GRXRINGS;
	ret = efx_sfctool_get_rxnfc(efx, &rx_rings, NULL);
	if (ret)
		goto out;

	/* rxfh.indir_size == 0 means reset the indir table to default (master
	 * context) or delete the context (other RSS contexts).
	 * rxfh.indir_size == ETH_RXFH_INDIR_NO_CHANGE means leave it unchanged.
	 */
	if (rxfh.indir_size &&
	    rxfh.indir_size != ETH_RXFH_INDIR_NO_CHANGE) {
		indir = (u32 *)rss_config;
		ret = ethtool_copy_validate_indir(indir,
						  useraddr + rss_cfg_offset,
						  &rx_rings,
						  rxfh.indir_size);
		if (ret)
			goto out;
	} else if (rxfh.indir_size == 0) {
		if (rxfh.rss_context == 0) {
			indir = (u32 *)rss_config;
			for (i = 0; i < dev_indir_size; i++)
				indir[i] = ethtool_rxfh_indir_default(i, rx_rings.data);
		} else {
			delete = true;
		}
	}

	if (rxfh.key_size) {
		hkey = rss_config + indir_bytes;
		if (copy_from_user(hkey,
				   useraddr + rss_cfg_offset + indir_bytes,
				   rxfh.key_size)) {
			ret = -EFAULT;
			goto out;
		}
	}

	if (rxfh.rss_context)
		ret = efx_sfctool_set_rxfh_context(efx, indir, hkey, rxfh.hfunc,
						   &rxfh.rss_context, delete);
	else
#if defined(EFX_HAVE_ETHTOOL_GET_RXFH) || defined(EFX_HAVE_ETHTOOL_GET_RXFH_INDIR) || !defined(EFX_HAVE_ETHTOOL_RXFH_INDIR)
		return -EOPNOTSUPP; /* use ethtool instead */
#else
		ret = efx_sfctool_set_rxfh(efx, indir, hkey, rxfh.hfunc);
#endif
	if (ret)
		goto out;

	if (copy_to_user(useraddr + offsetof(struct sfctool_rxfh, rss_context),
			 &rxfh.rss_context, sizeof(rxfh.rss_context)))
		ret = -EFAULT;

#ifdef IFF_RXFH_CONFIGURED
	if (!rxfh.rss_context) {
		/* indicate whether rxfh was set to default */
		if (rxfh.indir_size == 0)
			efx->net_dev->priv_flags &= ~IFF_RXFH_CONFIGURED;
		else if (rxfh.indir_size != ETH_RXFH_INDIR_NO_CHANGE)
			efx->net_dev->priv_flags |= IFF_RXFH_CONFIGURED;
	}
#endif

out:
	kfree(rss_config);
	return ret;
}
#endif

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_GMODULEEEPROM)
static int sfctool_get_any_eeprom(struct net_device *dev, void __user *useraddr,
				  int (*getter)(struct net_device *,
						struct ethtool_eeprom *, u8 *),
				  u32 total_len)
{
	struct ethtool_eeprom eeprom;
	void __user *userbuf = useraddr + sizeof(eeprom);
	u32 bytes_remaining;
	u8 *data;
	int ret = 0;

	if (copy_from_user(&eeprom, useraddr, sizeof(eeprom)))
		return -EFAULT;

	/* Check for wrap and zero */
	if (eeprom.offset + eeprom.len <= eeprom.offset)
		return -EINVAL;

	/* Check for exceeding total eeprom len */
	if (eeprom.offset + eeprom.len > total_len)
		return -EINVAL;

	data = kmalloc(PAGE_SIZE, GFP_USER);
	if (!data)
		return -ENOMEM;

	bytes_remaining = eeprom.len;
	while (bytes_remaining > 0) {
		eeprom.len = min(bytes_remaining, (u32)PAGE_SIZE);

		ret = getter(dev, &eeprom, data);
		if (ret)
			break;
		if (copy_to_user(userbuf, data, eeprom.len)) {
			ret = -EFAULT;
			break;
		}
		userbuf += eeprom.len;
		eeprom.offset += eeprom.len;
		bytes_remaining -= eeprom.len;
	}

	eeprom.len = userbuf - (useraddr + sizeof(eeprom));
	eeprom.offset -= eeprom.len;
	if (copy_to_user(useraddr, &eeprom, sizeof(eeprom)))
		ret = -EFAULT;

	kfree(data);
	return ret;
}

static int sfctool_get_module_info(struct efx_nic *efx,
				   void __user *useraddr)
{
	int ret;
	struct ethtool_modinfo modinfo;

	if (copy_from_user(&modinfo, useraddr, sizeof(modinfo)))
		return -EFAULT;

	ret = efx_ethtool_get_module_info(efx->net_dev, &modinfo);
	if (ret)
		return ret;

	if (copy_to_user(useraddr, &modinfo, sizeof(modinfo)))
		return -EFAULT;

	return 0;
}

static int sfctool_get_module_eeprom(struct efx_nic *efx,
				     void __user *useraddr)
{
	int ret;
	struct ethtool_modinfo modinfo;

	ret = efx_ethtool_get_module_info(efx->net_dev, &modinfo);
	if (ret)
		return ret;

	return sfctool_get_any_eeprom(efx->net_dev, useraddr,
				      efx_ethtool_get_module_eeprom,
				      modinfo.eeprom_len);
}
#endif

/* WARNING!  For any return other than success or -EFAULT, methods called here
 * must NOT have written to *data, as the userland tool expects to be able to
 * re-use its command buffer to call the regular ethtool ioctl.
 */
int efx_sfctool(struct efx_nic *efx, u32 cmd, void __user *data)
{
	switch (cmd) {
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_FECPARAM)
	case ETHTOOL_GFECPARAM:
		return sfctool_get_fecparam(efx, data);
	case ETHTOOL_SFECPARAM:
		return sfctool_set_fecparam(efx, data);
#endif
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_RXFH_CONTEXT)
	case ETHTOOL_GRSSH:
		return sfctool_get_rxfh(efx, data);
	case ETHTOOL_SRSSH:
		return sfctool_set_rxfh(efx, data);
#endif
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_RXNFC_CONTEXT)
	case ETHTOOL_GRXCLSRLALL:
	case ETHTOOL_GRXFH:
	case ETHTOOL_GRXRINGS:
	case ETHTOOL_GRXCLSRLCNT:
	case ETHTOOL_GRXCLSRULE:
	case ETHTOOL_SRXCLSRLINS:
	case ETHTOOL_SRXCLSRLDEL:
		/* Use the old sfctool1 implementation, it deals with all the
		 * horrid 32-bit compat mess.
		 */
		return efx_ioctl_rxnfc(efx, data);
#endif
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_GMODULEEEPROM)
	case ETHTOOL_GMODULEEEPROM:
		return sfctool_get_module_eeprom(efx, data);
	case ETHTOOL_GMODULEINFO:
		return sfctool_get_module_info(efx, data);
#endif
	default:
		return -EOPNOTSUPP;
	};
}
