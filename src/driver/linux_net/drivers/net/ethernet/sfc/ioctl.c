/****************************************************************************
 * Driver for Solarflare network controllers
 *           (including support for SFE4001 10GBT NIC)
 *
 * Copyright 2005-2006: Fen Systems Ltd.
 * Copyright 2005-2012: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Initially developed by Michael Brown <mbrown@fensystems.co.uk>
 * Maintained by Solarflare Communications <linux-net-drivers@solarflare.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */
#include "net_driver.h"
#include "efx_ioctl.h"
#include "nic.h"
#include "efx_common.h"
#include "ioctl_common.h"
#include "mcdi.h"
#include "mcdi_port_common.h"
#include "mcdi_pcol.h"
#include "ethtool_common.h"

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/fs.h>
#include <linux/compat.h>

static int efx_ioctl_do_mcdi_old(struct efx_nic *efx, union efx_ioctl_data *data)
{
	struct efx_mcdi_request *req = &data->mcdi_request;
	efx_dword_t *inbuf;
	size_t inbuf_len, outlen;
	int rc;

	if (req->len > sizeof(req->payload)) {
		netif_err(efx, drv, efx->net_dev, "inlen is too long");
		return -EINVAL;
	}

	inbuf_len = ALIGN(req->len, 4);
	inbuf = kmalloc(inbuf_len, GFP_KERNEL);
	if (!inbuf)
		return -ENOMEM;
	/* Ensure zero-padding if req->len not a multiple of 4 */
	if (req->len % 4)
		inbuf[req->len / 4].u32[0] = 0;

	memcpy(inbuf, req->payload, req->len);

	rc = efx_mcdi_rpc_quiet(efx, req->cmd, inbuf, inbuf_len,
				(efx_dword_t *)req->payload,
				sizeof(req->payload), &outlen);
	efx_ioctl_mcdi_complete_reset(efx, req->cmd, rc);

	req->rc = -rc;
	req->len = (__u8)outlen;

	kfree(inbuf);
	return 0;
}

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_RXFH_INDIR)

static int
efx_ioctl_rxfh_indir(struct efx_nic *efx, union efx_ioctl_data *data)
{
	BUILD_BUG_ON(ARRAY_SIZE(data->rxfh_indir.table) !=
		     ARRAY_SIZE(efx->rss_context.rx_indir_table));

	switch (data->rxfh_indir.head.cmd) {
	case ETHTOOL_GRXFHINDIR:
		return efx_ethtool_old_get_rxfh_indir(efx->net_dev,
						      &data->rxfh_indir.head);
	case ETHTOOL_SRXFHINDIR:
		return efx_ethtool_old_set_rxfh_indir(efx->net_dev,
						      &data->rxfh_indir.head);
	default:
		return -EOPNOTSUPP;
	}
}

#endif

static int
efx_ioctl_get_mod_eeprom(struct efx_nic *efx,
			 union efx_ioctl_data __user *useraddr)
{
	struct ethtool_eeprom eeprom;
	struct ethtool_modinfo modinfo;
	void __user *userbuf =
		((void __user *)&useraddr->eeprom.ee) + sizeof(eeprom);
	void __user *userbufptr = userbuf;
	u32 bytes_remaining;
	u32 total_len;
	u8 *data;
	int ret = 0;

	if (efx_mcdi_phy_get_module_info(efx, &modinfo))
		return -EINVAL;

	total_len = modinfo.eeprom_len;

	if (copy_from_user(&eeprom, &useraddr->eeprom.ee, sizeof(eeprom)))
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

		ret = efx_mcdi_phy_get_module_eeprom(efx, &eeprom, data);
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

	eeprom.len = userbuf - userbufptr;
	eeprom.offset -= eeprom.len;
	if (copy_to_user(&useraddr->eeprom.ee, &eeprom, sizeof(eeprom)))
		ret = -EFAULT;

	kfree(data);
	return ret;
}

static int
efx_ioctl_get_mod_info(struct efx_nic *efx, union efx_ioctl_data *data)
{
	return efx_mcdi_phy_get_module_info(efx, &data->modinfo.info);
}

#ifdef EFX_NOT_UPSTREAM
static int
efx_ioctl_update_license(struct efx_nic *efx, union efx_ioctl_data *data)
{
	struct efx_update_license2 *stats = &data->key_stats2;
	int rc;

	if (efx_nic_rev(efx) >= EFX_REV_HUNT_A0) {
		rc = efx_ef10_update_keys(efx, stats);
		/* return directly since SFA7942Q(Sorrento) only
		 * uses EF10 based licensing
		 */
		return rc;
	}

	memset(stats, 0, sizeof(*stats));
	return 0;
}
#endif

#ifdef EFX_NOT_UPSTREAM
static int
efx_ioctl_licensed_app_state(struct efx_nic *efx, union efx_ioctl_data *data)
{
	int rc;

	if (efx_nic_rev(efx) < EFX_REV_HUNT_A0)
		return -EOPNOTSUPP;
	rc = efx_ef10_licensed_app_state(efx, &data->app_state);
	return rc;
}
#endif

#ifdef CONFIG_SFC_DUMP
static int
efx_ioctl_dump(struct efx_nic *efx, union efx_ioctl_data __user *useraddr)
{
	struct ethtool_dump dump;
	void __user *userbuf =
		((void __user *)&useraddr->dump) + sizeof(dump);
	void *buffer;
	int ret;

	if (copy_from_user(&dump, useraddr, sizeof(dump)))
		return -EFAULT;

	switch (dump.cmd) {
	case ETHTOOL_SET_DUMP:
		ret = efx_ethtool_set_dump(efx->net_dev, &dump);
		if (ret < 0)
			return ret;
		break;
	case ETHTOOL_GET_DUMP_FLAG:
		ret = efx_ethtool_get_dump_flag(efx->net_dev, &dump);
		if (ret < 0)
			return ret;
		break;
	case ETHTOOL_GET_DUMP_DATA:
		ret = efx_ethtool_get_dump_flag(efx->net_dev, &dump);
		if (ret < 0)
			return ret;

		if (dump.len == 0)
			return -EFAULT;
		buffer = vzalloc(dump.len);
		if (!buffer)
			return -ENOMEM;

		ret = efx_ethtool_get_dump_data(efx->net_dev, &dump,
						buffer);
		if (ret == 0) {
			if (copy_to_user(userbuf, buffer, dump.len))
				ret = -EFAULT;
		}
		vfree(buffer);
		if (ret < 0)
			return ret;
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (copy_to_user(useraddr, &dump, sizeof(dump)))
		return -EFAULT;

	return 0;
}
#endif

/*****************************************************************************/

#ifndef netif_err_once
#define netif_err_once(priv, type, dev, fmt, args...) \
	netif_level(err_once, priv, type, dev, fmt, ##args)
#endif

int efx_private_ioctl(struct efx_nic *efx, u16 cmd,
		      union efx_ioctl_data __user *user_data)
{
	int (*op)(struct efx_nic *, union efx_ioctl_data *);
	union efx_ioctl_data *data = NULL;
	size_t size;
	int rc;

	rc = efx_private_ioctl_common(efx, cmd, user_data);
	if (rc != -EOPNOTSUPP)
		return rc;

	switch (cmd) {
	case EFX_MCDI_REQUEST:
		size = sizeof(data->mcdi_request);
		op = efx_ioctl_do_mcdi_old;
		break;
#ifdef EFX_USE_KCOMPAT
	case EFX_RXNFC:
		/* This command has variable length */
		return efx_ioctl_rxnfc(efx, &user_data->rxnfc);
#endif
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_RXFH_INDIR)
	case EFX_RXFHINDIR:
		size = sizeof(data->rxfh_indir);
		op = efx_ioctl_rxfh_indir;
		break;
#endif
	case EFX_MODULEEEPROM:
		return efx_ioctl_get_mod_eeprom(efx, user_data);

	case EFX_GMODULEINFO:
		size = sizeof(data->modinfo);
		op = efx_ioctl_get_mod_info;
		break;
#ifdef EFX_NOT_UPSTREAM
	case EFX_LICENSE_UPDATE2:
		size = sizeof(data->key_stats2);
		op = efx_ioctl_update_license;
		break;
#endif
#ifdef EFX_NOT_UPSTREAM
	case EFX_LICENSED_APP_STATE:
		size = sizeof(data->app_state);
		op = efx_ioctl_licensed_app_state;
		break;
#endif
#ifdef CONFIG_SFC_DUMP
	case EFX_DUMP:
		return efx_ioctl_dump(efx, user_data);
#endif
	case EFX_TS_INIT:
	case EFX_TS_SETTIME:
	case EFX_TS_ADJTIME:
	case EFX_TS_GET_PPS:
	case EFX_TS_ENABLE_HW_PPS:
	case EFX_GET_TS_CONFIG:
		/* Obsolete private ioctls that now have upstream
		 * equivalents
		 */
		netif_err_once(efx, drv, efx->net_dev,
			       "obsolete private timestamping ioctl cmd %x\n",
			       cmd);
		return -EOPNOTSUPP;
	default:
		netif_err(efx, drv, efx->net_dev,
			  "unknown private ioctl cmd %x\n", cmd);
		return -EOPNOTSUPP;
	}

	data = kmalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	if (copy_from_user(data, user_data, size)) {
		kfree(data);
		return -EFAULT;
	}

	rc = op(efx, data);
	if (!rc) {
		if (copy_to_user(user_data, data, size))
			rc = -EFAULT;
	}

	kfree(data);
	return rc;
}

