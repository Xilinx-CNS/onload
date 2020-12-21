/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "net_driver.h"
#include "efx.h"
#include "efx_ioctl.h"
#include "nic.h"
#include "efx_common.h"
#include "mcdi.h"
#include "mcdi_pcol.h"
#include "sfctool.h"
#include "ioctl_common.h"

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/fs.h>
#include <linux/compat.h>

#ifdef EFX_NOT_EXPORTED

static int efx_ioctl_reset(struct efx_nic *efx, union efx_ioctl_data *data)
{
	enum reset_type method = data->reset.method;

	if ((method < 0) || (method >= RESET_TYPE_MAX_METHOD) ||
	    (method == RESET_TYPE_MC_BIST)) {
		netif_err(efx, drv, efx->net_dev,
			  "unsupported reset_method=%d\n", method);
		return -EINVAL;
	}
	if (!efx_net_active(efx->state))
		return -EOPNOTSUPP;

	efx_schedule_reset(efx, method);
	return 0;
}

/* Rewrite event queue read pointer ioctl */
static int efx_ioctl_evq_ack(struct efx_nic *efx, union efx_ioctl_data *data)
{
	unsigned int channel_idx = data->evq_ack.channel;

	/* Range-check channel number */
	if (channel_idx >= efx_channels(efx))
		return -EINVAL;

	efx_nic_eventq_read_ack(efx_get_channel(efx, channel_idx));

	return 0;
}

static int efx_ioctl_set_loopback(struct efx_nic *efx,
				  union efx_ioctl_data *data)
{
	enum efx_loopback_mode mode = data->set_loopback.mode;
	enum efx_loopback_mode old_mode;
	int rc;

	/* Check that any mode is supported before we search for a set bit */
	if (efx->loopback_modes == 0)
		return -EOPNOTSUPP;
	if (!efx_net_active(efx->state))
		return -EOPNOTSUPP;

	if (mode == LOOPBACK_NEAR)
		mode = ffs(efx->loopback_modes) - 1;
	if (mode == LOOPBACK_FAR)
		/* The furthest internal facing loopback, so exclude network
		 * loopback */
		mode = fls(efx->loopback_modes & ~LOOPBACKS_WS) - 1;

	/* Check mode is supported by port */
	if (mode && (!(efx->loopback_modes & (1 << mode))))
		return -EOPNOTSUPP;

	mutex_lock(&efx->mac_lock);
	old_mode = efx->loopback_mode;
	efx->loopback_mode = mode;
	rc = __efx_reconfigure_port(efx);
	if (rc)
		efx->loopback_mode = old_mode;
	mutex_unlock(&efx->mac_lock);

	return rc;
}

static int efx_ioctl_set_carrier(struct efx_nic *efx,
				 union efx_ioctl_data *data)
{
	struct efx_set_carrier_ioctl *eci = &data->set_carrier;

	if (eci->on)
		netif_carrier_on(efx->net_dev);
	else
		netif_carrier_off(efx->net_dev);

	return 0;
}

static int efx_ioctl_set_phy_power(struct efx_nic *efx,
				   union efx_ioctl_data *data)
{
	enum efx_phy_mode old_mode;
	int rc;

	mutex_lock(&efx->mac_lock);

	old_mode = efx->phy_mode;
	if (data->set_phy_power.on)
		efx->phy_mode &= ~PHY_MODE_LOW_POWER;
	else
		efx->phy_mode |= PHY_MODE_LOW_POWER;

	rc = __efx_reconfigure_port(efx);
	if (rc != 0)
		efx->phy_mode = old_mode;
	else
		efx->phy_power_force_off = !data->set_phy_power.on;

	mutex_unlock(&efx->mac_lock);

	return rc;
}

#endif /* EFX_NOT_EXPORTED */

void efx_ioctl_mcdi_complete_reset(struct efx_nic *efx, unsigned int cmd,
				   int rc)
{
	/* efx_mcdi_rpc() will not schedule a reset if MC_CMD_REBOOT causes
	 * a reboot. But from the user's POV, they're triggering a reboot
	 * 'externally', and want both ports to recover. So schedule the
	 * reset here.
	 */
	if (cmd == MC_CMD_REBOOT && rc == -EIO) {
		netif_warn(efx, drv, efx->net_dev, "Expected MC rebooted\n");
		efx_schedule_reset(efx, RESET_TYPE_MC_FAILURE);
	}
}

static int efx_ioctl_do_mcdi(struct efx_nic *efx,
			     struct efx_mcdi_request2 __user *user_req)
{
	struct efx_mcdi_request2 *req;
	size_t inbuf_len, req_outlen, outlen_actual;
	efx_dword_t *inbuf = NULL;
	efx_dword_t *outbuf = NULL;
	int rc;

	req = kmalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	if (copy_from_user(req, user_req, sizeof(*req))) {
		rc = -EFAULT;
		goto out_free;
	}

	/* No input flags are defined yet */
	if (req->flags != 0) {
		rc = -EINVAL;
		goto out_free;
	}

	/* efx_mcdi_rpc() will check the length anyway, but this avoids
	 * trying to allocate an extreme amount of memory.
	 */
	if (req->inlen > MCDI_CTL_SDU_LEN_MAX_V2 ||
	    req->outlen > MCDI_CTL_SDU_LEN_MAX_V2) {
		rc = -EINVAL;
		goto out_free;
	}

	inbuf_len = ALIGN(req->inlen, 4);
	inbuf = kmalloc(inbuf_len, GFP_USER);
	if (!inbuf) {
		rc = -ENOMEM;
		goto out_free;
	}
	/* Ensure zero-padding if req.inlen not a multiple of 4 */
	if (req->inlen % 4)
		inbuf[req->inlen / 4].u32[0] = 0;

	outbuf = kmalloc(ALIGN(req->outlen, 4), GFP_USER);
	if (!outbuf) {
		rc = -ENOMEM;
		goto out_free;
	}

	if (copy_from_user(inbuf, &user_req->payload, req->inlen)) {
		rc = -EFAULT;
		goto out_free;
	}

	/* We use inbuf_len as an inlen not divisible by 4 annoys mcdi-logging.
	 * It doesn't care about outlen however.
	 */
	rc = efx_mcdi_rpc_quiet(efx, req->cmd, inbuf, inbuf_len,
				outbuf, req->outlen, &outlen_actual);
	efx_ioctl_mcdi_complete_reset(efx, req->cmd, rc);

	if (rc) {
		if (outlen_actual) {
			/* Error was reported by the MC */
			req->flags |= EFX_MCDI_REQUEST_ERROR;
			req->host_errno = -rc;
			rc = 0;
		} else {
			/* Communication failure */
			goto out_free;
		}
	}
	req_outlen = req->outlen;
	req->outlen = outlen_actual;

	if (copy_to_user(user_req, req, sizeof(*req)) ||
	    copy_to_user(&user_req->payload, outbuf,
		             min(outlen_actual, req_outlen)))
		rc = -EFAULT;

out_free:
	kfree(outbuf);
	kfree(inbuf);
	kfree(req);
	return rc;
}

#ifdef CONFIG_SFC_PTP
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
static int efx_ioctl_ts_init(struct efx_nic *efx, union efx_ioctl_data *data)
{
	/* bug 33070: We use a bit in the flags field to indicate that
	 * the application wants to use PTPV2 enhanced UUID
	 * filtering. Old application code has this bit set to
	 * zero. Note that this has no effect if a V1 mode is
	 * specified.
	 */
	if (data->ts_init.rx_filter >= HWTSTAMP_FILTER_PTP_V2_L4_EVENT &&
	    !(data->ts_init.flags & EFX_TS_INIT_FLAGS_PTP_V2_ENHANCED)) {
		netif_err(efx, drv, efx->net_dev,
			  "PTPv2 now requires at least sfptpd 2.0.0.5\n");
		return -EINVAL;
	}

	data->ts_init.flags &= ~EFX_TS_INIT_FLAGS_PTP_V2_ENHANCED;
	return efx_ptp_ts_init(efx, &data->ts_init);
}

static int efx_ioctl_ts_read(struct efx_nic *efx, union efx_ioctl_data *data)
{
	return efx_ptp_ts_read(efx, &data->ts_read);
}
#endif

#ifdef EFX_NOT_UPSTREAM
static int efx_ioctl_get_ts_config(struct efx_nic *efx,
				   union efx_ioctl_data __user *user_data)
{
	struct ifreq ifr;

	/* ifr_data is declared as __user */
	ifr.ifr_data = &user_data->ts_init;
	return efx_ptp_get_ts_config(efx, &ifr);
}

static int efx_ioctl_ts_settime(struct efx_nic *efx, union efx_ioctl_data *data)
{
	return efx_ptp_ts_settime(efx, &data->ts_settime);
}

static int efx_ioctl_ts_adjtime(struct efx_nic *efx, union efx_ioctl_data *data)
{
	return efx_ptp_ts_adjtime(efx, &data->ts_adjtime);
}

static int efx_ioctl_ts_sync(struct efx_nic *efx, union efx_ioctl_data *data)
{
	return efx_ptp_ts_sync(efx, &data->ts_sync);
}

static int efx_ioctl_ts_set_sync_status(struct efx_nic *efx,
					union efx_ioctl_data *data)
{
	return efx_ptp_ts_set_sync_status(efx, &data->ts_set_sync_status);
}

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_GET_TS_INFO) && !defined(EFX_HAVE_ETHTOOL_EXT_GET_TS_INFO)
static int efx_ioctl_get_ts_info(struct efx_nic *efx,
				 union efx_ioctl_data *data)
{
	memset(&data->ts_info, 0, sizeof(data->ts_info));
	data->ts_info.cmd = ETHTOOL_GET_TS_INFO;
	return efx_ethtool_get_ts_info(efx->net_dev, &data->ts_info);
}
#endif

static int efx_ioctl_ts_set_vlan_filter(struct efx_nic *efx,
					union efx_ioctl_data *data)
{
	return efx_ptp_ts_set_vlan_filter(efx, &data->ts_vlan_filter);
}

static int efx_ioctl_ts_set_uuid_filter(struct efx_nic *efx,
					union efx_ioctl_data *data)
{
	return efx_ptp_ts_set_uuid_filter(efx, &data->ts_uuid_filter);
}

static int efx_ioctl_ts_set_domain_filter(struct efx_nic *efx,
					  union efx_ioctl_data *data)
{
	return efx_ptp_ts_set_domain_filter(efx, &data->ts_domain_filter);
}
#endif

#endif

#ifdef CONFIG_SFC_PPS
static int efx_ioctl_get_pps_event(struct efx_nic *efx,
				   union efx_ioctl_data *data)
{
	return efx_ptp_pps_get_event(efx, &data->pps_event);
}
#endif

static int efx_ioctl_get_device_ids(struct efx_nic *efx,
				    union efx_ioctl_data *data)
{
	struct efx_device_ids *ids = &data->device_ids;

	ids->vendor_id = efx->pci_dev->vendor;
	ids->device_id = efx->pci_dev->device;
	ids->subsys_vendor_id = efx->pci_dev->subsystem_vendor;
	ids->subsys_device_id = efx->pci_dev->subsystem_device;
	ids->phy_type = efx->phy_type;
	ids->port_num = efx_port_num(efx);
	/* ids->perm_addr isn't __aligned(2), so we can't use ether_addr_copy
	 * (and we can't change it because it's an ioctl argument)
	 */
	ether_addr_copy(ids->perm_addr, efx->net_dev->perm_addr);

	return 0;
}

#ifdef EFX_USE_KCOMPAT

#ifdef CONFIG_COMPAT
/* struct ethtool_rxnfc has extra padding on 64-bit architectures.
 * And we have to follow this stupidity in order to use the same
 * underlying implementation for both SIOCEFX and SIOCETHTOOL
 * operations.
 */
struct efx_compat_ethtool_rx_flow_spec {
	u32		flow_type;
	union efx_ethtool_flow_union h_u;
	struct efx_ethtool_flow_ext h_ext;
	union efx_ethtool_flow_union m_u;
	struct efx_ethtool_flow_ext m_ext;
	compat_u64	ring_cookie;
	u32		location;
};
struct efx_compat_ethtool_rxnfc {
	u32				cmd;
	u32				flow_type;
	compat_u64			data;
	struct efx_compat_ethtool_rx_flow_spec fs;
	u32				rule_cnt;
	u32				rule_locs[0];
};
#endif

int efx_ioctl_rxnfc(struct efx_nic *efx, void __user *useraddr)
{
#ifdef CONFIG_COMPAT
	struct efx_compat_ethtool_rxnfc __user *compat_rxnfc = useraddr;
#endif
	struct efx_ethtool_rxnfc info;
	int ret;
	void *rule_buf = NULL;

#ifdef CONFIG_COMPAT
	if (is_compat_task()) {
		if (copy_from_user(&info, compat_rxnfc,
				   (void *)(&info.fs.m_ext + 1) -
				   (void *)&info) ||
		    copy_from_user(&info.fs.ring_cookie,
				   &compat_rxnfc->fs.ring_cookie,
				   (void *)(&info.fs.location + 1) -
				   (void *)&info.fs.ring_cookie) ||
		    copy_from_user(&info.rule_cnt, &compat_rxnfc->rule_cnt,
				   sizeof(info.rule_cnt)))
			return -EFAULT;
	} else
#endif
	if (copy_from_user(&info, useraddr, sizeof(info)))
		return -EFAULT;

	switch (info.cmd) {
	case ETHTOOL_GRXCLSRLALL:
		if (info.rule_cnt > 0) {
			/* No more than 1 MB of rule indices - way
			 * more than we could possibly have! */
			if (info.rule_cnt <= (1 << 18))
				rule_buf = kzalloc(info.rule_cnt * sizeof(u32),
						   GFP_USER);
			if (!rule_buf)
				return -ENOMEM;
		}
		/* fall through */
	case ETHTOOL_GRXFH:
	case ETHTOOL_GRXRINGS:
	case ETHTOOL_GRXCLSRLCNT:
	case ETHTOOL_GRXCLSRULE:
		ret = efx_ethtool_get_rxnfc(efx->net_dev, &info, rule_buf);
		break;
	case ETHTOOL_SRXCLSRLINS:
	case ETHTOOL_SRXCLSRLDEL:
		ret = efx_ethtool_set_rxnfc(efx->net_dev, &info);
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (ret < 0)
		goto err_out;

	ret = -EFAULT;
#ifdef CONFIG_COMPAT
	if (is_compat_task()) {
		if (copy_to_user(compat_rxnfc, &info,
				 (const void *)(&info.fs.m_ext + 1) -
				 (const void *)&info) ||
		    copy_to_user(&compat_rxnfc->fs.ring_cookie,
				 &info.fs.ring_cookie,
				 (const void *)(&info.fs.location + 1) -
				 (const void *)&info.fs.ring_cookie) ||
		    copy_to_user(&compat_rxnfc->rule_cnt, &info.rule_cnt,
				 sizeof(info.rule_cnt)))
			goto err_out;
	} else
#endif
	if (copy_to_user(useraddr, &info, sizeof(info)))
		goto err_out;

	if (rule_buf) {
#ifdef CONFIG_COMPAT
		if (is_compat_task())
			useraddr += offsetof(struct efx_compat_ethtool_rxnfc,
					     rule_locs);
		else
#endif
			useraddr += offsetof(struct efx_ethtool_rxnfc,
					     rule_locs);
		if (copy_to_user(useraddr, rule_buf,
				 info.rule_cnt * sizeof(u32)))
			goto err_out;
	}
	ret = 0;

err_out:
	kfree(rule_buf);

	return ret;
}
#endif

#ifdef EFX_NOT_UPSTREAM
static int efx_ioctl_sfctool(struct efx_nic *efx,
			     union efx_ioctl_data __user *useraddr)
{
	struct efx_sfctool sfctool;
	u32 ethcmd;

	if (copy_from_user(&sfctool, useraddr, sizeof(sfctool)))
		return -EFAULT;

	if (copy_from_user(&ethcmd, sfctool.data, sizeof(ethcmd)))
		return -EFAULT;

	return efx_sfctool(efx, ethcmd, sfctool.data);
}
#endif

/*****************************************************************************/

int efx_private_ioctl_common(struct efx_nic *efx, u16 cmd,
			     union efx_ioctl_data __user *user_data)
{
	int (*op)(struct efx_nic *, union efx_ioctl_data *);
	union efx_ioctl_data *data = NULL;
	size_t size;
	int rc;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	switch (cmd) {
#ifdef EFX_NOT_EXPORTED
	case EFX_RESET:
		size = sizeof(data->reset);
		op = efx_ioctl_reset;
		break;
	case EFX_EVQ_ACK:
		size = sizeof(data->evq_ack);
		op = efx_ioctl_evq_ack;
		break;
	case EFX_SET_LOOPBACK:
		size = sizeof(data->set_loopback);
		op = efx_ioctl_set_loopback;
		break;
	case EFX_SET_CARRIER:
		size = sizeof(data->set_carrier);
		op = efx_ioctl_set_carrier;
		break;
	case EFX_SET_PHY_POWER:
		size = sizeof(data->set_phy_power);
		op = efx_ioctl_set_phy_power;
		break;
#endif
	case EFX_MCDI_REQUEST2:
		/* This command has variable length */
		return efx_ioctl_do_mcdi(efx, &user_data->mcdi_request2);
#ifdef CONFIG_SFC_PTP
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
	case EFX_TS_INIT:
		size = sizeof(data->ts_init);
		op = efx_ioctl_ts_init;
		break;
	case EFX_TS_READ:
		size = sizeof(data->ts_read);
		op = efx_ioctl_ts_read;
		break;
#else
	case EFX_TS_INIT:
		return -EOPNOTSUPP;
#endif
#if defined(EFX_NOT_UPSTREAM)
	case EFX_GET_TS_CONFIG:
		return efx_ioctl_get_ts_config(efx, user_data);

	case EFX_TS_SETTIME:
		size = sizeof(data->ts_settime);
		op = efx_ioctl_ts_settime;
		break;
	case EFX_TS_ADJTIME:
		size = sizeof(data->ts_adjtime);
		op = efx_ioctl_ts_adjtime;
		break;
	case EFX_TS_SYNC:
		size = sizeof(data->ts_sync);
		op = efx_ioctl_ts_sync;
		break;
	case EFX_TS_SET_SYNC_STATUS:
		size = sizeof(data->ts_set_sync_status);
		op = efx_ioctl_ts_set_sync_status;
		break;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_GET_TS_INFO) && !defined(EFX_HAVE_ETHTOOL_EXT_GET_TS_INFO)
	case EFX_GET_TS_INFO:
		size = sizeof(data->ts_info);
		op = efx_ioctl_get_ts_info;
		break;
#endif
	case EFX_TS_SET_VLAN_FILTER:
		size = sizeof(data->ts_vlan_filter);
		op = efx_ioctl_ts_set_vlan_filter;
		break;
	case EFX_TS_SET_UUID_FILTER:
		size = sizeof(data->ts_uuid_filter);
		op = efx_ioctl_ts_set_uuid_filter;
		break;
	case EFX_TS_SET_DOMAIN_FILTER:
		size = sizeof(data->ts_domain_filter);
		op = efx_ioctl_ts_set_domain_filter;
		break;
#endif
#endif
	case EFX_SFCTOOL:
		return efx_ioctl_sfctool(efx, user_data);
#ifdef CONFIG_SFC_PPS
	case EFX_TS_GET_PPS:
		size = sizeof(data->pps_event);
		op = efx_ioctl_get_pps_event;
		break;
	case EFX_TS_ENABLE_HW_PPS:
		/* This no longer does anything, PPS is always enabled */
		return 0;
#endif
	case EFX_GET_DEVICE_IDS:
		size = sizeof(data->device_ids);
		op = efx_ioctl_get_device_ids;
		break;
	default:
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
