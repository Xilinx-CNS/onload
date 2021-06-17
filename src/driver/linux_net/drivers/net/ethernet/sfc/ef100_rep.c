/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "ef100_rep.h"
#include "ef100_netdev.h"
#include "ef100_nic.h"
#include "mae.h"
#include "rx_common.h"

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)

#define EFX_EF100_REP_DRIVER	"efx_ef100_rep"
#define EFX_EF100_REP_VERSION	"0.0.1"

#define EFX_REP_DEFAULT_PSEUDO_RING_SIZE	64

static int efx_ef100_rep_poll(struct napi_struct *napi, int weight);

static int efx_ef100_rep_init_struct(struct efx_nic *efx,
				     struct efx_rep *efv, unsigned int i)
{
	efv->parent = efx;
	BUILD_BUG_ON(MAE_MPORT_SELECTOR_NULL);
	efv->idx = i;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB__LIST)
	INIT_LIST_HEAD(&efv->rx_list);
#else
	__skb_queue_head_init(&efv->rx_list);
#endif
	spin_lock_init(&efv->rx_lock);
	efv->msg_enable = NETIF_MSG_DRV | NETIF_MSG_PROBE |
			  NETIF_MSG_LINK | NETIF_MSG_IFDOWN |
			  NETIF_MSG_IFUP | NETIF_MSG_RX_ERR |
			  NETIF_MSG_TX_ERR | NETIF_MSG_HW;
	return 0;
}

static int efx_ef100_rep_open(struct net_device *net_dev)
{
	struct efx_rep *efv = netdev_priv(net_dev);

	netif_napi_add(net_dev, &efv->napi, efx_ef100_rep_poll,
		       NAPI_POLL_WEIGHT);
	napi_enable(&efv->napi);
	return 0;
}

static int efx_ef100_rep_close(struct net_device *net_dev)
{
	struct efx_rep *efv = netdev_priv(net_dev);

	napi_disable(&efv->napi);
	netif_napi_del(&efv->napi);
	return 0;
}

static netdev_tx_t efx_ef100_rep_xmit(struct sk_buff *skb,
					struct net_device *dev)
{
	struct efx_rep *efv = netdev_priv(dev);
	struct efx_nic *efx = efv->parent;
	netdev_tx_t rc;

	/* __ef100_hard_start_xmit() will always return success even in the
	 * case of TX drops, where it will increment efx's tx_dropped.  The
	 * efv stats really only count attempted TX, not success/failure.
	 */
	atomic64_inc(&efv->stats.tx_packets);
	atomic64_add(skb->len, &efv->stats.tx_bytes);
	netif_tx_lock(efx->net_dev);
	rc = __ef100_hard_start_xmit(skb, efx, dev, efv);
	netif_tx_unlock(efx->net_dev);
	return rc;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PORT_PARENT_ID)
static int efx_ef100_rep_get_port_parent_id(struct net_device *dev,
					    struct netdev_phys_item_id *ppid)
{
	struct efx_rep *efv = netdev_priv(dev);
	struct efx_nic *efx = efv->parent;
	struct ef100_nic_data *nic_data;

	nic_data = efx->nic_data;
	/* nic_data->port_id is a u8[] */
	ppid->id_len = sizeof(nic_data->port_id);
	memcpy(ppid->id, nic_data->port_id, sizeof(nic_data->port_id));
	return 0;
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PHYS_PORT_NAME)
static int efx_ef100_rep_get_phys_port_name(struct net_device *dev,
					    char *buf, size_t len)
{
	struct efx_rep *efv = netdev_priv(dev);
	struct efx_nic *efx = efv->parent;
	struct ef100_nic_data *nic_data;
	int ret;

	nic_data = efx->nic_data;
	if (efv->remote) {
		struct mae_mport_desc *mport_desc =
			&efx->tc->mports[efv->mport_desc_idx];

		ret = snprintf(buf, len, "p%uif%upf%u", efx->port_num,
			       mport_desc->interface_idx, mport_desc->pf_idx);
		if (ret > 0 && mport_desc->vf_idx != 0xFFFF)
			ret = snprintf(buf + ret, len - ret,
				       "vf%u", mport_desc->vf_idx);
	} else {
		ret = snprintf(buf, len, "p%upf%uvf%u", efx->port_num,
			       nic_data->pf_index, efv->idx);
	}
	if (ret >= len)
		return -EOPNOTSUPP;

	return 0;
}
#endif

static int efx_ef100_rep_set_mac_address(struct net_device *net_dev, void *data)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_SET_CLIENT_MAC_ADDRESSES_IN_LEN(1));
	struct efx_rep *efv = netdev_priv(net_dev);
	struct efx_nic *efx = efv->parent;
	struct sockaddr *addr = data;
	u8 *new_addr = addr->sa_data;
	int rc;

	if (efv->clid == CLIENT_HANDLE_NULL) {
		netif_info(efx, drv, net_dev, "Unable to set representee MAC address (client ID is null)\n");
	} else {
		BUILD_BUG_ON(MC_CMD_SET_CLIENT_MAC_ADDRESSES_OUT_LEN);
		MCDI_SET_DWORD(inbuf, SET_CLIENT_MAC_ADDRESSES_IN_CLIENT_HANDLE,
			       efv->clid);
		ether_addr_copy(MCDI_PTR(inbuf, SET_CLIENT_MAC_ADDRESSES_IN_MAC_ADDRS),
				new_addr);
		rc = efx_mcdi_rpc(efx, MC_CMD_SET_CLIENT_MAC_ADDRESSES, inbuf,
				  sizeof(inbuf), NULL, 0, NULL);
		if (rc)
			return rc;
	}

	ether_addr_copy(net_dev->dev_addr, new_addr);
	return 0;
}

static int efx_ef100_rep_setup_tc(struct net_device *net_dev,
				  enum tc_setup_type type, void *type_data)
{
	struct efx_rep *efv = netdev_priv(net_dev);
	struct efx_nic *efx = efv->parent;

	if (type == TC_SETUP_CLSFLOWER)
		return efx_tc_flower(efx, net_dev, type_data, efv);
	if (type == TC_SETUP_BLOCK)
		return efx_tc_setup_block(net_dev, efx, type_data, efv);

	return -EOPNOTSUPP;
}

static void efx_ef100_rep_get_stats64(struct net_device *dev,
				      struct rtnl_link_stats64 *stats)
{
	struct efx_rep *efv = netdev_priv(dev);

	stats->rx_packets = atomic64_read(&efv->stats.rx_packets);
	stats->tx_packets = atomic64_read(&efv->stats.tx_packets);
	stats->rx_bytes = atomic64_read(&efv->stats.rx_bytes);
	stats->tx_bytes = atomic64_read(&efv->stats.tx_bytes);
	stats->rx_dropped = atomic64_read(&efv->stats.rx_dropped);
	stats->tx_errors = atomic64_read(&efv->stats.tx_errors);
}

const struct net_device_ops efx_ef100_rep_netdev_ops = {
	.ndo_open		= efx_ef100_rep_open,
	.ndo_stop		= efx_ef100_rep_close,
	.ndo_start_xmit		= efx_ef100_rep_xmit,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PORT_PARENT_ID)
	.ndo_get_port_parent_id	= efx_ef100_rep_get_port_parent_id,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PHYS_PORT_NAME)
	.ndo_get_phys_port_name	= efx_ef100_rep_get_phys_port_name,
#endif
	.ndo_set_mac_address    = efx_ef100_rep_set_mac_address,
	.ndo_get_stats64	= efx_ef100_rep_get_stats64,
	.ndo_setup_tc		= efx_ef100_rep_setup_tc,
};

static void efx_ef100_rep_get_drvinfo(struct net_device *dev,
				      struct ethtool_drvinfo *drvinfo)
{
	strlcpy(drvinfo->driver, EFX_EF100_REP_DRIVER, sizeof(drvinfo->driver));
	strlcpy(drvinfo->version, EFX_EF100_REP_VERSION, sizeof(drvinfo->version));
}

static u32 efx_ef100_rep_ethtool_get_msglevel(struct net_device *net_dev)
{
	struct efx_rep *efv = netdev_priv(net_dev);
	return efv->msg_enable;
}

static void efx_ef100_rep_ethtool_set_msglevel(struct net_device *net_dev,
					       u32 msg_enable)
{
	struct efx_rep *efv = netdev_priv(net_dev);
	efv->msg_enable = msg_enable;
}

static void efx_ef100_rep_ethtool_get_ringparam(struct net_device *net_dev,
						struct ethtool_ringparam *ring)
{
	struct efx_rep *efv = netdev_priv(net_dev);

	ring->rx_max_pending = U32_MAX;
	ring->rx_pending = efv->rx_pring_size;
}

static int efx_ef100_rep_ethtool_set_ringparam(struct net_device *net_dev,
					       struct ethtool_ringparam *ring)
{
	struct efx_rep *efv = netdev_priv(net_dev);

	if (ring->rx_mini_pending || ring->rx_jumbo_pending || ring->tx_pending)
		return -EINVAL;

	efv->rx_pring_size = ring->rx_pending;
	return 0;
}

const static struct ethtool_ops efx_ef100_rep_ethtool_ops = {
	.get_drvinfo		= efx_ef100_rep_get_drvinfo,
	.get_msglevel		= efx_ef100_rep_ethtool_get_msglevel,
	.set_msglevel		= efx_ef100_rep_ethtool_set_msglevel,
	.get_ringparam		= efx_ef100_rep_ethtool_get_ringparam,
	.set_ringparam		= efx_ef100_rep_ethtool_set_ringparam,
};

static struct efx_rep *efx_ef100_rep_create_netdev(struct efx_nic *efx,
						   unsigned int i, bool remote)
{
	struct net_device *net_dev;
	struct efx_rep *efv;
	int rc;

	net_dev = alloc_etherdev_mq(sizeof(*efv), 1);
	if (!net_dev)
		return ERR_PTR(-ENOMEM);

	efv = netdev_priv(net_dev);
	rc = efx_ef100_rep_init_struct(efx, efv, i);
	if (rc)
		goto fail1;
	efv->net_dev = net_dev;
	efv->remote = remote;
	netif_carrier_off(net_dev);

	net_dev->netdev_ops = &efx_ef100_rep_netdev_ops;
	net_dev->ethtool_ops = &efx_ef100_rep_ethtool_ops;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NETDEV_MTU_LIMITS)
	net_dev->min_mtu = EFX_MIN_MTU;
	net_dev->max_mtu = EFX_100_MAX_MTU;
#elif defined(EFX_HAVE_NETDEV_EXT_MTU_LIMITS)
	net_dev->extended->min_mtu = EFX_MIN_MTU;
	net_dev->extended->max_mtu = EFX_100_MAX_MTU;
#endif
	net_dev->features |= NETIF_F_HW_TC | NETIF_F_LLTX;
	net_dev->hw_features |= NETIF_F_HW_TC | NETIF_F_LLTX;
	return efv;
fail1:
	free_netdev(net_dev);
	return ERR_PTR(rc);
}

static void efx_ef100_rep_destroy_netdev(struct efx_rep *efv)
{
	free_netdev(efv->net_dev);
}

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER) && !defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER)
static int efx_ef100_rep_tc_egdev_cb(enum tc_setup_type type, void *type_data,
				       void *cb_priv)
{
	struct efx_rep *efv = cb_priv;

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		return efx_tc_flower(efv->parent, NULL, type_data, efv);
	default:
		return -EOPNOTSUPP;
	}
}
#endif

static int efx_ef100_lookup_client_id(struct efx_nic *efx, efx_qword_t pciefn,
				      u32 *id)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_CLIENT_HANDLE_OUT_LEN);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_GET_CLIENT_HANDLE_IN_LEN);
	u64 pciefn_flat = le64_to_cpu(pciefn.u64[0]);
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, GET_CLIENT_HANDLE_IN_TYPE,
		       MC_CMD_GET_CLIENT_HANDLE_IN_TYPE_FUNC);
	MCDI_SET_QWORD(inbuf, GET_CLIENT_HANDLE_IN_FUNC,
		       pciefn_flat);

	rc = efx_mcdi_rpc(efx, MC_CMD_GET_CLIENT_HANDLE, inbuf,
			  sizeof(inbuf), outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;
	*id = MCDI_DWORD(outbuf, GET_CLIENT_HANDLE_OUT_HANDLE);
	return 0;
}

static int efx_ef100_configure_rep(struct efx_rep *efv)
{
	struct net_device *net_dev = efv->net_dev;
	struct efx_nic *efx = efv->parent;
	efx_qword_t pciefn;
	u32 selector;
	int rc;

	efv->rx_pring_size = EFX_REP_DEFAULT_PSEUDO_RING_SIZE;
	/* Construct mport selector for corresponding VF */
	efx_mae_mport_vf(efx, efv->idx, &selector);
	/* Look up actual mport ID */
	rc = efx_mae_lookup_mport(efx, selector, &efv->mport);
	if (rc)
		return rc;
	netif_dbg(efx, probe, net_dev,
		  "Representee mport ID %#x\n", efv->mport);
	/* mport label should fit in 16 bits */
	WARN_ON(efv->mport >> 16);

	/* Construct PCIE_FUNCTION structure for the VF */
	EFX_POPULATE_QWORD_3(pciefn,
			     PCIE_FUNCTION_PF, PCIE_FUNCTION_PF_NULL,
			     PCIE_FUNCTION_VF, efv->idx,
			     PCIE_FUNCTION_INTF, PCIE_INTERFACE_CALLER);
	/* look up VF's client ID */
	rc = efx_ef100_lookup_client_id(efx, pciefn, &efv->clid);
	if (rc) {
		/* We won't be able to set the representee's MAC address */
		efv->clid = CLIENT_HANDLE_NULL;
		netif_dbg(efx, probe, net_dev,
			  "Failed to get representee client ID, rc %d\n", rc);
	} else {
		netif_dbg(efx, probe, net_dev,
			  "Representee client ID %#x\n", efv->clid);

		/* Get the assigned MAC address */
		(void)ef100_get_mac_address(efx, net_dev->perm_addr, efv->clid,
					    true);
		memcpy(net_dev->dev_addr, net_dev->perm_addr, ETH_ALEN);
	}

	mutex_lock(&efx->tc->mutex);
	rc = efx_tc_configure_default_rule(efx, EFX_TC_DFLT_VF(efv->idx));
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER) && !defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER)
	if (!rc) {
		rc = tc_setup_cb_egdev_register(net_dev,
						efx_ef100_rep_tc_egdev_cb, efv);
		if (rc)
			efx_tc_deconfigure_default_rule(efx, EFX_TC_DFLT_VF(efv->idx));
	}
#endif
	mutex_unlock(&efx->tc->mutex);
	return rc;
}

static int efx_ef100_configure_remote_rep(struct efx_rep *efv,
					  struct mae_mport_desc *mport_desc)
{
	struct net_device *net_dev = efv->net_dev;
	struct efx_nic *efx = efv->parent;
	struct ef100_nic_data *nic_data;
	efx_qword_t pciefn;
	int rc;

	nic_data = efx->nic_data;
	efv->rx_pring_size = EFX_REP_DEFAULT_PSEUDO_RING_SIZE;
	efv->mport = mport_desc->mport_id;
	netif_dbg(efx, probe, net_dev, "Remote representee mport ID %#x\n",
		  efv->mport);
	/* mport label should fit in 16 bits */
	WARN_ON(efv->mport >> 16);

	/* Construct PCIE_FUNCTION structure for the representee */
	EFX_POPULATE_QWORD_3(pciefn,
			     PCIE_FUNCTION_PF, mport_desc->pf_idx,
			     PCIE_FUNCTION_VF, mport_desc->vf_idx,
			     PCIE_FUNCTION_INTF, mport_desc->interface_idx);
	/* look up representee's client ID */
	rc = efx_ef100_lookup_client_id(efx, pciefn, &efv->clid);
	if (rc) {
		/* We won't be able to set the representee's MAC address */
		efv->clid = CLIENT_HANDLE_NULL;
		netif_dbg(efx, probe, net_dev,
			  "Failed to get representee client ID, rc %d\n", rc);
	} else {
		netif_dbg(efx, probe, net_dev,
			  "Remote representee client ID %#x\n", efv->clid);

		/* Get the assigned MAC address */
		(void)ef100_get_mac_address(efx, net_dev->perm_addr, efv->clid,
					    true);
		memcpy(net_dev->dev_addr, net_dev->perm_addr, ETH_ALEN);
	}

	mutex_lock(&efx->tc->mutex);
	rc = efx_tc_configure_default_rule(efx,
					   EFX_TC_DFLT_REM(efv->idx));
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER) && !defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER)
	if (!rc) {
		rc = tc_setup_cb_egdev_register(net_dev,
						efx_ef100_rep_tc_egdev_cb, efv);
		if (rc) {
			efx_tc_deconfigure_default_rule(efx,
							EFX_TC_DFLT_REM(efv->idx));
		}
	}
#endif
	mutex_unlock(&efx->tc->mutex);
	return rc;
}

static void efx_ef100_deconfigure_rep(struct efx_rep *efv)
{
	struct efx_nic *efx = efv->parent;

	mutex_lock(&efx->tc->mutex);
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER) && !defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER)
	tc_setup_cb_egdev_unregister(efv->net_dev, efx_ef100_rep_tc_egdev_cb,
				     efv);
#endif
	if (efv->remote)
		efx_tc_deconfigure_default_rule(efx, EFX_TC_DFLT_REM(efv->idx));
	else
		efx_tc_deconfigure_default_rule(efx, EFX_TC_DFLT_VF(efv->idx));
	mutex_unlock(&efx->tc->mutex);
}

int efx_ef100_vfrep_create(struct efx_nic *efx, unsigned int i)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct efx_rep *efv;
	int rc;

	efv = efx_ef100_rep_create_netdev(efx, i, false);
	if (IS_ERR(efv)) {
		rc = PTR_ERR(efv);
		netif_err(efx, drv, efx->net_dev,
			  "Failed to create representor for VF %d, rc %d\n", i,
			  rc);
		return rc;
	}
	nic_data->vf_rep[i] = efv->net_dev;
	rc = efx_ef100_configure_rep(efv);
	if (rc) {
		netif_err(efx, drv, efx->net_dev,
			  "Failed to configure representor for VF %d, rc %d\n",
			  i, rc);
		goto fail1;
	}
	rc = register_netdev(efv->net_dev);
	if (rc) {
		netif_err(efx, drv, efx->net_dev,
			  "Failed to register representor for VF %d, rc %d\n",
			  i, rc);
		goto fail2;
	}
	netif_dbg(efx, drv, efx->net_dev, "Representor for VF %d is %s\n", i,
		  efv->net_dev->name);
	return 0;
fail2:
	efx_ef100_deconfigure_rep(efv);
fail1:
	nic_data->vf_rep[i] = NULL;
	efx_ef100_rep_destroy_netdev(efv);
	return rc;
}

int efx_ef100_remote_rep_create(struct efx_nic *efx, unsigned int i,
				unsigned int mport_desc_idx)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct mae_mport_desc *mport_desc = &efx->tc->mports[mport_desc_idx];
	struct efx_rep *efv;
	int rc;

	efv = efx_ef100_rep_create_netdev(efx, i, true);
	if (IS_ERR(efv)) {
		rc = PTR_ERR(efv);
		netif_err(efx, drv, efx->net_dev,
			  "Failed to create representor for IF %u PF %u VF %u, rc %d\n",
			  mport_desc->interface_idx, mport_desc->pf_idx,
			  mport_desc->vf_idx, rc);
		return rc;
	}
	efv->mport_desc_idx = mport_desc_idx;
	nic_data->rem_rep[i] = efv->net_dev;
	rc = efx_ef100_configure_remote_rep(efv, mport_desc);
	if (rc) {
		netif_err(efx, drv, efx->net_dev,
			  "Failed to configure representor for IF %u PF %u VF %u, rc %d\n",
			  mport_desc->interface_idx, mport_desc->pf_idx,
			  mport_desc->vf_idx, rc);
		goto fail1;
	}
	nic_data->rem_rep[i] = efv->net_dev;
	rc = register_netdev(efv->net_dev);
	if (rc) {
		netif_err(efx, drv, efx->net_dev,
			  "Failed to register representor for IF %u PF %u VF %u, rc %d\n",
			  mport_desc->interface_idx, mport_desc->pf_idx,
			  mport_desc->vf_idx, rc);
		goto fail2;
	}
	netif_dbg(efx, drv, efx->net_dev,
		  "Representor for IF %u PF %u VF %u is %s\n",
		  mport_desc->interface_idx, mport_desc->pf_idx,
		  mport_desc->vf_idx, efv->net_dev->name);
	return 0;
fail2:
	efx_ef100_deconfigure_rep(efv);
fail1:
	nic_data->rem_rep[i] = NULL;
	efx_ef100_rep_destroy_netdev(efv);
	return rc;
}

void efx_ef100_vfrep_destroy(struct efx_nic *efx, unsigned int i)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct net_device *rep_dev;
	struct efx_rep *efv;

	rep_dev = nic_data->vf_rep[i];
	if (!rep_dev)
		return;
	efv = netdev_priv(rep_dev);
	unregister_netdev(rep_dev);
	efx_ef100_deconfigure_rep(efv);
	nic_data->vf_rep[i] = NULL;
	efx_ef100_rep_destroy_netdev(efv);
}

void efx_ef100_remote_rep_destroy(struct efx_nic *efx, unsigned int i)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct net_device *rep_dev;
	struct efx_rep *efv;

	rep_dev = nic_data->rem_rep[i];
	if (!rep_dev)
		return;
	efv = netdev_priv(rep_dev);
	unregister_netdev(rep_dev);
	efx_ef100_deconfigure_rep(efv);
	nic_data->rem_rep[i] = NULL;
	efx_ef100_rep_destroy_netdev(efv);
}

static int efx_ef100_rep_poll(struct napi_struct *napi, int weight)
{
	struct efx_rep *efv = container_of(napi, struct efx_rep, napi);
	unsigned int read_index;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB__LIST)
	struct list_head head;
#else
	struct sk_buff_head head;
#endif
	struct sk_buff *skb;
	bool need_resched;
	int spent = 0;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB__LIST)
	INIT_LIST_HEAD(&head);
#else
	__skb_queue_head_init(&head);
#endif
	/* Grab up to 'weight' pending SKBs */
	spin_lock_bh(&efv->rx_lock);
	read_index = efv->write_index;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB__LIST)
	while (spent < weight && !list_empty(&efv->rx_list)) {
		skb = list_first_entry(&efv->rx_list, struct sk_buff, list);
		list_del(&skb->list);
		list_add_tail(&skb->list, &head);
#else
	while (spent < weight) {
		skb = __skb_dequeue(&efv->rx_list);
		if (!skb)
			break;
		__skb_queue_tail(&head, skb);
#endif
		spent++;
	}
	spin_unlock_bh(&efv->rx_lock);
	/* Receive them */
	netif_receive_skb_list(&head);
	if (spent < weight)
		if (napi_complete_done(napi, spent)) {
			spin_lock_bh(&efv->rx_lock);
			efv->read_index = read_index;
			/* If write_index advanced while we were doing the
			 * RX, then storing our read_index won't re-prime the
			 * fake-interrupt.  In that case, we need to schedule
			 * NAPI again to consume the additional packet(s).
			 */
			need_resched = efv->write_index != read_index;
			spin_unlock_bh(&efv->rx_lock);
			if (need_resched)
				napi_schedule(&efv->napi);
		}
	return spent;
}

void efx_ef100_rep_rx_packet(struct efx_rep *efv, struct efx_rx_buffer *rx_buf)
{
	u8 *eh = efx_rx_buf_va(rx_buf);
	struct sk_buff *skb;
	bool primed;

	/* Don't allow too many queued SKBs to build up, as they consume
	 * GFP_ATOMIC memory.  If we overrun, just start dropping.
	 */
	if (efv->write_index - READ_ONCE(efv->read_index) > efv->rx_pring_size) {
		atomic64_inc(&efv->stats.rx_dropped);
		if (net_ratelimit())
			netif_dbg(efv->parent, rx_err, efv->net_dev,
				  "nodesc-dropped packet of length %u\n",
				  rx_buf->len);
		return;
	}

	skb = netdev_alloc_skb(efv->net_dev, rx_buf->len);
	if (!skb) {
		atomic64_inc(&efv->stats.rx_dropped);
		if (net_ratelimit())
			netif_dbg(efv->parent, rx_err, efv->net_dev,
				  "noskb-dropped packet of length %u\n",
				  rx_buf->len);
		return;
	}
	memcpy(skb->data, eh, rx_buf->len);
	__skb_put(skb, rx_buf->len);

	skb_record_rx_queue(skb, 0); /* rep is single-queue */

	/* Move past the ethernet header */
	skb->protocol = eth_type_trans(skb, efv->net_dev);

	skb_checksum_none_assert(skb);

	atomic64_inc(&efv->stats.rx_packets);
	atomic64_add(rx_buf->len, &efv->stats.rx_bytes);

	/* Add it to the rx list */
	spin_lock_bh(&efv->rx_lock);
	primed = efv->read_index == efv->write_index;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB__LIST)
	list_add_tail(&skb->list, &efv->rx_list);
#else
	__skb_queue_tail(&efv->rx_list, skb);
#endif
	efv->write_index++;
	spin_unlock_bh(&efv->rx_lock);
	/* Trigger rx work */
	if (primed)
		napi_schedule(&efv->napi);
}

struct net_device *efx_ef100_find_rep_by_mport(struct efx_nic *efx, u16 mport)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct efx_rep *efv;
	unsigned int i;

	for (i = 0; i < nic_data->rem_rep_count; i++) {
		efv = netdev_priv(nic_data->rem_rep[i]);
		if (efv->mport == mport)
			return nic_data->rem_rep[i];
	}
#if defined(CONFIG_SFC_SRIOV)
	if (nic_data->vf_rep)
		for (i = 0; i < nic_data->vf_rep_count; i++) {
			if (!nic_data->vf_rep[i])
				continue;
			efv = netdev_priv(nic_data->vf_rep[i]);
			if (efv->mport == mport)
				return nic_data->vf_rep[i];
		}
#endif
	return NULL;
}

#else /* EFX_TC_OFFLOAD */

int efx_ef100_vfrep_create(struct efx_nic *efx, unsigned int i)
{
	/* Without all the various bits we need to make TC flower offload work,
	 * there's not much use in VFs or their representors, even if we
	 * technically could create them - they'd never be connected to the
	 * outside world.
	 */
	if (net_ratelimit())
		netif_info(efx, drv, efx->net_dev, "VF representors not supported on this kernel version\n");
	return -EOPNOTSUPP;
}

int efx_ef100_remote_rep_create(struct efx_nic *efx, unsigned int i,
				unsigned int mport_desc_idx)
{
	/* Without all the various bits we need to make TC flower offload work,
	 * there's not much use in VFs or their representors, even if we
	 * technically could create them - they'd never be connected to the
	 * outside world.
	 */
	if (net_ratelimit())
		netif_info(efx, drv, efx->net_dev, "Representors not supported on this kernel version\n");
	return -EOPNOTSUPP;
}

void efx_ef100_vfrep_destroy(struct efx_nic *efx, unsigned int i)
{
}

const struct net_device_ops efx_ef100_rep_netdev_ops = {};

void efx_ef100_rep_rx_packet(struct efx_rep *efv, struct efx_rx_buffer *rx_buf)
{
	WARN_ON_ONCE(1);
}

struct net_device *efx_ef100_find_rep_by_mport(struct efx_nic *efx, u16 mport)
{
	return NULL;
}
#endif /* EFX_TC_OFFLOAD */
