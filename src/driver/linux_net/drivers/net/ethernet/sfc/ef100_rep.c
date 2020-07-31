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

#define EFX_EF100_VFREP_DRIVER	"efx_ef100_vfrep"
#define EFX_EF100_VFREP_VERSION	"0.0.1"

static int efx_ef100_vfrep_poll(struct napi_struct *napi, int weight);

static int efx_ef100_vfrep_init_struct(struct efx_nic *efx,
				       struct efx_vfrep *efv, unsigned int i)
{
	efv->parent = efx;
	BUILD_BUG_ON(MAE_MPORT_SELECTOR_NULL);
	efv->vf_idx = i;
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

static int efx_ef100_vfrep_open(struct net_device *net_dev)
{
	struct efx_vfrep *efv = netdev_priv(net_dev);

	netif_napi_add(net_dev, &efv->napi, efx_ef100_vfrep_poll, NAPI_POLL_WEIGHT);
	napi_enable(&efv->napi);
	return 0;
}

static int efx_ef100_vfrep_close(struct net_device *net_dev)
{
	struct efx_vfrep *efv = netdev_priv(net_dev);

	napi_disable(&efv->napi);
	netif_napi_del(&efv->napi);
	return 0;
}

static netdev_tx_t efx_ef100_vfrep_xmit(struct sk_buff *skb,
					struct net_device *dev)
{
	struct efx_vfrep *efv = netdev_priv(dev);
	struct efx_nic *efx = efv->parent;
	netdev_tx_t rc;

	/* __ef100_hard_start_xmit() will always return success even in the
	 * case of TX drops, where it will increment efx's tx_dropped.  The
	 * efv stats really only count attempted TX, not success/failure.
	 */
	atomic_inc(&efv->stats.tx_packets);
	atomic_add(skb->len, &efv->stats.tx_bytes);
	netif_tx_lock(efx->net_dev);
	rc = __ef100_hard_start_xmit(skb, efx->net_dev, efv);
	netif_tx_unlock(efx->net_dev);
	return rc;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PORT_PARENT_ID)
static int efx_ef100_vfrep_get_port_parent_id(struct net_device *dev,
					      struct netdev_phys_item_id *ppid)
{
	struct efx_vfrep *efv = netdev_priv(dev);
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
static int efx_ef100_vfrep_get_phys_port_name(struct net_device *dev,
					      char *buf, size_t len)
{
	struct efx_vfrep *efv = netdev_priv(dev);
	struct efx_nic *efx = efv->parent;
	struct ef100_nic_data *nic_data;
	int ret;

	nic_data = efx->nic_data;
	ret = snprintf(buf, len, "p%upf%uvf%u", efx->port_num,
		       nic_data->pf_index, efv->vf_idx);
	if (ret >= len)
		return -EOPNOTSUPP;

	return 0;
}
#endif

/* Nothing to configure hw-wise, just set sw state */
static int efx_ef100_vfrep_set_mac_address(struct net_device *net_dev,
					   void *data)
{
	struct sockaddr *addr = data;
	u8 *new_addr = addr->sa_data;

	ether_addr_copy(net_dev->dev_addr, new_addr);

	return 0;
}

static int efx_ef100_vfrep_setup_tc(struct net_device *net_dev,
				    enum tc_setup_type type, void *type_data)
{
	struct efx_vfrep *efv = netdev_priv(net_dev);
	struct efx_nic *efx = efv->parent;

	if (type == TC_SETUP_CLSFLOWER)
		return efx_tc_flower(efx, net_dev, type_data, efv);
	if (type == TC_SETUP_BLOCK)
		return efx_tc_setup_block(net_dev, efx, type_data, efv);

	return -EOPNOTSUPP;
}

static void efx_ef100_vfrep_get_stats64(struct net_device *dev,
					struct rtnl_link_stats64 *stats)
{
	struct efx_vfrep *efv = netdev_priv(dev);

	stats->rx_packets = atomic_read(&efv->stats.rx_packets);
	stats->tx_packets = atomic_read(&efv->stats.tx_packets);
	stats->rx_bytes = atomic_read(&efv->stats.rx_bytes);
	stats->tx_bytes = atomic_read(&efv->stats.tx_bytes);
	stats->rx_dropped = atomic_read(&efv->stats.rx_dropped);
	stats->tx_errors = atomic_read(&efv->stats.tx_errors);
}

const struct net_device_ops efx_ef100_vfrep_netdev_ops = {
	.ndo_open		= efx_ef100_vfrep_open,
	.ndo_stop		= efx_ef100_vfrep_close,
	.ndo_start_xmit		= efx_ef100_vfrep_xmit,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PORT_PARENT_ID)
	.ndo_get_port_parent_id	= efx_ef100_vfrep_get_port_parent_id,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PHYS_PORT_NAME)
	.ndo_get_phys_port_name	= efx_ef100_vfrep_get_phys_port_name,
#endif
	.ndo_set_mac_address    = efx_ef100_vfrep_set_mac_address,
	.ndo_get_stats64	= efx_ef100_vfrep_get_stats64,
	.ndo_setup_tc		= efx_ef100_vfrep_setup_tc,
};

static void efx_ef100_vfrep_get_drvinfo(struct net_device *dev,
					struct ethtool_drvinfo *drvinfo)
{
	strlcpy(drvinfo->driver, EFX_EF100_VFREP_DRIVER, sizeof(drvinfo->driver));
	strlcpy(drvinfo->version, EFX_EF100_VFREP_VERSION, sizeof(drvinfo->version));
}

static u32 efx_ef100_vfrep_ethtool_get_msglevel(struct net_device *net_dev)
{
	struct efx_vfrep *efv = netdev_priv(net_dev);
	return efv->msg_enable;
}

static void efx_ef100_vfrep_ethtool_set_msglevel(struct net_device *net_dev,
						 u32 msg_enable)
{
	struct efx_vfrep *efv = netdev_priv(net_dev);
	efv->msg_enable = msg_enable;
}

const static struct ethtool_ops efx_ef100_vfrep_ethtool_ops = {
	.get_drvinfo		= efx_ef100_vfrep_get_drvinfo,
	.get_msglevel		= efx_ef100_vfrep_ethtool_get_msglevel,
	.set_msglevel		= efx_ef100_vfrep_ethtool_set_msglevel,
};

static struct efx_vfrep *efx_ef100_vfrep_create_netdev(struct efx_nic *efx,
						       unsigned int i)
{
	struct net_device *net_dev;
	struct efx_vfrep *efv;
	int rc;

	net_dev = alloc_etherdev_mq(sizeof(*efv), 1);
	if (!net_dev)
		return ERR_PTR(-ENOMEM);

	efv = netdev_priv(net_dev);
	rc = efx_ef100_vfrep_init_struct(efx, efv, i);
	if (rc)
		goto fail1;
	efv->net_dev = net_dev;

	/* Ensure we don't race with ef100_{start,stop}_reps() and the setting
	 * of efx->port_enabled under ef100_net_{start,stop}().
	 */
	rtnl_lock();
	if (efx->port_enabled)
		netif_carrier_on(net_dev);
	else
		netif_carrier_off(net_dev);
	rtnl_unlock();

	net_dev->netdev_ops = &efx_ef100_vfrep_netdev_ops;
	net_dev->ethtool_ops = &efx_ef100_vfrep_ethtool_ops;
	net_dev->features |= NETIF_F_HW_TC;
	net_dev->hw_features |= NETIF_F_HW_TC;
	return efv;
fail1:
	free_netdev(net_dev);
	return ERR_PTR(rc);
}

static void efx_ef100_vfrep_destroy_netdev(struct efx_vfrep *efv)
{
	free_netdev(efv->net_dev);
}

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER) && !defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER)
static int efx_ef100_vfrep_tc_egdev_cb(enum tc_setup_type type, void *type_data,
				       void *cb_priv)
{
	struct efx_vfrep *efv = cb_priv;

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		return efx_tc_flower(efv->parent, NULL, type_data, efv);
	default:
		return -EOPNOTSUPP;
	}
}
#endif

static int efx_ef100_configure_rep(struct efx_vfrep *efv)
{
	struct efx_nic *efx = efv->parent;
	u32 selector;
	int rc;

	/* Construct mport selector for corresponding VF */
	efx_mae_mport_vf(efx, efv->vf_idx, &selector);
	/* Look up actual mport ID */
	rc = efx_mae_lookup_mport(efx, selector, &efv->vf_mport);
	if (rc)
		return rc;
	netif_dbg(efv->parent, probe, efv->net_dev,
		  "Representor mport ID %#x\n", efv->vf_mport);
	/* mport label should fit in 16 bits */
	WARN_ON(efv->vf_mport >> 16);
	mutex_lock(&efx->tc->mutex);
	rc = efx_tc_configure_default_rule(efx, EFX_TC_DFLT_VF(efv->vf_idx));
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER) && !defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER)
	if (!rc) {
		rc = tc_setup_cb_egdev_register(efv->net_dev,
						efx_ef100_vfrep_tc_egdev_cb, efv);
		if (rc)
			efx_tc_deconfigure_default_rule(efx, EFX_TC_DFLT_VF(efv->vf_idx));
	}
#endif
	mutex_unlock(&efx->tc->mutex);
	return rc;
}

static void efx_ef100_deconfigure_rep(struct efx_vfrep *efv)
{
	struct efx_nic *efx = efv->parent;

	mutex_lock(&efx->tc->mutex);
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER) && !defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER)
	tc_setup_cb_egdev_unregister(efv->net_dev, efx_ef100_vfrep_tc_egdev_cb,
				     efv);
#endif
	efx_tc_deconfigure_default_rule(efx, EFX_TC_DFLT_VF(efv->vf_idx));
	mutex_unlock(&efx->tc->mutex);
}

int efx_ef100_vfrep_create(struct efx_nic *efx, unsigned int i)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct efx_vfrep *efv;
	int rc;

	efv = efx_ef100_vfrep_create_netdev(efx, i);
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
	efx_ef100_vfrep_destroy_netdev(efv);
	return rc;
}

void efx_ef100_vfrep_destroy(struct efx_nic *efx, unsigned int i)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct net_device *rep_dev;
	struct efx_vfrep *efv;

	rep_dev = nic_data->vf_rep[i];
	if (!rep_dev)
		return;
	efv = netdev_priv(rep_dev);
	efx_ef100_deconfigure_rep(efv);
	nic_data->vf_rep[i] = NULL;
	unregister_netdev(rep_dev);
	efx_ef100_vfrep_destroy_netdev(efv);
}

static int efx_ef100_vfrep_poll(struct napi_struct *napi, int weight)
{
	struct efx_vfrep *efv = container_of(napi, struct efx_vfrep, napi);
	unsigned int read_index;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB__LIST)
	struct list_head head;
#else
	struct sk_buff_head head;
#endif
	struct sk_buff *skb;
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
		if (napi_complete_done(napi, spent))
			efv->read_index = read_index;
	return spent;
}

void efx_ef100_vfrep_rx_packet(struct efx_vfrep *efv, struct efx_rx_buffer *rx_buf)
{
	u8 *eh = efx_rx_buf_va(rx_buf);
	struct sk_buff *skb;
	bool primed;

	skb = netdev_alloc_skb(efv->net_dev, rx_buf->len);
	if (!skb) {
		atomic_inc(&efv->stats.rx_dropped);
		netif_dbg(efv->parent, rx_err, efv->net_dev,
			  "noskb-dropped packet of length %u\n", rx_buf->len);
		return;
	}
	memcpy(skb->data, eh, rx_buf->len);
	__skb_put(skb, rx_buf->len);

	skb_record_rx_queue(skb, 0); /* vfrep is single-queue */

	/* Move past the ethernet header */
	skb->protocol = eth_type_trans(skb, efv->net_dev);

	skb_checksum_none_assert(skb);

	atomic_inc(&efv->stats.rx_packets);
	atomic_add(rx_buf->len, &efv->stats.rx_bytes);

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

/* Returns the representor netdevice corresponding to a VF m-port, or NULL.
 * @mport is an m-port label, *not* an m-port ID!
 */
struct net_device *efx_ef100_find_vfrep_by_mport(struct efx_nic *efx, u16 mport)
{
#if defined(CONFIG_SFC_SRIOV)
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct efx_vfrep *efv;
	unsigned int i;

	if (nic_data->vf_rep)
		for (i = 0; i < efx->vf_count; i++) {
			if (!nic_data->vf_rep[i])
				continue;
			efv = netdev_priv(nic_data->vf_rep[i]);
			if (efv->vf_mport == mport)
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

void efx_ef100_vfrep_destroy(struct efx_nic *efx, unsigned int i)
{
}

const struct net_device_ops efx_ef100_vfrep_netdev_ops = {};

void efx_ef100_vfrep_rx_packet(struct efx_vfrep *efv, struct efx_rx_buffer *rx_buf)
{
	WARN_ON_ONCE(1);
}

struct net_device *efx_ef100_find_vfrep_by_mport(struct efx_nic *efx, u16 mport)
{
	return NULL;
}
#endif /* EFX_TC_OFFLOAD */
