/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2014-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#include <linux/module.h>
#include "net_driver.h"
#include "nic.h"
#include "sriov.h"

#define EFX_MAX_PFS		16

#define MAX_VFS_ENABLE_ALL	INT_MAX
#define MAX_VFS_DEF		0

static int max_vfs[EFX_MAX_PFS];
static unsigned int max_vfs_count;
module_param_array(max_vfs, int, &max_vfs_count, 0444);
MODULE_PARM_DESC(max_vfs,
		 "Specify the number of VFs initialized by the driver");

#ifdef EFX_NOT_UPSTREAM
/* Original name for max_vfs */
module_param_array_named(vf_count, max_vfs, int, &max_vfs_count, 0);
MODULE_PARM_DESC(vf_count, "Duplicate of the max_vfs parameter");
#endif

#ifdef CONFIG_SFC_SRIOV


void efx_sriov_init_max_vfs(struct efx_nic *efx, unsigned int pf_index)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	unsigned int idx;

	if (!efx->type->sriov_init)
		return;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_NUM_VF)
	/* If there are already VFs, don't initialise more */
	if (pci_num_vf(efx->pci_dev))
		return;
#endif

	idx = pf_index;

	if (max_vfs_count == 0)
		nic_data->max_vfs = MAX_VFS_DEF;
	else if (max_vfs_count == 1)
		/* If there is only one entry in max_vfs array,
		 * use it for all NICs for backward compatibility.
		 */
		nic_data->max_vfs = max_vfs[0];
	else if (idx >= max_vfs_count)
		nic_data->max_vfs = 0;
	else
		nic_data->max_vfs = max_vfs[idx];

	if (nic_data->max_vfs < 0)
		nic_data->max_vfs = MAX_VFS_ENABLE_ALL;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_VF_MAC)
int efx_sriov_get_vf_config(struct net_device *net_dev, int vf_i, struct ifla_vf_info *ivi)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx->type->sriov_get_vf_config)
		return efx->type->sriov_get_vf_config(efx, vf_i, ivi);
	else
		return -EOPNOTSUPP;
}
#endif

int efx_sriov_set_vf_mac(struct net_device *net_dev, int vf_i, u8 *mac)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx->type->sriov_set_vf_mac)
		return efx->type->sriov_set_vf_mac(efx, vf_i, mac);
	else
		return -EOPNOTSUPP;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_VF_VLAN_PROTO) || defined(EFX_HAVE_NDO_EXT_SET_VF_VLAN_PROTO)
int efx_sriov_set_vf_vlan(struct net_device *net_dev, int vf_i, u16 vlan,
			  u8 qos, __be16 vlan_proto)
#else
int efx_sriov_set_vf_vlan(struct net_device *net_dev, int vf_i, u16 vlan,
			  u8 qos)
#endif
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx->type->sriov_set_vf_vlan) {
		if ((vlan & ~VLAN_VID_MASK) ||
		    (qos & ~(VLAN_PRIO_MASK >> VLAN_PRIO_SHIFT)))
			return -EINVAL;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_VF_VLAN_PROTO) || defined(EFX_HAVE_NDO_EXT_SET_VF_VLAN_PROTO)
		if (vlan_proto != htons(ETH_P_8021Q))
			return -EPROTONOSUPPORT;
#endif

		return efx->type->sriov_set_vf_vlan(efx, vf_i, vlan, qos);
	} else {
		return -EOPNOTSUPP;
	}
}

int efx_sriov_set_vf_spoofchk(struct net_device *net_dev, int vf_i,
			      bool spoofchk)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx->type->sriov_set_vf_spoofchk)
		return efx->type->sriov_set_vf_spoofchk(efx, vf_i, spoofchk);
	else
		return -EOPNOTSUPP;
}

int efx_sriov_set_vf_link_state(struct net_device *net_dev, int vf_i,
				int link_state)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx->type->sriov_set_vf_link_state)
		return efx->type->sriov_set_vf_link_state(efx, vf_i, link_state);
	else
		return -EOPNOTSUPP;
}


#endif
