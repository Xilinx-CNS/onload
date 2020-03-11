/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2014-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_SRIOV_H
#define EFX_SRIOV_H

#include "net_driver.h"

#ifdef CONFIG_SFC_SRIOV


void efx_sriov_init_max_vfs(struct efx_nic *efx, unsigned int pf_index);

int efx_sriov_set_vf_mac(struct net_device *net_dev, int vf_i, u8 *mac);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_VF_VLAN_PROTO) || defined(EFX_HAVE_NDO_EXT_SET_VF_VLAN_PROTO)
int efx_sriov_set_vf_vlan(struct net_device *net_dev, int vf_i, u16 vlan,
			  u8 qos, __be16 vlan_proto);
#else
int efx_sriov_set_vf_vlan(struct net_device *net_dev, int vf_i, u16 vlan,
			  u8 qos);
#endif
int efx_sriov_set_vf_spoofchk(struct net_device *net_dev, int vf_i,
			      bool spoofchk);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_VF_MAC)
int efx_sriov_get_vf_config(struct net_device *net_dev, int vf_i,
			    struct ifla_vf_info *ivi);
#endif
int efx_sriov_set_vf_link_state(struct net_device *net_dev, int vf_i,
				int link_state);
#endif /* CONFIG_SFC_SRIOV */

static inline bool efx_sriov_wanted(struct efx_nic *efx)
{
	return efx->type->sriov_wanted && efx->type->sriov_wanted(efx);
}

#endif /* EFX_SRIOV_H */
