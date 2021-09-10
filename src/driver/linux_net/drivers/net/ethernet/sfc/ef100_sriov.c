/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#include "ef100_sriov.h"
#include "ef100_rep.h"
#include "ef100_nic.h"

#if defined(CONFIG_SFC_SRIOV)
static int efx_ef100_pci_sriov_enable(struct efx_nic *efx, int num_vfs)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct pci_dev *dev = efx->pci_dev;
	int rc, i;

	EFX_WARN_ON_PARANOID(efx->vf_count);
	efx->vf_count = num_vfs;

	rc = pci_enable_sriov(dev, num_vfs);
	if (rc)
		goto fail1;

	if (!nic_data->grp_mae)
		return 0;

	if (!nic_data->have_local_intf)
		/* We weren't able to identify our local interface, so we will
		 * have created remote_reps for these VFs.  Thus, don't create
		 * local vf_reps for them too.
		 */
		return 0;

	nic_data->vf_rep = kcalloc(num_vfs, sizeof(struct net_device *),
				GFP_KERNEL);
	if (!nic_data->vf_rep) {
		rc = -ENOMEM;
		goto fail1;
	}

	for (i = 0; i < num_vfs; i++) {
		rc = efx_ef100_vfrep_create(efx, i);
		if (rc)
			goto fail2;
	}
	spin_lock_bh(&nic_data->vf_reps_lock);
	nic_data->vf_rep_count = num_vfs;
	if (netif_running(efx->net_dev) &&
	    (efx->state == STATE_NET_UP))
		__ef100_attach_reps(efx);
	else
		__ef100_detach_reps(efx);
	spin_unlock_bh(&nic_data->vf_reps_lock);

	return 0;

fail2:
	for (; i--;)
		efx_ef100_vfrep_destroy(efx, i);
	pci_disable_sriov(dev);
	kfree(nic_data->vf_rep);
	nic_data->vf_rep = NULL;
fail1:
	efx->vf_count = 0;
	netif_err(efx, probe, efx->net_dev, "Failed to enable SRIOV VFs\n");
	return rc;
}

int efx_ef100_pci_sriov_disable(struct efx_nic *efx, bool force)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct pci_dev *dev = efx->pci_dev;
	unsigned int vfs_assigned = 0;
	int i;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_DEV_FLAGS_ASSIGNED)
	vfs_assigned = pci_vfs_assigned(dev);

	if (vfs_assigned && !force) {
		netif_info(efx, drv, efx->net_dev, "VFs are assigned to guests; "
			   "please detach them before disabling SR-IOV\n");
		return -EBUSY;
	}
#endif

	/* We take the lock as a barrier to ensure no-one holding the lock
	 * still sees nonzero rep_count when we start destroying reps
	 */
	if (nic_data->grp_mae) {
		unsigned int vf_rep_count;

		spin_lock_bh(&nic_data->vf_reps_lock);
		vf_rep_count = nic_data->vf_rep_count;
		nic_data->vf_rep_count = 0;
		spin_unlock_bh(&nic_data->vf_reps_lock);

		for (i = 0; i < vf_rep_count; i++)
			efx_ef100_vfrep_destroy(efx, i);
	}

	if (!vfs_assigned)
		pci_disable_sriov(dev);

	kfree(nic_data->vf_rep);
	nic_data->vf_rep = NULL;
	efx->vf_count = 0;
	return 0;
}

int efx_ef100_sriov_configure(struct efx_nic *efx, int num_vfs)
{
	if (num_vfs == 0)
		return efx_ef100_pci_sriov_disable(efx, false);
	else
		return efx_ef100_pci_sriov_enable(efx, num_vfs);
}
#endif
