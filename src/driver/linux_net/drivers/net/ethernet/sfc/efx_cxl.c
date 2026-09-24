// SPDX-License-Identifier: GPL-2.0-only
/****************************************************************************
 *
 * Driver for AMD network controllers and boards
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "net_driver.h"
#include <linux/pci.h>
#include <linux/range.h>
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_CXL_H)
#include <cxl/cxl.h>
#include <cxl/pci.h>
#endif
#include <linux/kref.h>

#include "nic.h"
#include "mcdi.h"

#include "efx_cxl.h"

#define EFX_CTPIO_BUFFER_SIZE	SZ_256M

#if defined(CONFIG_SFC_CXL) && (!defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CXL))
static char *cxl_transmit_str;
module_param_named(cxl_transmit, cxl_transmit_str, charp, 0444);
MODULE_PARM_DESC(cxl_transmit,
		 "Control CXL transmit method, 'auto', 'mem', or 'disabled'");

static char *cxl_receive_str;
module_param_named(cxl_receive, cxl_receive_str, charp, 0444);
MODULE_PARM_DESC(cxl_receive,
		 "Control CXL receive method, 'auto', 'cache', or 'disabled'");

int efx_cxl_init(struct efx_probe_data *probe_data)
{
	struct efx_nic *efx = &probe_data->efx;
	struct pci_dev *pci_dev = efx->pci_dev;
	struct range cxl_pio_range;
	struct efx_cxl *cxl;
	uint8_t devfn;
	u16 dvsec;
	int rc;

	if (efx->type->is_vf)
		return 0;

	/* are we PF0? */
	devfn = PCI_FUNC(pci_dev->devfn);
	if (devfn != 0) {
		struct efx_probe_data *pf0_probe_data;
		struct device_link *get_link;
		struct pci_dev *pf0_pci_dev;
		struct efx_nic *pf0_efx;

		pf0_pci_dev = pci_get_slot(pci_dev->bus,
					   PCI_DEVFN(PCI_SLOT(pci_dev->devfn),
					   0));

		/* This should not happen! */
		if (pf0_pci_dev == NULL)
			return 0;

		/* Is PF0 configured with and using CXL? */
		if (!pcie_is_cxl(pf0_pci_dev)) {
			pci_dev_put(pf0_pci_dev);
			return 0;
		}

		/* While we obtain PF0 device through the mutex, PF0 can not
		 * change CXL configuration as that is initialized during PF0
		 * driver probing or when PF0 unbinds from the driver, both
		 * requiring to obtain the PF0 mutex first.
		 */
		mutex_lock(&pf0_pci_dev->dev.mutex);
		pf0_efx = pci_get_drvdata(pf0_pci_dev);
		if (pf0_efx == NULL) {
			mutex_unlock(&pf0_pci_dev->dev.mutex);
			/* If PF0 is not probed yet, this PF will be probed
			 * again later on. Note if CXL is enabled in PF0, the
			 * other PFs count on PF0 initializing it and CTPIO
			 * relying only on CXL.
			 */
			pci_dev_put(pf0_pci_dev);
			return -EPROBE_DEFER;
		}

		pf0_probe_data = efx_nic_to_probe_data(pf0_efx);
		if (!pf0_probe_data->cxl) {
			/* This is a sanity check as it should not happen
			 * because the PF0 device mutex obtained. If CXL is
			 * enabled and PF0 can not initialize it, the PF0 will
			 * be unbound, therefore the previous check would be
			 * enough.
			 */
			mutex_unlock(&pf0_pci_dev->dev.mutex);
			pci_dev_put(pf0_pci_dev);
			return -ENODEV;
		}

		/* This PF is going to use the CTPIO aperture. If PF0 unbinds,
		 * this PF needs to be told. This device link will do so. With
		 * the AUTOREMOVE flag, the link will be deleted if this PF
		 * unbinds first.
		 */
		get_link = device_link_add(&pci_dev->dev, &pf0_pci_dev->dev,
					  DL_FLAG_AUTOREMOVE_CONSUMER);
		if (!get_link) {
			/* We need to check for this and it implies a problem
			 * we can not deal with.
			 */
			mutex_unlock(&pf0_pci_dev->dev.mutex);
			pci_err(pci_dev,
				"device link creation as a CXL consumer failed.\n");
			pci_dev_put(pf0_pci_dev);
			return -EIO;
		}

		probe_data->cxl = pf0_probe_data->cxl;
		mutex_unlock(&pf0_pci_dev->dev.mutex);
		pci_dev_put(pf0_pci_dev);

		return 0;
	}

	/* Is the device configured with and using CXL? */
	if (!pcie_is_cxl(pci_dev))
		return 0;

	dvsec = pci_find_dvsec_capability(pci_dev, PCI_VENDOR_ID_CXL,
					  PCI_DVSEC_CXL_DEVICE);
	if (!dvsec) {
		pci_err(pci_dev, "CXL_DVSEC_PCIE_DEVICE capability not found\n");
		return 0;
	}

	pci_info(pci_dev, "CXL_DVSEC_PCIE_DEVICE capability found\n");

	/* Create a cxl_dev_state embedded in the cxl struct using cxl core api
	 * specifying no mbox available.
	 */
	cxl = devm_cxl_dev_state_create(&pci_dev->dev, CXL_DEVTYPE_DEVMEM,
					pci_dev->dev.id, dvsec, struct efx_cxl,
					cxlds, false);

	if (!cxl)
		return -ENOMEM;

	rc = cxl_pci_setup_regs(pci_dev, CXL_REGLOC_RBI_COMPONENT,
				&cxl->cxlds.reg_map);
	if (rc) {
		pci_err(pci_dev, "No component registers\n");
		return rc;
	}

	if (!cxl->cxlds.reg_map.component_map.hdm_decoder.valid) {
		pci_err(pci_dev, "Expected HDM component register not found\n");
		return -ENODEV;
	}

	if (!cxl->cxlds.reg_map.component_map.ras.valid) {
		pci_err(pci_dev, "Expected RAS component register not found\n");
		return -ENODEV;
	}

	/*
	 * Set media ready explicitly as there are neither mailbox for checking
	 * this state nor the CXL register involved, both not mandatory for
	 * type2.
	 */
	cxl->cxlds.media_ready = true;

	if (cxl_set_capacity(&cxl->cxlds, EFX_CTPIO_BUFFER_SIZE)) {
		pci_err(pci_dev, "dpa capacity setup failed\n");
		return -ENODEV;
	}

	cxl->cxlmd = devm_cxl_probe_mem(&cxl->cxlds, &cxl_pio_range);
	if (IS_ERR(cxl->cxlmd)) {
		pci_err(pci_dev, "CXL accel memdev creation failed\n");
		rc = PTR_ERR(cxl->cxlmd);
		return rc;
	}

	cxl->ctpio_membase = cxl_pio_range.start;
	cxl->ctpio_cxl = ioremap_wc(cxl_pio_range.start, range_len(&cxl_pio_range));
	if (!cxl->ctpio_cxl) {
		pci_err(pci_dev, "CXL ioremap region (%pra) failed\n",
				 &cxl_pio_range);
		return -ENOMEM;
	}

	pci_info(pci_dev, "CXL ioremap region (%pra) mapped to %p\n",
				 &cxl_pio_range, cxl->ctpio_cxl);

	probe_data->cxl = cxl;

	return 0;
}

void efx_cxl_exit(struct efx_probe_data *probe_data)
{
	struct efx_nic *efx = &probe_data->efx;
	struct pci_dev *pci_dev = efx->pci_dev;
	uint8_t devfn;

	if (!probe_data->cxl)
		return;

	devfn = PCI_FUNC(pci_dev->devfn);
	if (devfn != 0)
		return;

	/* This is safe as PF0 exits with rmmod sfc or unbinding device from
	 * driver. Both cases do trigger first the release of other PFs through
	 * the device link functionality.
	 *
	 * This does not solve the problem of CXL mem linked to X4 CXL being
	 * unbound from the CXL mem driver or if the cxl_acpi kernel module is
	 * removed. Only through kernel CXL core is possible to get protection
	 * against this.
	 */
	iounmap(probe_data->cxl->ctpio_cxl);
}

int efx_cxl_configure_datapath(struct efx_nic *efx)
{
	struct efx_probe_data *probe_data;
	int rc;

	if (!efx)
		return -EINVAL;

	probe_data = efx_nic_to_probe_data(efx);
	if (!probe_data->cxl)
		return 0;

	rc = efx_nic_cxl_set_datapath(efx, &probe_data->cxl->transmit_mode,
				      &probe_data->cxl->receive_mode);
	if (rc)
		return rc == -EOPNOTSUPP ? 0 : rc;

	probe_data->cxl->cxl_datapath_configured = true;

	return 0;
}

static const char *
efx_cxl_transmit_mode_to_string(enum cxl_transmit_mode transmit_mode)
{
	switch (transmit_mode) {
	case CXL_TRANSMIT_MODE_AUTO:
		return "auto";
	case CXL_TRANSMIT_MODE_MEM:
		return "CXL.mem enabled";
	case CXL_TRANSMIT_MODE_DISABLED:
		return "CXL.mem disabled";
	default:
		return "unknown";
	}
}

static const char *
efx_cxl_receive_mode_to_string(enum cxl_receive_mode receive_mode)
{
	switch (receive_mode) {
	case CXL_RECEIVE_MODE_AUTO:
		return "auto";
	case CXL_RECEIVE_MODE_CACHE:
		return "CXL.cache enabled";
	case CXL_RECEIVE_MODE_DISABLED:
		return "CXL.cache disabled";
	default:
		return "unknown";
	}
}

static enum cxl_transmit_mode
efx_cxl_get_transmit_mode_option(struct efx_nic *efx)
{
	enum cxl_transmit_mode transmit_mode = CXL_TRANSMIT_MODE_AUTO;

	if (!cxl_transmit_str)
		return transmit_mode;

	if (strcmp(cxl_transmit_str, "auto") == 0)
		transmit_mode = CXL_TRANSMIT_MODE_AUTO;
	else if (strcmp(cxl_transmit_str, "mem") == 0)
		transmit_mode = CXL_TRANSMIT_MODE_MEM;
	else if (strcmp(cxl_transmit_str, "disabled") == 0)
		transmit_mode = CXL_TRANSMIT_MODE_DISABLED;
	else
		pci_err(efx->pci_dev,
			"Bad value for module parameter cxl_transmit='%s', using default\n",
			cxl_transmit_str);

	return transmit_mode;
}

static enum cxl_receive_mode
efx_cxl_get_receive_mode_option(struct efx_nic *efx)
{
	enum cxl_receive_mode receive_mode = CXL_RECEIVE_MODE_AUTO;

	if (!cxl_receive_str)
		return receive_mode;

	if (strcmp(cxl_receive_str, "auto") == 0)
		receive_mode = CXL_RECEIVE_MODE_AUTO;
	else if (strcmp(cxl_receive_str, "cache") == 0)
		receive_mode = CXL_RECEIVE_MODE_CACHE;
	else if (strcmp(cxl_receive_str, "disabled") == 0)
		receive_mode = CXL_RECEIVE_MODE_DISABLED;
	else
		pci_err(efx->pci_dev,
			"Bad value for module parameter cxl_receive='%s', using default\n",
			cxl_receive_str);

	return receive_mode;
}

int efx_cxl_set_datapath(struct efx_nic *efx,
			 enum cxl_transmit_mode *got_transmit_mode,
			 enum cxl_receive_mode *got_receive_mode)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_SET_DATAPATH_CXL_MODE_OUT_LEN);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_SET_DATAPATH_CXL_MODE_IN_LEN);
	enum cxl_transmit_mode transmit_mode;
	enum cxl_receive_mode receive_mode;
	bool cxl_cache_enabled;
	bool cxl_mem_enabled;
	size_t out_len;
	int rc;

	transmit_mode = efx_cxl_get_transmit_mode_option(efx);
	receive_mode = efx_cxl_get_receive_mode_option(efx);
	MCDI_SET_DWORD(inbuf, SET_DATAPATH_CXL_MODE_IN_UPDATE, 1);
	MCDI_POPULATE_DWORD_2(inbuf, SET_DATAPATH_CXL_MODE_IN_REQUESTED_MODE,
			      SET_DATAPATH_CXL_MODE_IN_WANT_CXL_MEM_LL,
			      transmit_mode != CXL_TRANSMIT_MODE_DISABLED,
			      SET_DATAPATH_CXL_MODE_IN_WANT_CXL_CACHE_LL,
			      receive_mode != CXL_RECEIVE_MODE_DISABLED);

	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_SET_DATAPATH_CXL_MODE, inbuf,
				sizeof(inbuf), outbuf, sizeof(outbuf),
				&out_len);
	if (rc)
		return rc;
	else if (out_len < MC_CMD_SET_DATAPATH_CXL_MODE_OUT_LEN)
		return -EIO;

	/* Note that the "mode" field has the same layout for both IN and OUT,
	 * by definition, so only one definition for this field is created but
	 * is correct to use for retrieval of data here.
	 */
	BUILD_BUG_ON(MC_CMD_SET_DATAPATH_CXL_MODE_OUT_CURRENT_MODE_OFST !=
		     MC_CMD_SET_DATAPATH_CXL_MODE_IN_REQUESTED_MODE_OFST);
	BUILD_BUG_ON(MC_CMD_SET_DATAPATH_CXL_MODE_OUT_CURRENT_MODE_LEN !=
		     MC_CMD_SET_DATAPATH_CXL_MODE_IN_REQUESTED_MODE_LEN);
	cxl_mem_enabled =
		MCDI_FIELD(outbuf, SET_DATAPATH_CXL_MODE_IN, WANT_CXL_MEM_LL);
	cxl_cache_enabled =
		MCDI_FIELD(outbuf, SET_DATAPATH_CXL_MODE_IN, WANT_CXL_CACHE_LL);

	*got_transmit_mode = cxl_mem_enabled ? CXL_TRANSMIT_MODE_MEM
					     : CXL_TRANSMIT_MODE_DISABLED;
	*got_receive_mode = cxl_cache_enabled ? CXL_RECEIVE_MODE_CACHE
					      : CXL_RECEIVE_MODE_DISABLED;

	if (transmit_mode != CXL_TRANSMIT_MODE_AUTO &&
	    transmit_mode != *got_transmit_mode) {
		pci_err(efx->pci_dev,
			"CXL datapath config mismatch: requested transmit mode %s got %s\n",
			efx_cxl_transmit_mode_to_string(transmit_mode),
			efx_cxl_transmit_mode_to_string(*got_transmit_mode));
		rc = -EEXIST;
	}

	if (receive_mode != CXL_RECEIVE_MODE_AUTO &&
	    receive_mode != *got_receive_mode) {
		pci_err(efx->pci_dev,
			"CXL datapath config mismatch: requested receive mode %s got %s\n",
			efx_cxl_receive_mode_to_string(receive_mode),
			efx_cxl_receive_mode_to_string(*got_receive_mode));
		rc = -EEXIST;
	}

	return rc;
}

int efx_cxl_get_config(struct efx_probe_data *probe_data,
		       bool *cxl_mem_enabled,
		       bool *cxl_cache_enabled)
{
	bool cxl_cache = false;
	bool cxl_mem = false;

	if (probe_data->cxl) {
		struct efx_cxl *cxl = probe_data->cxl;

		if (!cxl->cxl_datapath_configured)
			return -EAGAIN;

		cxl_cache = cxl->receive_mode == CXL_RECEIVE_MODE_CACHE;
		cxl_mem = cxl->transmit_mode == CXL_TRANSMIT_MODE_MEM;
	}

	if (cxl_cache_enabled)
		*cxl_cache_enabled = cxl_cache;

	if (cxl_mem_enabled)
		*cxl_mem_enabled = cxl_mem;

	return 0;
}

int efx_cxl_get_ctpio_membase(struct efx_probe_data *probe_data,
			      resource_size_t *membase)
{
	if (!probe_data || !membase)
		return -EINVAL;

	if (!probe_data->cxl)
		return -EINVAL;

	*membase = probe_data->cxl->ctpio_membase;

	return 0;
}

MODULE_IMPORT_NS("CXL");
#endif
