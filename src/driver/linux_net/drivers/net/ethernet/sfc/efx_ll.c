// SPDX-License-Identifier: GPL-2.0-only
/****************************************************************************
 * Driver for AMD network controllers and boards
 *
 * Copyright 2024, Advanced Micro Devices, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#include "efx_ll.h"
#include "net_driver.h"
#include "efx_common.h"
#include "llct_regs.h"

/**
 * struct efx_ll - Represents a PCI function memory mapped BAR region.
 * @mem_bar: BAR number of the pci function
 * @membase_phys: Physical address of BAR memory region.
 * @uc_membase: Virtual address of BAR memory region mapped with
 *		UC memory attribute.
 * @uc_mem_map_size: Size of the UC memory mapping of the BAR
 * @wc_membase: Virtual address of BAR memory region mapped with
 *		WC memory attribute.
 * @wc_mem_map_size: Size of the WC memory mapping of the BAR
 * @design_parameters: Design parameters read from the BAR
 */
struct efx_ll {
	int mem_bar;
	resource_size_t membase_phys;
	void __iomem *uc_membase;
	unsigned int uc_mem_map_size;
	void __iomem *wc_membase;
	unsigned int wc_mem_map_size;
	struct efx_design_params design_parameters;
};

static int efx_ll_bar(struct efx_nic *efx)
{
	/* Check for X4 PCI functions that have access to the LL datapath. */
	if (efx->pci_dev->vendor == PCI_VENDOR_ID_SOLARFLARE &&
	    (efx->pci_dev->device == 0x0c03 || efx->pci_dev->device == 0x1c03))
		return 4;
	return -EOPNOTSUPP;
}

resource_size_t efx_llct_mem_phys(struct efx_probe_data *pd, unsigned int addr)
{
	return pd->efx_ll->membase_phys + addr;
}

void __iomem *efx_llct_mem(struct efx_probe_data *pd, unsigned int addr)
{
	return pd->efx_ll->uc_membase + addr;
}

static __le32 _efx_llct_readd(struct efx_probe_data *pd, unsigned int reg)
{
	return (__force __le32)__raw_readl(efx_llct_mem(pd, reg));
}

static void efx_llct_readd(struct efx_nic *efx, efx_dword_t *value,
			   unsigned int reg)
{
	value->u32[0] = _efx_llct_readd(efx_nic_to_probe_data(efx), reg);
	netif_vdbg(efx, hw, efx->net_dev,
		   "read from register %x, got " EFX_DWORD_FMT "\n",
		   reg, EFX_DWORD_VAL(*value));
}

static int efx_llct_process_design_param(struct efx_nic *efx,
					 const struct efx_tlv_state *reader)
{
	struct efx_probe_data *pd = efx_nic_to_probe_data(efx);
	struct efx_design_params *dp = &pd->efx_ll->design_parameters;

	switch (reader->type) {
	case ESE_IZ_LLCT_DP_PAD:
		return 0;
	case ESE_IZ_LLCT_DP_RX_STRIDE:
		dp->rx_stride = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_EVQ_STRIDE:
		dp->evq_stride = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_CTPIO_STRIDE:
		dp->tx_aperture_size = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_RX_BUFFER_SIZE:
		dp->rx_buffer_len = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_RX_QUEUES:
		dp->rx_queues = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_TX_CTPIO_APERTURES:
		dp->tx_apertures = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_RX_BUFFER_FIFO_SIZE:
		dp->rx_buf_fifo_size = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_FRAME_OFFSET_FIXED:
		dp->frame_offset_fixed = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_RX_METADATA_LENGTH:
		dp->rx_metadata_len = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_TX_MAXIMUM_REORDER:
		dp->tx_max_reorder = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_TX_CTPIO_APERTURE_SIZE:
		dp->tx_aperture_size = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_TX_PACKET_FIFO_SIZE:
		dp->tx_fifo_size = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_PARTIAL_TSTAMP_SUB_NANO_BITS:
		dp->ts_subnano_bit = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_EVQ_UNSOL_CREDIT_SEQ_BITS:
		dp->unsol_credit_seq_mask = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_RX_L4_CSUM_PROTOCOLS:
		dp->l4_csum_proto = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_RX_MAX_RUNT:
		dp->max_runt = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_EVQ_SIZES:
		dp->evq_sizes = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_EV_QUEUES:
		dp->ev_queues = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_NUM_FILTERS:
		dp->num_filters = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_MD_USER_BITS_WIDTH:
		dp->user_bits_width = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_MD_TIMESTAMP_SET_SYNC:
		dp->timestamp_set_sync = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_EV_LABEL_WIDTH:
		dp->ev_label_width = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_MD_LOCATION:
		dp->meta_location = reader->value;
		return 0;
	case ESE_IZ_LLCT_DP_ROLLOVER_ZEROS_PKT:
		dp->rollover_zeros_pkt = reader->value;
		return 0;

	default:
		/* Host interface says "Drivers should ignore design parameters
		 * that they do not recognise."
		 */
		netif_info(efx, probe, efx->net_dev,
			   "Ignoring unrecognised design parameter %u\n",
			   reader->type);
		return 0;
	}
}

struct efx_design_params *efx_llct_get_design_parameters(struct efx_nic *efx)
{
	if (!efx_ll_is_enabled(efx))
		return ERR_PTR(-ENODEV);
	return &efx_nic_to_probe_data(efx)->efx_ll->design_parameters;
}

int efx_ll_init(struct efx_nic *efx)
{
	struct efx_probe_data *probe_data;
	unsigned int uc_mem_map_size;
	struct efx_ll *efx_ll;
	int bar;
	int rc;

	bar = efx_ll_bar(efx);
	if (bar == -EOPNOTSUPP)
		return 0;
	if (bar < 0)
		return bar;

	probe_data = efx_nic_to_probe_data(efx);
	/* Map up to the design params so they may be used at probe time. */
	uc_mem_map_size = PAGE_SIZE;

	efx_ll = kzalloc(sizeof(*efx_ll), GFP_KERNEL);
	if (!efx_ll)
		return -ENOMEM;

	rc = efx_pci_map_bar(efx, bar, uc_mem_map_size,
			     &efx_ll->membase_phys,
			     &efx_ll->uc_membase);
	if (rc) {
		kfree(efx_ll);
		return rc;
	}

	efx_ll->mem_bar = bar;
	efx_ll->uc_mem_map_size = uc_mem_map_size;
	probe_data->efx_ll = efx_ll;

	rc = efx_check_design_params(efx, efx_llct_process_design_param,
				     ER_IZ_LLCT_PARAMS_TLV_LEN,
				     ER_IZ_LLCT_PARAMS_TLV,
				     efx_ll->uc_mem_map_size, efx_llct_readd);
	if (rc) {
		kfree(efx_ll);
		probe_data->efx_ll = NULL;
		return rc;
	}

	return 0;
}

bool efx_ll_is_enabled(struct efx_nic *efx)
{
	return efx_nic_to_probe_data(efx)->efx_ll;
}

void efx_ll_fini(struct efx_nic *efx)
{
	struct efx_probe_data *probe_data = efx_nic_to_probe_data(efx);
	struct efx_ll *efx_ll = probe_data->efx_ll;

	if (efx_ll_is_enabled(efx)) {
		if (efx_ll->wc_membase)
			iounmap(efx_ll->wc_membase);

		efx_pci_unmap_bar(efx, efx_ll->mem_bar, efx_ll->membase_phys,
				  efx_ll->uc_membase);
		kfree(efx_ll);
		probe_data->efx_ll = NULL;
	}
}

bool efx_ll_is_bar_remapped(struct efx_nic *efx)
{
	struct efx_probe_data *probe_data = efx_nic_to_probe_data(efx);

	return probe_data->efx_ll && probe_data->efx_ll->wc_membase;
}

int efx_ll_remap_bar(struct efx_nic *efx)
{
	struct efx_probe_data *probe_data = efx_nic_to_probe_data(efx);
	struct efx_ll *efx_ll = probe_data->efx_ll;
	unsigned int uc_mem_map_size;
	unsigned int wc_mem_map_size;
	void __iomem *membase;

	if (!efx_ll_is_enabled(efx) || efx_ll_is_bar_remapped(efx))
		return -EINVAL;

	uc_mem_map_size = ER_IZ_LLCT_CTPIO_REGION;
#if defined(EFX_USE_KCOMPAT)
	membase = efx_ioremap(efx->membase_phys, uc_mem_map_size);
#else
	membase = ioremap(efx->membase_phys, uc_mem_map_size);
#endif
	if (!membase) {
		pci_err(probe_data->pci_dev,
			"could not extend memory BAR[%d] to %#llx+%#x\n",
			efx_ll->mem_bar, efx_ll->membase_phys, uc_mem_map_size);
		return -ENOMEM;
	}

	iounmap(efx_ll->uc_membase);
	efx_ll->uc_membase = membase;
	efx_ll->uc_mem_map_size = uc_mem_map_size;

	/* Map CTPIO region - TODO: Use design params to calculate the length
	 * once they're available.
	 */
	wc_mem_map_size = 0x100000;
	efx_ll->wc_membase = ioremap_wc(efx_ll->membase_phys + uc_mem_map_size,
					wc_mem_map_size);
	if (!efx_ll->wc_membase) {
		pci_err(probe_data->pci_dev,
			"could not map CTPIO region of BAR[%d] at %#llx+%#x\n",
			efx_ll->mem_bar, efx_ll->membase_phys + uc_mem_map_size,
			wc_mem_map_size);
		return -ENOMEM;
	}

	efx_ll->wc_mem_map_size = wc_mem_map_size;
	pci_dbg(probe_data->pci_dev,
		"memory BAR[%d] at %#llx (virtual %p+%#x UC, %p+%#x WC)\n",
		efx_ll->mem_bar, efx_ll->membase_phys, efx_ll->uc_membase,
		efx_ll->uc_mem_map_size, efx_ll->wc_membase,
		efx_ll->wc_mem_map_size);
	return 0;
}
