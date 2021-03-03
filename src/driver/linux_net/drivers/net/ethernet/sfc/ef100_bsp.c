// SPDX-License-Identifier: GPL-2.0
/****************************************************************************
 * Driver for Xilinx network controllers and boards
 * Copyright 2021 Xilinx Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#include "net_driver.h"
#include "ef100_nic.h"
#ifdef CONFIG_OF
#include <linux/of.h>
#endif

#define MAX_MCDI_REGIONS	MC_CMD_GET_DESC_ADDR_REGIONS_OUT_REGIONS_MAXNUM
#define MAX_BANKS		MAX_MCDI_REGIONS
#define DESC_ADDR_REGION_TRGT_ADDR_INVALID	((uint64_t)-1)

struct bank_info {
	phys_addr_t addr;
	phys_addr_t size;
};

static int get_mem_banks(struct bank_info *trgt_addr)
{
#ifdef CONFIG_OF
	struct device_node *memnode;
	int rc;

	if (!of_have_populated_dt())
		return -ENODEV;

	memnode = of_find_node_by_name(NULL, "memory");
	if (!memnode)
		return -ENOMEM;

	rc = of_property_read_variable_u64_array(memnode, "reg",
						 (u64 *)trgt_addr,
						 1, MAX_BANKS);
	of_node_put(memnode);
	/* For each bank there is a base address and a size register */
	if (rc > 0)
		rc /= 2;
	return rc;
#else
	return -ENOTSUPP;
#endif
}

static uint64_t region_start_for_bank(const struct bank_info *bank,
				      const struct ef100_addr_region *region)
{
	return bank->addr & ~DMA_BIT_MASK(region->trgt_alignment_log2);
}

static bool bank_fits_in_region(const struct bank_info *bank,
				const struct ef100_addr_region *region)
{
	dma_addr_t region_start, region_end, bank_end;

	if (region->trgt_addr == DESC_ADDR_REGION_TRGT_ADDR_INVALID)
		region_start = region_start_for_bank(bank, region);
	else
		region_start = region->trgt_addr;

	region_end = region_start + (1ULL << region->size_log2);
	bank_end = bank->addr + bank->size;

	if ((bank->addr < region_start) || (bank_end > region_end))
		return false;

	return true;
}

static bool try_bank_region(const struct bank_info *bank,
			    struct ef100_addr_region *region)
{
	if (bank_fits_in_region(bank, region)) {
		if (region->trgt_addr == DESC_ADDR_REGION_TRGT_ADDR_INVALID) {
			region->trgt_addr = region_start_for_bank(bank,
								  region);
		}
		return true;
	}
	return false;
}

int ef100_set_address_mapping(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_SET_DESC_ADDR_REGIONS_IN_LENMAX);
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct bank_info banks[MAX_BANKS] = { { 0, 0 } };
	struct ef100_addr_region *region;
	int i, k, n_banks, n_regions = 0;
	u32 mask = 0;
	u64 *trgt;

	if (nic_data->addr_mapping_type ==
	    MC_CMD_GET_DESC_ADDR_INFO_OUT_MAPPING_FLAT)
		return 0;

	n_banks = get_mem_banks(banks);
	if (n_banks < 0) {
		pci_err(efx->pci_dev, "Error %d getting memory banks\n",
			-n_banks);
		return n_banks;
	}

	/* Reset target addresses */
	for (i = 0; i < MAX_MCDI_REGIONS; i++) {
		region = &nic_data->addr_region[i];
		region->trgt_addr = DESC_ADDR_REGION_TRGT_ADDR_INVALID;

		if (ef100_region_addr_is_populated(&nic_data->addr_region[i]))
			n_regions = i + 1;
	}

	/* Try to assign target addresses for all memory banks */
	for (i = 0; i < n_banks; i++) {
		for (k = 0; k < n_regions; k++) {
			region = &nic_data->addr_region[k];

			if (try_bank_region(&banks[i], region))
				break;
		}
		if (k == n_regions) {
			pci_err(efx->pci_dev,
				"Memory bank %pa(%pa) is not addressable by QDMA\n",
				&banks[i].addr, &banks[i].size);
			return -ENOSPC;
		}
	}

	trgt = (uint64_t *)MCDI_PTR(inbuf,
				    SET_DESC_ADDR_REGIONS_IN_TRGT_ADDR_BASE);
	for (i = 0; i < n_regions; i++) {
		region = &nic_data->addr_region[i];
		if (region->trgt_addr == DESC_ADDR_REGION_TRGT_ADDR_INVALID)
			continue;

		trgt[i] = region->trgt_addr;
		mask |= (1ULL << i);
	}
	MCDI_SET_DWORD(inbuf, SET_DESC_ADDR_REGIONS_IN_SET_REGION_MASK, mask);

	if (mask != (1 << n_regions) - 1) {
		pci_err(efx->pci_dev,
			"Not all memory is addressable by QDMA: mask %x with %d QDMA regions\n",
			mask, n_regions);
		return -ENOSPC;
	}

	return (efx_mcdi_rpc(efx, MC_CMD_SET_DESC_ADDR_REGIONS, inbuf,
			     MC_CMD_SET_DESC_ADDR_REGIONS_IN_LEN(i),
			     NULL, 0, NULL));
}

/* Regioned address mappings are only supported on 64-bit architectures.
 * We only support the 32-bit driver on X86, which uses the flat address
 * mapping.
 */
static void ef100_get_address_region(struct ef100_addr_region *region,
				     efx_qword_t *qbuf)
{
#if defined(CONFIG_ARCH_DMA_ADDR_T_64BIT)
	region->qdma_addr = le64_to_cpu(qbuf[0].u64[0]);
	region->trgt_addr = le64_to_cpu(qbuf[1].u64[0]);
	region->size_log2 = le32_to_cpu(qbuf[2].u32[0]);
	region->trgt_alignment_log2 = le32_to_cpu(qbuf[2].u32[1]);
#endif
}

#define MC_CMD_GET_QDMA_ADDR_OUT_LEN \
	max(MC_CMD_GET_DESC_ADDR_INFO_OUT_LEN, \
	    MC_CMD_GET_DESC_ADDR_REGIONS_OUT_LEN(MC_CMD_GET_DESC_ADDR_REGIONS_OUT_REGIONS_MAXNUM))

static int ef100_get_address_mapping(struct efx_nic *efx)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	efx_dword_t *outbuf;
	efx_qword_t *qbuf;
	size_t outlen = 0;
	int rc, i;

	BUILD_BUG_ON(MC_CMD_GET_DESC_ADDR_INFO_IN_LEN != 0);
	BUILD_BUG_ON(MC_CMD_GET_DESC_ADDR_REGIONS_IN_LEN != 0);

	outbuf = kzalloc(MC_CMD_GET_QDMA_ADDR_OUT_LEN, GFP_KERNEL);
	if (!outbuf)
		return -ENOMEM;

	nic_data->addr_mapping_type =
		MC_CMD_GET_DESC_ADDR_INFO_OUT_MAPPING_FLAT;
	rc = efx_mcdi_rpc(efx, MC_CMD_GET_DESC_ADDR_INFO, NULL, 0,
			  outbuf, MC_CMD_GET_QDMA_ADDR_OUT_LEN, &outlen);
	if (rc)
		goto fail;

	nic_data->addr_mapping_type =
		MCDI_DWORD(outbuf, GET_DESC_ADDR_INFO_OUT_MAPPING_TYPE);
	if (nic_data->addr_mapping_type ==
	    MC_CMD_GET_DESC_ADDR_INFO_OUT_MAPPING_FLAT)
		goto fail;

	rc = efx_mcdi_rpc(efx, MC_CMD_GET_DESC_ADDR_REGIONS, NULL, 0,
			  outbuf, MC_CMD_GET_QDMA_ADDR_OUT_LEN, &outlen);
	if (rc)
		goto fail;
	if (outlen > MC_CMD_GET_QDMA_ADDR_OUT_LEN) {
		rc = -ENOSPC;
		goto fail;
	}

	for (i = 0;
	     i < MC_CMD_GET_DESC_ADDR_REGIONS_OUT_REGIONS_NUM(outlen);
	     i++) {
		qbuf = (efx_qword_t *)MCDI_ARRAY_STRUCT_PTR(outbuf,
				GET_DESC_ADDR_REGIONS_OUT_REGIONS, i);
		ef100_get_address_region(&nic_data->addr_region[i], qbuf);
	}

fail:
	kfree(outbuf);
	return rc;
}

int ef100_bsp_init(struct efx_nic *efx)
{
	int rc;

	rc = ef100_get_address_mapping(efx);
	if (rc)
		return rc;
	rc = ef100_set_address_mapping(efx);
	if (rc)
		return rc;

	return ef100_get_address_mapping(efx);
}
