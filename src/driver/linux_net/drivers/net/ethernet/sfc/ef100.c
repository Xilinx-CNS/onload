/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2018 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "net_driver.h"
#include <linux/module.h>
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_AER)
#include <linux/aer.h>
#endif
#include "efx_common.h"
#include "efx_channels.h"
#include "efx_auxbus.h"
#include "debugfs.h"
#include "io.h"
#include "ef100_nic.h"
#include "ef100_netdev.h"
#include "ef100_regs.h"
#include "ef100_bsp.h"
#include "ef100.h"
#ifdef CONFIG_SFC_TRACING
#include <trace/events/sfc.h>
#endif
#include "mcdi_pcol.h"

#define EFX_EF100_PCI_DEFAULT_BAR	0

/* Number of bytes at start of vendor specified extended capability that indicate
 * that the capability is vendor specified. i.e. offset from value returned by
 * pci_find_next_ext_capability() to beginning of vendor specified capability
 * header.
*/
#define PCI_EXT_CAP_HDR_LENGTH  4

/* Expected size of a Xilinx continuation address table entry. */
#define ESE_GZ_CFGBAR_CONT_CAP_MIN_LENGTH      16

struct ef100_func_ctl_window
{
	bool valid;
	unsigned int bar;
	u64 offset;
};

static int ef100_pci_walk_xilinx_table(struct efx_nic *efx, u64 offset,
				       struct ef100_func_ctl_window *result);

/* Number of bytes to offset when reading bit position x with dword accessors. */
#define ROUND_DOWN_TO_DWORD(x) (((x) & (~31)) >> 3)

#define EXTRACT_BITS(x, lbn, width) \
	((x) >> ((lbn) & 31)) & ((1ull << (width)) - 1)

static u32 _ef100_pci_get_bar_bits_with_width(struct efx_nic *efx,
					      int structure_start,
					      int lbn, int width)
{
	efx_dword_t dword;

	efx_readd(efx, &dword, structure_start + ROUND_DOWN_TO_DWORD(lbn));

	return EXTRACT_BITS(le32_to_cpu(dword.u32[0]), lbn, width);
}

#define ef100_pci_get_bar_bits(efx, entry_location, bitdef) \
	_ef100_pci_get_bar_bits_with_width(efx, entry_location, \
		bitdef ## _LBN, bitdef ## _WIDTH)

static int ef100_pci_parse_ef100_entry(struct efx_nic *efx, int entry_location,
				       struct ef100_func_ctl_window *result)
{
	u32 bar = ef100_pci_get_bar_bits(efx, entry_location,
					 ESF_GZ_CFGBAR_EF100_BAR);
	u64 offset = ef100_pci_get_bar_bits(efx, entry_location,
					    ESF_GZ_CFGBAR_EF100_FUNC_CTL_WIN_OFF) << ESE_GZ_EF100_FUNC_CTL_WIN_OFF_SHIFT;

	pci_dbg(efx->pci_dev,
		"Found EF100 function control window bar=%d offset=0x%llx\n",
		bar, offset);

	if (result->valid) {
		pci_err(efx->pci_dev, "Duplicated EF100 table entry.\n");
		return -EINVAL;
	}

	if ((bar == ESE_GZ_CFGBAR_EF100_BAR_NUM_EXPANSION_ROM) ||
	    (bar == ESE_GZ_CFGBAR_EF100_BAR_NUM_INVALID)) {
		pci_err(efx->pci_dev,
			"Bad BAR value of %d in Xilinx capabilities EF100 entry.\n",
			bar);
		return -EINVAL;
	}

	result->bar = bar;
	result->offset = offset;
	result->valid = true;
	return 0;
}

static bool ef100_pci_does_bar_overflow(struct efx_nic *efx, int bar,
					u64 next_entry)
{
	return next_entry + ESE_GZ_CFGBAR_ENTRY_HEADER_SIZE >
		pci_resource_len(efx->pci_dev, bar);
}

/* Parse a Xilinx capabilities table entry describing a continuation to a new
 * sub-table.
 */
static int ef100_pci_parse_continue_entry(struct efx_nic *efx, int entry_location,
					  struct ef100_func_ctl_window *result)
{
	unsigned int previous_bar;
	efx_oword_t entry;
	u64 offset;
	int rc = 0;
	u32 bar;

	efx_reado(efx, &entry, entry_location);

	bar = EFX_OWORD_FIELD32(entry, ESF_GZ_CFGBAR_CONT_CAP_BAR);

	offset = EFX_OWORD_FIELD64(entry, ESF_GZ_CFGBAR_CONT_CAP_OFFSET) <<
		ESE_GZ_CONT_CAP_OFFSET_BYTES_SHIFT;

	previous_bar = efx->mem_bar;

	if ((bar == ESE_GZ_VSEC_BAR_NUM_EXPANSION_ROM) ||
	    (bar == ESE_GZ_VSEC_BAR_NUM_INVALID)) {
		pci_err(efx->pci_dev,
			"Bad BAR value of %d in Xilinx capabilities sub-table.\n",
			bar);
		return -EINVAL;
	}

	if (bar != previous_bar) {
		efx_fini_io(efx);

		if (ef100_pci_does_bar_overflow(efx, bar, offset)) {
			pci_err(efx->pci_dev,
				"Xilinx table will overrun BAR[%d] offset=0x%llx\n",
				bar, offset);
			return -EINVAL;
		}

		/* Temporarily map new BAR. */
		rc = efx_init_io(efx, bar, efx->type->max_dma_mask,
				 pci_resource_len(efx->pci_dev, bar));
		if (rc) {
			pci_err(efx->pci_dev,
				"Mapping new BAR for Xilinx table failed, rc=%d\n", rc);
			return rc;
		}
	}

	rc = ef100_pci_walk_xilinx_table(efx, offset, result);
	if (rc)
		return rc;

	if (bar != previous_bar) {
		efx_fini_io(efx);

		/* Put old BAR back. */
		rc = efx_init_io(efx, previous_bar, efx->type->max_dma_mask,
				 pci_resource_len(efx->pci_dev, previous_bar));
		if (rc) {
			pci_err(efx->pci_dev,
				"Putting old BAR back failed, rc=%d\n", rc);
			return rc;
		}
	}

	return 0;
}

/* Iterate over the Xilinx capabilities table in the currently mapped BAR and
 * call ef100_pci_parse_ef100_entry() on any EF100 entries and
 * ef100_pci_parse_continue_entry() on any table continuations.
 */
static int ef100_pci_walk_xilinx_table(struct efx_nic *efx, u64 offset,
				       struct ef100_func_ctl_window *result)
{
	u64 current_entry = offset;
	int rc = 0;

	while (true) {
		u32 id = ef100_pci_get_bar_bits(efx, current_entry,
						ESF_GZ_CFGBAR_ENTRY_FORMAT);
		u32 last = ef100_pci_get_bar_bits(efx, current_entry,
						  ESF_GZ_CFGBAR_ENTRY_LAST);
		u32 rev = ef100_pci_get_bar_bits(efx, current_entry,
						 ESF_GZ_CFGBAR_ENTRY_REV);
		u32 entry_size;

		if (id == ESE_GZ_CFGBAR_ENTRY_LAST)
			return 0;

		entry_size = ef100_pci_get_bar_bits(efx, current_entry,
						    ESF_GZ_CFGBAR_ENTRY_SIZE);

		pci_dbg(efx->pci_dev,
			"Seen Xilinx table entry 0x%x size 0x%x at 0x%llx in BAR[%d]\n",
			id, entry_size, current_entry, efx->mem_bar);

		if (entry_size < sizeof(uint32_t)*2) {
			pci_err(efx->pci_dev,
				"Xilinx table entry too short len=0x%x\n", entry_size);
			return -EINVAL;
		}

		switch(id) {
		case ESE_GZ_CFGBAR_ENTRY_EF100:
			if ((rev != ESE_GZ_CFGBAR_ENTRY_REV_EF100) ||
			    (entry_size < ESE_GZ_CFGBAR_ENTRY_SIZE_EF100)) {
				pci_err(efx->pci_dev,
					"Bad length or rev for EF100 entry in Xilinx capabilities table. entry_size=%d rev=%d.\n",
					entry_size, rev);
				return -EINVAL;
			}

			rc = ef100_pci_parse_ef100_entry(efx, current_entry,
							 result);
			if (rc)
				return rc;
			break;
		case ESE_GZ_CFGBAR_ENTRY_CONT_CAP_ADDR:
			if ((rev != 0) || (entry_size < ESE_GZ_CFGBAR_CONT_CAP_MIN_LENGTH)) {
				pci_err(efx->pci_dev,
					"Bad length or rev for continue entry in Xilinx capabilities table. entry_size=%d rev=%d.\n",
					entry_size, rev);
				return -EINVAL;
			}

			rc = ef100_pci_parse_continue_entry(efx, current_entry, result);
			if (rc)
				return rc;
			break;
		default:
			/* Ignore unknown table entries. */
			break;
		}

		if (last)
			return 0;

		current_entry += entry_size;

		if (ef100_pci_does_bar_overflow(efx, efx->mem_bar, current_entry)) {
			pci_err(efx->pci_dev,
				"Xilinx table overrun at position=0x%llx.\n",
				current_entry);
			return -EINVAL;
		}
	}
}

static int _ef100_pci_get_config_bits_with_width(struct efx_nic *efx,
						 int structure_start, int lbn,
						 int width, u32 *result)
{
	int pos = structure_start + ROUND_DOWN_TO_DWORD(lbn);
	u32 temp;

	int rc = pci_read_config_dword(efx->pci_dev, pos, &temp);
	if (rc) {
		pci_err(efx->pci_dev,
			"Failed to read PCI config dword at %d\n",
			pos);
		return rc;
	}

	*result = EXTRACT_BITS(temp, lbn, width);

	return 0;
}

#define ef100_pci_get_config_bits(efx, entry_location, bitdef, result) \
	_ef100_pci_get_config_bits_with_width(efx, entry_location,  \
		bitdef ## _LBN, bitdef ## _WIDTH, result)

/* Call ef100_pci_walk_xilinx_table() for the Xilinx capabilities table pointed
 * to by this PCI_EXT_CAP_ID_VNDR.
 */
static int ef100_pci_parse_xilinx_cap(struct efx_nic *efx, int vndr_cap,
				      bool has_offset_hi,
				      struct ef100_func_ctl_window *result)
{
	u32 offset_high = 0;
	u32 offset_lo = 0;
	u64 offset = 0;
	u32 bar = 0;
	int rc = 0;

	rc = ef100_pci_get_config_bits(efx, vndr_cap, ESF_GZ_VSEC_TBL_BAR, &bar);
	if (rc) {
		pci_err(efx->pci_dev,
			"Failed to read ESF_GZ_VSEC_TBL_BAR, rc=%d\n",
			rc);
		return rc;
	}

	if ((bar == ESE_GZ_CFGBAR_CONT_CAP_BAR_NUM_EXPANSION_ROM) ||
	    (bar == ESE_GZ_CFGBAR_CONT_CAP_BAR_NUM_INVALID)) {
		pci_err(efx->pci_dev,
			"Bad BAR value of %d in Xilinx capabilities sub-table.\n",
			bar);
		return -EINVAL;
	}

	rc = ef100_pci_get_config_bits(efx, vndr_cap, ESF_GZ_VSEC_TBL_OFF_LO, &offset_lo);
	if (rc) {
		pci_err(efx->pci_dev,
			"Failed to read ESF_GZ_VSEC_TBL_OFF_LO, rc=%d\n",
			rc);
		return rc;
	}

	/* Get optional extension to 64bit offset. */
	if (has_offset_hi) {
		rc = ef100_pci_get_config_bits(efx, vndr_cap, ESF_GZ_VSEC_TBL_OFF_HI, &offset_high);
		if (rc) {
			pci_err(efx->pci_dev,
				"Failed to read ESF_GZ_VSEC_TBL_OFF_HI, rc=%d\n",
				rc);
			return rc;
		}
	}

	offset = (((u64)offset_lo) << ESE_GZ_VSEC_TBL_OFF_LO_BYTES_SHIFT) |
		 (((u64)offset_high) << ESE_GZ_VSEC_TBL_OFF_HI_BYTES_SHIFT);

	if (offset > pci_resource_len(efx->pci_dev, bar) - sizeof(uint32_t)*2) {
		pci_err(efx->pci_dev,
			"Xilinx table will overrun BAR[%d] offset=0x%llx\n",
			bar, offset);
		return -EINVAL;
	}

	/* Temporarily map BAR. */
	rc = efx_init_io(efx, bar, efx->type->max_dma_mask,
			 pci_resource_len(efx->pci_dev, bar));
	if (rc) {
		pci_err(efx->pci_dev, "efx_init_io failed, rc=%d\n", rc);
		return rc;
	}

	rc = ef100_pci_walk_xilinx_table(efx, offset, result);

	/* Unmap temporarily mapped BAR. */
	efx_fini_io(efx);
	return rc;
}

/* Call ef100_pci_parse_ef100_entry() for each Xilinx PCI_EXT_CAP_ID_VNDR
 * capability.
 */
static int ef100_pci_find_func_ctrl_window(struct efx_nic *efx,
	struct ef100_func_ctl_window *result)
{
	int num_xilinx_caps = 0;
	int cap = 0;

	result->valid = false;

	while ((cap = pci_find_next_ext_capability(efx->pci_dev, cap,
				PCI_EXT_CAP_ID_VNDR)) != 0) {
		int vndr_cap = cap + PCI_EXT_CAP_HDR_LENGTH;
		u32 vsec_ver = 0;
		u32 vsec_len = 0;
		u32 vsec_id = 0;
		int rc = 0;

		num_xilinx_caps++;

		rc = ef100_pci_get_config_bits(efx, vndr_cap, ESF_GZ_VSEC_ID,
					       &vsec_id);
		if (rc) {
			pci_err(efx->pci_dev,
				"Failed to read ESF_GZ_VSEC_ID, rc=%d\n",
				rc);
			return rc;
		}

		rc = ef100_pci_get_config_bits(efx, vndr_cap, ESF_GZ_VSEC_VER,
					       &vsec_ver);
		if (rc) {
			pci_err(efx->pci_dev,
				"Failed to read ESF_GZ_VSEC_VER, rc=%d\n",
				rc);
			return rc;
		}

		/* Get length of whole capability - i.e. starting at cap */
		rc = ef100_pci_get_config_bits(efx, vndr_cap, ESF_GZ_VSEC_LEN,
					       &vsec_len);
		if (rc) {
			pci_err(efx->pci_dev,
				"Failed to read ESF_GZ_VSEC_LEN, rc=%d\n",
				rc);
			return rc;
		}

		if ((vsec_id == ESE_GZ_XILINX_VSEC_ID) &&
		    (vsec_ver == ESE_GZ_VSEC_VER_XIL_CFGBAR) &&
		    (vsec_len >= ESE_GZ_VSEC_LEN_MIN)) {
			bool has_offset_hi = (vsec_len >= ESE_GZ_VSEC_LEN_HIGH_OFFT);

			rc = ef100_pci_parse_xilinx_cap(efx, vndr_cap,
							has_offset_hi, result);
			if (rc)
				return rc;
		}
	}

	if (num_xilinx_caps && !result->valid) {
		pci_err(efx->pci_dev,
			"Seen %d Xilinx tables, but no EF100 entry.\n",
			num_xilinx_caps);
		return -EINVAL;
	}

	return 0;
}

/* Support for address regions */
static bool ef100_addr_in(dma_addr_t addr, dma_addr_t base, ssize_t size)
{
	return (addr >= base && addr < (base + size));
}

int ef100_regionmap_buffer(struct efx_nic *efx, dma_addr_t *addr)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct ef100_addr_region *region;
	int i;

	if (likely(nic_data->addr_mapping_type ==
		   MC_CMD_GET_DESC_ADDR_INFO_OUT_MAPPING_FLAT))
		return 0;

	for (i = 0; i < EF100_QDMA_ADDR_REGIONS_MAX; i++) {
		region = &nic_data->addr_region[i];
		if (!ef100_region_addr_is_populated(region))
			break;

		if (ef100_addr_in(*addr, region->trgt_addr,
				  1UL << region->size_log2)) {
			*addr |= region->qdma_addr;
			return 0;
		}
	}
	if (net_ratelimit())
		netif_err(efx, tx_err, efx->net_dev,
			  "Cannot map %pad to QDMA\n", addr);
	return -ENOMEM;
}

/* Final NIC shutdown
 * This is called only at module unload (or hotplug removal).  A PF can call
 * this on its VFs to ensure they are unbound first.
 */
static void ef100_pci_remove(struct pci_dev *pci_dev)
{
	struct efx_probe_data *probe_data;
	struct efx_nic *efx = pci_get_drvdata(pci_dev);

	if (!efx)
		return;

	probe_data = container_of(efx, struct efx_probe_data, efx);
	ef100_remove_netdev(probe_data);
	efx_auxbus_unregister(efx);
	efx_fini_struct_tc(efx);
	ef100_remove(efx);
	efx_fini_io(efx);
	pci_dbg(pci_dev, "shutdown successful\n");

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_AER)
	pci_disable_pcie_error_reporting(pci_dev);
#endif
	pci_set_drvdata(pci_dev, NULL);
	efx_fini_struct(efx);
	kfree(probe_data);
};

static int efx_check_func_ctl_magic(struct efx_nic *efx)
{
	efx_dword_t reg;

	efx_readd(efx, &reg, efx_reg(efx, ER_GZ_NIC_MAGIC));
	if (EFX_DWORD_FIELD(reg, EFX_DWORD_0) != EFE_GZ_NIC_MAGIC_EXPECTED)
		return -EIO;

	return 0;
}

static int ef100_pci_probe(struct pci_dev *pci_dev,
			   const struct pci_device_id *entry)
{
	struct ef100_func_ctl_window fcw = { 0 };
	struct efx_probe_data *probe_data;
	struct efx_nic *efx;
	int rc;

	/* Allocate probe data and struct efx_nic */
	probe_data = kzalloc(sizeof(*probe_data), GFP_KERNEL);
	if (!probe_data)
		return -ENOMEM;
	probe_data->pci_dev = pci_dev;
	efx = &probe_data->efx;

	efx->type = (const struct efx_nic_type *)entry->driver_data;
	efx->pci_dev = pci_dev;
	pci_set_drvdata(pci_dev, efx);
	rc = efx_init_struct(efx, pci_dev);
	if (rc)
		goto fail;

	efx->vi_stride = EF100_DEFAULT_VI_STRIDE;
	pci_info(pci_dev, "Solarflare EF100 NIC detected\n");

	rc = ef100_pci_find_func_ctrl_window(efx, &fcw);
	if (rc) {
		pci_err(pci_dev,
			"Error looking for ef100 function control window, rc=%d\n",
			rc);
		goto fail;
	}

	if (!fcw.valid) {
		/* Extended capability not found - use defaults. */
		fcw.bar = EFX_EF100_PCI_DEFAULT_BAR;
		fcw.offset = 0;
		fcw.valid = true;
	}

	if (fcw.offset > pci_resource_len(efx->pci_dev, fcw.bar) - ESE_GZ_FCW_LEN) {
		pci_err(pci_dev, "Func control window overruns BAR\n");
		rc = -EIO;
		goto fail;
	}

	/* Set up basic I/O (BAR mappings etc) */
	rc = efx_init_io(efx, fcw.bar, efx->type->max_dma_mask,
			 pci_resource_len(efx->pci_dev, fcw.bar));
	if (rc)
		goto fail;

	efx->reg_base = fcw.offset;

	rc = efx_check_func_ctl_magic(efx);
	if (rc) {
		pci_err(pci_dev, "Func control window magic is wrong\n");
		goto fail;
	}

	rc = efx->type->probe(efx);
	if (rc)
		goto fail;

	rc = ef100_bsp_init(efx);
	if (rc)
		goto fail;
	rc = efx_auxbus_register(efx);
	if (rc)
		pci_warn(pci_dev,
			 "Unable to register auxiliary bus driver (%d)\n", rc);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_AER)
	(void)pci_enable_pcie_error_reporting(pci_dev);
#endif
	efx->state = STATE_PROBED;
	rc = ef100_probe_netdev(probe_data);
	if (rc)
		goto fail;

	pci_dbg(pci_dev, "initialisation successful\n");
	return 0;

fail:
	ef100_pci_remove(pci_dev);
	return rc;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SRIOV_CONFIGURE) || (defined(CONFIG_SFC_SRIOV) && defined(EFX_HAVE_PCI_DRIVER_RH))
static int ef100_pci_sriov_configure(struct pci_dev *dev, int num_vfs)
{
	struct efx_nic *efx = pci_get_drvdata(dev);
	int rc;

	if (efx->type->sriov_configure) {
		rc = efx->type->sriov_configure(efx, num_vfs);
		if (rc)
			return rc;
		else
			return num_vfs;
	}
	else
		return -ENOSYS;
}
#endif

/* PCI device ID table.
 * On changes make sure to update sfc_pci_table in efx.c
 */
static const struct pci_device_id ef100_pci_table[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_XILINX, 0x0100),  /* Riverhead PF */
		.driver_data = (unsigned long) &ef100_pf_nic_type },
	{PCI_DEVICE(PCI_VENDOR_ID_XILINX, 0x1100),  /* Riverhead VF */
		.class = PCI_CLASS_NETWORK_ETHERNET << 8,
		.class_mask =  0xffff00,
		.driver_data = (unsigned long) &ef100_vf_nic_type },
	{0}                     /* end of list */
};

#if defined(CONFIG_SFC_SRIOV) && defined(EFX_HAVE_PCI_DRIVER_RH) && !defined(EFX_HAVE_SRIOV_CONFIGURE)
static struct pci_driver_rh ef100_pci_driver_rh = {
	.sriov_configure = ef100_pci_sriov_configure,
};
#endif

struct pci_driver ef100_pci_driver = {
	.name           = "sfc_ef100",
	.id_table       = ef100_pci_table,
	.probe          = ef100_pci_probe,
	.remove         = ef100_pci_remove,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_AER)
	.err_handler    = &efx_err_handlers,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SRIOV_CONFIGURE)
	.sriov_configure = ef100_pci_sriov_configure,
#elif defined(EFX_HAVE_PCI_DRIVER_RH)
	.rh_reserved    = &ef100_pci_driver_rh,
#endif
};
