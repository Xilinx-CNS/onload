/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2015 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "net_driver.h"
#include "dump.h"
#include "mcdi.h"
#include "mcdi_pcol.h"
#include "nic.h"
#include "efx_ioctl.h"

#define DUMPSPEC_FP_DEFAULT  NULL
#define DUMPSPEC_MAX_SIZE    (64 * 1024)
#define DUMPFILE_MAX_SIZE    (5 * 1024 * 1024)
#define DUMPFILE_MAX_PAGES   DUMPFILE_MAX_SIZE/MLI_PAGE_SIZE

#define DH_NIDENT     16
#define DH_IDENT_INIT "\x7fSFDUMP\x0\x0\x0\x0\x0\x0\x0\x0\x0"
#define DH_CLEAR_INIT "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"

#define MLI_PAGE_SIZE   4096
#define PAGE_N_ENTRIES  (MLI_PAGE_SIZE / sizeof(uint64_t))
#define IPAGES(npages_) DIV_ROUND_UP(npages_, PAGE_N_ENTRIES)

/**
 * struct dump_header - Header for the dump buffer
 * @ident: Dump header identifier
 * @type: Dump header type (e.g. file or spec)
 * @version: Dump header version
 * @arch: Dump header architecture (e.g. EF10)
 * @dh_size: Dump header size, in bytes
 * @sh_offset: Section header offset
 * @sh_entsize: Section header size, in bytes
 * @sh_count:  Number of section headers
 * @dumpfile_size: Dump buffer size, in bytes
 */
struct dump_header {
	unsigned char ident[DH_NIDENT];
	uint32_t type;
	uint32_t version; /* increase means incompatible changes */
	uint32_t arch;
	uint32_t dh_size;
	uint32_t sh_offset;
	uint32_t sh_entsize; /* sizeof (struct section_header) */
	uint32_t sh_count;
	uint32_t dumpfile_size;
};

/**
 * struct dump_location - Location of dumpfile or dumpspec
 * @location: Dump location (e.g. default or custom)
 * @buffer: Dump buffer address
 * @root_dma_handle: Dump buffer MLI root handle physical address
 * @mli_depth: Dump buffer MLI depth
 * @size: Dump buffer size, in bytes
 */
struct dump_location {
	unsigned int location;
	void *buffer;
	uint64_t root_dma_handle;
	int mli_depth;
	size_t size;
};

/**
 * struct efx_dump_data - Context for dump data
 * @dumpspec: Dumpspec location
 * @dumpfile: Dumpfile location
 * @addr: Dumpfile buffer address
 * @dma_addr: Dumpfile buffer physical address
 * @enabled: Flag for dump enable
 */
struct efx_dump_data {
	struct dump_location dumpspec;
	struct dump_location dumpfile;
	void **addr;
	dma_addr_t *dma_addr;
	size_t total_pages;
	bool enabled;
};

static int efx_dump_get_boot_status(struct efx_nic *efx,
				    unsigned long *boot_offset,
				    unsigned long *flags)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_BOOT_STATUS_OUT_LEN);
	size_t outlen;
	int rc;

	rc = efx_mcdi_rpc(efx, MC_CMD_GET_BOOT_STATUS, NULL, 0,
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;

	if (boot_offset)
		*boot_offset = MCDI_DWORD(outbuf,
					  GET_BOOT_STATUS_OUT_BOOT_OFFSET);
	if (flags)
		*flags = MCDI_DWORD(outbuf, GET_BOOT_STATUS_OUT_FLAGS);

	return 0;
}

static int efx_dump_do(struct efx_nic *efx,
		       const struct dump_location *dumpspec,
		       const struct dump_location *dumpfile,
		       size_t *dumpfile_size)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_DUMP_DO_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_DUMP_DO_OUT_LEN);
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, DUMP_DO_IN_DUMPSPEC_SRC, dumpspec->location);
	if (dumpspec->location == MC_CMD_DUMP_DO_IN_DUMPSPEC_SRC_CUSTOM) {
		MCDI_SET_DWORD(inbuf,
		    DUMP_DO_IN_DUMPSPEC_SRC_CUSTOM_TYPE,
		    MC_CMD_DUMP_DO_IN_DUMP_LOCATION_HOST_MEMORY_MLI);
		MCDI_SET_DWORD(inbuf,
		    DUMP_DO_IN_DUMPSPEC_SRC_CUSTOM_SIZE,
		    dumpspec->size);
		MCDI_SET_DWORD(inbuf,
		    DUMP_DO_IN_DUMPSPEC_SRC_CUSTOM_HOST_MEMORY_MLI_ROOT_ADDR_LO,
		    (dumpspec->root_dma_handle >> 0) & 0xffffffff);
		MCDI_SET_DWORD(inbuf,
		    DUMP_DO_IN_DUMPSPEC_SRC_CUSTOM_HOST_MEMORY_MLI_ROOT_ADDR_HI,
		    (dumpspec->root_dma_handle >> 32) & 0xffffffff);
		MCDI_SET_DWORD(inbuf,
		    DUMP_DO_IN_DUMPSPEC_SRC_CUSTOM_HOST_MEMORY_MLI_DEPTH,
		    dumpspec->mli_depth);
	}
	MCDI_SET_DWORD(inbuf, DUMP_DO_IN_DUMPFILE_DST, dumpfile->location);
	if (dumpfile->location == MC_CMD_DUMP_DO_IN_DUMPFILE_DST_CUSTOM) {
		MCDI_SET_DWORD(inbuf,
		    DUMP_DO_IN_DUMPFILE_DST_CUSTOM_TYPE,
		    MC_CMD_DUMP_DO_IN_DUMP_LOCATION_HOST_MEMORY_MLI);
		MCDI_SET_DWORD(inbuf,
		    DUMP_DO_IN_DUMPFILE_DST_CUSTOM_SIZE,
		    dumpfile->size);
		MCDI_SET_DWORD(inbuf,
		    DUMP_DO_IN_DUMPFILE_DST_CUSTOM_HOST_MEMORY_MLI_ROOT_ADDR_LO,
		    (dumpfile->root_dma_handle >> 0) & 0xffffffff);
		MCDI_SET_DWORD(inbuf,
		    DUMP_DO_IN_DUMPFILE_DST_CUSTOM_HOST_MEMORY_MLI_ROOT_ADDR_HI,
		    (dumpfile->root_dma_handle >> 32) & 0xffffffff);
		MCDI_SET_DWORD(inbuf,
		    DUMP_DO_IN_DUMPFILE_DST_CUSTOM_HOST_MEMORY_MLI_DEPTH,
		    dumpfile->mli_depth);
	}
	rc = efx_mcdi_rpc(efx, MC_CMD_DUMP_DO, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;

	*dumpfile_size = MCDI_DWORD(outbuf, DUMP_DO_OUT_DUMPFILE_SIZE);

	return 0;
}

static int efx_dump_config_unsolicited(struct efx_nic *efx,
				const struct dump_location *dumpspec,
				const struct dump_location *dumpfile,
				bool enabled)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_DUMP_CONFIGURE_UNSOLICITED_IN_LEN);

	MCDI_SET_DWORD(inbuf, DUMP_CONFIGURE_UNSOLICITED_IN_ENABLE, enabled);
	MCDI_SET_DWORD(inbuf, DUMP_CONFIGURE_UNSOLICITED_IN_DUMPSPEC_SRC,
		       dumpspec->location);
	if (dumpspec->location == MC_CMD_DUMP_DO_IN_DUMPSPEC_SRC_CUSTOM) {
		MCDI_SET_DWORD(inbuf,
		    DUMP_CONFIGURE_UNSOLICITED_IN_DUMPSPEC_SRC_CUSTOM_TYPE,
		    MC_CMD_DUMP_DO_IN_DUMP_LOCATION_HOST_MEMORY_MLI);
		MCDI_SET_DWORD(inbuf,
		    DUMP_CONFIGURE_UNSOLICITED_IN_DUMPSPEC_SRC_CUSTOM_SIZE,
		    dumpspec->size);
		MCDI_SET_DWORD(inbuf,
		    DUMP_CONFIGURE_UNSOLICITED_IN_DUMPSPEC_SRC_CUSTOM_HOST_MEMORY_MLI_ROOT_ADDR_LO,
		    (dumpspec->root_dma_handle >> 0) & 0xffffffff);
		MCDI_SET_DWORD(inbuf,
		    DUMP_CONFIGURE_UNSOLICITED_IN_DUMPSPEC_SRC_CUSTOM_HOST_MEMORY_MLI_ROOT_ADDR_HI,
		    (dumpspec->root_dma_handle >> 32) & 0xffffffff);
		MCDI_SET_DWORD(inbuf,
		    DUMP_CONFIGURE_UNSOLICITED_IN_DUMPSPEC_SRC_CUSTOM_HOST_MEMORY_MLI_DEPTH,
		    dumpspec->mli_depth);
	}
	MCDI_SET_DWORD(inbuf, DUMP_CONFIGURE_UNSOLICITED_IN_DUMPFILE_DST,
		       dumpfile->location);
	if (dumpfile->location == MC_CMD_DUMP_DO_IN_DUMPFILE_DST_CUSTOM) {
		MCDI_SET_DWORD(inbuf,
		    DUMP_CONFIGURE_UNSOLICITED_IN_DUMPFILE_DST_CUSTOM_TYPE,
		    MC_CMD_DUMP_DO_IN_DUMP_LOCATION_HOST_MEMORY_MLI);
		MCDI_SET_DWORD(inbuf,
		    DUMP_CONFIGURE_UNSOLICITED_IN_DUMPFILE_DST_CUSTOM_SIZE,
		    dumpfile->size);
		MCDI_SET_DWORD(inbuf,
		    DUMP_CONFIGURE_UNSOLICITED_IN_DUMPFILE_DST_CUSTOM_HOST_MEMORY_MLI_ROOT_ADDR_LO,
		    (dumpfile->root_dma_handle >> 0) & 0xffffffff);
		MCDI_SET_DWORD(inbuf,
		    DUMP_CONFIGURE_UNSOLICITED_IN_DUMPFILE_DST_CUSTOM_HOST_MEMORY_MLI_ROOT_ADDR_HI,
		    (dumpfile->root_dma_handle >> 32) & 0xffffffff);
		MCDI_SET_DWORD(inbuf,
		    DUMP_CONFIGURE_UNSOLICITED_IN_DUMPFILE_DST_CUSTOM_HOST_MEMORY_MLI_DEPTH,
		    dumpfile->mli_depth);
	}
	return efx_mcdi_rpc(efx, MC_CMD_DUMP_CONFIGURE_UNSOLICITED, inbuf,
			    sizeof(inbuf), NULL, 0, NULL);
	return 0;
}

static void efx_dump_free_buffer(struct efx_nic *efx)
{
	struct efx_dump_data *dump_data = efx->dump_data;
	size_t pgn;

	/* Free all MLI pages */
	if (dump_data->addr && dump_data->dma_addr) {
		for (pgn = 0; pgn < dump_data->total_pages; pgn++) {
			if (dump_data->addr[pgn])
				dma_free_coherent(&efx->pci_dev->dev,
						  MLI_PAGE_SIZE,
						  dump_data->addr[pgn],
						  dump_data->dma_addr[pgn]);
		}
	}
	if (dump_data->addr) {
		kfree(dump_data->addr);
		dump_data->addr = NULL;
	}
	if (dump_data->dma_addr) {
		kfree(dump_data->dma_addr);
		dump_data->dma_addr = NULL;
	}
	dump_data->dumpfile.location = 0;
	dump_data->dumpfile.buffer = NULL;
	dump_data->dumpfile.root_dma_handle = 0;
	dump_data->dumpfile.mli_depth = 0;
	dump_data->dumpfile.size = 0;
	dump_data->total_pages = 0;
}

static int efx_dump_alloc_buffer(struct efx_nic *efx)
{
	struct efx_dump_data *dump_data = efx->dump_data;
	size_t level_pages;
	size_t pgn;
	int mli_depth;

	/* Check if dump buffer already allocated */
	if (dump_data->dumpfile.buffer)
		return 0;

	/* Calculate total number of pages needed and MLI depth */
	mli_depth = 0;
	pgn = 0;
	for (level_pages = DUMPFILE_MAX_PAGES; level_pages > 1;
	     level_pages = IPAGES(level_pages)) {
		mli_depth++;
		pgn += level_pages;
	}

	dump_data->total_pages = pgn + 1;
	netif_dbg(efx, drv, efx->net_dev, "total_pages=%zd, mli_depth=%d\n",
		  dump_data->total_pages, mli_depth);

	/* Allocate all MLI pages */
	dump_data->addr = kmalloc(dump_data->total_pages *
				  sizeof(void *), GFP_KERNEL);
	if (!dump_data->addr) {
		return -ENOMEM;
	}
	memset(dump_data->addr, 0, dump_data->total_pages*sizeof(void *));
	dump_data->dma_addr = kmalloc(dump_data->total_pages *
				      sizeof(dma_addr_t), GFP_KERNEL);
	if (!dump_data->dma_addr) {
		efx_dump_free_buffer(efx);
		return -ENOMEM;
	}
	memset(dump_data->dma_addr, 0, dump_data->total_pages*sizeof(dma_addr_t));
	for (pgn = 0; pgn < dump_data->total_pages; pgn++) {
		dump_data->addr[pgn] =
			dma_alloc_coherent(&efx->pci_dev->dev, MLI_PAGE_SIZE,
					   &dump_data->dma_addr[pgn],
					   GFP_KERNEL);
		if (!dump_data->addr[pgn]) {
			efx_dump_free_buffer(efx);
			return -ENOMEM;
		}
		memset(dump_data->addr[pgn], 0, MLI_PAGE_SIZE);
	}

	/* Populate multi-level indirection (MLI) pages */
	pgn = 0;
	for (level_pages = DUMPFILE_MAX_PAGES; level_pages > 1;
	     level_pages = IPAGES(level_pages)) {
		__le64 *entries;
		size_t s;

		for (s = 0; s < level_pages; s++) {
			entries = dump_data->
				addr[pgn+level_pages+s/PAGE_N_ENTRIES];
			entries[s%PAGE_N_ENTRIES] = cpu_to_le64(dump_data->
				dma_addr[pgn+s]);
		}
		pgn += level_pages;
	}
	dump_data->dumpfile.location = MC_CMD_DUMP_DO_IN_DUMPFILE_DST_CUSTOM;
	dump_data->dumpfile.buffer = dump_data->addr[0];
	dump_data->dumpfile.root_dma_handle = dump_data->dma_addr[pgn];
	dump_data->dumpfile.mli_depth = mli_depth;
	dump_data->dumpfile.size = DUMPFILE_MAX_SIZE;

	/* Clear dump identifier to prepare for next dump */
	memcpy(dump_data->dumpfile.buffer, DH_CLEAR_INIT, DH_NIDENT);

	return 0;
}

int efx_dump_init(struct efx_nic *efx)
{
	struct efx_dump_data *dump_data;

	dump_data = kzalloc(sizeof(*dump_data), GFP_KERNEL);
	if (!dump_data)
		return -ENOMEM;
	efx->dump_data = dump_data;

	return 0;
}

void efx_dump_fini(struct efx_nic *efx)
{
	struct efx_dump_data *dump_data = efx->dump_data;

	efx_dump_free_buffer(efx);
	kfree(dump_data);
	efx->dump_data = NULL;
}

int efx_dump_reset(struct efx_nic *efx)
{
	struct efx_dump_data *dump_data = efx->dump_data;
	struct ethtool_dump val;
	int rc;

	if (!dump_data)
		return 0;

	if (dump_data->enabled) {
		dump_data->enabled = false;
		val.flag = EFX_DUMP_ENABLE;
		rc = efx_dump_set(efx, &val);
		if (rc)
			return rc;
	}

	return 0;
}

int efx_dump_get_flag(struct efx_nic *efx, struct ethtool_dump *dump)
{
	struct efx_dump_data *dump_data = efx->dump_data;
	struct dump_header *dump_header = dump_data->dumpfile.buffer;
	size_t dumpfile_size;

	/* Get dump size */
	dumpfile_size = 0;
	if (dump_header) {
		if (memcmp(dump_header, DH_IDENT_INIT, DH_NIDENT) == 0)
			dumpfile_size = dump_header->dumpfile_size;
		else if (memcmp(dump_header, DH_CLEAR_INIT, DH_NIDENT) != 0)
			netif_warn(efx, drv, efx->net_dev,
				   "Invalid dump header detected\n");
	}

	dump->version = 0;
	dump->flag = dump_data->enabled;
	dump->len = dumpfile_size;

	return 0;
}

int efx_dump_get_data(struct efx_nic *efx, struct ethtool_dump *dump,
		      void *buffer)
{
	struct efx_dump_data *dump_data = efx->dump_data;
	struct dump_header *dump_header = dump_data->dumpfile.buffer;
	size_t dumpfile_size;
	uint8_t *ptr;
	size_t pgn;

	/* Get dump size */
	dumpfile_size = 0;
	if (dump_header) {
		if (memcmp(dump_header, DH_IDENT_INIT, DH_NIDENT) == 0)
			dumpfile_size = dump_header->dumpfile_size;
		else if (memcmp(dump_header, DH_CLEAR_INIT, DH_NIDENT) != 0)
			netif_warn(efx, drv, efx->net_dev,
				   "Invalid dump header detected\n");
	} else {
		netif_warn(efx, drv, efx->net_dev, "Dumping  not enabled\n");
		return -EINVAL;
	}

	/* Copy dump data and clear identifier to prepare for next dump */
	ptr = buffer;
	for (pgn = 0;
	     (ptr - (uint8_t *)buffer) < dumpfile_size;
	     pgn++, ptr += MLI_PAGE_SIZE)
		memcpy(ptr, dump_data->addr[pgn], MLI_PAGE_SIZE);

	memcpy(dump_data->dumpfile.buffer, DH_CLEAR_INIT, DH_NIDENT);

	return 0;
}

int efx_dump_set(struct efx_nic *efx, struct ethtool_dump *val)
{
	struct efx_dump_data *dump_data = efx->dump_data;
	unsigned long boot_offset = 0;
	size_t dumpfile_size;
	int rc;

	if ((val->flag != EFX_DUMP_DISABLE) &&
	    (val->flag != EFX_DUMP_ENABLE)  &&
	    (val->flag != EFX_DUMP_FORCE)) {
		return -EINVAL;
	}

	if ((val->flag == EFX_DUMP_ENABLE) ||
	    (val->flag == EFX_DUMP_FORCE)) {
		rc = efx_dump_alloc_buffer(efx);
		if (rc)
			return rc;
	}

	/* Initialize dumpspec */
	efx_dump_get_boot_status(efx, &boot_offset, NULL);
	if (boot_offset == MC_CMD_GET_BOOT_STATUS_OUT_BOOT_OFFSET_NULL) {
		netif_err(efx, drv, efx->net_dev,
			  "MC wasn't booted; the default dumpspec "
			  "is unlikely to exist.\n");
		return -EIO;
	}
	dump_data->dumpspec.location = MC_CMD_DUMP_DO_IN_DUMPSPEC_SRC_DEFAULT;

	/* Send MC dump command */
	if ((val->flag == EFX_DUMP_DISABLE) ||
	    (val->flag == EFX_DUMP_ENABLE)) {
		if (dump_data->enabled !=
		    (val->flag == EFX_DUMP_ENABLE ?  true : false)) {
			rc = efx_dump_config_unsolicited(
					efx, &dump_data->dumpspec,
					&dump_data->dumpfile,
					val->flag == EFX_DUMP_ENABLE ?
					true : false);
			if (rc)
				return rc;

			dump_data->enabled = val->flag == EFX_DUMP_ENABLE ?
					     true : false;
		}

	} else if (val->flag == EFX_DUMP_FORCE) {
		rc = efx_dump_do(efx, &dump_data->dumpspec,
				 &dump_data->dumpfile, &dumpfile_size);
		if (rc)
			return rc;
	}

	if (val->flag == EFX_DUMP_DISABLE) {
		efx_dump_free_buffer(efx);
	}

	return 0;
}

