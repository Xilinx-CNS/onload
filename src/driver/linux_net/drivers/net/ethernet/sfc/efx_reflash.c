// SPDX-License-Identifier: GPL-2.0
/* Driver for Xilinx network controllers and boards
 * Copyright 2021 Xilinx Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/crc32.h>

#include "net_driver.h"
#include "efx.h"
#include "nic.h"
#include "efx_reflash.h"
#include "efx_devlink.h"

/* Reflash firmware data header and trailer fields (see SF-121352-AN) */
#define EFX_REFLASH_HEADER_MAGIC_OFST 0
#define EFX_REFLASH_HEADER_MAGIC_LEN 4
#define EFX_REFLASH_HEADER_MAGIC_VALUE 0x106F1A5

#define EFX_REFLASH_HEADER_VERSION_OFST 4
#define EFX_REFLASH_HEADER_VERSION_LEN 4
#define EFX_REFLASH_HEADER_VERSION_VALUE 4

#define EFX_REFLASH_HEADER_FIRMWARE_TYPE_OFST 8
#define EFX_REFLASH_HEADER_FIRMWARE_TYPE_LEN 4
#define EFX_REFLASH_FIRMWARE_TYPE_BOOTROM 0x2
#define EFX_REFLASH_FIRMWARE_TYPE_BUNDLE 0xd

#define EFX_REFLASH_HEADER_FIRMWARE_SUBTYPE_OFST 12
#define EFX_REFLASH_HEADER_FIRMWARE_SUBTYPE_LEN 4

#define EFX_REFLASH_HEADER_PAYLOAD_SIZE_OFST 16
#define EFX_REFLASH_HEADER_PAYLOAD_SIZE_LEN 4

#define EFX_REFLASH_HEADER_LENGTH_OFST 20
#define EFX_REFLASH_HEADER_LENGTH_LEN 4

#define EFX_REFLASH_HEADER_MINLEN	\
	(EFX_REFLASH_HEADER_LENGTH_OFST + EFX_REFLASH_HEADER_LENGTH_LEN)

#define EFX_REFLASH_TRAILER_CRC_OFST 0
#define EFX_REFLASH_TRAILER_CRC_LEN 4

#define EFX_REFLASH_TRAILER_LEN	\
	(EFX_REFLASH_TRAILER_CRC_OFST + EFX_REFLASH_TRAILER_CRC_LEN)

static bool efx_reflash_parse_reflash_header(const struct firmware *fw,
					     size_t header_offset, u32 *type,
					     u32 *subtype, const u8 **data,
					     size_t *data_size)
{
	u32 magic, version, payload_size, header_len, trailer_offset;
	const u8 *header, *trailer;
	u32 expected_crc, crc;

	if (fw->size < header_offset + EFX_REFLASH_HEADER_MINLEN)
		return false;

	header = fw->data + header_offset;
	magic = get_unaligned_le32(header + EFX_REFLASH_HEADER_MAGIC_OFST);
	if (magic != EFX_REFLASH_HEADER_MAGIC_VALUE)
		return false;

	version = get_unaligned_le32(header + EFX_REFLASH_HEADER_VERSION_OFST);
	if (version != EFX_REFLASH_HEADER_VERSION_VALUE)
		return false;

	payload_size = get_unaligned_le32(header + EFX_REFLASH_HEADER_PAYLOAD_SIZE_OFST);
	header_len = get_unaligned_le32(header + EFX_REFLASH_HEADER_LENGTH_OFST);
	trailer_offset = header_offset + header_len + payload_size;
	if (fw->size < trailer_offset + EFX_REFLASH_TRAILER_LEN)
		return false;

	trailer = fw->data + trailer_offset;
	expected_crc = get_unaligned_le32(trailer + EFX_REFLASH_TRAILER_CRC_OFST);
	crc = crc32_le(0, header, header_len + payload_size);
	if (crc != expected_crc)
		return false;

	*type = get_unaligned_le32(header + EFX_REFLASH_HEADER_FIRMWARE_TYPE_OFST);
	*subtype = get_unaligned_le32(header + EFX_REFLASH_HEADER_FIRMWARE_SUBTYPE_OFST);
	if (*type == EFX_REFLASH_FIRMWARE_TYPE_BUNDLE) {
		/* All the bundle data is written verbatim to NVRAM */
		*data = fw->data;
		*data_size = fw->size;
	} else {
		/* Other payload types strip the reflash header and trailer
		 * from the data written to NVRAM
		 */
		*data = header + header_len;
		*data_size = payload_size;
	}

	return true;
}

static int efx_reflash_partition_type(u32 type, u32 subtype,
				      u32 *partition_type,
				      u32 *partition_subtype)
{
	int rc = 0;

	/* Map from FIRMWARE_TYPE to NVRAM_PARTITION_TYPE */
	switch (type) {
	case EFX_REFLASH_FIRMWARE_TYPE_BOOTROM:
		*partition_type = NVRAM_PARTITION_TYPE_EXPANSION_ROM;
		*partition_subtype = subtype;
		break;
	case EFX_REFLASH_FIRMWARE_TYPE_BUNDLE:
		*partition_type = NVRAM_PARTITION_TYPE_BUNDLE;
		*partition_subtype = subtype;
		break;
	default:
		/* Not supported */
		rc = -EINVAL;
	}

	return rc;
}

/* SmartNIC image header fields */
#define EFX_SNICIMAGE_HEADER_MAGIC_OFST 16
#define EFX_SNICIMAGE_HEADER_MAGIC_LEN 4
#define EFX_SNICIMAGE_HEADER_MAGIC_VALUE 0x541C057A

#define EFX_SNICIMAGE_HEADER_VERSION_OFST 20
#define EFX_SNICIMAGE_HEADER_VERSION_LEN 4
#define EFX_SNICIMAGE_HEADER_VERSION_VALUE 1

#define EFX_SNICIMAGE_HEADER_LENGTH_OFST 24
#define EFX_SNICIMAGE_HEADER_LENGTH_LEN 4

#define EFX_SNICIMAGE_HEADER_PARTITION_TYPE_OFST 36
#define EFX_SNICIMAGE_HEADER_PARTITION_TYPE_LEN 4

#define EFX_SNICIMAGE_HEADER_PARTITION_SUBTYPE_OFST 40
#define EFX_SNICIMAGE_HEADER_PARTITION_SUBTYPE_LEN 4

#define EFX_SNICIMAGE_HEADER_PAYLOAD_SIZE_OFST 60
#define EFX_SNICIMAGE_HEADER_PAYLOAD_SIZE_LEN 4

#define EFX_SNICIMAGE_HEADER_CRC_OFST 64
#define EFX_SNICIMAGE_HEADER_CRC_LEN 4

#define EFX_SNICIMAGE_HEADER_MINLEN 256

static bool efx_reflash_parse_snic_header(const struct firmware *fw,
					  size_t header_offset,
					  u32 *partition_type,
					  u32 *partition_subtype,
					  const u8 **data, size_t *data_size)
{
	u32 magic, version, payload_size, header_len, expected_crc, crc;
	const u8 *header;

	if (fw->size < header_offset + EFX_SNICIMAGE_HEADER_MINLEN)
		return false;

	header = fw->data + header_offset;
	magic = get_unaligned_le32(header + EFX_SNICIMAGE_HEADER_MAGIC_OFST);
	if (magic != EFX_SNICIMAGE_HEADER_MAGIC_VALUE)
		return false;

	version = get_unaligned_le32(header + EFX_SNICIMAGE_HEADER_VERSION_OFST);
	if (version != EFX_SNICIMAGE_HEADER_VERSION_VALUE)
		return false;

	header_len = get_unaligned_le32(header + EFX_SNICIMAGE_HEADER_LENGTH_OFST);
	payload_size = get_unaligned_le32(header + EFX_SNICIMAGE_HEADER_PAYLOAD_SIZE_OFST);
	if (fw->size < header_len + payload_size)
		return false;

	expected_crc = get_unaligned_le32(header + EFX_SNICIMAGE_HEADER_CRC_OFST);

	/* Calculate CRC omitting the expected CRC field itself */
	crc = crc32_le(~0, header, EFX_SNICIMAGE_HEADER_CRC_OFST);
	crc = ~crc32_le(crc,
			header + EFX_SNICIMAGE_HEADER_CRC_OFST +
			EFX_SNICIMAGE_HEADER_CRC_LEN,
			header_len + payload_size - EFX_SNICIMAGE_HEADER_CRC_OFST -
			EFX_SNICIMAGE_HEADER_CRC_LEN);
	if (crc != expected_crc)
		return false;

	*partition_type =
		get_unaligned_le32(header + EFX_SNICIMAGE_HEADER_PARTITION_TYPE_OFST);
	*partition_subtype =
		get_unaligned_le32(header + EFX_SNICIMAGE_HEADER_PARTITION_SUBTYPE_OFST);
	*data = fw->data;
	*data_size = fw->size;
	return true;
}

/* SmartNIC bundle header fields (see SF-122606-TC) */
#define EFX_SNICBUNDLE_HEADER_MAGIC_OFST 0
#define EFX_SNICBUNDLE_HEADER_MAGIC_LEN 4
#define EFX_SNICBUNDLE_HEADER_MAGIC_VALUE 0xB1001001

#define EFX_SNICBUNDLE_HEADER_VERSION_OFST 4
#define EFX_SNICBUNDLE_HEADER_VERSION_LEN 4
#define EFX_SNICBUNDLE_HEADER_VERSION_VALUE 1

#define EFX_SNICBUNDLE_HEADER_BUNDLE_TYPE_OFST 8
#define EFX_SNICBUNDLE_HEADER_BUNDLE_TYPE_LEN 4

#define EFX_SNICBUNDLE_HEADER_BUNDLE_SUBTYPE_OFST 12
#define EFX_SNICBUNDLE_HEADER_BUNDLE_SUBTYPE_LEN 4

#define EFX_SNICBUNDLE_HEADER_LENGTH_OFST 20
#define EFX_SNICBUNDLE_HEADER_LENGTH_LEN 4

#define EFX_SNICBUNDLE_HEADER_CRC_OFST 224
#define EFX_SNICBUNDLE_HEADER_CRC_LEN 4

#define EFX_SNICBUNDLE_HEADER_LEN	\
	(EFX_SNICBUNDLE_HEADER_CRC_OFST + EFX_SNICBUNDLE_HEADER_CRC_LEN)

static bool efx_reflash_parse_snic_bundle_header(const struct firmware *fw,
						 size_t header_offset,
						 u32 *partition_type,
						 u32 *partition_subtype,
						 const u8 **data,
						 size_t *data_size)
{
	u32 magic, version, bundle_type, header_len, expected_crc, crc;
	const u8 *header;

	if (fw->size < header_offset + EFX_SNICBUNDLE_HEADER_LEN)
		return false;

	header = fw->data + header_offset;
	magic = get_unaligned_le32(header + EFX_SNICBUNDLE_HEADER_MAGIC_OFST);
	if (magic != EFX_SNICBUNDLE_HEADER_MAGIC_VALUE)
		return false;

	version = get_unaligned_le32(header + EFX_SNICBUNDLE_HEADER_VERSION_OFST);
	if (version != EFX_SNICBUNDLE_HEADER_VERSION_VALUE)
		return false;

	bundle_type = get_unaligned_le32(header + EFX_SNICBUNDLE_HEADER_BUNDLE_TYPE_OFST);
	if (bundle_type != NVRAM_PARTITION_TYPE_BUNDLE)
		return false;

	header_len = get_unaligned_le32(header + EFX_SNICBUNDLE_HEADER_LENGTH_OFST);
	if (header_len != EFX_SNICBUNDLE_HEADER_LEN)
		return false;

	expected_crc = get_unaligned_le32(header + EFX_SNICBUNDLE_HEADER_CRC_OFST);
	crc = ~crc32_le(~0, header, EFX_SNICBUNDLE_HEADER_CRC_OFST);
	if (crc != expected_crc)
		return false;

	*partition_type = NVRAM_PARTITION_TYPE_BUNDLE;
	*partition_subtype = get_unaligned_le32(header + EFX_SNICBUNDLE_HEADER_BUNDLE_SUBTYPE_OFST);
	*data = fw->data;
	*data_size = fw->size;
	return true;
}

static int efx_reflash_parse_firmware_data(const struct firmware *fw,
					   u32 *partition_type,
					   u32 *partition_subtype,
					   const u8 **data, size_t *data_size)
{
	size_t header_offset;
	u32 type, subtype;

	/* Try to find a valid firmware payload in the firmware data.  Some
	 * packaging formats (such as CMS/PKCS#7 signed images) prepend a
	 * header for which finding the size is a non-trivial task.
	 *
	 * The checks are intended to reject firmware data that is clearly not
	 * in the expected format.  They do not need to be exhaustive as the
	 * running firmware will perform its own comprehensive validity and
	 * compatibility checks during the update procedure.
	 *
	 * Firmware packages may contain multiple reflash images, e.g. a
	 * bundle containing one or more other images.  Only check the
	 * outermost container by stopping after the first candidate image
	 * found even it is for an unsupported partition type.
	 */
	for (header_offset = 0; header_offset < fw->size; header_offset++) {
		if (efx_reflash_parse_snic_bundle_header(fw, header_offset,
							 partition_type,
							 partition_subtype,
							 data, data_size))
			return 0;

		if (efx_reflash_parse_snic_header(fw, header_offset,
						  partition_type,
						  partition_subtype, data,
						  data_size))
			return 0;

		if (efx_reflash_parse_reflash_header(fw, header_offset, &type,
						     &subtype, data, data_size))
			return efx_reflash_partition_type(type, subtype,
							  partition_type,
							  partition_subtype);
	}

	return -EINVAL;
}

/* Limit the number of status updates during the erase or write phases */
#define EFX_DEVLINK_STATUS_UPDATE_COUNT		50

/* Expected timeout for the efx_mcdi_nvram_update_finish_polled() */
#define EFX_DEVLINK_UPDATE_FINISH_TIMEOUT	900

/* Ideal erase chunk size.  This is a balance between minimising the number of
 * MCDI requests to erase an entire partition whilst avoiding tripping the MCDI
 * RPC timeout.
 */
#define EFX_NVRAM_ERASE_IDEAL_CHUNK_SIZE	(64 * 1024)

static int efx_reflash_erase_partition(struct efx_nic *efx,
				       struct devlink *devlink, u32 type,
				       size_t partition_size,
				       size_t align)
{
	size_t chunk, offset, next_update;
	int rc;

	/* Partitions that cannot be erased or do not require erase before
	 * write are advertised with a erase alignment/sector size of zero.
	 */
	if (align == 0)
		/* Nothing to do */
		return 0;

	if (partition_size % align)
		return -EINVAL;

#ifdef EFX_NOT_UPSTREAM
	netif_info(efx, hw, efx->net_dev, "Erasing NVRAM partition %#x\n", type);
#endif

	/* Erase the entire NVRAM partition a chunk at a time to avoid
	 * potentially tripping the MCDI RPC timeout.
	 */
	if (align >= EFX_NVRAM_ERASE_IDEAL_CHUNK_SIZE)
		chunk = align;
	else
		chunk = rounddown(EFX_NVRAM_ERASE_IDEAL_CHUNK_SIZE, align);

	for (offset = 0, next_update = 0; offset < partition_size; offset += chunk) {
		if (offset >= next_update) {
			devlink_flash_update_status_notify(devlink, "Erasing",
							   NULL, offset,
							   partition_size);
			next_update += partition_size / EFX_DEVLINK_STATUS_UPDATE_COUNT;
		}

		chunk = min_t(size_t, partition_size - offset, chunk);
		rc = efx_mcdi_nvram_erase(efx, type, offset, chunk);
		if (rc) {
			netif_err(efx, hw, efx->net_dev,
				  "Erase failed for NVRAM partition %#x at %#zx-%#zx with error %d\n",
				  type, offset, offset + chunk - 1, rc);
			return rc;
		}
	}

	devlink_flash_update_status_notify(devlink, "Erasing", NULL,
					   partition_size, partition_size);

	return 0;
}

static int efx_reflash_write_partition(struct efx_nic *efx,
				       struct devlink *devlink, u32 type,
				       const u8 *data, size_t data_size,
				       size_t align)
{
	size_t write_max, chunk, offset, next_update;
	int rc;

	if (align == 0)
		return -EINVAL;

#ifdef EFX_NOT_UPSTREAM
	netif_info(efx, drv, efx->net_dev,
		   "Writing firmware image to NVRAM partition %#x\n", type);
#endif

	/* Write the NVRAM partition in chunks that are the largest multiple
	 * of the partiion's required write alignment that will fit into the
	 * MCDI NVRAM_WRITE RPC payload.
	 */
	if (efx->type->mcdi_max_ver < 2)
		write_max = MC_CMD_NVRAM_WRITE_IN_WRITE_BUFFER_LEN *
			    MC_CMD_NVRAM_WRITE_IN_WRITE_BUFFER_MAXNUM;
	else
		write_max = MC_CMD_NVRAM_WRITE_IN_WRITE_BUFFER_LEN *
			    MC_CMD_NVRAM_WRITE_IN_WRITE_BUFFER_MAXNUM_MCDI2;
	chunk = rounddown(write_max, align);

	for (offset = 0, next_update = 0; offset + chunk <= data_size; offset += chunk) {
		if (offset >= next_update) {
			devlink_flash_update_status_notify(devlink, "Writing",
							   NULL, offset,
							   data_size);
			next_update += data_size / EFX_DEVLINK_STATUS_UPDATE_COUNT;
		}

		rc = efx_mcdi_nvram_write(efx, type, offset, data + offset, chunk);
		if (rc) {
			netif_err(efx, hw, efx->net_dev,
				  "Write failed for NVRAM partition %#x at %#zx-%#zx with error %d\n",
				  type, offset, offset + chunk - 1, rc);
			return rc;
		}
	}

	/* Round up left over data to satisfy write alignment */
	if (offset < data_size) {
		size_t remaining = data_size - offset;
		u8 *buf;

		if (offset >= next_update)
			devlink_flash_update_status_notify(devlink, "Writing",
							   NULL, offset,
							   data_size);

		chunk = roundup(remaining, align);
		buf = kmalloc(chunk, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;

		memcpy(buf, data + offset, remaining);
		memset(buf + remaining, 0xFF, chunk - remaining);
		rc = efx_mcdi_nvram_write(efx, type, offset, buf, chunk);
		kfree(buf);
		if (rc) {
			netif_err(efx, hw, efx->net_dev,
				  "Write failed for NVRAM partition %#x at %#zx-%#zx with error %d\n",
				  type, offset, offset + chunk - 1, rc);
			return rc;
		}
	}

	devlink_flash_update_status_notify(devlink, "Writing", NULL, data_size,
					   data_size);

	return 0;
}

int efx_reflash_flash_firmware(struct efx_nic *efx, const struct firmware *fw)
{
	size_t data_size, size, erase_align, write_align;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_DEVLINK)
	struct devlink *devlink = efx->devlink;
#else
	struct devlink *devlink = NULL;		/* devlink not available */
#endif
	u32 type, data_subtype, subtype;
	const u8 *data;
	bool protected;
	int rc, rc2;

	if (!efx_has_cap(efx, BUNDLE_UPDATE)) {
		netif_err(efx, hw, efx->net_dev,
			  "NVRAM bundle updates are not supported by the firmware\n");
		return -EOPNOTSUPP;
	}

#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_DEVLINK) && defined(EFX_HAVE_DEVLINK_FLASH_UPDATE_BEGIN_NOTIFY)
	devlink_flash_update_begin_notify(devlink);
#endif

	devlink_flash_update_status_notify(devlink, "Checking update", NULL, 0, 0);

	rc = efx_reflash_parse_firmware_data(fw, &type, &data_subtype, &data,
					     &data_size);
	if (rc) {
		netif_err(efx, drv, efx->net_dev,
			  "Firmware image validation check failed with error %d\n",
			  rc);
		goto out;
	}

	rc = efx_mcdi_nvram_metadata(efx, type, &subtype, NULL, NULL, 0);
	if (rc) {
		netif_err(efx, drv, efx->net_dev,
			  "Metadata query for NVRAM partition %#x failed with error %d\n",
			  type, rc);
		goto out;
	}

	if (subtype != data_subtype) {
		netif_err(efx, drv, efx->net_dev,
			  "Firmware image is not appropriate for this adapter");
		rc = -EINVAL;
		goto out;
	}

	rc = efx_mcdi_nvram_info(efx, type, &size, &erase_align, &write_align,
				 &protected);
	if (rc) {
		netif_err(efx, hw, efx->net_dev,
			  "Info query for NVRAM partition %#x failed with error %d\n",
			  type, rc);
		goto out;
	}

	if (protected) {
		netif_err(efx, drv, efx->net_dev,
			  "NVRAM partition %#x is protected\n", type);
		rc = -EPERM;
		goto out;
	}

	if (write_align == 0) {
		netif_err(efx, drv, efx->net_dev,
			  "NVRAM partition %#x is not writable\n", type);
		rc = -EACCES;
		goto out;
	}

	if (erase_align != 0 && size % erase_align) {
		netif_err(efx, drv, efx->net_dev,
			  "NVRAM partition %#x has a bad partition table entry and therefore is not erasable\n", type);
		rc = -EACCES;
		goto out;
	}

	if (data_size > size) {
		netif_err(efx, drv, efx->net_dev,
			  "Firmware image is too big for NVRAM partition %#x\n",
			  type);
		rc = -EFBIG;
		goto out;
	}

	devlink_flash_update_status_notify(devlink, "Starting update", NULL, 0, 0);

	rc = efx_mcdi_nvram_update_start(efx, type);
	if (rc) {
		netif_err(efx, hw, efx->net_dev,
			  "Update start request for NVRAM partition %#x failed with error %d\n",
			  type, rc);
		goto out;
	}

	rc = efx_reflash_erase_partition(efx, devlink, type, size, erase_align);
	if (rc)
		goto out_update_finish;

	rc = efx_reflash_write_partition(efx, devlink, type, data, data_size,
					 write_align);
	if (rc)
		goto out_update_finish;

#ifdef EFX_NOT_UPSTREAM
	netif_info(efx, drv, efx->net_dev,
		   "Finalizing and validating NVRAM partition %#x\n", type);
#endif

	devlink_flash_update_timeout_notify(devlink, "Finishing update", NULL,
					    EFX_DEVLINK_UPDATE_FINISH_TIMEOUT);

out_update_finish:
	rc2 = efx_mcdi_nvram_update_finish_polled(efx, type);
	/* Don't obscure the return code from an earlier failure */
	if (!rc)
		rc = rc2;

out:
	if (!rc) {
#ifdef EFX_NOT_UPSTREAM
		netif_info(efx, hw, efx->net_dev,
			   "NVRAM partition %#x update complete\n", type);
#endif
		devlink_flash_update_status_notify(devlink, "Update complete",
						   NULL, 0, 0);
	} else {
		devlink_flash_update_status_notify(devlink, "Update failed",
						   NULL, 0, 0);
	}

#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_DEVLINK) && defined(EFX_HAVE_DEVLINK_FLASH_UPDATE_BEGIN_NOTIFY)
	devlink_flash_update_end_notify(devlink);
#endif

	return rc;
}
