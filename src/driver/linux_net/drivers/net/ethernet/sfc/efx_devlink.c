/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#include <linux/rtc.h>
#include "net_driver.h"
#include "efx_devlink.h"
#include "nic.h"
#include "mcdi.h"
#include "mcdi_functions.h"
#include "mcdi_pcol.h"
#include "efx_reflash.h"
#include "nvlog.h"
#include "nvcfg.h"

/* Custom devlink-info version object names for details that do not map to the
 * generic standardized names.
 */
#define EFX_DEVLINK_INFO_VERSION_FW_MGMT_SUC	"fw.mgmt.suc"
#define EFX_DEVLINK_INFO_VERSION_FW_MGMT_CMC	"fw.mgmt.cmc"
#define EFX_DEVLINK_INFO_VERSION_FPGA_REV	"fpga.rev"
#define EFX_DEVLINK_INFO_VERSION_DATAPATH_HW	"fpga.app"
#define EFX_DEVLINK_INFO_VERSION_DATAPATH_FW	DEVLINK_INFO_VERSION_GENERIC_FW_APP
#define EFX_DEVLINK_INFO_VERSION_SOC_BOOT	"coproc.boot"
#define EFX_DEVLINK_INFO_VERSION_SOC_UBOOT	"coproc.uboot"
#define EFX_DEVLINK_INFO_VERSION_SOC_MAIN	"coproc.main"
#define EFX_DEVLINK_INFO_VERSION_SOC_RECOVERY	"coproc.recovery"
#define EFX_DEVLINK_INFO_VERSION_FW_EXPROM	"fw.exprom"
#define EFX_DEVLINK_INFO_VERSION_FW_UEFI	"fw.uefi"
#define EFX_DEVLINK_INFO_VERSION_FW_MGMT_BUILD	"fw.mgmt.buildid"

#define EFX_MAX_VERSION_INFO_LEN	64

static int efx_devlink_info_nvram_partition(struct efx_nic *efx,
					    struct devlink_info_req *req,
					    unsigned int partition_type,
					    const char *version_name)
{
	char buf[EFX_MAX_VERSION_INFO_LEN];
	u16 version[4];
	int rc;

	rc = efx_mcdi_nvram_metadata(efx, partition_type, NULL, version, NULL, 0);
	if (rc)
		return rc;

	snprintf(buf, EFX_MAX_VERSION_INFO_LEN, "%u.%u.%u.%u", version[0],
		 version[1], version[2], version[3]);
	devlink_info_version_stored_put(req, version_name, buf);

	return 0;
}

static void efx_devlink_info_stored_versions(struct efx_nic *efx,
					     struct devlink_info_req *req)
{
	efx_devlink_info_nvram_partition(efx, req, NVRAM_PARTITION_TYPE_BUNDLE,
					 DEVLINK_INFO_VERSION_GENERIC_FW_BUNDLE_ID);
	efx_devlink_info_nvram_partition(efx, req,
					 NVRAM_PARTITION_TYPE_MC_FIRMWARE,
					 DEVLINK_INFO_VERSION_GENERIC_FW_MGMT);
	efx_devlink_info_nvram_partition(efx, req,
					 NVRAM_PARTITION_TYPE_SUC_FIRMWARE,
					 EFX_DEVLINK_INFO_VERSION_FW_MGMT_SUC);
	efx_devlink_info_nvram_partition(efx, req,
					 NVRAM_PARTITION_TYPE_EXPANSION_ROM,
					 EFX_DEVLINK_INFO_VERSION_FW_EXPROM);
	efx_devlink_info_nvram_partition(efx, req,
					 NVRAM_PARTITION_TYPE_EXPANSION_UEFI,
					 EFX_DEVLINK_INFO_VERSION_FW_UEFI);
}

#define EFX_MAX_SERIALNUM_LEN	(ETH_ALEN * 2 + 1)

static void efx_devlink_info_board_cfg(struct efx_nic *efx,
				       struct devlink_info_req *req)
{
	char sn[EFX_MAX_SERIALNUM_LEN];
	u8 mac_address[ETH_ALEN];
	int rc;

	rc = efx_mcdi_get_board_cfg(efx, 0, mac_address, NULL, NULL);
	if (!rc) {
		snprintf(sn, EFX_MAX_SERIALNUM_LEN, "%pm", mac_address);
		devlink_info_serial_number_put(req, sn);
	}
}

#define EFX_VER_PRESENT(_flags, _f) \
	(_flags & BIT(MC_CMD_GET_VERSION_V6_OUT_ ## _f ## _PRESENT_LBN))

static void efx_devlink_info_running_versions(struct efx_nic *efx,
					      struct devlink_info_req *req)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_GET_VERSION_EXT_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_VERSION_V6_OUT_LEN);
	char buf[EFX_MAX_VERSION_INFO_LEN];
	unsigned int flags, build_id;
	union {
		const __le32 *dwords;
		const __le16 *words;
		const char *str;
	} ver;
	struct rtc_time build_date;
	size_t outlength, offset;
	u64 tstamp;
	int rc;

	rc = efx_mcdi_rpc(efx, MC_CMD_GET_VERSION, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlength);
	if (rc || outlength < MC_CMD_GET_VERSION_OUT_LEN)
		return;

	/* Handle V1 output */
	ver.words = (__le16 *)MCDI_PTR(outbuf,
				       GET_VERSION_OUT_VERSION);
	offset = snprintf(buf, EFX_MAX_VERSION_INFO_LEN, "%u.%u.%u.%u",
			  le16_to_cpu(ver.words[0]),
			  le16_to_cpu(ver.words[1]),
			  le16_to_cpu(ver.words[2]),
			  le16_to_cpu(ver.words[3]));

	/* Handle EXT additions */
	if (outlength >= MC_CMD_GET_VERSION_EXT_OUT_LEN) {
		ver.str = MCDI_PTR(outbuf, GET_VERSION_EXT_OUT_EXTRA);
		offset += snprintf(&buf[offset],
				   EFX_MAX_VERSION_INFO_LEN - offset,
				   " (%.*s)",
				   MC_CMD_GET_VERSION_EXT_OUT_EXTRA_LEN,
				   ver.str);
	}

	if (outlength < MC_CMD_GET_VERSION_V2_OUT_LEN) {
		devlink_info_version_running_put(req,
						 DEVLINK_INFO_VERSION_GENERIC_FW_MGMT,
						 buf);
		return;
	}

	/* Handle V2 additions */
	flags = MCDI_DWORD(outbuf, GET_VERSION_V2_OUT_FLAGS);

	devlink_info_version_running_put(req,
					 DEVLINK_INFO_VERSION_GENERIC_FW_MGMT,
					 buf);

	if (EFX_VER_PRESENT(flags, BOARD_EXT_INFO)) {
		/* Favour full board version if present (in V5 or later) */
		if (!EFX_VER_PRESENT(flags, BOARD_VERSION)) {
			snprintf(buf, EFX_MAX_VERSION_INFO_LEN, "%u",
				 MCDI_DWORD(outbuf,
					    GET_VERSION_V2_OUT_BOARD_REVISION));
			devlink_info_version_fixed_put(req,
						       DEVLINK_INFO_VERSION_GENERIC_BOARD_REV,
						       buf);
		}

		ver.str = MCDI_PTR(outbuf, GET_VERSION_V2_OUT_BOARD_SERIAL);
		if (ver.str[0])
			devlink_info_board_serial_number_put(req, ver.str);
	}

	if (EFX_VER_PRESENT(flags, FPGA_EXT_INFO)) {
		ver.dwords = (__le32 *)MCDI_PTR(outbuf,
						GET_VERSION_V2_OUT_FPGA_VERSION);
		offset = snprintf(buf, EFX_MAX_VERSION_INFO_LEN, "%u_%c%u",
				  le32_to_cpu(ver.dwords[0]),
				  'A' + le32_to_cpu(ver.dwords[1]),
				  le32_to_cpu(ver.dwords[2]));

		ver.str = MCDI_PTR(outbuf, GET_VERSION_V2_OUT_FPGA_EXTRA);
		if (ver.str[0])
			snprintf(&buf[offset], EFX_MAX_VERSION_INFO_LEN - offset,
				 " (%s)", ver.str);

		devlink_info_version_running_put(req,
						 EFX_DEVLINK_INFO_VERSION_FPGA_REV,
						 buf);
	}

	if (EFX_VER_PRESENT(flags, CMC_EXT_INFO)) {
		ver.dwords = (__le32 *)MCDI_PTR(outbuf,
						GET_VERSION_V2_OUT_CMCFW_VERSION);
		offset = snprintf(buf, EFX_MAX_VERSION_INFO_LEN, "%u.%u.%u.%u",
				  le32_to_cpu(ver.dwords[0]),
				  le32_to_cpu(ver.dwords[1]),
				  le32_to_cpu(ver.dwords[2]),
				  le32_to_cpu(ver.dwords[3]));

		tstamp = MCDI_QWORD(outbuf,
				    GET_VERSION_V2_OUT_CMCFW_BUILD_DATE);
		if (tstamp) {
			rtc_time64_to_tm(tstamp, &build_date);
			snprintf(&buf[offset], EFX_MAX_VERSION_INFO_LEN - offset,
				 " (%ptRd)", &build_date);
		}

		devlink_info_version_running_put(req,
						 EFX_DEVLINK_INFO_VERSION_FW_MGMT_CMC,
						 buf);
	}

	if (EFX_VER_PRESENT(flags, MCFW_EXT_INFO)) {
		ver.str = MCDI_PTR(outbuf, GET_VERSION_V2_OUT_MCFW_BUILD_ID);
		snprintf(buf, EFX_MAX_VERSION_INFO_LEN, "%*phN",
			 MC_CMD_GET_VERSION_V2_OUT_MCFW_BUILD_ID_LEN, ver.str);
		devlink_info_version_running_put(req,
						 EFX_DEVLINK_INFO_VERSION_FW_MGMT_BUILD,
						 buf);
	}

	if (EFX_VER_PRESENT(flags, SUCFW_EXT_INFO)) {
		ver.dwords = (__le32 *)MCDI_PTR(outbuf,
						GET_VERSION_V2_OUT_SUCFW_VERSION);
		tstamp = MCDI_QWORD(outbuf,
				    GET_VERSION_V2_OUT_SUCFW_BUILD_DATE);
		rtc_time64_to_tm(tstamp, &build_date);
		build_id = MCDI_DWORD(outbuf, GET_VERSION_V2_OUT_SUCFW_CHIP_ID);

		snprintf(buf, EFX_MAX_VERSION_INFO_LEN,
			 "%u.%u.%u.%u type %x (%ptRd)",
			 le32_to_cpu(ver.dwords[0]), le32_to_cpu(ver.dwords[1]),
			 le32_to_cpu(ver.dwords[2]), le32_to_cpu(ver.dwords[3]),
			 build_id, &build_date);

		devlink_info_version_running_put(req,
						 EFX_DEVLINK_INFO_VERSION_FW_MGMT_SUC,
						 buf);
	}

	if (outlength < MC_CMD_GET_VERSION_V3_OUT_LEN)
		return;

	/* Handle V3 additions */
	if (EFX_VER_PRESENT(flags, DATAPATH_HW_VERSION)) {
		ver.dwords = (__le32 *)MCDI_PTR(outbuf,
						GET_VERSION_V3_OUT_DATAPATH_HW_VERSION);

		snprintf(buf, EFX_MAX_VERSION_INFO_LEN, "%u.%u.%u",
			 le32_to_cpu(ver.dwords[0]), le32_to_cpu(ver.dwords[1]),
			 le32_to_cpu(ver.dwords[2]));

		devlink_info_version_running_put(req,
						 EFX_DEVLINK_INFO_VERSION_DATAPATH_HW,
						 buf);
	}

	if (EFX_VER_PRESENT(flags, DATAPATH_FW_VERSION)) {
		ver.dwords = (__le32 *)MCDI_PTR(outbuf,
						GET_VERSION_V3_OUT_DATAPATH_FW_VERSION);

		snprintf(buf, EFX_MAX_VERSION_INFO_LEN, "%u.%u.%u",
			 le32_to_cpu(ver.dwords[0]), le32_to_cpu(ver.dwords[1]),
			 le32_to_cpu(ver.dwords[2]));

		devlink_info_version_running_put(req,
						 EFX_DEVLINK_INFO_VERSION_DATAPATH_FW,
						 buf);
	}

	if (outlength < MC_CMD_GET_VERSION_V4_OUT_LEN)
		return;

	/* Handle V4 additions */
	if (EFX_VER_PRESENT(flags, SOC_BOOT_VERSION)) {
		ver.dwords = (__le32 *)MCDI_PTR(outbuf,
						GET_VERSION_V4_OUT_SOC_BOOT_VERSION);

		snprintf(buf, EFX_MAX_VERSION_INFO_LEN, "%u.%u.%u.%u",
			 le32_to_cpu(ver.dwords[0]), le32_to_cpu(ver.dwords[1]),
			 le32_to_cpu(ver.dwords[2]),
			 le32_to_cpu(ver.dwords[3]));

		devlink_info_version_running_put(req,
						 EFX_DEVLINK_INFO_VERSION_SOC_BOOT,
						 buf);
	}

	if (EFX_VER_PRESENT(flags, SOC_UBOOT_VERSION)) {
		ver.dwords = (__le32 *)MCDI_PTR(outbuf,
						GET_VERSION_V4_OUT_SOC_UBOOT_VERSION);

		snprintf(buf, EFX_MAX_VERSION_INFO_LEN, "%u.%u.%u.%u",
			 le32_to_cpu(ver.dwords[0]), le32_to_cpu(ver.dwords[1]),
			 le32_to_cpu(ver.dwords[2]),
			 le32_to_cpu(ver.dwords[3]));

		devlink_info_version_running_put(req,
						 EFX_DEVLINK_INFO_VERSION_SOC_UBOOT,
						 buf);
	}

	if (EFX_VER_PRESENT(flags, SOC_MAIN_ROOTFS_VERSION)) {
		ver.dwords = (__le32 *)MCDI_PTR(outbuf,
						GET_VERSION_V4_OUT_SOC_MAIN_ROOTFS_VERSION);

		snprintf(buf, EFX_MAX_VERSION_INFO_LEN, "%u.%u.%u.%u",
			 le32_to_cpu(ver.dwords[0]), le32_to_cpu(ver.dwords[1]),
			 le32_to_cpu(ver.dwords[2]),
			 le32_to_cpu(ver.dwords[3]));

		devlink_info_version_running_put(req,
						 EFX_DEVLINK_INFO_VERSION_SOC_MAIN,
						 buf);
	}

	if (EFX_VER_PRESENT(flags, SOC_RECOVERY_BUILDROOT_VERSION)) {
		ver.dwords = (__le32 *)MCDI_PTR(outbuf,
						GET_VERSION_V4_OUT_SOC_RECOVERY_BUILDROOT_VERSION);

		snprintf(buf, EFX_MAX_VERSION_INFO_LEN, "%u.%u.%u.%u",
			 le32_to_cpu(ver.dwords[0]), le32_to_cpu(ver.dwords[1]),
			 le32_to_cpu(ver.dwords[2]),
			 le32_to_cpu(ver.dwords[3]));

		devlink_info_version_running_put(req,
						 EFX_DEVLINK_INFO_VERSION_SOC_RECOVERY,
						 buf);
	}

	if (EFX_VER_PRESENT(flags, SUCFW_VERSION) &&
	    !EFX_VER_PRESENT(flags, SUCFW_EXT_INFO)) {
		ver.dwords = (__le32 *)MCDI_PTR(outbuf,
						GET_VERSION_V4_OUT_SUCFW_VERSION);

		snprintf(buf, EFX_MAX_VERSION_INFO_LEN, "%u.%u.%u.%u",
			 le32_to_cpu(ver.dwords[0]), le32_to_cpu(ver.dwords[1]),
			 le32_to_cpu(ver.dwords[2]),
			 le32_to_cpu(ver.dwords[3]));

		devlink_info_version_running_put(req,
						 EFX_DEVLINK_INFO_VERSION_FW_MGMT_SUC,
						 buf);
	}

	if (outlength < MC_CMD_GET_VERSION_V5_OUT_LEN)
		return;

	/* Handle V5 additions */

	if (EFX_VER_PRESENT(flags, BOARD_VERSION)) {
		ver.dwords = (__le32 *)MCDI_PTR(outbuf,
						GET_VERSION_V5_OUT_BOARD_VERSION);

		snprintf(buf, EFX_MAX_VERSION_INFO_LEN, "%u.%u.%u.%u",
			 le32_to_cpu(ver.dwords[0]), le32_to_cpu(ver.dwords[1]),
			 le32_to_cpu(ver.dwords[2]),
			 le32_to_cpu(ver.dwords[3]));

		devlink_info_version_running_put(req,
						 DEVLINK_INFO_VERSION_GENERIC_BOARD_REV,
						 buf);
	}

	if (EFX_VER_PRESENT(flags, BUNDLE_VERSION)) {
		ver.dwords = (__le32 *)MCDI_PTR(outbuf,
						GET_VERSION_V5_OUT_BUNDLE_VERSION);

		snprintf(buf, EFX_MAX_VERSION_INFO_LEN, "%u.%u.%u.%u",
			 le32_to_cpu(ver.dwords[0]), le32_to_cpu(ver.dwords[1]),
			 le32_to_cpu(ver.dwords[2]),
			 le32_to_cpu(ver.dwords[3]));

		devlink_info_version_running_put(req,
						 DEVLINK_INFO_VERSION_GENERIC_FW_BUNDLE_ID,
						 buf);
	}

	if (outlength < MC_CMD_GET_VERSION_V6_OUT_LEN)
		return;

	/* Handle V6 additions */
	if (EFX_VER_PRESENT(flags, BOOTLOADER_VERSION)) {
		ver.dwords = (__le32 *)MCDI_PTR(outbuf,
						GET_VERSION_V6_OUT_BOOTLOADER_VERSION);

		snprintf(buf, EFX_MAX_VERSION_INFO_LEN, "%u.%u.%u.%u",
			 le32_to_cpu(ver.dwords[0]), le32_to_cpu(ver.dwords[1]),
			 le32_to_cpu(ver.dwords[2]),
			 le32_to_cpu(ver.dwords[3]));

		devlink_info_version_running_put(req,
						 DEVLINK_INFO_VERSION_GENERIC_FW_BOOTLOADER,
						 buf);
	}

	if (EFX_VER_PRESENT(flags, EXPANSION_ROM_VERSION)) {
		ver.dwords = (__le32 *)MCDI_PTR(outbuf,
						GET_VERSION_V6_OUT_EXPANSION_ROM_VERSION);

		snprintf(buf, EFX_MAX_VERSION_INFO_LEN, "%u.%u.%u.%u",
			 le32_to_cpu(ver.dwords[0]), le32_to_cpu(ver.dwords[1]),
			 le32_to_cpu(ver.dwords[2]),
			 le32_to_cpu(ver.dwords[3]));

		devlink_info_version_running_put(req,
						 EFX_DEVLINK_INFO_VERSION_FW_UEFI,
						 buf);
	}
}

#undef EFX_VER_PRESENT

static void efx_devlink_info_query_all(struct efx_nic *efx,
				       struct devlink_info_req *req)
{
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_DEVLINK_INFO_DRIVER_NAME_PUT)
	devlink_info_driver_name_put(req, efx->pci_dev->driver->name);
#endif
	efx_devlink_info_board_cfg(efx, req);
	efx_devlink_info_stored_versions(efx, req);
	efx_devlink_info_running_versions(efx, req);
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_DEVLINK)

/* This is the private data we have in struct devlink */
struct efx_devlink {
	struct efx_nic *efx;
};

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NDO_GET_DEVLINK_PORT)
struct devlink_port *efx_get_devlink_port(struct net_device *dev)
{
	struct efx_nic *efx = efx_netdev_priv(dev);
	struct efx_devlink *devlink_private;

	if (!efx->devlink)
		return NULL;

	devlink_private = devlink_priv(efx->devlink);
	if (devlink_private)
		return efx->devlink_port;
	else
		return NULL;
}
#endif

static int efx_devlink_info_get(struct devlink *devlink,
				struct devlink_info_req *req,
				struct netlink_ext_ack *extack)
{
	struct efx_devlink *devlink_private = devlink_priv(devlink);
	struct efx_nic *efx = devlink_private->efx;

	efx_devlink_info_query_all(efx, req);
	return 0;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_DEVLINK_FLASH_UPDATE_PARAMS)
static int efx_devlink_flash_update(struct devlink *devlink,
				    struct devlink_flash_update_params *params,
				    struct netlink_ext_ack *extack)
#else
static int efx_devlink_flash_update(struct devlink *devlink,
				    const char *file_name,
				    const char *component,
				    struct netlink_ext_ack *extack)
#endif
{
	struct efx_devlink *devlink_private = devlink_priv(devlink);
	struct efx_nic *efx = devlink_private->efx;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_DEVLINK_FLASH_UPDATE_PARAMS_FW)
	const struct firmware *fw;
	int rc;
#endif

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_DEVLINK_FLASH_UPDATE_PARAMS)
	if (component) {
		pci_err(efx->pci_dev,
			"Updates to NVRAM component %s are not supported\n",
			component);
		return -EINVAL;
	}
#endif

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_DEVLINK_FLASH_UPDATE_PARAMS_FW)
#ifdef EFX_HAVE_DEVLINK_FLASH_UPDATE_PARAMS
	rc = request_firmware(&fw, params->file_name, &efx->pci_dev->dev);
#else
	rc = request_firmware(&fw, file_name, &efx->pci_dev->dev);
#endif
	if (rc)
		return rc;

	rc = efx_reflash_flash_firmware(efx, fw);

	release_firmware(fw);
	return rc;
#else
	return efx_reflash_flash_firmware(efx, params->fw);
#endif
}

static const struct devlink_ops sfc_devlink_ops = {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_DEVLINK_OPS_SUPPORTED_FLASH_UPDATE_PARAMS)
	.supported_flash_update_params	= 0,
#endif
	.flash_update			= efx_devlink_flash_update,
	.info_get			= efx_devlink_info_get,
};

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_DEVLINK_HEALTH_REPORTER)
static int efx_devlink_reporter_log(struct devlink_health_reporter *reporter,
				    struct devlink_fmsg *fmsg,
				    u32 type, unsigned int flags)
{
	struct efx_devlink *devlink_private =
		devlink_health_reporter_priv(reporter);
	struct efx_nvlog_data *nvlog_data =
		kzalloc(sizeof(*nvlog_data), GFP_KERNEL);
	struct efx_nic *efx = devlink_private->efx;
	int rc;

	if (!nvlog_data)
		return -ENOMEM;

	if (flags & EFX_NVLOG_F_READ) {
		rc = efx_nvlog_do(efx, nvlog_data, type, EFX_NVLOG_F_READ);
		if (rc)
			goto out_free;

		rc = efx_nvlog_to_devlink(nvlog_data, fmsg);
		if (rc)
			goto out_free;
	}

	/* if log output was requested then this is ready, so now safe
	 * to clear flash
	 */
	if (flags & EFX_NVLOG_F_CLEAR)
		rc = efx_nvlog_do(efx, nvlog_data, type, EFX_NVLOG_F_CLEAR);

 out_free:
	kfree(nvlog_data->nvlog);
	kfree(nvlog_data);

	return rc;
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_DEVLINK_HEALTH_REPORTER)
static int efx_devlink_reporter_nvlog_diagnose(struct devlink_health_reporter *reporter,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_DEVLINK_HEALTH_REPORTER_OPS_EXTACK)
					       struct devlink_fmsg *fmsg,
					       struct netlink_ext_ack *extack)
#else
					       struct devlink_fmsg *fmsg)
#endif
{
	return efx_devlink_reporter_log(reporter, fmsg,
					NVRAM_PARTITION_TYPE_LOG,
					EFX_NVLOG_F_READ);
}

static const struct devlink_health_reporter_ops sfc_devlink_nvlog_ops = {
	.name		= "nvlog",
	.diagnose	= efx_devlink_reporter_nvlog_diagnose,
};

static int efx_devlink_reporter_nvlog_clear_diagnose(struct devlink_health_reporter *reporter,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_DEVLINK_HEALTH_REPORTER_OPS_EXTACK)
						     struct devlink_fmsg *fmsg,
						     struct netlink_ext_ack *extack)
#else
						     struct devlink_fmsg *fmsg)
#endif
{
	return efx_devlink_reporter_log(reporter, fmsg,
					NVRAM_PARTITION_TYPE_LOG,
					EFX_NVLOG_F_READ | EFX_NVLOG_F_CLEAR);
}

static const struct devlink_health_reporter_ops sfc_devlink_nvlog_clear_ops = {
	.name		= "nvlog-clear",
	.diagnose	= efx_devlink_reporter_nvlog_clear_diagnose,
};

static int efx_devlink_reporter_ramlog_diagnose(struct devlink_health_reporter *reporter,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_DEVLINK_HEALTH_REPORTER_OPS_EXTACK)
						struct devlink_fmsg *fmsg,
						struct netlink_ext_ack *extack)
#else
						struct devlink_fmsg *fmsg)
#endif
{
	return efx_devlink_reporter_log(reporter, fmsg,
					NVRAM_PARTITION_TYPE_RAM_LOG,
					EFX_NVLOG_F_READ);
}

static const struct devlink_health_reporter_ops sfc_devlink_ramlog_ops = {
	.name		= "ramlog",
	.diagnose	= efx_devlink_reporter_ramlog_diagnose,
};

static int efx_devlink_reporter_ramlog_clear_diagnose(struct devlink_health_reporter *reporter,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_DEVLINK_HEALTH_REPORTER_OPS_EXTACK)
						      struct devlink_fmsg *fmsg,
						      struct netlink_ext_ack *extack)
#else
						      struct devlink_fmsg *fmsg)
#endif
{
	return efx_devlink_reporter_log(reporter, fmsg,
					NVRAM_PARTITION_TYPE_RAM_LOG,
					EFX_NVLOG_F_READ | EFX_NVLOG_F_CLEAR);
}

static const struct devlink_health_reporter_ops sfc_devlink_ramlog_clear_ops = {
	.name		= "ramlog-clear",
	.diagnose	= efx_devlink_reporter_ramlog_clear_diagnose,
};

static int efx_devlink_reporter_cfg(struct devlink_health_reporter *reporter,
				    struct devlink_fmsg *fmsg, u32 type)
{
	struct efx_devlink *devlink_private = devlink_health_reporter_priv(reporter);
	struct efx_nic *efx = devlink_private->efx;
	struct efx_nvlog_data data = {};
	int rc;

	rc = efx_nvcfg_read(efx, &data, type);
	if (!rc)
		rc = efx_nvlog_to_devlink(&data, fmsg);
	kfree(data.nvlog);
	return rc;
}

static int efx_devlink_reporter_nvcfg_next_diagnose(struct devlink_health_reporter *reporter,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_DEVLINK_HEALTH_REPORTER_OPS_EXTACK)
						    struct devlink_fmsg *fmsg,
						    struct netlink_ext_ack *extack)
#else
						    struct devlink_fmsg *fmsg)
#endif
{
	return efx_devlink_reporter_cfg(reporter, fmsg,
					MC_CMD_READ_CONFIGURATION_IN_NEXT);
}

static const struct devlink_health_reporter_ops sfc_devlink_nvcfg_next_ops = {
	.name		= "nvcfg-next",
	.diagnose	= efx_devlink_reporter_nvcfg_next_diagnose,
};

static int efx_devlink_reporter_nvcfg_active_diagnose(struct devlink_health_reporter *reporter,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_DEVLINK_HEALTH_REPORTER_OPS_EXTACK)
						      struct devlink_fmsg *fmsg,
						      struct netlink_ext_ack *extack)
#else
						      struct devlink_fmsg *fmsg)
#endif
{
	return efx_devlink_reporter_cfg(reporter, fmsg,
					MC_CMD_READ_CONFIGURATION_IN_ACTIVE);
}

static const struct devlink_health_reporter_ops sfc_devlink_nvcfg_active_ops = {
	.name		= "nvcfg-active",
	.diagnose	= efx_devlink_reporter_nvcfg_active_diagnose,
};

static int efx_devlink_reporter_nvcfg_stored_diagnose(struct devlink_health_reporter *reporter,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_DEVLINK_HEALTH_REPORTER_OPS_EXTACK)
						      struct devlink_fmsg *fmsg,
						      struct netlink_ext_ack *extack)
#else
						      struct devlink_fmsg *fmsg)
#endif
{
	return efx_devlink_reporter_cfg(reporter, fmsg,
					MC_CMD_READ_CONFIGURATION_IN_STORED);
}

static const struct devlink_health_reporter_ops sfc_devlink_nvcfg_stored_ops = {
	.name		= "nvcfg-stored",
	.diagnose	= efx_devlink_reporter_nvcfg_stored_diagnose,
};

#endif /* EFX_HAVE_DEVLINK_HEALTH */

void efx_fini_devlink(struct efx_nic *efx)
{
	if (efx->devlink) {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_DEVLINK_HEALTH_REPORTER)
		if (efx->devlink_reporter_nvlog)
			devlink_health_reporter_destroy(efx->devlink_reporter_nvlog);
		if (efx->devlink_reporter_nvlog_clear)
			devlink_health_reporter_destroy(efx->devlink_reporter_nvlog_clear);
		if (efx->devlink_reporter_ramlog)
			devlink_health_reporter_destroy(efx->devlink_reporter_ramlog);
		if (efx->devlink_reporter_ramlog_clear)
			devlink_health_reporter_destroy(efx->devlink_reporter_ramlog_clear);
		if (efx->devlink_reporter_nvcfg_next)
			devlink_health_reporter_destroy(efx->devlink_reporter_nvcfg_next);
		if (efx->devlink_reporter_nvcfg_active)
			devlink_health_reporter_destroy(efx->devlink_reporter_nvcfg_active);
		if (efx->devlink_reporter_nvcfg_stored)
			devlink_health_reporter_destroy(efx->devlink_reporter_nvcfg_stored);
#endif
		devlink_unregister(efx->devlink);
		devlink_free(efx->devlink);
	}
	efx->devlink = NULL;
}

void efx_fini_devlink_port(struct efx_nic *efx)
{
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_SET_NETDEV_DEVLINK_PORT)
	if (efx->net_dev && efx->net_dev->devlink_port)
		efx->net_dev->devlink_port->type = DEVLINK_PORT_TYPE_NOTSET;
#endif
	if (efx->devlink && efx->devlink_port) {
		devlink_port_unregister(efx->devlink_port);
		kfree(efx->devlink_port);
		efx->devlink_port = NULL;
	}
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_SET_NETDEV_DEVLINK_PORT)
	if (efx->net_dev)
		efx->net_dev->devlink_port = NULL;
#endif
}

int efx_probe_devlink(struct efx_nic *efx)
{
	struct efx_devlink *devlink_private;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_VOID_DEVLINK_REGISTER)
	int rc;
#endif

	efx->devlink = devlink_alloc(&sfc_devlink_ops,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_DEVLINK_ALLOC_DEV)
				     sizeof(struct efx_devlink),
				     &efx->pci_dev->dev);
#else
				     sizeof(struct efx_devlink));
#endif
	if (!efx->devlink)
		return -ENOMEM;
	devlink_private = devlink_priv(efx->devlink);
	devlink_private->efx = efx;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VOID_DEVLINK_REGISTER)
	devlink_register(efx->devlink);
#elif defined(EFX_HAVE_DEVLINK_ALLOC_DEV)
	rc = devlink_register(efx->devlink);
	if (rc)
		goto out_free;
#else
	rc = devlink_register(efx->devlink, &efx->pci_dev->dev);
	if (rc)
		goto out_free;
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_DEVLINK_HEALTH_REPORTER)
	if (PCI_FUNC(efx->pci_dev->devfn) == 0) {
		efx->devlink_reporter_nvlog =
			devlink_health_reporter_create(efx->devlink,
						       &sfc_devlink_nvlog_ops,
						       0,
						       devlink_private);
		efx->devlink_reporter_nvlog_clear =
			devlink_health_reporter_create(efx->devlink,
						       &sfc_devlink_nvlog_clear_ops,
						       0,
						       devlink_private);
		if (efx->type->revision == EFX_REV_X4) {
			efx->devlink_reporter_ramlog =
				devlink_health_reporter_create(efx->devlink,
							       &sfc_devlink_ramlog_ops,
							       0,
							       devlink_private);
			efx->devlink_reporter_ramlog_clear =
				devlink_health_reporter_create(efx->devlink,
							       &sfc_devlink_ramlog_clear_ops,
							       0,
							       devlink_private);
			efx->devlink_reporter_nvcfg_next =
				devlink_health_reporter_create(efx->devlink,
							       &sfc_devlink_nvcfg_next_ops,
							       0,
							       devlink_private);
			efx->devlink_reporter_nvcfg_active =
				devlink_health_reporter_create(efx->devlink,
							       &sfc_devlink_nvcfg_active_ops,
							       0,
							       devlink_private);
			efx->devlink_reporter_nvcfg_stored =
				devlink_health_reporter_create(efx->devlink,
							       &sfc_devlink_nvcfg_stored_ops,
							       0,
							       devlink_private);
		}
	}
#endif
	return 0;

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_VOID_DEVLINK_REGISTER)
out_free:
	devlink_free(efx->devlink);
	efx->devlink = NULL;
	return rc;
#endif
}

int efx_probe_devlink_port(struct efx_nic *efx)
{
	int rc;

	if (!efx->devlink)
		return -ENODEV;

	efx->devlink_port = kzalloc(sizeof(*efx->devlink_port), GFP_KERNEL);
	if (!efx->devlink_port)
		return -ENOMEM;

	rc = devlink_port_register(efx->devlink, efx->devlink_port,
				   efx->port_num);
	if (rc)
		goto out_free_port;

#if defined(EFX_USE_KCOMPAT)
#if defined(EFX_HAVE_SET_NETDEV_DEVLINK_PORT)
	efx->net_dev->devlink_port = efx->devlink_port;
	efx->net_dev->devlink_port->type = DEVLINK_PORT_TYPE_ETH;
#else
	devlink_port_type_eth_set(efx->devlink_port, efx->net_dev);
#endif
#endif
	return 0;

out_free_port:
	kfree(efx->devlink_port);
	efx->devlink_port = NULL;

	return rc;
}
#else

static ssize_t versions_show(struct device *dev, struct device_attribute *attr,
			     char *buf_out)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
	struct devlink_info_req req = {
		.buf = buf_out,
		.bufsize = PAGE_SIZE
	};

	buf_out[0] = '\0';
	efx_devlink_info_query_all(efx, &req);
	return strlen(buf_out);
}

static DEVICE_ATTR_RO(versions);

int efx_probe_devlink(struct efx_nic *efx)
{
	return device_create_file(&efx->pci_dev->dev, &dev_attr_versions);
}

int efx_probe_devlink_port(struct efx_nic *efx)
{
	return 0;
}

void efx_fini_devlink(struct efx_nic *efx)
{
	device_remove_file(&efx->pci_dev->dev, &dev_attr_versions);
}

void efx_fini_devlink_port(struct efx_nic *efx) {}

#endif	/* EFX_USE_DEVLINK */
