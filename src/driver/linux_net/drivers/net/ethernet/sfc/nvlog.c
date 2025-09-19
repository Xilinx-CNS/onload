/****************************************************************************
 * Driver for AMD Solarflare network controllers and boards
 * Copyright 2023 Advanced Micro Devices Inc.
 */

#include "nvlog.h"

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_DEVLINK_HEALTH_REPORTER)
#include "mcdi.h"
#include <net/genetlink.h>

#define NV_LOG_VERSION 0

static int efx_nvlog_read(struct efx_nic *efx,
			  struct efx_nvlog_data *nvlog_data,
			  u32 type, u32 size)
{
	u32 offset;
	u32 version_offset;
	char buffer[EFX_MCDI_NVRAM_LEN_MAX];
	u32 len;
	char *p;
	u8 version_bytes[4];
	u32 version;
	char *ptr;
	int rc;

	kfree(nvlog_data->nvlog);
	nvlog_data->nvlog = kmalloc(size, GFP_KERNEL);
	nvlog_data->nvlog_len = 0;
	if (!nvlog_data->nvlog)
		return -ENOMEM;
	nvlog_data->nvlog_max_len = size;

	version_offset = (type == NVRAM_PARTITION_TYPE_MUM_LOG) ? 28 : 0;
	rc = efx_mcdi_nvram_read(efx, type, version_offset, version_bytes,
				 sizeof(version_bytes));
	if (rc)
		return rc;

	version = ((u32)(version_bytes[0]) << 0 |
		   (u32)(version_bytes[1]) << 8 |
		   (u32)(version_bytes[2]) << 16 |
		   (u32)(version_bytes[3]) << 24);
	if (version != NV_LOG_VERSION) {
		if (version == 0xffffffff)
			return 0; /* empty */

		netif_warn(efx, drv, efx->net_dev, "Bad NVLOG version: 0x%x",
			   version);
	}

	ptr = nvlog_data->nvlog;
	for (offset = (sizeof(version_bytes) + version_offset); offset < size;
	     offset += EFX_MCDI_NVRAM_LEN_MAX) {
		len = size - offset;
		if (len > EFX_MCDI_NVRAM_LEN_MAX)
			len = EFX_MCDI_NVRAM_LEN_MAX;
		rc = efx_mcdi_nvram_read(efx, type, offset, buffer, len);
		if (rc) {
			netif_warn(efx, drv, efx->net_dev,
				   "Failure reading from NVLOG.");
			return -ENETDOWN;
		}
		p = memchr(buffer, 0xff, len);
		if (p) {
			len = p - buffer;
			memcpy(ptr, buffer, len);
			nvlog_data->nvlog_len += len;
			break;
		}
		memcpy(ptr, buffer, len);
		nvlog_data->nvlog_len += len;
		ptr += len;
	}

	return 0;
}

static int efx_nvlog_erase(struct efx_nic *efx, u32 type, u32 size,
			   u32 erase_size)
{
	int rc;
	u32 offset;

	mutex_lock(&efx->reflash_mutex);
	rc = efx_mcdi_nvram_update_start(efx, type);
	if (rc) {
		netif_err(efx, hw, efx->net_dev,
			  "Update start request for NVLOG partition %#x failed with error %d\n",
			  type, rc);
		goto out;
	}

	for (offset = 0; offset < size; offset += erase_size) {
		rc = efx_mcdi_nvram_erase(efx, type, offset, erase_size);
		if (rc) {
			netif_err(efx, hw, efx->net_dev,
				  "Erase failed for NVLOG partition %#x at %#x-%#x with error %d\n",
				  type, offset, offset + erase_size - 1, rc);
			goto out_update_finish;
		}
	}

out_update_finish:
	if (rc)
		/* Don't obscure the return code from an earlier failure */
		(void)efx_mcdi_nvram_update_finish(efx, type,
						   EFX_UPDATE_FINISH_ABORT);
	else
		rc = efx_mcdi_nvram_update_finish_polled(efx, type);

out:
	if (!rc) {
#ifdef EFX_NOT_UPSTREAM
		netif_info(efx, hw, efx->net_dev,
			   "NVLOG partition %#x erase complete\n", type);
#endif
	}

	mutex_unlock(&efx->reflash_mutex);

	return rc;
}

static int efx_nvlog_copy(struct efx_nvlog_data *nvlog_data,
			  char *src, size_t bytes)
{
	size_t remaining = nvlog_data->nvlog_max_len - nvlog_data->nvlog_len;
	char *dest = nvlog_data->nvlog + nvlog_data->nvlog_len;

	if (bytes > remaining)
		return -ENOSPC;

	memcpy(dest, src, bytes);
	nvlog_data->nvlog_len += bytes;
	return 0;
}

static char *month[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
			 "Aug", "Sep", "Oct", "Nov", "Dec" };

static int efx_nvlog_print_time(struct efx_nvlog_data *nvlog_data,
				struct tm *tm)
{
	size_t remaining = nvlog_data->nvlog_max_len - nvlog_data->nvlog_len;
	char *dest = nvlog_data->nvlog + nvlog_data->nvlog_len;
	int rc;

	rc = snprintf(dest, remaining,
		      "%d:%02d:%02d %s %d %ld UTC:",
		      tm->tm_hour, tm->tm_min, tm->tm_sec,
		      month[tm->tm_mon], tm->tm_mday,
		      tm->tm_year + 1900);

	if (rc >= remaining)
		return -ENOSPC;

	nvlog_data->nvlog_len += rc;
	return 0;
}

static int efx_nvlog_print_header(struct efx_nic *efx,
				  struct efx_nvlog_data *nvlog_data,
				  char *type_str)
{
	size_t remaining = nvlog_data->nvlog_max_len - nvlog_data->nvlog_len;
	char *dest = nvlog_data->nvlog + nvlog_data->nvlog_len;
	int rc;

	rc = snprintf(dest, remaining,
		      "********* Reading %s log from interface %s **********\n",
		      type_str, efx->name);

	if (rc >= remaining)
		return -ENOSPC;

	nvlog_data->nvlog_len += rc;
	return 0;
}

static int efx_nvlog_expand_timestamps(struct efx_nic *efx,
				       struct efx_nvlog_data *nvlog_data,
				       u32 type)
{
	size_t len = nvlog_data->nvlog_len;
	char *old_buffer = nvlog_data->nvlog;
	char *buffer = nvlog_data->nvlog;
	char *p = memchr(buffer, '{', len);
	size_t offset;
	time64_t time;
	struct tm tm;
	int rc = 0;

	nvlog_data->nvlog_max_len += nvlog_data->nvlog_len;
	nvlog_data->nvlog = kmalloc(nvlog_data->nvlog_max_len, GFP_KERNEL);
	nvlog_data->nvlog_len = 0;
	if (!nvlog_data->nvlog) {
		rc = -ENOMEM;
		goto out;
	}

	if (type == NVRAM_PARTITION_TYPE_RAM_LOG)
		rc = efx_nvlog_print_header(efx, nvlog_data, "MC RAM");
	else
		rc = efx_nvlog_print_header(efx, nvlog_data, "MC");

	if (rc)
		goto out;

	while (p) {
		p++;
		offset = p - buffer;
		rc = efx_nvlog_copy(nvlog_data, buffer, offset);
		if (rc)
			goto out;
		buffer += offset;
		len -= offset;

		time = 0;
		for (; len && *((char *)buffer) >= '0' &&
		     *((char *)buffer) <= '9'; buffer++) {
			time = time * 10 + (*((char *)buffer) - '0');
			len--;
		}
		time64_to_tm(time, 0, &tm);
		rc = efx_nvlog_print_time(nvlog_data, &tm);
		if (rc)
			goto out;

		for (; len && *((char *)buffer) != ' '; buffer++)
			len--;

		p = memchr(buffer, '{', len);
	}

	rc = efx_nvlog_copy(nvlog_data, buffer, len);

out:
	kfree(old_buffer);
	return rc;
}

int efx_nvlog_do(struct efx_nic *efx, struct efx_nvlog_data *nvlog_data,
		 u32 type, unsigned int flags)
{
	int rc;
	size_t size, erase_size, write_size;
	bool protected;

	rc = efx_mcdi_nvram_info(efx, type,
				 &size, &erase_size,
				 &write_size, &protected);
	if (rc)
		return rc;

	if (flags & EFX_NVLOG_F_READ) {
		/* Get nvlog */
		rc = efx_nvlog_read(efx, nvlog_data, type, size);
		if (rc)
			return rc;

		rc = efx_nvlog_expand_timestamps(efx, nvlog_data, type);
		if (rc)
			return rc;
	}

	if (flags & EFX_NVLOG_F_CLEAR)
		rc = efx_nvlog_erase(efx, type, size, erase_size);
	return rc;
}

#define DEVLINK_FMSG_MAX_SIZE (GENLMSG_DEFAULT_SIZE - GENL_HDRLEN - NLA_HDRLEN)

/* len is the length of the characters to be output (excluding trailing \0)
 * buf must be at least one character longer than the visible output
 */
static int buffer_to_fmsg_string(struct devlink_fmsg *fmsg, char *buf, size_t len)
{
	char *terminator;
	size_t seg_len;
	size_t offset;
	char temp;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_VOID_DEVLINK_FMSG_STRING_PUT)
	int rc;
#endif

	for (offset = 0; offset < len; offset += seg_len) {
		seg_len = len - offset;
		if (seg_len > DEVLINK_FMSG_MAX_SIZE)
			seg_len = DEVLINK_FMSG_MAX_SIZE;
		/* This is the location *after* the last printed character */
		terminator = buf + offset + seg_len;
		temp = *terminator;
		*terminator = '\0';

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VOID_DEVLINK_FMSG_STRING_PUT)
		devlink_fmsg_string_put(fmsg, buf + offset);
#else
		rc = devlink_fmsg_string_put(fmsg, buf + offset);
#endif

		*terminator = temp;

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_VOID_DEVLINK_FMSG_STRING_PUT)
		if (rc)
			return rc;
#endif
	}

	return 0;
}

int efx_nvlog_to_devlink(struct efx_nvlog_data *nvlog_data,
			 struct devlink_fmsg *fmsg)
{
	int rc;
	char *buffer = nvlog_data->nvlog;
	size_t len = nvlog_data->nvlog_len;
	char *p = memchr(buffer, '\n', len);

	/* Ensure that buffer has space for trailing NULL after len bytes */
	if (len >= nvlog_data->nvlog_max_len)
		len = nvlog_data->nvlog_max_len - 1;
	nvlog_data->nvlog[len] = '\0';

	while (p) {
		p++;
		rc = buffer_to_fmsg_string(fmsg, buffer, p - buffer);
		if (rc)
			goto out;
		len -= p - buffer;
		buffer = p;
		p = memchr(buffer, '\n', len);
	}

	rc = buffer_to_fmsg_string(fmsg, buffer, len);
out:
	return rc;
}
#endif /* EFX_HAVE_DEVLINK_HEALTH_REPORTER */
