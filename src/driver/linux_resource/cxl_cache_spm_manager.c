/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include <cxl_cache_spm_manager_priv.h>
#include <ci/efhw/sysdep.h>
#include <ci/compat.h>
#include <ci/efrm/debug_linux.h>

#include <linux/acpi.h>
#include <linux/types.h>

#define SPMT_SIG "SPMT"
#define SPMT_FLAG_2K_INTLV BIT(2)

static int efrm_find_cxl_cache_spmt_range(phys_addr_t *membase, u64 *size)
{
  struct acpi_table_header *table = NULL;
  struct __packed spmt_entry_raw {
    u64 base;
    u64 len;
    u8 owner_guid[16];
    u8 owner_name[16];
    u32 flags;
    u32 reserved;
  } *entry;
  const char x4_name[] = "X4_NIC";
  const u8 x4_guid[16] = {
    0x78, 0x56, 0x34, 0x12, 0xCD, 0xAB, 0x01, 0xEF,
    0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
  };
  acpi_status status;
  u8 *payload;
  u32 count;
  int rc = -ENOKEY;
  u32 i;

  status = acpi_get_table(SPMT_SIG, 0, &table);
  if( ACPI_FAILURE(status) )
    return -ENODATA;

  /* We need the table to be long enough to encompass the header as well as the
   * following 8 bytes (4 bytes of "TableRevision" and 4 bytes of "count"). */
  if( table->length < sizeof(struct acpi_table_header) + 8 ) {
    EFRM_ERR("%s: CXL.cache SPMT too small (%d bytes)", __FUNCTION__,
              table->length);
    rc = -ENOMSG;
    goto out;
  }

  payload = (u8*)table + sizeof(struct acpi_table_header) + 4;
  count = le32_to_cpup((const __le32*)payload);
  payload += 4;

  count = CI_MIN((table->length - ((u8*)payload - (u8*)table)) / sizeof(*entry),
                 count);
  entry = (struct spmt_entry_raw*)payload;
  for( i = 0; i < count; i++ ) {
    if( memcmp(entry[i].owner_guid, x4_guid, sizeof(x4_guid)) == 0 &&
        memcmp(entry[i].owner_name, x4_name, sizeof(x4_name)) == 0 &&
        entry[i].flags & SPMT_FLAG_2K_INTLV ) {
      *membase = le64_to_cpu(entry[i].base);
      *size = le64_to_cpu(entry[i].len);
      EFRM_NOTICE("%s: found CXL.cache SPM region base %llx size %llx",
                  __FUNCTION__, *membase, *size);
      rc = 0;
      goto out;
    }
  }

out:
  acpi_put_table(table);
  return rc;
}

void efrm_cxl_cache_spm_discover(void)
{
  phys_addr_t cxl_cache_spm_membase;
  u64 cxl_cache_spm_size;
  int rc;

  rc = efrm_find_cxl_cache_spmt_range(&cxl_cache_spm_membase,
                                      &cxl_cache_spm_size);
  if( rc < 0 ) {
    EFRM_ERR("%s: failed to find region, rc=%d", __FUNCTION__, rc);
  }
}
