/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include <cxl_cache_spm_manager_priv.h>
#include <ci/efhw/sysdep.h>
#include <ci/compat.h>
#include <ci/efrm/debug_linux.h>

#include <linux/memremap.h>
#include <linux/acpi.h>
#include <linux/types.h>

struct efrm_cxl_cache_region {
  phys_addr_t membase;
  u64 size;
  u32 numa_node;
  void *vaddr;
  struct dev_pagemap pgmap;
};

struct efrm_cxl_cache_spm {
  int n_regions;
  struct efrm_cxl_cache_region *region;
};

static DEFINE_MUTEX(global_cxl_cache_spm_lock);
static struct efrm_cxl_cache_spm *global_cxl_cache_spm;

#define SPMT_SIG "SPMT"
#define SPMT_FLAG_2K_INTLV BIT(2)
#define CXL_CACHE_REGION_NAME "sfc_resource_cxl_cache_region"

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

static int search_for_numa_size(phys_addr_t membase, u64 size, int *out_node,
                                u64 *out_size)
{
  int node_base = phys_to_target_node(membase);
  phys_addr_t high = membase + size;
  phys_addr_t low = membase;

  /* We need NUMA information to make an informed decision about the memory
   * region to provide to users. This information should be programmed into
   * the SRAT table and parsed by the kernel before this point. */
  if( node_base == NUMA_NO_NODE )
    return -EBADSLT;

  /* Search for the start of the next range. This search assumes that memory
   * for each NUMA node is contiguous in the physical region and a NUMA node
   * only appears once in the entire region. */
  while( low < high ) {
    phys_addr_t mid = low + (high - low) / 2;
    int mid_node = phys_to_target_node(mid);

    if( mid_node == node_base )
      low = mid + 1;
    else
      high = mid;
  }

  *out_node = node_base;
  *out_size = high - membase;

  return 0;
}

static int efrm_split_cxl_cache_spmt_range(struct efrm_cxl_cache_spm *spm,
                                           phys_addr_t membase, u64 size)
{
  while( size > 0 ) {
    u64 node_size;
    int node;
    int rc;

    rc = search_for_numa_size(membase, size, &node, &node_size);
    if( rc < 0 )
      return rc;

    if( node < 0 || node >= spm->n_regions )
      return -ENODEV;

    if( node_size == 0 )
      return -ENOMEM;

    /* We expect only one range per NUMA node */
    if( spm->region[node].size )
      return -EALREADY;

    spm->region[node].membase = membase;
    spm->region[node].size = node_size;
    spm->region[node].numa_node = node;

    EFRM_NOTICE("%s: found CXL.cache SPM region for node %d base %llx size %llx",
                __FUNCTION__, node, membase, node_size);

    membase += node_size;
    size -= node_size;
  }

  return 0;
}

static int efrm_cxl_cache_region_register(struct efrm_cxl_cache_region *region)
{
  int rc = 0;

  /* If this region has no size then there's nothing to register. */
  if( ! region->size )
    return 0;

  if( ! request_mem_region(region->membase, region->size,
                           CXL_CACHE_REGION_NAME) ) {
    rc = -EBUSY;
    EFRM_ERR("%s: failed to request memory region", __FUNCTION__);
    goto fail_out;
  }

  region->pgmap.type = MEMORY_DEVICE_GENERIC;
  region->pgmap.range.start = region->membase;
  region->pgmap.range.end = region->membase + region->size - 1;
  region->pgmap.nr_range = 1;
  region->pgmap.owner = THIS_MODULE;

  region->vaddr = memremap_pages(&region->pgmap, region->numa_node);
  if( IS_ERR(region->vaddr) ) {
    rc = PTR_ERR(region->vaddr);
    EFRM_ERR("%s: failed to remap pages, rc=%d", __FUNCTION__, rc);
    goto fail_memremap_pages;
  }

  return rc;

fail_memremap_pages:
  release_mem_region(region->membase, region->size);
fail_out:
  return rc;
}

static void efrm_cxl_cache_region_release(struct efrm_cxl_cache_region *region)
{
  if( region->size ) {
    memunmap_pages(&region->pgmap);
    release_mem_region(region->membase, region->size);
  }
}

void efrm_cxl_cache_spm_discover(void)
{
  phys_addr_t cxl_cache_spm_membase;
  struct efrm_cxl_cache_spm *spm;
  u64 cxl_cache_spm_size;
  int rc;
  int i;

  mutex_lock(&global_cxl_cache_spm_lock);
  BUG_ON(global_cxl_cache_spm != NULL);

  rc = efrm_find_cxl_cache_spmt_range(&cxl_cache_spm_membase,
                                      &cxl_cache_spm_size);
  if( rc < 0 ) {
    EFRM_ERR("%s: failed to find region, rc=%d", __FUNCTION__, rc);
    goto out;
  }

  spm = kzalloc(sizeof(*spm), GFP_KERNEL);
  if( !spm ) {
    EFRM_ERR("%s: failed to allocate memory for SPM data", __FUNCTION__);
    goto out;
  }

  spm->n_regions = nr_node_ids;
  spm->region = kzalloc(sizeof(*spm->region) * spm->n_regions, GFP_KERNEL);
  if( ! spm->region ) {
    EFRM_ERR("%s: failed to allocate memory for region data", __FUNCTION__);
    goto fail_region_alloc;
  }

  rc = efrm_split_cxl_cache_spmt_range(spm, cxl_cache_spm_membase,
                                       cxl_cache_spm_size);
  if( rc < 0 ) {
    EFRM_ERR("%s: failed to split memory into NUMA nodes", __FUNCTION__);
    goto fail_split_range;
  }

  for( i = 0; i < spm->n_regions; i++ ) {
    rc = efrm_cxl_cache_region_register(&spm->region[i]);
    if( rc < 0 ) {
      EFRM_ERR("%s: failed to register CXL.cache region %d/%d, rc=%d",
               __FUNCTION__, i + 1, spm->n_regions, rc);
      goto fail_register_regions;
    }
  }

  global_cxl_cache_spm = spm;
  goto out;

fail_register_regions:
  for( i--; i >= 0; i-- )
    efrm_cxl_cache_region_release(&spm->region[i]);
fail_split_range:
  kfree(spm->region);
fail_region_alloc:
  kfree(spm);
out:
  mutex_unlock(&global_cxl_cache_spm_lock);
}

void efrm_cxl_cache_spm_free(void)
{
  int i;

  mutex_lock(&global_cxl_cache_spm_lock);

  if( ! global_cxl_cache_spm )
    goto out;

  for( i = 0; i < global_cxl_cache_spm->n_regions; i++ )
    efrm_cxl_cache_region_release(&global_cxl_cache_spm->region[i]);

  kfree(global_cxl_cache_spm->region);
  kfree(global_cxl_cache_spm);
  global_cxl_cache_spm = NULL;

out:
  mutex_unlock(&global_cxl_cache_spm_lock);
}
