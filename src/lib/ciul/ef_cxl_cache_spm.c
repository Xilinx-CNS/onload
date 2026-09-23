/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include <ci/efrm/resource_id.h>
#include "ef_vi_internal.h"
#include <ci/efch/op_types.h>
#include "driver_access.h"
#include <etherfabric/ef_cxl_cache_spm.h>

int ef_cxl_cache_spm_allocator_create(ef_cxl_cache_spm* spm,
                                      ef_driver_handle spm_dh)
{
  ci_resource_alloc_t ra;
  int rc;

  ef_vi_init_resource_alloc(&ra, EFRM_RESOURCE_CXL_CACHE_SPM);
  rc = ci_resource_alloc(spm_dh, &ra);
  if( rc < 0 )
    return rc;

  memset(spm, 0, sizeof(*spm));
  spm->res_id = ra.out_id;
  spm->dh = spm_dh;

  return 0;
}

int ef_cxl_cache_spm_allocate(ef_cxl_cache_spm* spm, size_t len_bytes,
                              void** alloc_out)
{
  unsigned int map_id = 0;
  return ci_resource_mmap(spm->dh, spm->res_id.index, map_id, len_bytes,
                          alloc_out);
}

int ef_cxl_cache_spm_free(ef_cxl_cache_spm* spm, void* allocation,
                          size_t len_bytes)
{
  return ci_resource_munmap(spm->dh, allocation, len_bytes);
}

