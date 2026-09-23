/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#ifndef EF_CXL_CACHE_SPM_H
#define EF_CXL_CACHE_SPM_H

#include <etherfabric/base.h>
#include <ci/efch/op_types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ef_cxl_cache_spm {
  efch_resource_id_t res_id;
  ef_driver_handle dh;
} ef_cxl_cache_spm;

/* TODO: docs */
extern int ef_cxl_cache_spm_allocator_create(ef_cxl_cache_spm* spm,
                                             ef_driver_handle spm_dh);

/* TODO: docs */
extern int ef_cxl_cache_spm_allocate(ef_cxl_cache_spm* spm, size_t len_bytes,
                                     void** alloc_out);

/* TODO: docs */
extern int ef_cxl_cache_spm_free(ef_cxl_cache_spm* spm, void* allocation,
                                 size_t len_bytes);

#ifdef __cplusplus
}
#endif

#endif
