/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#ifndef CXL_CACHE_SPM_RESOURCE_H
#define CXL_CACHE_SPM_RESOURCE_H

struct efrm_resource_manager;
struct efrm_cxl_cache_spm_resource;

int
efrm_cxl_cache_spm_resource_manager_ctor(struct efrm_resource_manager **rm_out);

extern int
efrm_cxl_cache_spm_resource_create(struct efrm_cxl_cache_spm_resource** out);
extern void
efrm_cxl_cache_spm_resource_destroy(struct efrm_cxl_cache_spm_resource* spm_rs);

extern struct efrm_resource*
cxl_cache_spm_to_resource(struct efrm_cxl_cache_spm_resource* spm_rs);
extern struct efrm_cxl_cache_spm_resource*
cxl_cache_spm_from_resource(struct efrm_resource* rs);

#endif
