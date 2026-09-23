/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#ifndef CXL_CACHE_SPM_RESOURCE_H
#define CXL_CACHE_SPM_RESOURCE_H

struct efrm_resource_manager;
struct efrm_cxl_cache_spm_resource;
struct efrm_cxl_cache_spm_allocation;

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

extern int
efrm_cxl_cache_spm_resource_allocate(struct efrm_cxl_cache_spm_resource* spm_rs,
                                     int numa_node, unsigned long n_pages,
                                     struct efrm_cxl_cache_spm_allocation** out);
extern void
efrm_cxl_cache_spm_resource_free(struct efrm_cxl_cache_spm_resource* spm_rs,
                                 struct efrm_cxl_cache_spm_allocation* alloc,
                                 int/*bool*/ locked);
extern void
efrm_cxl_cache_spm_resource_free_all(struct efrm_cxl_cache_spm_resource* spm_rs);

extern struct page**
efrm_cxl_cache_spm_pages(struct efrm_cxl_cache_spm_allocation* allocation);
extern unsigned long
efrm_cxl_cache_spm_num_pages(struct efrm_cxl_cache_spm_allocation* allocation);

#endif
