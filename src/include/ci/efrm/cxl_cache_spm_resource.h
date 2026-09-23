/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#ifndef CXL_CACHE_SPM_RESOURCE_H
#define CXL_CACHE_SPM_RESOURCE_H

struct efrm_resource_manager;

int
efrm_cxl_cache_spm_resource_manager_ctor(struct efrm_resource_manager **rm_out);

#endif
