/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#ifndef EFRM_CXL_CACHE_SPM_MANAGER_H
#define EFRM_CXL_CACHE_SPM_MANAGER_H

extern int efrm_cxl_cache_spm_exists(void);

/* Allocates `n_pages` contiguously from `spm` and returns the first page frame
 * number of the contiguous region. */
extern int efrm_cxl_cache_spm_pages_allocate(int *numa_node,
                                             unsigned long n_pages,
                                             unsigned long *first_pfn_out);
extern int efrm_cxl_cache_spm_pages_free(int numa_node,
                                         unsigned long n_pages,
                                         unsigned long first_pfn);

#endif
