/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

/* Access to kernel resources for kernel efct_ubufs */

#include "ef_vi_internal.h"
#include <linux/slab.h>

void* efct_ubufs_alloc_mem(size_t size)
{
  return kzalloc(size, GFP_KERNEL);
}

void efct_ubufs_free_mem(void* p)
{
  kfree(p);
}

int efct_ubufs_init_rxq_resource(ef_vi *vi, int qid, unsigned n_superbufs)
{
  return -EOPNOTSUPP;
}

int efct_ubufs_init_rxq_buffers(ef_vi* vi, int qid, int ix,
                                int buffers_fd, unsigned n_superbufs,
                                unsigned resource_id,
                                ef_pd* pd, ef_driver_handle pd_dh,
                                volatile uint64_t** post_buffer_reg_out)
{
  return -EOPNOTSUPP;
}

void efct_ubufs_cleanup_rxq(ef_vi* vi, volatile uint64_t* post_buffer_reg)
{
}

int efct_ubufs_set_shared_rxq_token(ef_vi* vi, uint64_t token)
{
  return -EOPNOTSUPP;
}
