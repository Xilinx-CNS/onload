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

int efct_ubufs_init_rxq_resource(ef_vi *vi, int qid, unsigned n_superbufs,
                                 bool interrupt_mode,
                                 efch_resource_id_t* resource_id_out)
{
  return -EOPNOTSUPP;
}

void efct_ubufs_free_resource(ef_vi* vi, efch_resource_id_t id)
{
  /* not supported */
}

int efct_ubufs_init_rxq_buffers(ef_vi* vi, int ix, int fd,
                                unsigned n_superbufs,
                                efch_resource_id_t rxq_id,
                                ef_pd* pd, ef_driver_handle pd_dh,
                                efch_resource_id_t* memreg_id,
                                volatile uint64_t** post_buffer_reg_out)
{
  return -EOPNOTSUPP;
}

void efct_ubufs_free_rxq_buffers(ef_vi* vi, int ix, volatile uint64_t* reg)
{
  /* not supported */
}

int efct_ubufs_set_shared_rxq_token(ef_vi* vi, uint64_t token)
{
  return -EOPNOTSUPP;
}
