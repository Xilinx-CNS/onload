/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

/* Access to kernel resources for userland efct_ubufs */

#include <etherfabric/memreg.h>
#include <etherfabric/internal/efct_uk_api.h>
#include <sys/mman.h>
#include <linux/mman.h>
#include "ef_vi_internal.h"
#include "driver_access.h"
#include "logging.h"

void* efct_ubufs_alloc_mem(size_t size)
{
  return calloc(size, 1);
}

void efct_ubufs_free_mem(void* p)
{
  return free(p);
}

void efct_ubufs_post_kernel(ef_vi* vi, int ix, int sbid, bool sentinel)
{
  ef_addr addr = efct_rx_desc_for_sb(vi, ix, sbid)->dma_addr;

  ci_resource_op_t op = {};

  op.op = CI_RSOP_RX_BUFFER_POST;
  op.id = efch_make_resource_id(vi->vi_resource_id);
  op.u.buffer_post.qid = efct_get_rxq_state(vi, ix)->qid;
  op.u.buffer_post.user_addr = (uint64_t)addr;
  op.u.buffer_post.sentinel = sentinel;
  op.u.buffer_post.rollover = 0; // TBD support for rollover?

  /* TBD should we handle/report errors? */
  ci_resource_op(vi->dh, &op);
}

int efct_ubufs_init_rxq_resource(ef_vi *vi, int qid, unsigned n_superbufs)
{
  int rc;
  ci_resource_alloc_t ra;
  unsigned n_hugepages = (n_superbufs + CI_EFCT_SUPERBUFS_PER_PAGE - 1) /
                          CI_EFCT_SUPERBUFS_PER_PAGE;

  ef_vi_init_resource_alloc(&ra, EFRM_RESOURCE_EFCT_RXQ);
  ra.u.rxq.in_abi_version = CI_EFCT_SWRXQ_ABI_VERSION;
  ra.u.rxq.in_flags = EFCH_EFCT_RXQ_FLAG_UBUF;
  ra.u.rxq.in_qid = qid;
  ra.u.rxq.in_shm_ix = -1;
  ra.u.rxq.in_vi_rs_id = efch_make_resource_id(vi->vi_resource_id);
  ra.u.rxq.in_n_hugepages = n_hugepages;
  ra.u.rxq.in_timestamp_req = true;
  rc = ci_resource_alloc(vi->dh, &ra);
  if( rc < 0 ) {
    LOGVV(ef_log("%s: ci_resource_alloc rxq %d", __FUNCTION__, rc));
    return rc;
  }
  return ra.out_id.index;
}

int efct_ubufs_init_rxq_buffers(ef_vi* vi, int qid, int ix, int fd,
                                unsigned n_superbufs, unsigned resource_id,
                                ef_pd* pd, ef_driver_handle pd_dh,
                                volatile uint64_t** post_buffer_reg_out)
{
  int rc, sb;
  void* map;
  ef_memreg memreg;

  int flags = (fd < 0 ? MAP_PRIVATE | MAP_ANONYMOUS : MAP_SHARED);
  size_t map_bytes = CI_ROUND_UP((size_t)n_superbufs * EFCT_RX_SUPERBUF_BYTES,
                                 CI_HUGEPAGE_SIZE);

  map = mmap((void*)vi->efct_rxqs.q[ix].superbuf, map_bytes,
             PROT_READ | PROT_WRITE,
             flags  | MAP_NORESERVE | MAP_HUGETLB | MAP_HUGE_2MB |
             MAP_FIXED | MAP_POPULATE,
             fd, 0);
  if( map == MAP_FAILED )
    return -errno;
  if( map != vi->efct_rxqs.q[ix].superbuf ) {
    munmap(map, map_bytes);
    return -ENOMEM;
  }

  rc = ef_memreg_alloc_flags(&memreg, vi->dh, pd, pd_dh, map, map_bytes, 0);
  if( rc < 0 ) {
    munmap(map, map_bytes);
    LOG(ef_log("%s: Unable to alloc buffers (%d). Are sufficient hugepages available?",
               __FUNCTION__, rc));
    return rc;
  }

  for( sb = 0; sb < n_superbufs; ++sb )
    efct_rx_desc_for_sb(vi, ix, sb)->dma_addr =
      ef_memreg_dma_addr(&memreg, sb * EFCT_RX_SUPERBUF_BYTES);

  ef_memreg_free(&memreg, vi->dh);

  if( vi->vi_flags & EF_VI_RX_PHYS_ADDR ) {
    void *p;

    rc = ci_resource_mmap(vi->dh, resource_id, EFCH_VI_MMAP_RX_BUFFER_POST,
                          CI_ROUND_UP(sizeof(uint64_t), CI_PAGE_SIZE),
                          &p);
    if( rc < 0 ) {
      munmap(map, map_bytes);
      return rc;
    }
    *post_buffer_reg_out = (volatile uint64_t *)p;
  }

  return 0;
}

void efct_ubufs_cleanup_rxq(ef_vi* vi, volatile uint64_t* post_buffer_reg)
{
  if( post_buffer_reg != NULL )
    ci_resource_munmap(vi->dh, (void*)post_buffer_reg,
                       CI_ROUND_UP(sizeof(uint64_t), CI_PAGE_SIZE));
}

int efct_ubufs_set_shared_rxq_token(ef_vi* vi, uint64_t token)
{
  ci_resource_op_t op = {};
  op.op = CI_RSOP_SHARED_RXQ_TOKEN_SET;
  op.id = efch_make_resource_id(vi->vi_resource_id);
  op.u.shared_rxq_tok_set.token = token;
  return ci_resource_op(vi->dh, &op);
}
