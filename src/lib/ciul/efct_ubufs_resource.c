/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

/* Access to kernel resources for userland efct_ubufs */

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

int efct_ubufs_init_rxq_resource(ef_vi *vi, int qid, unsigned n_superbufs,
                                 bool interrupt_mode,
                                 efch_resource_id_t* resource_id_out)
{
  int rc;
  ci_resource_alloc_t ra;
  unsigned n_hugepages = (n_superbufs + CI_EFCT_SUPERBUFS_PER_PAGE - 1) /
                          CI_EFCT_SUPERBUFS_PER_PAGE;

  ef_vi_init_resource_alloc(&ra, EFRM_RESOURCE_EFCT_RXQ);
  ra.u.rxq.in_abi_version = CI_EFCT_SWRXQ_ABI_VERSION;
  ra.u.rxq.in_flags = EFCH_EFCT_RXQ_FLAG_UBUF |
                      (interrupt_mode ? EFCH_EFCT_RXQ_FLAG_IRQ : 0);
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

  *resource_id_out = ra.out_id;
  return 0;
}

void efct_ubufs_free_resource(ef_vi* vi, efch_resource_id_t resource_id)
{
  ci_resource_free_t op = {};

  if( efch_resource_id_is_none(resource_id) )
    return;

  op.id = resource_id;
  ci_resource_free(vi->dh, &op);
}

static int memreg_alloc(ef_driver_handle vi_dh,
                        ef_pd* pd, ef_driver_handle pd_dh,
                        void* start, size_t bytes,
                        ef_addr* dma_addrs_out,
                        efch_resource_id_t* memreg_id_out)
{
  int rc;
  ci_resource_alloc_t ra;

  ef_vi_init_resource_alloc(&ra, EFRM_RESOURCE_MEMREG);
  ra.u.memreg.in_vi_or_pd_id = efch_make_resource_id(pd->pd_resource_id);
  ra.u.memreg.in_vi_or_pd_fd = pd_dh;
  ra.u.memreg.in_mem_ptr = (uintptr_t) start;
  ra.u.memreg.in_mem_bytes = bytes;
  ra.u.memreg.in_addrs_out_ptr = (uintptr_t) dma_addrs_out;
  ra.u.memreg.in_addrs_out_stride = sizeof(ef_addr);
  ra.u.memreg.in_flags = 0;

  rc = ci_resource_alloc(vi_dh, &ra);
  if( rc == 0 )
    *memreg_id_out = ra.out_id;
  return rc;
}

int efct_ubufs_init_rxq_buffers(ef_vi* vi, int ix, int fd,
                                unsigned n_superbufs,
                                efch_resource_id_t rxq_id,
                                ef_pd* pd, ef_driver_handle pd_dh,
                                efch_resource_id_t* memreg_id_out,
                                volatile uint64_t** post_buffer_reg_out)
{
  int rc, sb;
  void* map;
  ef_addr* dma_addrs;

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
    /* Paranoia: unmap the memory and bail if MAP_FIXED did the wrong thing */
    munmap(map, map_bytes);
    return -ENOMEM;
  }

  dma_addrs = malloc((map_bytes >> EF_VI_NIC_PAGE_SHIFT) * sizeof(ef_addr));
  if( dma_addrs == NULL ) {
    rc = -ENOMEM;
    goto fail;
  }

  rc = memreg_alloc(vi->dh, pd, pd_dh, map, map_bytes, dma_addrs, memreg_id_out);
  if( rc < 0 ) {
    LOG(ef_log("%s: Unable to alloc buffers (%d). Are sufficient hugepages available?",
               __FUNCTION__, rc));
    goto fail;
  }

  for( sb = 0; sb < n_superbufs; ++sb )
    efct_rx_desc_for_sb(vi, ix, sb)->dma_addr =
      dma_addrs[sb * (EFCT_RX_SUPERBUF_BYTES >> EF_VI_NIC_PAGE_SHIFT)];

  free(dma_addrs);

  if( vi->vi_flags & EF_VI_RX_PHYS_ADDR ) {
    void *p;

    rc = ci_resource_mmap(vi->dh, rxq_id.index, EFCH_VI_MMAP_RX_BUFFER_POST,
                          CI_ROUND_UP(sizeof(uint64_t), CI_PAGE_SIZE),
                          &p);
    if( rc < 0 )
      goto fail;

    *post_buffer_reg_out = (volatile uint64_t *)p;
  }

  return 0;

fail:
  efct_ubufs_free_rxq_buffers(vi, ix, NULL);
  return rc;
}

void efct_ubufs_free_rxq_buffers(ef_vi* vi, int ix,
                                 volatile uint64_t* post_buffer_reg)
{
  if( post_buffer_reg != NULL )
    ci_resource_munmap(vi->dh, (void*)post_buffer_reg,
                       CI_ROUND_UP(sizeof(uint64_t), CI_PAGE_SIZE));

  /* Don't unmap the buffer memory as we want to keep the address space
   * reserved, and re-use it when attaching to another queue. Replace it
   * with an inaccessible mapping to release the buffer pages. */
  mmap((void*)vi->efct_rxqs.q[ix].superbuf,
       (size_t)CI_EFCT_MAX_SUPERBUFS * EFCT_RX_SUPERBUF_BYTES,
       PROT_NONE,
       MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE |
                   MAP_HUGETLB | MAP_HUGE_2MB,
       -1, 0);
}

int efct_ubufs_set_shared_rxq_token(ef_vi* vi, uint64_t token)
{
  ci_resource_op_t op = {};
  op.op = CI_RSOP_SHARED_RXQ_TOKEN_SET;
  op.id = efch_make_resource_id(vi->vi_resource_id);
  op.u.shared_rxq_tok_set.token = token;
  return ci_resource_op(vi->dh, &op);
}
