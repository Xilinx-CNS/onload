/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2012-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  David Riddoch <driddoch@solarflare.com>
**  \brief  Registered memory.
**   \date  2012/02/06
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <ci/efhw/common.h>
#include <etherfabric/base.h>
#include <etherfabric/memreg.h>
#include <etherfabric/pd.h>
#include "ef_vi_internal.h"
#include "driver_access.h"
#include "logging.h"


static int memreg_alloc(ef_driver_handle mr_dh,
                        ef_pd* pd, ef_driver_handle pd_dh,
                        ef_addr* dma_addrs, char* chunk_start, char* chunk_end)
{
  ci_resource_alloc_t ra;

  /* For a pd in a cluster, use the handle from clusterd */
  if( pd->pd_cluster_sock != -1 )
    pd_dh = pd->pd_cluster_dh;

  memset(&ra, 0, sizeof(ra));
  ef_vi_set_intf_ver(ra.intf_ver, sizeof(ra.intf_ver));
  ra.ra_type = EFRM_RESOURCE_MEMREG;
  ra.u.memreg.in_vi_or_pd_id = efch_make_resource_id(pd->pd_resource_id);
  ra.u.memreg.in_vi_or_pd_fd = pd_dh;
  ra.u.memreg.in_mem_ptr = (uintptr_t) chunk_start;
  ra.u.memreg.in_mem_bytes = chunk_end - chunk_start;
  ra.u.memreg.in_addrs_out_ptr = (uintptr_t) dma_addrs;
  ra.u.memreg.in_addrs_out_stride = sizeof(dma_addrs[0]);

  return ci_resource_alloc(mr_dh, &ra);
}


int ef_memreg_alloc(ef_memreg* mr, ef_driver_handle mr_dh, 
                    ef_pd* pd, ef_driver_handle pd_dh,
                    void* p_mem, size_t len_bytes)
{
  /* The memory region must be aligned on a 4K boundary. */
  if( ((uintptr_t) p_mem & (EFHW_NIC_PAGE_SIZE - 1)) != 0 )
    return -EINVAL;

  /* Note: At time of writing the driver rounds the registered region to
   * whole system pages.  It then writes a DMA address for each 4K page
   * within the system-aligned region.  This means that on PPC (where
   * system page size is 64K) we potentially get a bunch of DMA addresses
   * for 4K pages before the region we're registering.
   */
  char* p_mem_sys_base = (void*) ((uintptr_t) p_mem & CI_PAGE_MASK);
  char* p_end = (char*) p_mem + len_bytes;
  char* p_mem_sys_end = CI_PTR_ALIGN_FWD(p_end, CI_PAGE_SIZE);
  size_t sys_len = p_mem_sys_end - p_mem_sys_base;
  size_t n_nic_pages = sys_len >> EFHW_NIC_PAGE_SHIFT;

  mr->mr_dma_addrs_base = malloc(n_nic_pages * sizeof(mr->mr_dma_addrs[0]));
  if( mr->mr_dma_addrs_base == NULL )
    return -ENOMEM;

  /* In openonload-201509-u2 and earlier the driver has an overflow bug so
   * that registering >= 4GiB goes wrong.  We work around this bug here,
   * with some care to ensure we register chunks that are nicely aligned to
   * take advantage of large NIC page sizes.
   */
  char* chunk_start = p_mem_sys_base;
  char* chunk_end = p_mem_sys_end;
  size_t align = 1 << 22;
  size_t max_chunk = ((uint64_t) 1u << 32) - align;
  if( chunk_end - chunk_start >= ((uint64_t) 1u << 32) ) {
    chunk_end = chunk_start + max_chunk;
    chunk_end = CI_PTR_ALIGN_BACK(chunk_end, align);
  }
  ef_addr* dma_addrs = mr->mr_dma_addrs_base;

  do {
    LOGVVV(ef_log("ef_memreg_alloc(base=%p, len=%zu): chunk=%p+%zu\n",
		  p_mem, len_bytes, chunk_start, chunk_end - chunk_start));
    int rc = memreg_alloc(mr_dh, pd, pd_dh, dma_addrs, chunk_start, chunk_end);
    if( rc < 0 ) {
      LOGVV(ef_log("ef_memreg_alloc(base=%p, len=%zu): ERROR: chunk=%p-%p "
		   "rc=%d", p_mem, len_bytes, chunk_start, chunk_end, rc));
      free(mr->mr_dma_addrs_base);
      return rc;
    }
    dma_addrs += (chunk_end - chunk_start) >> EFHW_NIC_PAGE_SHIFT;
    chunk_start = chunk_end;
    if( p_mem_sys_end - chunk_start <= max_chunk )
      chunk_end = p_mem_sys_end;
    else
      chunk_end = chunk_start + max_chunk;
  } while( chunk_start < p_mem_sys_end );

  mr->mr_dma_addrs = mr->mr_dma_addrs_base;
  mr->mr_dma_addrs += ((char*) p_mem - p_mem_sys_base) >> EFHW_NIC_PAGE_SHIFT;
  return 0;
}


int ef_memreg_free(ef_memreg* mr, ef_driver_handle mr_dh)
{
  free(mr->mr_dma_addrs_base);
  EF_VI_DEBUG(memset(mr, 0, sizeof(*mr)));
  return 0;
}
