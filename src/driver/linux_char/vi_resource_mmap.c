/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2006-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  ndt
**  \brief  Memory mapping of the VI resources.
**   \date  2006/10/19
**    \cop  (c) Solarflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_driver_efab */

#include <ci/driver/internal.h>
#include <ci/driver/efab/hardware.h>
#include <ci/driver/resource/linux_efhw_nic.h>
#include <ci/efrm/vi_resource_manager.h>
#include <ci/efrm/efrm_client.h>
#include <etherfabric/internal/internal.h>
#include <etherfabric/internal/efct_uk_api.h>
#include <ci/efch/mmap.h>
#include "linux_char_internal.h"
#include "char_internal.h"


/*************************************************************************/


static int
efab_vi_rm_mmap_io(struct efrm_vi *virs,
                   unsigned long *bytes, void *opaque,
                   int *map_num, unsigned long *offset)
{
  int rc;
  int len;
  int instance;
  int base;
  unsigned vi_stride;
  struct efhw_nic *nic;

  nic = efrm_client_get_nic(virs->rs.rs_client);
  if( efhw_nic_vi_io_size(nic) == 0 )
    return 0;

  instance = virs->rs.rs_instance;

  len = CI_MIN(*bytes, (unsigned long)CI_PAGE_SIZE);
  *bytes -=len;

  /* Make sure we can get away with a single page here. */
  switch (nic->devtype.arch) {
  case EFHW_ARCH_EF10:
    vi_stride = nic->vi_stride;
    ci_assert_lt(ef10_tx_dma_page_offset(vi_stride, instance), CI_PAGE_SIZE);
    ci_assert_lt(ef10_rx_dma_page_offset(vi_stride, instance), CI_PAGE_SIZE);
    ci_assert_equal(ef10_tx_dma_page_base(vi_stride, instance),
                    ef10_rx_dma_page_base(vi_stride, instance));
    base = ef10_tx_dma_page_base(vi_stride, instance);
    break;

  case EFHW_ARCH_EF100:
    vi_stride = nic->vi_stride;
    ci_assert_lt(ef100_tx_dma_page_offset(vi_stride, instance), CI_PAGE_SIZE);
    ci_assert_lt(ef100_rx_dma_page_offset(vi_stride, instance), CI_PAGE_SIZE);
    ci_assert_equal(ef100_tx_dma_page_base(vi_stride, instance),
                    ef100_rx_dma_page_base(vi_stride, instance));
    base = ef100_tx_dma_page_base(vi_stride, instance);
    break;

  default:
    EFCH_ERR("%s: ERROR: unknown nic type (%d)", __FUNCTION__,
	     nic->devtype.arch);
    base = 0; /* To quiet the compiler */
    BUG();
  }

  rc = ci_mmap_io(nic, nic->ctr_ap_dma_addr + base, len, opaque, map_num,
                  offset, 0);
  if (rc < 0 ) {
    EFCH_ERR("%s: ERROR: ci_mmap_bar failed rc=%d", __FUNCTION__, rc);
    return rc;
  }

  return 0;
}

static int
efab_vi_rm_mmap_pio(struct efrm_vi *virs,
		    unsigned long *bytes, void *opaque,
		    int *map_num, unsigned long *offset)
{
  int rc;
  int len;
  int instance;
  struct efhw_nic *nic;
  int bar_off;

  nic = efrm_client_get_nic(virs->rs.rs_client);

  if( nic->devtype.arch != EFHW_ARCH_EF10 ) {
    EFRM_ERR("%s: Only ef10 supports PIO."
	     "  Expected arch=%d but got %d\n", __FUNCTION__,
	     EFHW_ARCH_EF10, nic->devtype.arch);
    return -EINVAL;
  }

  instance = virs->rs.rs_instance;

  /* Map the control page. */
  len = CI_MIN(*bytes, (unsigned long)CI_PAGE_SIZE);
  *bytes -= len;
  bar_off = (ef10_tx_dma_page_base(nic->vi_stride, instance) + 4096) &
            PAGE_MASK;
  rc = ci_mmap_io(nic, nic->ctr_ap_dma_addr + bar_off, len, opaque, map_num,
                  offset, 1);
  if( rc < 0 )
    EFCH_ERR("%s: ERROR: ci_mmap_io failed rc=%d", __FUNCTION__, rc);
  return rc;
}


static int
efab_vi_rm_mmap_ctpio(struct efrm_vi *virs, unsigned long *bytes, void *opaque,
                      int *map_num, unsigned long *offset)
{
  int rc;
  int len;
  int instance;
  struct efhw_nic *nic;
  resource_size_t ctpio_addr;
  resource_size_t ctpio_page_addr;

  instance = virs->rs.rs_instance;

  if( ! (virs->flags & EFHW_VI_TX_CTPIO) ) {
    EFRM_ERR("%s: CTPIO is not enabled on VI instance %d\n", __FUNCTION__,
	     instance);
    return -EINVAL;
  }

  /* Map the CTPIO region. */
  len = CI_MIN(*bytes, (unsigned long)CI_PAGE_SIZE);
  *bytes -= len;
  nic = efrm_client_get_nic(virs->rs.rs_client);

  rc = efhw_nic_ctpio_addr(nic, efrm_vi_qid(virs, EFHW_TXQ), &ctpio_addr);
  if( rc < 0 ) {
    EFRM_ERR("%s: CTPIO is not available on TXQ %d\n", __FUNCTION__,
	     efrm_vi_qid(virs, EFHW_TXQ));
    return rc;
  }

  ctpio_page_addr = ctpio_addr & PAGE_MASK;
  rc = ci_mmap_io(nic, ctpio_page_addr, len, opaque, map_num, offset, 1);
  if( rc < 0 )
    EFCH_ERR("%s: ERROR: ci_mmap_io failed rc=%d", __FUNCTION__, rc);
  return rc;
}


static int
efab_vi_rm_mmap_plugin(struct efrm_vi *virs, unsigned subpage,
                       unsigned long *bytes, void *opaque,
                       int *map_num, unsigned long *offset)
{
  int rc;
  int instance = virs->rs.rs_instance;
  struct efhw_nic *nic = efrm_client_get_nic(virs->rs.rs_client);
  off_t io_off = nic->vi_stride * instance + subpage * PAGE_SIZE;

  /* More checking should be here, to avoid mapping non-plugin regions */
  if( subpage == 0 || subpage >= nic->vi_stride / PAGE_SIZE ||
      *bytes % PAGE_SIZE || subpage * PAGE_SIZE + *bytes > nic->vi_stride ) {
    EFRM_ERR("%s: abuse of plugin mmap\n", __FUNCTION__);
    return -EINVAL;
  }

  rc = ci_mmap_io(nic, nic->ctr_ap_dma_addr + io_off, *bytes, opaque, map_num,
                  offset, 0);
  if( rc < 0 )
    EFCH_ERR("%s: ERROR: ci_mmap_io failed rc=%d", __FUNCTION__, rc);
  else
    *bytes = 0;
  return rc;
}


static int
efab_vi_rm_mmap_state(struct efrm_vi *virs, unsigned long *bytes, void *opaque,
                      int *map_num, unsigned long *offset)
{
  struct vm_area_struct* vma = opaque;
  int rc;
  int len;

  if( ! virs->ep_state )
    return -EINVAL;  /* Someone used an Onload VI rather than an ef_vi one */
  if( *offset != 0 )
    return -EINVAL;
  len = ef_vi_calc_state_bytes(virs->q[EFHW_RXQ].capacity,
                               virs->q[EFHW_TXQ].capacity);
  len = CI_ROUND_UP(len, CI_PAGE_SIZE);
  if( *bytes != len )
    return -EINVAL;

  /* ep_state came from vmalloc_user, which handles most of the safety issues
   * itself (i.e. all memory is zeroed and page-aligned) */
  rc = remap_vmalloc_range(vma, (void*)virs->ep_state, 0);
  if( rc < 0 )
    EFCH_ERR("%s: ERROR: remap_vmalloc_range_partial failed rc=%d",
             __FUNCTION__, rc);
  else
    *bytes -= len;
  return rc;
}


static int
efab_vi_rm_mmap_rxq_shm(struct efrm_vi *virs, unsigned long *bytes,
                        void *opaque, int *map_num, unsigned long *offset)
{
  struct vm_area_struct* vma = opaque;
  int rc;
  int len;

  if( ! virs->efct_shm )
    return -EINVAL;  /* A NIC arch which doesn't have shm */
  len = efrm_vi_get_efct_shm_bytes(virs);
  if( *bytes < len )
    return -EINVAL;

  rc = oo_remap_vmalloc_range_partial(vma, vma->vm_start + *offset,
                                      virs->efct_shm,
                                      DIV_ROUND_UP(len, PAGE_SIZE));
  if( rc < 0 )
    EFCH_ERR("%s: ERROR: remap_vmalloc_range failed rc=%d", __func__, rc);
  else {
    vma->vm_flags &= ~VM_DONTDUMP; /* remap_vmalloc_range_partial sets this */
    *bytes -= len;
    *offset += len;
  }
  return rc;
}


static int 
efab_vi_rm_mmap_mem(struct efrm_vi *virs,
                    unsigned long *bytes, void *opaque,
                    int *map_num, unsigned long *offset)
{
  unsigned long map_bytes = efhw_page_map_bytes(&virs->mem_mmap);

  *bytes -= map_bytes;
  *map_num += virs->mem_mmap.n_lumps;
  *offset += map_bytes;

  return 0;
}

int efab_vi_resource_mmap(struct efrm_vi *virs, unsigned long *bytes,
                          struct vm_area_struct* vma, int *map_num,
                          unsigned long *offset, int index)
{
  int rc = -EINVAL;

  EFRM_RESOURCE_ASSERT_VALID(&virs->rs, 0);
  ci_assert_equal((*bytes &~ CI_PAGE_MASK), 0);

  switch( index ) {
    case EFCH_VI_MMAP_IO:
      rc = efab_vi_rm_mmap_io(virs, bytes, vma, map_num, offset);
      break;
    case EFCH_VI_MMAP_MEM:
      rc = efab_vi_rm_mmap_mem(virs, bytes, vma, map_num, offset);
      break;
    case EFCH_VI_MMAP_PIO:
      rc = efab_vi_rm_mmap_pio(virs, bytes, vma, map_num, offset);
      break;
    case EFCH_VI_MMAP_CTPIO:
      rc = efab_vi_rm_mmap_ctpio(virs, bytes, vma, map_num, offset);
      break;
    case EFCH_VI_MMAP_STATE:
      rc = efab_vi_rm_mmap_state(virs, bytes, vma, map_num, offset);
      break;
    case EFCH_VI_MMAP_RXQ_SHM:
      rc = efab_vi_rm_mmap_rxq_shm(virs, bytes, vma, map_num, offset);
      break;
    case EFCH_VI_MMAP_PLUGIN_BASE ... EFCH_VI_MMAP_PLUGIN_MAX:
      rc = efab_vi_rm_mmap_plugin(virs, index - EFCH_VI_MMAP_PLUGIN_BASE,
                                  bytes, vma, map_num, offset);
      break;
    default:
      ci_assert(0);
  }

  return rc;
}
EXPORT_SYMBOL(efab_vi_resource_mmap);

int
efab_vi_resource_mmap_bytes(struct efrm_vi* virs, int map_type)
{
  int bytes = 0;
  struct efhw_nic *nic = efrm_client_get_nic(virs->rs.rs_client);

  EFRM_RESOURCE_ASSERT_VALID(&virs->rs, 0);

  if( map_type == 0 ) /* I/O mapping. */
    bytes += efhw_nic_vi_io_size(nic);
  else /* Memory mapping. */
    bytes += efhw_page_map_bytes(&virs->mem_mmap);

  /* Round up to whole number of pages. */
  return bytes;
}
EXPORT_SYMBOL(efab_vi_resource_mmap_bytes);


struct page*
efab_vi_resource_nopage(struct efrm_vi *virs, struct vm_area_struct *opaque,
                        unsigned long offset, unsigned long map_size)
{
  return efhw_page_map_page(&virs->mem_mmap, offset >> PAGE_SHIFT);
}
EXPORT_SYMBOL(efab_vi_resource_nopage);


/* ************************************************************************** */

