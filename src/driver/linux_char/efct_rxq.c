/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <ci/efrm/efrm_client.h>
#include "efch.h"
#include <ci/efrm/vi_resource_manager.h>
#include <ci/efrm/efct_rxq.h>
#include <ci/efch/op_types.h>
#include <ci/efhw/mc_driver_pcol.h>
#include <etherfabric/internal/efct_uk_api.h>
#include "char_internal.h"
#include <kernel_utils/hugetlb.h>
#include "linux_char_internal.h"
#include <ci/efch/mmap.h>
#include <ci/efhw/efct.h>




/* ************************************************************************ */
/*                            ioctl interface                               */

static int
rxq_rm_alloc(ci_resource_alloc_t* alloc_, ci_resource_table_t* priv_opt,
             efch_resource_t* rs, int intf_ver_id)
{
  struct efch_efct_rxq_alloc* alloc = &alloc_->u.rxq;
  struct efrm_efct_rxq* rxq;
  struct efrm_vi* vi;
  struct oo_hugetlb_allocator *hugetlb_alloc = NULL;
  efch_resource_t* vi_rs;
  int shm_ix;
  int rc;

  if ((alloc->in_flags & ~EFCH_EFCT_RXQ_GOOD_FLAGS) != 0) {
    EFCH_ERR("%s: ERROR: flags = 0x%x != 0", __FUNCTION__, alloc->in_flags);
    return -EINVAL;
  }

  /* NB: we'd need to do more with this once we actually have more than one
   * version */
  if (alloc->in_abi_version > CI_EFCT_SWRXQ_ABI_VERSION) {
    EFCH_ERR("%s: ERROR: ABI version from the future (%u > %d)",
             __FUNCTION__, alloc->in_abi_version, CI_EFCT_SWRXQ_ABI_VERSION);
    return -EINVAL;
  }

  rc = efch_resource_id_lookup(alloc->in_vi_rs_id, priv_opt, &vi_rs);
  if (rc < 0) {
    EFCH_ERR("%s: ERROR: id="EFCH_RESOURCE_ID_FMT" (%d)",
             __FUNCTION__,
             EFCH_RESOURCE_ID_PRI_ARG(alloc->in_vi_rs_id), rc);
    return rc;
  }
  if (vi_rs->rs_base->rs_type != EFRM_RESOURCE_VI) {
    EFCH_ERR("%s: ERROR: id="EFCH_RESOURCE_ID_FMT" is not a VI",
             __FUNCTION__,
             EFCH_RESOURCE_ID_PRI_ARG(alloc->in_vi_rs_id));
    rc = -EINVAL;
    goto out;
  }

  vi = efrm_vi_from_resource(vi_rs->rs_base);

  if( (alloc->in_flags & EFCH_EFCT_RXQ_FLAG_UBUF) == 0 ) {
    if( alloc->in_shm_ix < 0 ) {
      EFCH_ERR("%s: ERROR: id="EFCH_RESOURCE_ID_FMT" provides bad shm ix %d",
               __FUNCTION__,
               EFCH_RESOURCE_ID_PRI_ARG(alloc->in_vi_rs_id), alloc->in_shm_ix);
      rc = -EINVAL;
      goto out;
    }
    shm_ix = alloc->in_shm_ix;

    hugetlb_alloc = oo_hugetlb_allocator_create(alloc->in_memfd);
    if (IS_ERR(hugetlb_alloc)) {
      EFCH_ERR("%s: ERROR: Unable to create hugetlb allocator (%ld)",
               __FUNCTION__, PTR_ERR(hugetlb_alloc));
      rc = PTR_ERR(hugetlb_alloc);
      goto out;
    }
  }
  else {
    shm_ix = -1;
  }

  rc = efrm_rxq_alloc(vi, alloc->in_qid, shm_ix, alloc->in_timestamp_req,
                      !!(alloc->in_flags & EFCH_EFCT_RXQ_FLAG_IRQ),
                      alloc->in_n_hugepages, hugetlb_alloc, &rxq);
  if( (alloc->in_flags & EFCH_EFCT_RXQ_FLAG_UBUF) == 0 )
    oo_hugetlb_allocator_put(hugetlb_alloc);

  if (rc < 0) {
    EFCH_ERR("%s: ERROR: rxq_alloc failed (%d)", __FUNCTION__, rc);
    goto out;
  }

  /* If we have allocated an RXQ which does not use a shared EVQ, we assume it
   * generates RX events into its EVQ. In such a case, we need to perform some
   * accounting of these events to avoid overflowing the EVQ. Since ef_vi does
   * not currently support this mode of operation, the necessary plumbing to
   * configure the starting conditions for such a mode is not in place. Should
   * this ever change, ef_vi would need to grab the inverse of rxq->shared_evq
   * to populate efct_get_rxq_state(vi, ix)->generates-events and also add the
   * number of initial RX packets vi->ep_state->rxq.n_evq_rx_pkts. See also
   * tcp_helper_post_filter_add for how onload does this.
   * Currently, we can safely assume this as the interrupt_req parameter in the
   * above call to efrm_rxq_alloc is false, which implies a shared EVQ. */
  ci_assert(efrm_rxq_get_hw(rxq)->shared_evq);

  rs->rs_base = efrm_rxq_to_resource(rxq);
out:
  efch_resource_put(vi_rs);
  return rc;
}


static void
rxq_rm_free(efch_resource_t* rs)
{
  /* No need to mutex anything here: we're protected by only being callable
   * from userspace via a single ef_driver_handle, so the file lock is
   * guarding us */
  if( rs->rs_base ) {
    efrm_rxq_release(efrm_rxq_from_resource(rs->rs_base));
    rs->rs_base = NULL;
  }
}


static int
rxq_rm_rsops(efch_resource_t* rs, ci_resource_table_t* priv_opt,
             ci_resource_op_t* op, int* copy_out)
{
  struct efrm_efct_rxq* rxq = efrm_rxq_from_resource(rs->rs_base);

  switch (op->op) {
  case CI_RSOP_RXQ_REFRESH:
    return efrm_rxq_refresh(rxq, (uintptr_t)op->u.rxq_refresh.superbufs,
               (uint64_t __user*)(uintptr_t)op->u.rxq_refresh.current_mappings,
               op->u.rxq_refresh.max_superbufs);

  default:
    EFCH_ERR("%s: Invalid op, expected CI_RSOP_RXQ_*", __FUNCTION__);
    return -EINVAL;
  }
}

int efab_rxq_mmap_buffer_post(struct efrm_efct_rxq *rxq,
                              unsigned long *bytes, void *opaque,
                              int *map_num, unsigned long *offset)
{
  int rc;
  size_t len;
  resource_size_t io_addr;
  resource_size_t io_page_addr;
  struct efrm_resource *rs = efrm_rxq_to_resource(rxq);
  struct efhw_nic *nic = efrm_client_get_nic(rs->rs_client);

  if( ! ci_in_egroup(phys_mode_gid) )
    return -EPERM;

  io_addr = efrm_rxq_superbuf_window(rxq);

  len = CI_ROUND_UP(*bytes, (unsigned long)CI_PAGE_SIZE);
  *bytes -= len;

  io_page_addr = io_addr & CI_PAGE_MASK;

  rc = ci_mmap_io(nic, io_page_addr, len, opaque, map_num, offset, 0);
  if( rc < 0 )
    EFCH_ERR("%s: ERROR: ci_mmap_io failed rc=%d", __FUNCTION__, rc);

  return rc;
}
EXPORT_SYMBOL(efab_rxq_mmap_buffer_post);

static int rxq_rm_mmap(struct efrm_resource *rs, unsigned long *bytes,
                       struct vm_area_struct *vma, int index)
{
  int rc = -EINVAL;
  struct efrm_efct_rxq* rxq = efrm_rxq_from_resource(rs);
  int map_num = 0;
  unsigned long offset = 0;

  EFRM_RESOURCE_ASSERT_VALID(rs, 0);
  ci_assert_equal((*bytes &~ CI_PAGE_MASK), 0);

  switch( index ) {
    case EFCH_VI_MMAP_RX_BUFFER_POST:
      rc = efab_rxq_mmap_buffer_post(rxq, bytes, vma, &map_num, &offset);
      break;
    default:
      ci_assert(0);
  }

  return rc;
}


efch_resource_ops efch_efct_rxq_ops = {
  .rm_alloc  = rxq_rm_alloc,
  .rm_free   = rxq_rm_free,
  .rm_mmap   = rxq_rm_mmap,
  .rm_nopage = NULL,
  .rm_dump   = NULL,
  .rm_rsops  = rxq_rm_rsops,
};
