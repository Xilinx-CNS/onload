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




/* ************************************************************************ */
/*                            ioctl interface                               */

static int
rxq_rm_alloc(ci_resource_alloc_t* alloc_, ci_resource_table_t* priv_opt,
             efch_resource_t* rs, int intf_ver_id)
{
  struct efch_efct_rxq_alloc* alloc = &alloc_->u.rxq;
  struct efrm_efct_rxq* rxq;
  struct efrm_vi* vi;
  struct oo_hugetlb_allocator *hugetlb_alloc;
  efch_resource_t* vi_rs;
  int rc;

  if (alloc->in_flags != 0) {
    EFCH_ERR("%s: ERROR: flags != 0", __FUNCTION__);
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
    return -EINVAL;
  }

  vi = efrm_vi_from_resource(vi_rs->rs_base);

  hugetlb_alloc = oo_hugetlb_allocator_create(alloc->in_memfd);
  if (IS_ERR(hugetlb_alloc)) {
    EFCH_ERR("%s: ERROR: Unable to create hugetlb allocator (%ld)",
             __FUNCTION__, PTR_ERR(hugetlb_alloc));
    return PTR_ERR(hugetlb_alloc);
  }

  rc = efrm_rxq_alloc(vi, alloc->in_qid, alloc->in_shm_ix,
                      alloc->in_timestamp_req, alloc->in_n_hugepages,
                      hugetlb_alloc, &rxq);
  oo_hugetlb_allocator_put(hugetlb_alloc);

  if (rc < 0) {
    EFCH_ERR("%s: ERROR: rxq_alloc failed (%d)", __FUNCTION__, rc);
    return rc;
  }

  rs->rs_base = efrm_rxq_to_resource(rxq);
  return 0;
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


efch_resource_ops efch_efct_rxq_ops = {
  .rm_alloc  = rxq_rm_alloc,
  .rm_free   = rxq_rm_free,
  .rm_mmap   = NULL,
  .rm_nopage = NULL,
  .rm_dump   = NULL,
  .rm_rsops  = rxq_rm_rsops,
};
