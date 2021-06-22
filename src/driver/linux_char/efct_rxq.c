/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <ci/efrm/efrm_client.h>
#include "efch.h"
#include <ci/efrm/pd.h>
#include <ci/efch/op_types.h>
#include <ci/efhw/mc_driver_pcol.h>
#include "char_internal.h"




/* ************************************************************************ */
/*                            ioctl interface                               */

static int
rxq_rm_alloc(ci_resource_alloc_t* alloc_, ci_resource_table_t* priv_opt,
             efch_resource_t* rs, int intf_ver_id)
{
  return -ENOSYS;
}


static void
rxq_rm_free(efch_resource_t* rs)
{
}


static int
rxq_rm_rsops(efch_resource_t* rs, ci_resource_table_t* priv_opt,
             ci_resource_op_t* op, int* copy_out)
{
  switch (op->op) {
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
