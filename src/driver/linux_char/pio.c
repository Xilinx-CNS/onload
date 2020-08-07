/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2012-2019 Xilinx, Inc. */
#include <ci/efrm/efrm_client.h>
#include "efch.h"
#include <ci/efrm/pio.h>
#include <ci/efrm/pd.h>
#include <ci/efrm/vi_resource.h>
#include <ci/efch/op_types.h>
#include "char_internal.h"

#include <ci/driver/driverlink_api.h>


static int
pio_rm_alloc(ci_resource_alloc_t* alloc_, ci_resource_table_t* priv_opt,
	     efch_resource_t* rs, int intf_ver_id)
{
	struct efch_pio_alloc *alloc = &alloc_->u.pio;
	struct efrm_resource *pd_efrm_resource;
	struct efrm_pd *pd;
	struct efrm_pio *pio;
	int rc;

	rc = efch_lookup_rs(alloc->in_pd_fd, alloc->in_pd_id, EFRM_RESOURCE_PD,
			    &pd_efrm_resource);
	if (rc < 0) {
		EFCH_ERR("%s: ERROR: fd=%d id="EFCH_RESOURCE_ID_FMT" (%d)",
			 __FUNCTION__, alloc->in_pd_fd,
			 EFCH_RESOURCE_ID_PRI_ARG(alloc->in_pd_id), rc);
		return rc;
	}

	pd = efrm_pd_from_resource(pd_efrm_resource);
	rc = efrm_pio_alloc(pd, &pio);
	if (rc < 0) {
		EFCH_ERR("%s: ERROR: efrm_pio_alloc failed (%d)", __FUNCTION__,
			rc);
		goto done;
	}

	rs->rs_base = efrm_pio_to_resource(pio);

done:
	/* A reference to pd is maintained in resource driver so we
	 * can drop it here. */
	efrm_pd_release(pd);
	return rc;
}


static int
pio_rm_rsops(efch_resource_t* rs, ci_resource_table_t* priv_opt,
	     ci_resource_op_t* op, int* copy_out)
{
	struct efrm_pio *pio;
	struct efrm_resource *vi_resource;
	struct efrm_vi *vi;
	int rc;
	bool freed_resource;

	pio = efrm_pio_from_resource(rs->rs_base);

	switch(op->op) {
	case CI_RSOP_PIO_LINK_VI:
		rc = efch_lookup_rs(op->u.pio_link_vi.in_vi_fd,
				    op->u.pio_link_vi.in_vi_id,
				    EFRM_RESOURCE_VI, &vi_resource);
		if (rc < 0) {
			EFCH_ERR("%s: ERROR: fd=%d id="EFCH_RESOURCE_ID_FMT
			" (%d)", __FUNCTION__, op->u.pio_link_vi.in_vi_fd,
			EFCH_RESOURCE_ID_PRI_ARG(op->u.pio_link_vi.in_vi_id),
			rc);
			return rc;
		}

		vi = efrm_to_vi_resource(vi_resource);
		rc = efrm_pio_link_vi(pio, vi);
		if (rc < 0)
			EFCH_ERR("%s: efrm_pio_link_vi failed %d", __FUNCTION__,
				 rc);
		break;

	case CI_RSOP_PIO_UNLINK_VI:
		rc = efch_lookup_rs(op->u.pio_unlink_vi.in_vi_fd,
				    op->u.pio_unlink_vi.in_vi_id,
				    EFRM_RESOURCE_VI, &vi_resource);
		if (rc < 0) {
			EFCH_ERR("%s: ERROR: fd=%d id="EFCH_RESOURCE_ID_FMT
			" (%d)", __FUNCTION__, op->u.pio_unlink_vi.in_vi_fd,
			EFCH_RESOURCE_ID_PRI_ARG(op->u.pio_unlink_vi.in_vi_id),
			rc);
			return rc;
		}

		vi = efrm_to_vi_resource(vi_resource);
		rc = efrm_pio_unlink_vi(pio, vi, &freed_resource);
		if (rc < 0)
			EFCH_ERR("%s: efrm_pio_unlink_vi failed %d",
				 __FUNCTION__, rc);
		/* This prevents double-frees. */
		if (freed_resource)
			rs->rs_base = NULL;
		break;

	default:
		EFCH_ERR("%s: Invalid op, expected CI_RSOP_PIO_LINK_VI or"
			 " CI_RSOP_PIO_UNLINK_VI", __FUNCTION__);
		return -EINVAL;
	}

	efrm_vi_resource_release(vi);
	return rc;
}


efch_resource_ops efch_pio_ops = {
  .rm_alloc  = pio_rm_alloc,
  .rm_free   = NULL,
  .rm_mmap   = NULL,
  .rm_nopage = NULL,
  .rm_dump   = NULL,
  .rm_rsops  = pio_rm_rsops,
};


