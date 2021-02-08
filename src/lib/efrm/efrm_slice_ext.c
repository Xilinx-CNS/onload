/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */
#include <ci/efrm/private.h>
#include <ci/efrm/slice_ext.h>
#include <ci/driver/resource/linux_efhw_nic.h>
#include <ci/efhw/ef100.h>
#include "efrm_internal.h"

static bool check_ef100(const struct efrm_resource *rs)
{
	if (rs->rs_client->nic->devtype.arch != EFHW_ARCH_EF100) {
		EFRM_TRACE("%s: Only EF100 NIC supports slice extensions."
		           " Expected arch=%d but got %d\n", __FUNCTION__,
		           EFHW_ARCH_EF100, rs->rs_client->nic->devtype.arch);
		return false;
	}
	return true;
}


int efrm_ext_alloc(struct efrm_resource *rs,
                   const unsigned char* ext_guid, uint32_t* out_mc_id)
{
	if (!check_ef100(rs))
		return -EOPNOTSUPP;
	return ef100_nic_ext_alloc(rs->rs_client->nic, ext_guid, false,
	                           out_mc_id);
}
EXPORT_SYMBOL(efrm_ext_alloc);


int efrm_ext_alloc_rs(struct efrm_resource* pd_rs,
                      struct efrm_resource *ext_rs,
                      const unsigned char* ext_guid)
{
	uint32_t mc_handle;
	int rc = efrm_ext_alloc(pd_rs, ext_guid, &mc_handle);
	if (rc < 0)
		return rc;
	efrm_resource_init(ext_rs, EFRM_RESOURCE_SLICE_EXT, mc_handle);
	efrm_client_add_resource(pd_rs->rs_client, ext_rs);
	return 0;
}
EXPORT_SYMBOL(efrm_ext_alloc_rs);


int efrm_ext_free(struct efrm_resource *rs, uint32_t mc_id)
{
	if (!check_ef100(rs))
		return -EOPNOTSUPP;
	return ef100_nic_ext_free(rs->rs_client->nic, mc_id);
}
EXPORT_SYMBOL(efrm_ext_free);


void efrm_ext_release(struct efrm_resource *rs)
{
	if (__efrm_resource_release(rs))
		efrm_client_put(rs->rs_client);
}
EXPORT_SYMBOL(efrm_ext_release);


int efrm_ext_get_meta_global(struct efrm_resource *rs, uint32_t mc_handle,
                             struct efrm_ext_svc_meta *out)
{
	if (!check_ef100(rs))
		return -EOPNOTSUPP;
	return ef100_nic_ext_get_meta_global(rs->rs_client->nic, mc_handle,
	                                     out->uuid, &out->minor_ver,
	                                     &out->patch_ver, &out->nmsgs,
	                                     &out->mapped_csr_offset,
	                                     &out->mapped_csr_size,
	                                     &out->mapped_csr_flags,
	                                     &out->admin_group);
}
EXPORT_SYMBOL(efrm_ext_get_meta_global);


int efrm_ext_get_meta_msg(struct efrm_resource *rs, uint32_t mc_handle,
                          uint32_t msg_id, struct efrm_ext_msg_meta *out)
{
	if (!check_ef100(rs))
		return -EOPNOTSUPP;
	out->id = msg_id;
	return ef100_nic_ext_get_meta_msg(rs->rs_client->nic, mc_handle, msg_id,
	                                  &out->ix, out->name, sizeof(out->name),
	                                  &out->mcdi_param_size);
}
EXPORT_SYMBOL(efrm_ext_get_meta_msg);


int efrm_ext_msg(struct efrm_resource *rs, uint32_t mc_handle,
                 uint32_t msg_id, void* buf, size_t len)
{
	if (!check_ef100(rs))
		return -EOPNOTSUPP;
	return ef100_nic_ext_msg(rs->rs_client->nic, mc_handle, msg_id, buf, len);
}
EXPORT_SYMBOL(efrm_ext_msg);


static void efrm_ext_rm_dtor(struct efrm_resource_manager *rm)
{
	/* NOP */
}


int efrm_create_ext_resource_manager(struct efrm_resource_manager **rm_out)
{
	struct efrm_resource_manager *rm;
	int rc;

	rm = kzalloc(sizeof(*rm), GFP_KERNEL);
	if (rm == NULL)
		return -ENOMEM;

	rc = efrm_resource_manager_ctor(rm, efrm_ext_rm_dtor, "EXT",
					EFRM_RESOURCE_SLICE_EXT);
	if (rc < 0)
		goto fail;

	*rm_out = rm;
	return 0;

fail:
	kfree(rm);
	return rc;
}
