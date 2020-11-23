/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */
#include <ci/efrm/private.h>
#include <ci/efrm/slice_ext.h>
#include <ci/efrm/pd.h>
#include <ci/driver/resource/linux_efhw_nic.h>
#include <ci/efhw/ef100.h>
#include "efrm_internal.h"

struct efrm_ext {
	struct efrm_resource rs;
	struct efrm_pd *pd;
};

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

extern struct efrm_resource* efrm_ext_to_resource(struct efrm_ext *ext)
{
	return &ext->rs;
}
EXPORT_SYMBOL(efrm_ext_to_resource);


extern struct efrm_ext* efrm_ext_from_resource(struct efrm_resource *rs)
{
	return container_of(rs, struct efrm_ext, rs);
}
EXPORT_SYMBOL(efrm_ext_from_resource);


int efrm_ext_alloc_rs(struct efrm_pd* pd, const unsigned char* ext_guid,
                      struct efrm_ext **ext_out)
{
	uint32_t mc_handle;
	int rc;
	struct efrm_ext *ext;
	struct efrm_resource *pd_rs = efrm_pd_to_resource(pd);

	if (!check_ef100(pd_rs))
		return -EOPNOTSUPP;

	ext = kmalloc(sizeof(struct efrm_ext), GFP_KERNEL);
	if (!ext)
		return -ENOMEM;

	ext->pd = pd;
	rc = ef100_nic_ext_alloc(pd_rs->rs_client->nic,
	                         efrm_pd_get_nic_client_id(pd),
	                         ext_guid, false, &mc_handle);
	if (rc < 0) {
		kfree(ext);
		return rc;
	}
	efrm_resource_init(&ext->rs, EFRM_RESOURCE_SLICE_EXT, mc_handle);
	efrm_client_add_resource(pd_rs->rs_client, &ext->rs);
	efrm_resource_ref(pd_rs);
	*ext_out = ext;
	return 0;
}
EXPORT_SYMBOL(efrm_ext_alloc_rs);


void efrm_ext_release(struct efrm_ext *ext)
{
	if (__efrm_resource_release(&ext->rs)) {
		ef100_nic_ext_free(ext->rs.rs_client->nic,
		                   efrm_pd_get_nic_client_id(ext->pd),
		                   ext->rs.rs_instance);
		efrm_pd_release(ext->pd);
		efrm_client_put(ext->rs.rs_client);
		kfree(ext);
	}
}
EXPORT_SYMBOL(efrm_ext_release);


int efrm_ext_get_meta_global(struct efrm_ext *ext,
                             struct efrm_ext_svc_meta *out)
{
	if (!check_ef100(&ext->rs))
		return -EOPNOTSUPP;
	return ef100_nic_ext_get_meta_global(ext->rs.rs_client->nic,
	                                     efrm_pd_get_nic_client_id(ext->pd),
	                                     ext->rs.rs_instance,
	                                     out->uuid, &out->minor_ver,
	                                     &out->patch_ver, &out->nmsgs,
	                                     &out->mapped_csr_offset,
	                                     &out->mapped_csr_size,
	                                     &out->mapped_csr_flags,
	                                     &out->admin_group);
}
EXPORT_SYMBOL(efrm_ext_get_meta_global);


int efrm_ext_get_meta_msg(struct efrm_ext *ext, uint32_t msg_id,
                          struct efrm_ext_msg_meta *out)
{
	if (!check_ef100(&ext->rs))
		return -EOPNOTSUPP;
	out->id = msg_id;
	return ef100_nic_ext_get_meta_msg(ext->rs.rs_client->nic,
	                                  efrm_pd_get_nic_client_id(ext->pd),
	                                  ext->rs.rs_instance, msg_id,
	                                  &out->ix, out->name, sizeof(out->name),
	                                  &out->mcdi_param_size);
}
EXPORT_SYMBOL(efrm_ext_get_meta_msg);


int efrm_ext_msg(struct efrm_ext *ext, uint32_t msg_id, void* buf, size_t len)
{
	if (!check_ef100(&ext->rs))
		return -EOPNOTSUPP;
	return ef100_nic_ext_msg(ext->rs.rs_client->nic,
	                         efrm_pd_get_nic_client_id(ext->pd),
	                         ext->rs.rs_instance, msg_id, buf, len);
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
