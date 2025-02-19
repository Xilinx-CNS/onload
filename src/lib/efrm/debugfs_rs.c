/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: Copyright (C) 2023, Advanced Micro Devices, Inc. */

#include <linux/debugfs.h>
#include <linux/ctype.h>
#include <ci/efrm/resource.h>
#include "linux_resource_internal.h"
#include "efrm_internal.h"
#include "debugfs.h"

#ifdef CONFIG_DEBUG_FS

static void efrm_debugfs_add_rs_dir(struct dentry **rs_debug_dirs,
	                            int rs_type, struct dentry *parent)
{
	/* name holds longest EFRM_RESOURCE_NAME */
	char name[20];
	char *rs_name = EFRM_RESOURCE_NAME(rs_type);
	int i;

	if (IS_ERR_OR_NULL(parent))
		return;
	/* Resource names are in all caps but prefer lowercase for debugfs */
	for( i = 0; rs_name[i] && i < sizeof(name) - 1; ++i )
		name[i] = tolower(rs_name[i]);
	name[i] = '\0';
	rs_debug_dirs[rs_type] = debugfs_create_dir(name, parent);
}

/**
 * efrm_debugfs_add_rs() - Add resource to per-nic debugfs hierarchy
 * @rs: pointer to resource to add a debugfs entry for
 * @parent_rs: pointer to a parent resource in debugfs hierarchy
 * @id: id used to identify resource
 *
 * @id must be unique in context of parent.  rs_instance field
 * of @rs can be used but this is not set for all resources
 * (e.g. always 0 for EFCT RXQs)
 */
void efrm_debugfs_add_rs(struct efrm_resource *rs,
		         struct efrm_resource *parent_rs,
		         uint32_t id)
{
	/* Name is long enough to hold 32 bit id written in base 10 */
	char name[10 + 1];
	struct dentry *parent;
	struct dentry **rs_debug_dirs;

	/* Expect this resource to be associated with a NIC */
	EFRM_ASSERT(rs != NULL);
	EFRM_ASSERT(rs->rs_client != NULL);
	EFRM_ASSERT(rs->rs_client->nic != NULL);

	if (parent_rs) {
		/* Parent should be associated with same NIC as child */
		EFRM_ASSERT(parent_rs->rs_client);
		EFRM_ASSERT(parent_rs->rs_client->nic);
		EFRM_ASSERT(parent_rs->rs_client->nic == rs->rs_client->nic);
		parent = parent_rs->debug_dir.dir;
		rs_debug_dirs = parent_rs->rs_debug_dirs;
	}
	else {
		/* No parent, use nic debug_dir */
		struct efhw_nic *nic = rs->rs_client->nic;
		parent = nic->debug_dir.dir;
		rs_debug_dirs = nic->rs_debug_dirs;
	}

	/* If there isn't a directory for this resource type, make one. */
	if (IS_ERR_OR_NULL(rs_debug_dirs[rs->rs_type])) {
		efrm_debugfs_add_rs_dir(rs_debug_dirs, rs->rs_type, parent);
		if (IS_ERR_OR_NULL(rs_debug_dirs[rs->rs_type]))
			return;
	}
	snprintf(name, sizeof(name), "%d", id);
	rs->debug_dir.dir = debugfs_create_dir(name, rs_debug_dirs[rs->rs_type]);
}

/**
 * efrm_debugfs_remove_rs() - Add resource to per-nic debugfs hierarchy
 * @rs: pointer to resource to remove debugfs entry for
 */
void efrm_debugfs_remove_rs(struct efrm_resource *rs)
{
	efrm_fini_debugfs_files(&rs->debug_dir);
	memset(rs->rs_debug_dirs, 0, sizeof(rs->rs_debug_dirs));
}

/**
 * efrm_debugfs_add_rs_files() - Add files to debugfs folder for resource
 * @rs: pointer to resource to add files for
 * @parameters: pointer to debugfs parameter definition array
 * @ref: pointer passed to reader function
 */
void efrm_debugfs_add_rs_files(struct efrm_resource *rs,
	                       const struct efrm_debugfs_parameter *parameters,
	                       void *ref)
{
	efrm_init_debugfs_files(&rs->debug_dir, parameters, ref);
}
#else /* !CONFIG_DEBUG_FS */
void efrm_debugfs_add_rs(struct efrm_resource *rs,
		         struct efrm_resource *parent_rs,
		         uint32_t id) {}
void efrm_debugfs_remove_rs(struct efrm_resource *rs) {}
#endif /* CONFIG_DEBUG_FS */
