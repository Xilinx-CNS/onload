/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2022 Xilinx, Inc. */

#ifndef __EFRM_DEBUGFS_H__
#define __EFRM_DEBUGFS_H__

#include <ci/efrm/resource.h>
#include "debugfs.h"

extern void efrm_debugfs_add_rs(struct efrm_resource *rs,
		                struct efrm_resource *parent_rs,
		                uint32_t id);
extern void efrm_debugfs_remove_rs(struct efrm_resource *rs);
#ifdef CONFIG_DEBUG_FS
extern void
efrm_debugfs_add_rs_files(struct efrm_resource *rs,
	                  const struct efrm_debugfs_parameter *parameters,
	                  void *ref);
#endif

#endif
