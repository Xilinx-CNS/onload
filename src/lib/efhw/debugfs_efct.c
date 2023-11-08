/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: Copyright (C) 2023, Advanced Micro Devices, Inc. */

#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/dcache.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

#include <ci/efhw/nic.h>
#include <ci/efhw/efct.h>

#include "linux_resource_internal.h"
#include "debugfs.h"


#ifdef CONFIG_DEBUG_FS

static const struct efrm_debugfs_parameter efhw_debugfs_efct_parameters[] = {
  EFRM_U32_PARAMETER(struct efhw_nic_efct, rxq_n),
  EFRM_U32_PARAMETER(struct efhw_nic_efct, evq_n),
  EFRM_U32_PARAMETER(struct efhw_nic_efct, hw_filters_n),
  {NULL},
};

/**
 * efhw_init_debugfs_efct - create debugfs directory for efct details
 * @nic: efhw_nic
 *
 * Create debugfs directory containing parameter-files for @nic
 * The directories must be cleaned up using efhw_fini_debugfs_efct().
 */
void efhw_init_debugfs_efct(struct efhw_nic *nic)
{
  struct efhw_nic_efct *efct = (struct efhw_nic_efct *) nic->arch_extra;

  /* Create directory */
  efct->debug_dir = debugfs_create_dir("efct", nic->debug_dir);

  /* Create files */
  efrm_init_debugfs_files(efct->debug_dir, efhw_debugfs_efct_parameters, efct);
}

/**
 * efhw_fini_debugfs_efct - remove debugfs directories for efct
 * @nic: efhw_nic
 *
 * Remove debugfs directories created for @nic by efhw_init_debugfs_efct().
 */
void efhw_fini_debugfs_efct(struct efhw_nic *nic)
{
  struct efhw_nic_efct *efct = (struct efhw_nic_efct *) nic->arch_extra;

  debugfs_remove_recursive(efct->debug_dir);
  efct->debug_dir = NULL;
}

#else /* !CONFIG_DEBUG_FS */
void efhw_init_debugfs_efct(struct efhw_nic *nic)
{
  return 0;
}
void efhw_fini_debugfs_efct(struct efhw_nic *nic) {}
#endif /* CONFIG_DEBUG_FS */
