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


static int efct_debugfs_read_hw_filters(struct seq_file *file,
                                        const void *data)
{
  const struct efhw_nic_efct *efct = data;
  struct efct_hw_filter *filter;
  int i;

  for( i = 0; i < efct->hw_filters_n; i++ ) {
    filter = &efct->hw_filters[i];
    if( filter->refcount > 0 )
      seq_printf(file, "%03x: ref: %d\tid: %d/%d\trxq: %d\t%s:%pI4:%d "
                       "%pM %d\n", i,
                 filter->refcount, filter->hw_id, filter->drv_id, filter->rxq,
                 filter->proto == IPPROTO_UDP ? "udp" :
                 filter->proto == IPPROTO_TCP ? "tcp" : "unknown",
                 &filter->ip, ntohs(filter->port), &filter->loc_mac,
                 filter->outer_vlan < 0 ? -1 :
                 ntohs(filter->outer_vlan & 0xffff));
  }
  return 0;
}

static const struct efrm_debugfs_parameter efhw_debugfs_efct_parameters[] = {
  EFRM_U32_PARAMETER(struct efhw_nic_efct, rxq_n),
  EFRM_U32_PARAMETER(struct efhw_nic_efct, evq_n),
  EFRM_U32_PARAMETER(struct efhw_nic_efct, hw_filters_n),
  _EFRM_RAW_PARAMETER(hw_filters, efct_debugfs_read_hw_filters),
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
