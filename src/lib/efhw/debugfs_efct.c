/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: Copyright (C) 2023, Advanced Micro Devices, Inc. */

#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/dcache.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

#include <ci/efhw/nic.h>
#include <ci/efhw/efct.h>
#include <ci/efhw/ef10ct.h>
#include <ci/efhw/efct_filters.h>

#include "linux_resource_internal.h"
#include "debugfs.h"


#ifdef CONFIG_DEBUG_FS


static int efct_debugfs_read_hw_filters(struct seq_file *file,
                                        const struct efct_filter_state *fs)
{
  struct efct_hw_filter *filter;
  int i;
  /* 24 bytes should be enough to store remote ipv4 address and port:
   * 16 (ip address) + 1 (colon) + 5 (port) + 1 (trailing space) + 1 (null) */
  char remote_ip_buf[24] = {0};

  for( i = 0; i < fs->hw_filters_n; i++ ) {
    filter = &fs->hw_filters[i];
    if( filter->refcount > 0 ) {
      if( filter->drv_id == EFCT_HW_FILTER_DRV_ID_DUMMY)
        continue;
      if( filter->remote_ip )
        snprintf(remote_ip_buf, sizeof(remote_ip_buf), "%pI4:%d ",
                 &filter->remote_ip, ntohs(filter->remote_port));
      seq_printf(file, "%03x: ref: %d\tid: %d/%llu\trxq: %d\t%s:%pI4:%d %s"
                       "%pM %d\n", i,
                 filter->refcount, filter->hw_id, filter->drv_id, filter->rxq,
                 filter->ip_proto == IPPROTO_UDP ? "udp" :
                 filter->ip_proto == IPPROTO_TCP ? "tcp" : "unknown",
                 &filter->local_ip, ntohs(filter->local_port), remote_ip_buf,
                 &filter->loc_mac, filter->outer_vlan < 0 ? -1 :
                 ntohs(filter->outer_vlan & 0xffff));
    }
  }
  return 0;
}

static int
efct_debugfs_read_exclusive_rxq_mapping(struct seq_file *file, int rxq_n,
                                        const struct efct_filter_state *fs)
{
  int qid;
  seq_printf(file, "exclusive rxq map: ");
  for( qid = 0; qid < rxq_n; ++qid ) {
    uint32_t excl = fs->exclusive_rxq_mapping[qid];
    seq_printf(file, "%s%d",
               qid == 0 ? "" : " ",
               excl && excl != EFHW_PD_NON_EXC_TOKEN);
  }
  seq_printf(file, "\n");
  return 0;
}

static int
efct_debugfs_read_filter_state(struct seq_file *file, int rxq_n,
                               const struct efct_filter_state *fs)
{
  seq_printf(file, "%d\n", fs->hw_filters_n);
  efct_debugfs_read_hw_filters(file, fs);
  efct_debugfs_read_exclusive_rxq_mapping(file, rxq_n, fs);
  return 0;
}

static int
efct_debugfs_read_efct_filter_state(struct seq_file *file, const void *data)
{
  const struct efhw_nic_efct *efct = data;
  const struct efct_filter_state *fs = efct->filter_state;

  return efct_debugfs_read_filter_state(file, efct->rxq_n, fs);
}

static int
efct_debugfs_read_ef10ct_filter_state(struct seq_file *file, const void *data)
{
  const struct efhw_nic_ef10ct *ef10ct = data;
  const struct efct_filter_state *fs = ef10ct->filter_state;

  return efct_debugfs_read_filter_state(file, ef10ct->rxq_n, fs);
}


static const struct efrm_debugfs_parameter efhw_debugfs_efct_parameters[] = {
  EFRM_U32_PARAMETER(struct efhw_nic_efct, rxq_n),
  EFRM_U32_PARAMETER(struct efhw_nic_efct, evq_n),
  _EFRM_RAW_PARAMETER(hw_filters, efct_debugfs_read_efct_filter_state),
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
  efct->debug_dir.dir = debugfs_create_dir("efct", nic->debug_dir.dir);

  /* Create files */
  efrm_init_debugfs_files(&efct->debug_dir, efhw_debugfs_efct_parameters, efct);
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

  efrm_fini_debugfs_files(&efct->debug_dir);
}

static const struct efrm_debugfs_parameter efhw_debugfs_ef10ct_parameters[] = {
  EFRM_U32_PARAMETER(struct efhw_nic_ef10ct, rxq_n),
  EFRM_U32_PARAMETER(struct efhw_nic_ef10ct, evq_n),
  _EFRM_RAW_PARAMETER(hw_filters, efct_debugfs_read_ef10ct_filter_state),
  {NULL},
};

/**
 * efhw_init_debugfs_ef10ct - create debugfs directory for ef10ct details
 * @nic: efhw_nic
 *
 * Create debugfs directory containing parameter-files for @nic
 * The directories must be cleaned up using efhw_fini_debugfs_ef10ct().
 */
void efhw_init_debugfs_ef10ct(struct efhw_nic *nic)
{
  struct efhw_nic_ef10ct *ef10ct = (struct efhw_nic_ef10ct *) nic->arch_extra;

  /* Create directory */
  ef10ct->debug_dir.dir = debugfs_create_dir("ef10ct", nic->debug_dir.dir);

  /* Create files */
  efrm_init_debugfs_files(&ef10ct->debug_dir, efhw_debugfs_ef10ct_parameters, ef10ct);
}

/**
 * efhw_fini_debugfs_ef10ct - remove debugfs directories for ef10ct
 * @nic: efhw_nic
 *
 * Remove debugfs directories created for @nic by efhw_init_debugfs_ef10ct().
 */
void efhw_fini_debugfs_ef10ct(struct efhw_nic *nic)
{
  struct efhw_nic_ef10ct *ef10ct = (struct efhw_nic_ef10ct *) nic->arch_extra;

  efrm_fini_debugfs_files(&ef10ct->debug_dir);
}

#else /* !CONFIG_DEBUG_FS */
void efhw_init_debugfs_efct(struct efhw_nic *nic) {}
void efhw_fini_debugfs_efct(struct efhw_nic *nic) {}

void efhw_init_debugfs_ef10ct(struct efhw_nic *nic) {}
void efhw_fini_debugfs_ef10ct(struct efhw_nic *nic) {}
#endif /* CONFIG_DEBUG_FS */
