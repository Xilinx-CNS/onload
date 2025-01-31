/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: Copyright (C) 2023, Advanced Micro Devices, Inc. */

#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/dcache.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

#include <ci/efhw/nic.h>

#include "linux_resource_internal.h"
#include "debugfs.h"

#ifdef CONFIG_DEBUG_FS

static int efhw_debugfs_read_mac(struct seq_file *file, const void *data)
{
  const struct efhw_nic *nic = data;
  seq_printf(file, "%pM\n", &nic->mac_addr);
  return 0;
}

static int efhw_debugfs_read_netdev_name(struct seq_file *file,
                                         const void *data)
{
  const struct efhw_nic *nic = data;
  seq_printf(file, "%s\n", nic->net_dev->name);
  return 0;
}

static int efhw_debugfs_read_devname(struct seq_file *file,
                                     const void *data)
{
  const struct efhw_nic *nic = data;
  seq_printf(file, "%s\n", nic->dev ? dev_name(nic->dev) : "no dev");
  return 0;
}

static const char *const arch_names[] = {
  [EFHW_ARCH_EF10] = "EF10",
  [EFHW_ARCH_EFCT] = "EFCT",
  [EFHW_ARCH_EF10CT] = "EF10CT",
  [EFHW_ARCH_AF_XDP] = "AF_XDP",
};
static const unsigned int arch_max = CI_ARRAY_SIZE(arch_names);

static int efhw_debugfs_read_nic_devtype(struct seq_file *file,
                                         const void *data)
{
  const struct efhw_device_type *devtype = data;

  seq_printf(file, "%x:%x:%x => %s\n", devtype->arch, devtype->variant,
             devtype->revision, STRING_TABLE_LOOKUP(devtype->arch, arch));
  return 0;
}

#define EFRM_NIC_DEVTYPE_PARAMETER(container_type, parameter)  \
  EFRM_PARAMETER(container_type, parameter,  \
  struct efhw_device_type, efhw_debugfs_read_nic_devtype)

static int efhw_debugfs_read_irq_ranges(struct seq_file *file,
                                        const void *data)
{
  int i;
  const struct efhw_nic *nic = data;

  for( i = 0; i < nic->vi_irq_n_ranges; i++ )
    seq_printf(file, "base: %u range: %u\n", nic->vi_irq_ranges[i].base,
               nic->vi_irq_ranges[i].range);

  return 0;
}

static const char *const qtype_names[] = {
  [EFHW_TXQ] = "TXQ",
  [EFHW_RXQ] = "RXQ",
  [EFHW_EVQ] = "EVQ",
};
static const unsigned int qtype_max = CI_ARRAY_SIZE(qtype_names);

static int efhw_debugfs_read_nic_queue_sizes(struct seq_file *file,
                                             const void *data)
{
  int i;
  const struct efhw_nic *nic = data;

  for( i = 0; i < EFHW_N_Q_TYPES; i++ )
    seq_printf(file, "%s: %x\n", STRING_TABLE_LOOKUP(i, qtype),
               nic->q_sizes[i]);

  return 0;
}

/* Per-NIC parameters */
static const struct efrm_debugfs_parameter efhw_debugfs_nic_parameters[] = {
  _EFRM_RAW_PARAMETER(dev, efhw_debugfs_read_devname),
  _EFRM_RAW_PARAMETER(net_dev, efhw_debugfs_read_netdev_name),
  EFRM_NIC_DEVTYPE_PARAMETER(struct efhw_nic, devtype),
  EFRM_X64_PARAMETER(struct efhw_nic, flags),
  EFRM_X64_PARAMETER(struct efhw_nic, filter_flags),
  EFRM_U32_PARAMETER(struct efhw_nic, resetting),
  EFRM_U32_PARAMETER(struct efhw_nic, mtu),
  EFRM_U32_PARAMETER(struct efhw_nic, num_evqs),
  EFRM_U32_PARAMETER(struct efhw_nic, num_dmaqs),
  EFRM_U32_PARAMETER(struct efhw_nic, num_timers),
  EFRM_X32_PARAMETER(struct efhw_nic, timer_quantum_ns),
  EFRM_U32_PARAMETER(struct efhw_nic, rx_prefix_len),
  EFRM_S32_PARAMETER(struct efhw_nic, rx_ts_correction),
  EFRM_S32_PARAMETER(struct efhw_nic, tx_ts_correction),
  EFRM_X32_PARAMETER(struct efhw_nic, vi_stride),
  EFRM_U32_PARAMETER(struct efhw_nic, vi_base),
  EFRM_U32_PARAMETER(struct efhw_nic, vi_shift),
  EFRM_U32_PARAMETER(struct efhw_nic, vi_min),
  EFRM_U32_PARAMETER(struct efhw_nic, vi_lim),
  EFRM_U32_PARAMETER(struct efhw_nic, rss_channel_count),
  EFRM_X32_PARAMETER(struct efhw_nic, pio_size),
  EFRM_U32_PARAMETER(struct efhw_nic, pio_num),
  EFRM_U16_PARAMETER(struct efhw_nic, rx_variant),
  EFRM_U16_PARAMETER(struct efhw_nic, tx_variant),
  _EFRM_RAW_PARAMETER(mac_addr, efhw_debugfs_read_mac),
  EFRM_U32_PARAMETER(struct efhw_nic, vi_irq_n_ranges),
  _EFRM_RAW_PARAMETER(vi_irq_ranges, efhw_debugfs_read_irq_ranges),
  _EFRM_RAW_PARAMETER(q_sizes, efhw_debugfs_read_nic_queue_sizes),
  {NULL},
};


/**
 * efhw_init_debugfs_nic - create debugfs directory for NIC
 * @nic: efhw_nic
 *
 * Create debugfs directory containing parameter-files for @nic,
 * and a subdirectory "arch" containing any arch-specific info
 * The directories must be cleaned up using efhw_fini_debugfs_nic().
 */
void efhw_init_debugfs_nic(struct efhw_nic *nic)
{
  /* dir_name format: nic index (up to 3 digits) + _ + ifname */
  char dir_name[3 + 1 + IFNAMSIZ];
  EFHW_BUILD_ASSERT(EFHW_MAX_NR_DEVS < 1000);

  snprintf(dir_name, sizeof(dir_name), "%03d_%s", nic->index,
           nic->net_dev->name);

  /* Create directory */
  nic->debug_dir.dir = debugfs_create_dir(dir_name, efrm_debug_nics);

  /* Create files */
  efrm_init_debugfs_files(&nic->debug_dir, efhw_debugfs_nic_parameters, nic);
}

/**
 * efhw_fini_debugfs_nic - remove debugfs directories for NIC
 * @nic: efhw_nic
 *
 * Remove debugfs directories created for @nic by efhw_init_debugfs_nic().
 */
void efhw_fini_debugfs_nic(struct efhw_nic *nic)
{
  efrm_fini_debugfs_files(&nic->debug_dir);
  memset(nic->rs_debug_dirs, 0, sizeof(nic->rs_debug_dirs));
}

#else /* !CONFIG_DEBUG_FS */
void efhw_init_debugfs_nic(struct efhw_nic *nic)
{
  return 0;
}
void efhw_fini_debugfs_nic(struct efhw_nic *nic) {}
#endif /* CONFIG_DEBUG_FS */
