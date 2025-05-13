/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: Copyright (C) 2024, Advanced Micro Devices, Inc. */

#include <ci/driver/kernel_compat.h>

#ifdef EFRM_HAVE_LINUX_TPH_H
#include <linux/pci-tph.h>
#else
enum tph_mem_type {
        TPH_MEM_TYPE_VM,        /* volatile memory */
        TPH_MEM_TYPE_PM         /* persistent memory */
};
ci_inline int pcie_tph_get_cpu_st(struct pci_dev *dev,
                                  enum tph_mem_type mem_type,
                                  unsigned int cpu_uid, u16 *tag)
{
  // Match return code from kernel if !CONFIG_PCIE_TPH
  return -EINVAL;
}
#endif
