/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2012-2020 Xilinx, Inc. */
#ifndef	EFCT_HW_DEFS_H
#define	EFCT_HW_DEFS_H

#include <ci/driver/efab/hardware/efct.h>

/* The following definitions aren't hardware-specific, but they do describe
 * low-level contraints and properties of the efhw interface */

/* Max superbufs permitted to be assigned to a single rxq, across the whole
 * system. Can be adjusted at whim, but affects the size of preallocated
 * arrays in various places. Most notably the enormous address space
 * reservation done by ef_vi. */
#define CI_EFCT_MAX_SUPERBUFS   512

/* As defined by the CPU architecture */
#define CI_HUGEPAGE_SIZE   2097152

#define CI_EFCT_SUPERBUFS_PER_PAGE (CI_HUGEPAGE_SIZE / EFCT_RX_SUPERBUF_BYTES)
#define CI_EFCT_MAX_HUGEPAGES \
                          (CI_EFCT_MAX_SUPERBUFS / CI_EFCT_SUPERBUFS_PER_PAGE)

#endif /* EF10_HW_DEFS_H */
