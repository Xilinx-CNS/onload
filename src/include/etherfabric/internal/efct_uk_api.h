/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2021 Xilinx, Inc. */
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

/* Mask of efct_rx_superbuf_queue::q values to get the actual superbuf ID (the
 * top bit is use in the rxq to convey the sentinel). */
#define CI_EFCT_Q_SUPERBUF_ID_MASK  0x7fff

struct efab_efct_rx_superbuf_queue {
  uint16_t q[16];
  uint64_t added CI_ALIGN(8);
  uint32_t removed;
};

/* decimation of efab_efct_rxq_uk_shm::timestamp_hi relative to a 'full'
 * timestamp. A full timestamp is ((secs << 32) | quarterns), i.e.
 * timestamp_hi stores a value that looks like that but shifted down by 16.
 * This is done to give room to avoid y2.038k issues. */
#define CI_EFCT_SHM_TS_SHIFT 16

struct efab_efct_rxq_uk_shm {
  /* TODO EFCT look in to field ordering of this struct. Might be quicker, for
   * example, to collect all the superbuf_pkts fields for all the rxqs at the
   * top */
  struct efab_efct_rx_superbuf_queue rxq;
  struct efab_efct_rx_superbuf_queue freeq;
  uint64_t timestamp_hi CI_ALIGN(8);
  uint8_t tsync_flags;
  int8_t qid;                        /* hardware queue ID */
  unsigned config_generation;
  uint32_t superbuf_pkts;            /* number of packets per superbuf */
  struct {
    unsigned no_rxq_space;
    unsigned too_many_owned;
  } stats;
} CI_ALIGN(CI_CACHE_LINE_SIZE);

#endif /* EFCT_HW_DEFS_H */
