/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2021 Xilinx, Inc. */
#ifndef	EFCT_HW_DEFS_H
#define	EFCT_HW_DEFS_H

#include <ci/driver/efab/hardware/efct.h>
#include <ci/tools/sysdep.h>

/* Increment this when the layout of efab_efct_rxq_uk_shm_base changes. It's
 * passed to the kernel in struct efch_efct_rxq_alloc */
#define CI_EFCT_SWRXQ_ABI_VERSION  0

/* The following definitions aren't hardware-specific, but they do describe
 * low-level contraints and properties of the efhw interface */

/* Max superbufs permitted to be assigned to a single rxq, across the whole
 * system. */
#define CI_EFCT_MAX_SUPERBUFS   2048

/* As defined by the CPU architecture */
#define CI_HUGEPAGE_SIZE   2097152

#define CI_EFCT_SUPERBUFS_PER_PAGE (CI_HUGEPAGE_SIZE / EFCT_RX_SUPERBUF_BYTES)
#define CI_EFCT_MAX_HUGEPAGES \
                          (CI_EFCT_MAX_SUPERBUFS / CI_EFCT_SUPERBUFS_PER_PAGE)

#define CI_EFCT_DEFAULT_POISON  0x0000FFA0C09B0000ull

struct efab_efct_rxq_uk_shm_rxq_entry {
  uint16_t sbid;
  uint8_t sentinel;
  uint8_t unused_padding;
  uint32_t sbseq;
};

struct efab_efct_rxq_uk_shm_q {
  /* TODO EFCT look in to field ordering of this struct. Might be quicker, for
   * example, to collect all the superbuf_pkts fields for all the rxqs at the
   * top */
  struct {
    struct efab_efct_rxq_uk_shm_rxq_entry q[16];
    uint32_t added;
    uint32_t removed;
  } rxq;
  struct {
    /* There is no requirement that the rxq and freeq be similarly sized.
     * For use-cases supporting long-term app ownership, it could be
     * advantageous to allow the freeq to be much bigger. Anyway, that's the
     * reason why they don't share a macro to define the queue size */
    uint16_t q[16];
    uint32_t added;
    uint32_t removed;
  } freeq;
  int8_t qid;                        /* hardware queue ID */
  unsigned config_generation;
  uint32_t superbuf_pkts;            /* number of packets per superbuf.
                                      * 0 indicates inactive queue. */
  uint64_t time_sync;                /* latest time sync event */
  struct {
    unsigned no_rxq_space;
    unsigned too_many_owned;
    unsigned no_bufs;
    unsigned skipped_bufs;
  } stats;
} CI_ALIGN(CI_CACHE_LINE_SIZE);

struct efab_efct_rxq_uk_shm_base {
  /* Both q[i].superbuf_pkts != 0 and active_qs & (1 << i) indicate an active
   * queue and are synchronised with each other. Either may be used, with the
   * choice usually being made according to cache locality considerations */
  uint64_t active_qs;   /* Bitmask, same indices as 'q' */
  CI_DECLARE_FLEX_ARRAY(struct efab_efct_rxq_uk_shm_q, q);
};

#define CI_EFCT_SHM_BYTES(max_qs)  \
                        (sizeof(struct efab_efct_rxq_uk_shm_base) + \
                         (max_qs) * sizeof(struct efab_efct_rxq_uk_shm_q))

#endif /* EFCT_HW_DEFS_H */
