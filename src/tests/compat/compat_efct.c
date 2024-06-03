/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

#include <etherfabric/ef_vi.h>
#include <etherfabric/efct_vi.h>

#include <etherfabric/vi.h>
#include <ci/efhw/common.h>
#include <ci/tools/debug.h>

#include <etherfabric/internal/efct_uk_api.h>

CI_BUILD_ASSERT(sizeof(struct efab_efct_rxq_uk_shm_rxq_entry) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_rxq_entry, sbid) == 0);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_rxq_entry, sentinel) == 2);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_rxq_entry, unused_padding) == 3);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_rxq_entry, sbseq) == 4);

CI_BUILD_ASSERT(sizeof(struct efab_efct_rxq_uk_shm_q) == 256);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_q, rxq) == 0);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_q, rxq.q) == 0);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_q, rxq.added) == 128);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_q, rxq.removed) == 132);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_q, freeq) == 136);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_q, freeq.q) == 136);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_q, freeq.added) == 168);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_q, freeq.removed) == 172);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_q, qid) == 176);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_q, config_generation) == 180);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_q, superbuf_pkts) == 184);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_q, time_sync) == 192);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_q, stats.no_rxq_space) == 200);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_q, stats.too_many_owned) == 204);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_q, stats.no_bufs) == 208);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_q, stats.skipped_bufs) == 212);

CI_BUILD_ASSERT(sizeof(struct efab_efct_rxq_uk_shm_base) == 64);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_base, active_qs) == 0);
CI_BUILD_ASSERT(__builtin_offsetof(struct efab_efct_rxq_uk_shm_base, q) == 64);


