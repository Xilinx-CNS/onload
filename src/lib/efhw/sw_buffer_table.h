/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: Copyright (C) 2024, Advanced Micro Devices, Inc. */

#include <kernel_utils/iobufset.h>

#define EFHW_MAX_SW_BTS 256

struct efhw_sw_bt {
  struct oo_buffer_pages *pages;
  long buffer_table_count;
  long freed_buffer_table_count;
};

struct efhw_sw_bt* efhw_sw_bt_by_owner(struct efhw_nic* nic, int owner_id);

int efhw_sw_bt_alloc(struct efhw_nic *nic, int owner, int order,
                     struct efhw_buffer_table_block **block_out,
                     int reset_pending);

void efhw_sw_bt_free(struct efhw_nic *nic,
                     struct efhw_buffer_table_block *block, int reset_pending);

int efhw_sw_bt_set(struct efhw_nic *nic, struct efhw_buffer_table_block *block,
                   int first_entry, int n_entries, dma_addr_t *dma_addrs);

void efhw_sw_bt_clear(struct efhw_nic *nic,
                      struct efhw_buffer_table_block *block, int first_entry,
                      int n_entries);
