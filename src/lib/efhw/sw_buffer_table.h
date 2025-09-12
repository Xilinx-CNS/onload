/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: Copyright (C) 2024, Advanced Micro Devices, Inc. */

#include <kernel_utils/iobufset.h>

#define EFHW_MAX_SW_BTS 256

struct efhw_sw_bt_entries;

/* struct efhw_sw_bt is a buffer table implemented in software. It stores a set
 * of pages that are to be used by the nic, and allows for translation between
 * "pci" and "dma" addresses. ("pci" and "dma" don't actually mean pci and dma,
 * see the note in sw_buffer_table.c:efhw_sw_bt_set).
 *
 * Used by nic architectures that don't have native support for buffer tables,
 * but who still want address translation capabilities. */
struct efhw_sw_bt {
  /* The mapping applied to the entries. */
  enum efhw_page_map_type map_type;
  /* The order of the entries */
  int order;
  /* An array of arrays of entries. Each element in this array roughly
   * corresponds to a `struct efhw_buffer_table_block`. */
  struct efhw_sw_bt_entries **blocks;
  /* How many buffer table blocks are currently being used */
  long block_count;
  /* Capacity of the blocks array */
  long block_capacity;
  /* How many buffer table blocks have been freed. If this equals
   * block_count then the whole `efhw_sw_bt` is freed. */
  long freed_block_count;
  /* How many PAGE_SIZE pages are stored* in this buffer table. If the order of
   * buffer table is greater than 0, then the number of elements stored will be
   * lower than this value as we just store the head of a compound/huge page. */
  long used_page_count;
};

/* Gets the sw_bt by the owner id
 * returns NULL if the requested sw_bt isn't valid */
struct efhw_sw_bt* efhw_sw_bt_by_owner(struct efhw_nic* nic, int owner_id);

/* Allocates a new buffer table block and a new `oo_buffer_pages` element for
 * `efhw_sw_bt.pages`. The `efhw_sw_bt` to update is determined by `owner`. */
int efhw_sw_bt_alloc(struct efhw_nic *nic, int owner, int order,
                     struct efhw_buffer_table_block **block_out,
                     int reset_pending);

/* Frees `block` and updates `freed_buffer_table_count` in the `efhw_sw_bt`. If
 * this is the last block, then the entire `efhw_sw_bt` is freed. */
void efhw_sw_bt_free(struct efhw_nic *nic,
                     struct efhw_buffer_table_block *block, int reset_pending);

/* Sets `n_entries` pages in `efhw_sw_bt` based on the virtual addresses
 * provided by `block` and `first_entry`.
 * The pages to store  determined `dma_addrs`. */
int efhw_sw_bt_set(struct efhw_nic *nic, struct efhw_buffer_table_block *block,
                   int first_entry, int n_entries, dma_addr_t *dma_addrs);

/* Returns the pfn of the page for a given virtual/"dma" addr.
 * `index` is the page number of the virtual address */
unsigned long efhw_sw_bt_get_pfn(struct efhw_sw_bt *table, long index);
dma_addr_t efhw_sw_bt_get_dma_addr(struct efhw_sw_bt *table, long index);

/* Unsupported */
void efhw_sw_bt_clear(struct efhw_nic *nic,
                      struct efhw_buffer_table_block *block, int first_entry,
                      int n_entries);

/* Reallocates the sw buffer table as required. */
int efhw_sw_bt_realloc(struct efhw_nic *nic, int owner, int order,
                       struct efhw_buffer_table_block *block);
