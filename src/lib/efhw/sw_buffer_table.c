/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: Copyright (C) 2024, Advanced Micro Devices, Inc. */

#include <ci/efhw/efhw_types.h>
#include <kernel_utils/iobufset.h>

#include "sw_buffer_table.h"

struct efhw_sw_bt* efhw_sw_bt_by_owner(struct efhw_nic* nic, int owner_id)
{
  struct efhw_sw_bt* sw_bt = nic->sw_bts;

  if( sw_bt == NULL || owner_id > EFHW_MAX_SW_BTS || owner_id < 0 )
    return NULL;

  return &sw_bt[owner_id];
}

/* Reallocing isn't currently supported */
int efhw_sw_bt_alloc(struct efhw_nic *nic, int owner, int order,
                     struct efhw_buffer_table_block **block_out,
                     int reset_pending)
{
  struct efhw_buffer_table_block* block;
  struct efhw_sw_bt* bt = efhw_sw_bt_by_owner(nic, owner);
  int rc;
  void *alloc;

  if( bt == NULL )
    return -ENODEV;

  /* We reserve some bits of the handle to store the order, needed later to
   * calculate the address of each entry within the block. This limits the
   * number of owners we can support. Alternatively, we could use the high bits
   * of btb_vaddr (as ef10 does), and mask these out when using the addresses.
   */
  if( owner >= (1 << 24) )
    return -ENOSPC;

  block = kzalloc(sizeof(**block_out), GFP_KERNEL);
  if( block == NULL )
    return -ENOMEM;

  /* TODO use af_xdp-specific data rather than repurposing ef10-specific */
  block->btb_hw.ef10.handle = order | (owner << 8);
  /* This is assuming that all btb have the same order,
   * we could use used_page_count instead but that would assume that all btbs
   * are filled before moving onto the next one. */
  block->btb_vaddr = (bt->block_count *
                      (EFHW_BUFFER_TABLE_BLOCK_SIZE << order)) << PAGE_SHIFT;

  if( bt->block_capacity < bt->block_count + 1 ) {
    alloc = krealloc(bt->blocks,
                     (bt->block_count + 1) * sizeof(*bt->blocks),
                     GFP_KERNEL);
    if( alloc == NULL ) {
      kfree(block);
      return -ENOMEM;
    }
    bt->blocks = alloc;
    bt->block_capacity = bt->block_count + 1;
  }

  rc = oo_iobufset_init(&bt->blocks[bt->block_count],
                        EFHW_BUFFER_TABLE_BLOCK_SIZE << order);
  if( rc < 0 ) {
    kfree(block);
    bt->blocks[bt->block_count] = NULL;
    return rc;
  }
  ++bt->block_count;

  *block_out = block;
  return 0;
}

static void release_bt(struct efhw_nic* nic, int owner)
{
  struct efhw_sw_bt* bt = efhw_sw_bt_by_owner(nic, owner);
  int i;
  BUG_ON(bt == NULL);
  BUG_ON(bt->freed_block_count >= bt->block_count);

  if( ++bt->freed_block_count != bt->block_count )
    return;

  for( i = 0; i < bt->block_count; i++ )
    if( bt->blocks[i] != NULL )
      oo_iobufset_kfree(bt->blocks[i]);
  kfree(bt->blocks);
  memset(bt, 0, sizeof(*bt));
}

void efhw_sw_bt_free(struct efhw_nic *nic,
                     struct efhw_buffer_table_block *block, int reset_pending)
{
  int owner = block->btb_hw.ef10.handle >> 8;
  kfree(block);
  release_bt(nic, owner);
}

int efhw_sw_bt_set(struct efhw_nic *nic, struct efhw_buffer_table_block *block,
                   int first_entry, int n_entries, dma_addr_t *dma_addrs)
{
  int i, owner, order;
  long page, block_idx;
  struct efhw_sw_bt* bt;

  owner = block->btb_hw.ef10.handle >> 8;
  order = block->btb_hw.ef10.handle & 0xff;
  bt = efhw_sw_bt_by_owner(nic, owner);
  if( bt == NULL )
    return -ENODEV;

  /* We are mapping between two address types.
   *
   * block->btb_vaddr stores the byte offset within the umem block, suitable for
   * use with AF_XDP descriptor queues. This is eventually used to provide the
   * "user" addresses returned from efrm_pd_dma_map, which in turn provide the
   * packet "dma" addresses posted to ef_vi, which are passed on to AF_XDP.
   * (Note: "user" and "dma" don't mean userland and DMA in this context).
   *
   * dma_addr is the corresponding kernel address, which we use to calculate the
   * addresses to store in vi->addrs, and later map into userland. This comes
   * from the "dma" (or "pci") addresses obtained by efrm_pd_dma_map which, for
   * a non-PCI device, are copied from the provided kernel addresses.
   * (Note: "dma" and "pci" don't mean DMA and PCI in this context either).
   *
   * We get one umem address giving the start of each buffer table block. The
   * block might contain several consecutive pages, which might be compound
   * (but all with the same order).
   */

  block_idx = (block->btb_vaddr >> PAGE_SHIFT) /
              (EFHW_BUFFER_TABLE_BLOCK_SIZE << order);
  page = first_entry;

  if( block_idx >= bt->block_count )
    return -EINVAL;

  if( page + n_entries >= oo_iobufset_npages(bt->blocks[block_idx]))
    return -EINVAL;

  for( i = 0; i < n_entries; ++i ) {
    struct page *p = pfn_to_page(dma_addrs[i] >> PAGE_SHIFT);
    bt->blocks[block_idx]->pages[page + i] = p;
    bt->used_page_count += 1 << order;
  }

  return 0;
}

unsigned long efhw_sw_bt_get_pfn(struct efhw_sw_bt *table, long index)
{
  /* This assumes that the order is the same for all blocks */
  int order = compound_order(table->blocks[0]->pages[0]);
  long btb_size = EFHW_BUFFER_TABLE_BLOCK_SIZE << order;
  int btb_index = index / btb_size;

  EFRM_ASSERT(btb_index < table->block_count);

  return oo_iobufset_pfn(table->blocks[btb_index],
                         index % btb_size << PAGE_SHIFT);
}

void efhw_sw_bt_clear(struct efhw_nic *nic,
                      struct efhw_buffer_table_block *block, int first_entry,
                      int n_entries)
{
}
