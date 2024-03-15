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
  block->btb_vaddr = 0;

  rc = oo_iobufset_init(&bt->pages, EFHW_BUFFER_TABLE_BLOCK_SIZE << order);
  if( rc < 0 ) {
    kfree(block);
    return rc;
  }
  ++bt->buffer_table_count;

  *block_out = block;
  return 0;
}

static void release_bt(struct efhw_nic* nic, int owner)
{
  struct efhw_sw_bt* bt = efhw_sw_bt_by_owner(nic, owner);
  BUG_ON(bt == NULL);
  BUG_ON(bt->freed_buffer_table_count >= bt->buffer_table_count);

  if( ++bt->freed_buffer_table_count != bt->buffer_table_count )
    return;

  oo_iobufset_kfree(bt->pages);
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
  long page;
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

  page = (block->btb_vaddr >> PAGE_SHIFT) + (first_entry << order);
  if( n_entries > oo_iobufset_npages(bt->pages) )
    return -EINVAL;

  for( i = 0; i < n_entries; ++i ) {
    struct page *p = pfn_to_page(dma_addrs[i] >> PAGE_SHIFT);
    bt->pages->pages[(page >> order) + i] = p;
  }

  return 0;
}

void efhw_sw_bt_clear(struct efhw_nic *nic,
                      struct efhw_buffer_table_block *block, int first_entry,
                      int n_entries)
{
}
