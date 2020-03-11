/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

/* This file implements the handling for the data structure that OOF uses to
 * track NAT configuration.  The rest of OOF can query this in order to
 * deterimine when to install extra filters to receive NAT-ed traffic.
 *
 * NAT mappings are maintained in a hash table.  Since it is necessary
 * according to circumstances to perform lookups in the table in both
 * directions, each entry is added to the table in the hash-bucket for the
 * original address and for the translated address.
 */

#include "onload_kernel_compat.h"

#include <onload/oof_interface.h>
#include <onload/hash.h>
#include <onload/oof_nat.h>

#include "oof_impl.h"
#include "tcp_filters_internal.h"
#include "oo_hw_filter.h"


/* Number of oof_nat_filter structures to allocate or free in one go. */
#define FILTER_STORAGE_BATCH_SIZE 32


static inline ci_uint32
nat_hash(const struct oof_nat_table* tbl, ci_addr_t addr, ci_uint16 port)
{
  return onload_hash1(tbl->nattbl_size - 1, addr, port, (ci_addr_t) {}, 0, 0);
}


struct oof_nat_table* oof_nat_table_alloc(ci_uint32 size)
{
  ci_dllist* buckets = CI_ALLOC_ARRAY(ci_dllist, size);
  struct oof_nat_table* table;
  ci_uint32 i;

  ci_assert(CI_IS_POW2(size));

  if( buckets == NULL )
    return NULL;

  table = CI_ALLOC_OBJ(struct oof_nat_table);
  if( table == NULL ) {
    ci_free(buckets);
    return NULL;
  }

  table->nattbl_size = size;
  table->nattbl_buckets = buckets;
  table->nattbl_entries = 0;
  spin_lock_init(&table->nattbl_lock);
  for( i = 0; i < size; ++i )
    ci_dllist_init(&table->nattbl_buckets[i]);

  ci_dllist_init(&table->nattbl_filter_storage_list);
  table->nattbl_filter_storage_count = 0;

  return table;
}


void oof_nat_table_free(struct oof_nat_table* table)
{
  oof_nat_table_reset(table);
  ci_free(table->nattbl_buckets);
  CI_FREE_OBJ(table);
}


/* Allocates a batch of oof_nat_filter objects and adds them to the provided
 * list. */
static int alloc_filter_storage_batch(ci_dllist* extra_filter_storage_list)
{
  struct oof_nat_filter* filter;
  int i;

  for( i = 0; i < FILTER_STORAGE_BATCH_SIZE; ++i ) {
    filter = CI_ALLOC_OBJ(struct oof_nat_filter);
    if( filter == NULL ) {
      struct oof_nat_filter* next;
      CI_DLLIST_FOR_EACH3(struct oof_nat_filter, filter, link,
                          extra_filter_storage_list, next)
        CI_FREE_OBJ(filter);
      return -ENOMEM;
    }
    oo_hw_filter_init(&filter->natf_hwfilter);
    ci_dllist_push(extra_filter_storage_list, &filter->link);
  }

  return 0;
}


int oof_nat_table_add(struct oof_nat_table* table, ci_addr_t orig_addr,
                      ci_uint16 orig_port, ci_addr_t xlated_addr,
                      ci_uint16 xlated_port)
{
  int rc;

  /* Find the buckets to use for insertion. */
  ci_uint32 orig_hash = nat_hash(table, orig_addr, orig_port);
  ci_uint32 xlated_hash = nat_hash(table, xlated_addr, xlated_port);

  struct oof_nat_table_entry* entry_orig_hashed;
  struct oof_nat_table_entry* entry_xlated_hashed = NULL;
  ci_dllist extra_filter_storage_list;

  ci_dllist_init(&extra_filter_storage_list);

  entry_orig_hashed = CI_ALLOC_OBJ(struct oof_nat_table_entry);
  if( entry_orig_hashed == NULL ) {
    rc = -ENOMEM;
    goto fail;
  }

  entry_orig_hashed->orig_addr = orig_addr;
  entry_orig_hashed->orig_port = orig_port;
  entry_orig_hashed->xlated_addr = xlated_addr;
  entry_orig_hashed->xlated_port = xlated_port;

  /* If the original and translated address both happen to hash to the same
   * thing, we only need to add one entry to the table. */
  if( orig_hash != xlated_hash ) {
    entry_xlated_hashed = CI_ALLOC_OBJ(struct oof_nat_table_entry);
    if( entry_xlated_hashed == NULL ) {
      rc = -ENOMEM;
      goto fail;
    }
    *entry_xlated_hashed = *entry_orig_hashed;
    entry_xlated_hashed->dual_entry = entry_orig_hashed;
  }

  entry_orig_hashed->dual_entry = entry_xlated_hashed;

  spin_lock_bh(&table->nattbl_lock);

  /* If adding a new entry to the NAT table would take us over the limit of
   * allocated filter storage, allocate another batch of filter storage. */
  ci_assert_le(table->nattbl_entries, table->nattbl_filter_storage_count);
  if( table->nattbl_entries == table->nattbl_filter_storage_count ) {
    spin_unlock_bh(&table->nattbl_lock);
    rc = alloc_filter_storage_batch(&extra_filter_storage_list);
    if( rc < 0 )
      goto fail;
    spin_lock_bh(&table->nattbl_lock);
  }

  if( entry_xlated_hashed != NULL )
    ci_dllist_push(&table->nattbl_buckets[xlated_hash],
                   &entry_xlated_hashed->link);
  ci_dllist_push(&table->nattbl_buckets[orig_hash], &entry_orig_hashed->link);

  if( ! ci_dllist_is_empty(&extra_filter_storage_list) ) {
    ci_dllist_join(&table->nattbl_filter_storage_list,
                   &extra_filter_storage_list);
    table->nattbl_filter_storage_count += FILTER_STORAGE_BATCH_SIZE;
  }

  ++table->nattbl_entries;

  spin_unlock_bh(&table->nattbl_lock);

  return 0;

 fail:
  CI_FREE_OBJ(entry_xlated_hashed);
  CI_FREE_OBJ(entry_orig_hashed);
  return rc;
}


/* Populates the results structure with all un-NATed address:port pairs mapping
 * to xlated_addr:xlated_port.  The caller must call
 * oof_nat_table_lookup_free(results) when finished with the results, which
 * includes the case where the same structure is passed into another call to
 * oof_nat_table_lookup(). */
int
oof_nat_table_lookup(struct oof_nat_table* table, ci_addr_t xlated_addr,
                     ci_uint16 xlated_port,
                     struct oof_nat_lookup_result* results)
{
  ci_uint32 hash = nat_hash(table, xlated_addr, xlated_port);
  struct oof_nat_table_entry* entry;
  int rc;
  int num_bufs;

  num_bufs = sizeof(results->scratch_space) / sizeof(results->scratch_space[0]);
  results->results = results->scratch_space;

  do {
    rc = 0;
    results->n_results = 0;

    spin_lock_bh(&table->nattbl_lock);

    CI_DLLIST_FOR_EACH2(struct oof_nat_table_entry, entry, link,
                        &table->nattbl_buckets[hash])
      if( CI_IPX_ADDR_EQ(entry->xlated_addr, xlated_addr) &&
          entry->xlated_port == xlated_port ) {
        ci_assert_le(results->n_results, num_bufs);
        if( results->n_results >= num_bufs ) {
          rc = -ENOBUFS;
          break;
        }
        results->results[results->n_results].orig_addr = entry->orig_addr;
        results->results[results->n_results].orig_port = entry->orig_port;
        ++results->n_results;
      }

    spin_unlock_bh(&table->nattbl_lock);

    if( rc == -ENOBUFS ) {
      oof_nat_table_lookup_free(results);
      num_bufs *= 2;
      if( num_bufs > OOF_NAT_LOOKUP_RESULTS_MAX ) {
        rc = -E2BIG;
      }
      else {
        /* This will result in a long-lived GFP_ATOMIC allocation, which would
         * hardly be warranted were it not for the fact that in practice it is
         * very unlikely that this path will be taken, as it would require
         * several services to be pointing at the same backend. */
        results->results = CI_ALLOC_ARRAY(struct oof_nat_lookup_result_entry,
                                          num_bufs);
        if( results->results == NULL )
          rc = -ENOMEM;
      }
    }
  } while( rc == -ENOBUFS );

  return rc;
}


void oof_nat_table_lookup_free(struct oof_nat_lookup_result* results)
{
  if( results->results != results->scratch_space )
    kfree(results->results);
  results->results = NULL;
}


int oof_nat_table_del(struct oof_nat_table* table, ci_addr_t orig_addr,
                      ci_uint16 orig_port)
{
  /* We're guaranteed to have an entry in the table both at the hash of the
   * original address and of the translated address.  The two entries will be
   * linked by the dual_entry member, so it's enough just to do a lookup for
   * the hash of the original address.  In the event that the two hashes are
   * equal, there will be only a single entry and dual_entry will be NULL. */

  ci_uint32 hash = nat_hash(table, orig_addr, orig_port);
  struct oof_nat_table_entry* entry;
  struct oof_nat_table_entry* dual_entry = NULL;

  ci_dllist filter_storage_free_list;
  struct oof_nat_filter* filter;
  struct oof_nat_filter* next;

  ci_dllist_init(&filter_storage_free_list);

  spin_lock_bh(&table->nattbl_lock);

  CI_DLLIST_FOR_EACH2(struct oof_nat_table_entry, entry, link,
                      &table->nattbl_buckets[hash])
    if( CI_IPX_ADDR_EQ(entry->orig_addr, orig_addr) &&
        entry->orig_port == orig_port )
      break;

  if( entry != NULL ) {
    if( (dual_entry = entry->dual_entry) != NULL ) {
      ci_assert_equal(dual_entry->dual_entry, entry);
      ci_dllist_remove(&dual_entry->link);
    }
    ci_dllist_remove(&entry->link);
    --table->nattbl_entries;
  }

  /* If deleting this entry has left us with a surfeit of free oof_nat_filter
   * objects, free a batch.  The watermark below which we must fall is twice
   * the batch size below the number of free objects in order to avoid
   * oscillating (de)allocations. */
  if( table->nattbl_filter_storage_count - table->nattbl_entries >
      2 * FILTER_STORAGE_BATCH_SIZE ) {
    int i;
    for( i = 0; i < FILTER_STORAGE_BATCH_SIZE; ++i ) {
      ci_dllink* link = ci_dllist_pop(&table->nattbl_filter_storage_list);
      ci_dllist_push(&filter_storage_free_list, link);
    }
    table->nattbl_filter_storage_count -= FILTER_STORAGE_BATCH_SIZE;
  }

  spin_unlock_bh(&table->nattbl_lock);

  CI_DLLIST_FOR_EACH3(struct oof_nat_filter, filter, link,
                      &filter_storage_free_list, next)
    CI_FREE_OBJ(filter);
  CI_FREE_OBJ(entry);
  CI_FREE_OBJ(dual_entry);

  return entry == NULL ? -ENOENT : 0;
}


int oof_nat_table_reset(struct oof_nat_table* table)
{
  ci_uint32 bucket;
  struct oof_nat_table_entry* entry;
  struct oof_nat_table_entry* next;
  ci_dllist free_list;

  ci_dllist_init(&free_list);

  spin_lock_bh(&table->nattbl_lock);

  /* Move all of the entries from each bucket into one big list. */
  for( bucket = 0; bucket < table->nattbl_size; ++bucket )
    ci_dllist_join(&free_list, &table->nattbl_buckets[bucket]);

  spin_unlock_bh(&table->nattbl_lock);

  CI_DLLIST_FOR_EACH3(struct oof_nat_table_entry, entry, link, &free_list,
                      next)
    CI_FREE_OBJ(entry);

  return 0;
}


void
oof_nat_table_dump(struct oof_nat_table* table,
                   void (*log)(void* opaque, const char* fmt, ...), void* loga)
{
  ci_uint32 bucket;
  struct oof_nat_table_entry* entry;

  for( bucket = 0; bucket < table->nattbl_size; ++bucket )
    CI_DLLIST_FOR_EACH2(struct oof_nat_table_entry, entry, link,
                        &table->nattbl_buckets[bucket])
      if( bucket == nat_hash(table, entry->xlated_addr, entry->xlated_port) )
        log(loga, "%s: [%08x] "IPX_PORT_FMT" |--> "IPX_PORT_FMT,
            __FUNCTION__, bucket,
            IPX_ARG(AF_IP(entry->orig_addr)), FMT_PORT(entry->orig_port),
            IPX_ARG(AF_IP(entry->xlated_addr)), FMT_PORT(entry->xlated_port));
}


/* Returns an oof_nat_filter object from the pool of free such structures. */
struct oof_nat_filter* oof_nat_table_filter_get(struct oof_nat_table* table)
{
  ci_dllink* filter = NULL;

  spin_lock_bh(&table->nattbl_lock);
  if( ! ci_dllist_is_empty(&table->nattbl_filter_storage_list) )
    filter = ci_dllist_pop(&table->nattbl_filter_storage_list);
  spin_unlock_bh(&table->nattbl_lock);

  if( filter == NULL )
    return NULL;
  return CI_CONTAINER(struct oof_nat_filter, link, filter);
}


/* Releases an oof_nat_filter object to the pool of free such structures. */
void oof_nat_table_filter_put(struct oof_nat_table* table,
                              struct oof_nat_filter* filter)
{
  spin_lock_bh(&table->nattbl_lock);
  ci_dllist_push(&table->nattbl_filter_storage_list, &filter->link);
  spin_unlock_bh(&table->nattbl_lock);
}
