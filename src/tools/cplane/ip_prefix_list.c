/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <ci/compat.h>

#include "private.h"
#include "ip_prefix_list.h"


int cp_ippl_compare(const void *void_a, const void *void_b)
{
  const struct cp_ip_with_prefix* a = void_a;
  const struct cp_ip_with_prefix* b = void_b;

  if( a->sort_by != b->sort_by )
    return b->sort_by - a->sort_by;
  return memcmp(b->addr.ip6, a->addr.ip6, sizeof(a->addr.ip6));
}

struct cp_ip_with_prefix*
__cp_ippl_search(struct cp_ip_prefix_list* list,
                 struct cp_ip_with_prefix* ipp,
                 cp_ipp_compare_fn_t compare)
{
  CP_IPPL_ASSERT_VALID(list);
  struct cp_ip_with_prefix* entry = bsearch(ipp, list->list, list->sorted,
                                            list->stride, compare);

  if( entry != NULL )
    return entry;

  /* Look up in the unsorted part of the list */
  int i;
  for( i = list->sorted; i < list->used; i++ ) {
    struct cp_ip_with_prefix* ipp1 = cp_ippl_entry(list, i);
    if( compare(ipp1, ipp) == 0 )
      return ipp1;
  }

  return NULL;
}

/* Returns true if the list was modified */
bool cp_ippl_add(struct cp_ip_prefix_list* list,
                 struct cp_ip_with_prefix* ipp, int* idx_p)
{
  CP_IPPL_ASSERT_VALID(list);
  struct cp_ip_with_prefix* entry = cp_ippl_search(list, ipp);

  if( entry ) {
    int idx = cp_ippl_idx(list, entry);
    cp_row_mask_set(list->seen, idx);
    if( idx_p )
      *idx_p = idx;
    return false;
  }

  if( list->used == list->max ) {
    struct cp_ip_with_prefix* new_list =
      realloc(list->list, list->stride * list->max * 2);
    if( new_list == NULL ) {
      *idx_p = -1;
      return false;
    }
    list->list = new_list;
    int i;
    for( i = 0; i < list->max; i++ )
      cp_ippl_entry(list, i + list->max)->sort_by = -1;

    cp_row_mask_t new_seen = cp_row_mask_realloc(list->seen,
                                                 list->max, list->max * 2);
    if( new_seen == NULL ) {
      *idx_p = -1;
      return false;
    }
    list->seen = new_seen;

    list->max *= 2;
  }

  if( idx_p )
    *idx_p = list->used;
  cp_row_mask_set(list->seen, list->used);
  memcpy(cp_ippl_entry(list, list->used++), ipp, list->stride);

  if( ! list->in_dump )
    cp_ippl_sort(list);

  CP_IPPL_ASSERT_VALID(list);
  return true;
}

/* Print callback for printing ip/prefix */
void cp_ippl_print_cb_ip_prefix(struct cp_session* s, int i,
                                struct cp_ip_with_prefix* ipp)
{
  cp_print(s, "  [%d] %s/%d", i, AF_IP_L3(ipp->addr), ipp->prefix);
}

void cp_ippl_print(struct cp_session* s,
                   struct cp_ip_prefix_list* list,
                   cp_ippl_print_callback cb)
{
  int i;

  cp_print(s, "  allocated/used/sorted: %d / %d / %d",
           list->max, list->used, list->sorted);
  for( i = 0; i < list->used; i++ )
    cb(s, i, cp_ippl_entry(list, i));
}

