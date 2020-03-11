/* SPDX-License-Identifier: Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __TOOLS_CPLANE_IP_PREFIX_LIST_H__
#define __TOOLS_CPLANE_IP_PREFIX_LIST_H__

#include "print.h"


/* An entry for various "IP + some data" tables.  In the most cases "some
 * data" includes prefix length, or more rarely another integer value which
 * is convenient to sort by.
 * If "some data" is larger than simple integer, then this structure can be
 * embedded.  Even embedded structure can be used with cp_ip_prefix_list,
 * see the "stride" field.
 */
struct cp_ip_with_prefix {
  ci_addr_sh_t addr;
  union {
    int sort_by; /* the main key when sorting cp_ip_prefix_list;
                    negative means the whole entry is unused */
    int prefix;  /* convenient name when used for ip/prefix */
    int ifindex; /* ... when used for ip + ifindex */
  };
};

/* compare function suitable to passing to bsearch & qsort.
 * Must return b->prefix - a->prefix if it is non-zero (i.e. longer
 * prefixes should be sorted first).
 * See also cp_ippl_compare(), which fits for the most ip-prefix lists.
 */
typedef int (*cp_ipp_compare_fn_t)(const void *void_a, const void *void_b);

/* List of ip/prefix entries; can be updated and sorted if needed. */
struct cp_ip_prefix_list {
  /* an array of structures starting with cp_ip_with_prefix  */
  void* list;
  size_t stride;       /* size of the structures above */
  int in_dump;

  cp_ipp_compare_fn_t compare;
  cp_row_mask_t seen;  /* which entries we've seen during this dump? */
  cicp_rowid_t max;    /* allocated array size */
  cicp_rowid_t used;   /* number of entries in use */
  cicp_rowid_t sorted; /* number of sorted entries */
};
#define CP_IPPL_ASSERT_VALID(list) \
  ci_assert_le((list)->sorted, (list)->used);   \
  ci_assert_le((list)->used, (list)->max);      \
  ci_assert_impl(!(list)->in_dump, (list)->used == (list)->sorted);

static inline struct cp_ip_with_prefix*
cp_ippl_entry(struct cp_ip_prefix_list* list, int idx)
{
  return (struct cp_ip_with_prefix *)(((uintptr_t)list->list) +
                                      list->stride * idx);
}
static inline int
cp_ippl_idx(struct cp_ip_prefix_list* list, struct cp_ip_with_prefix* entry)
{
  return ((uintptr_t)entry - (uintptr_t)list->list) / list->stride;
}

int cp_ippl_compare(const void *void_a, const void *void_b);
static inline void
cp_ippl_init(struct cp_ip_prefix_list* list, size_t stride,
             cp_ipp_compare_fn_t compare, cicp_rowid_t size)
{
  list->stride = stride;
  list->compare = compare == NULL ? cp_ippl_compare : compare;
  list->list = calloc(list->stride, size);
  ci_assert(list->list);
  list->seen = cp_row_mask_alloc(size);
  list->max = size;
  list->used = list->sorted = 0;
  list->in_dump = false;

  int i;
  for( i = 0; i < size; i++ )
    cp_ippl_entry(list, i)->sort_by = -1;
  CP_IPPL_ASSERT_VALID(list);
}

typedef void (*cp_ippl_print_callback)(struct cp_session* s, int i,
                                       struct cp_ip_with_prefix*);
void cp_ippl_print_cb_ip_prefix(struct cp_session* s, int i,
                                struct cp_ip_with_prefix* ipp);
void cp_ippl_print(struct cp_session* s,
                   struct cp_ip_prefix_list* list,
                   cp_ippl_print_callback cb);
bool cp_ippl_add(struct cp_ip_prefix_list* list,
                 struct cp_ip_with_prefix* ipp, int* idx_p);
static inline void
cp_ippl_sort(struct cp_ip_prefix_list* list)
{
  qsort(list->list, list->used, list->stride, list->compare);

  /* Check that the last entries are really used */
  while( list->used > 0 &&
         cp_ippl_entry(list, list->used - 1)->sort_by == -1 )
    list->used--;

  list->sorted = list->used;
  CP_IPPL_ASSERT_VALID(list);
}

struct cp_ip_with_prefix*
__cp_ippl_search(struct cp_ip_prefix_list* list,
                 struct cp_ip_with_prefix* ipp,
                 cp_ipp_compare_fn_t compare);
static inline struct cp_ip_with_prefix*
cp_ippl_search(struct cp_ip_prefix_list* list,
               struct cp_ip_with_prefix* ipp)
{
  return __cp_ippl_search(list, ipp, list->compare);
}

/* The "entry" parameter should be the pointer to the member list.  I.e.
 * it is something returned by cp_ippl_search(). */
static inline void
cp_ippl_del(struct cp_ip_prefix_list* list,
            struct cp_ip_with_prefix* entry)
{
  CP_IPPL_ASSERT_VALID(list);
  int idx = cp_ippl_idx(list, entry);
  ci_assert_ge(idx, 0);
  ci_assert_lt(idx, list->max);

  entry->addr = addr_sh_any;
  entry->sort_by = -1;

  if( ! list->in_dump ) {
    cp_ippl_sort(list);
  }
  else {
    /* mark it as "not seen" */
    if( list->sorted > idx )
      list->sorted = idx;
    cp_row_mask_unset(list->seen, idx);
  }

  CP_IPPL_ASSERT_VALID(list);
}

typedef void (*cp_ippl_finalize_callback)(struct cp_session* s,
                                         struct cp_ip_with_prefix*);

/* Returns true if something changed */
static inline bool cp_ippl_finalize(struct cp_session* s,
                                    struct cp_ip_prefix_list* list,
                                    cp_ippl_finalize_callback cb)
{
  cicp_rowid_t id = -1;
  cicp_rowid_t removed = 0;

  ci_assert(list->in_dump);

  CP_IPPL_ASSERT_VALID(list);
  while( (id =
         cp_row_mask_iter_set(list->seen, ++id, list->used, false) ) !=
         CICP_MAC_ROWID_BAD ) {
    struct cp_ip_with_prefix* ipp = cp_ippl_entry(list, id);
    if( ipp->sort_by < 0 )
      break;

    if( cb != NULL )
      cb(s, ipp);

    /* We'll push this entry to the end with qsort(). */
    ipp->addr = addr_sh_any;
    ipp->sort_by = -1;
    removed++;
  }

  if( removed != 0 || list->used != list->sorted )
    cp_ippl_sort(list);

  list->in_dump = false;
  CP_IPPL_ASSERT_VALID(list);
  return removed != 0;
}


static inline void
cp_ippl_start_dump(struct cp_ip_prefix_list* list)
{
  ci_assert(!list->in_dump);
  CP_IPPL_ASSERT_VALID(list);
  cp_row_mask_init(list->seen, list->sorted);
  list->in_dump = true;
}


/**************************************************************************
 * Functions below assume that the cp_ip_prefix_list contains ip/prefix and
 * not ip+<any arbitrary integer such as ifindex>.
 */

/* Maximum address prefix leangth */
#define CI_IPX_MAX_PREFIX_LEN(af) (((af) == AF_INET6) ? 128 : 32)


static inline cicp_prefixlen_t
cp_ipx_clz(int af, ci_addr_sh_t addr)
{
  if( af == AF_INET6 ) {
    cicp_prefixlen_t l = 0;
    int i;

    for( i = 0; i < sizeof(ci_ip6_addr_t)/sizeof(uint32_t); i++ ) {
      if( ((uint32_t*)addr.ip6)[i] != 0 ) {
        l += __builtin_clz(CI_BSWAP_BE32(((uint32_t*)addr.ip6)[i]));
        break;
      }
      l += 32;
    }
    return l;
  }
  else
    return __builtin_clz(CI_BSWAP_BE32(addr.ip4));
}

static inline int
cp_ipx_ippl_pfx_match(int af, ci_addr_sh_t addr1, ci_addr_sh_t addr2,
                      cicp_prefixlen_t pfx)
{
  return (af == AF_INET6) ? cp_ip6_pfx_match(&addr1, &addr2, pfx) :
      cp_ip_prefix_match(addr1.ip4, addr2.ip4, pfx);
}

static inline cicp_prefixlen_t
cp_ipx_ippl_pfx_get(int af, ci_addr_sh_t addr1, ci_addr_sh_t addr2)
{
  return cp_ipx_clz(af, ci_ipx_addr_xor(af, &addr1, &addr2));
}

/*
 * Calculate the prefix-length at which an entry should be added to the
 * route table.  This is equal to the maximum of
 * (1) the prefix-length of the most specific matching rule and
 * (2) the smallest prefix-length ensuring that all non-matching rules
 *     do not match the new rule either.
 */
static inline cicp_prefixlen_t
cp_ippl_get_prefix(struct cp_ip_prefix_list* list, int af, ci_addr_sh_t addr)
{
  cicp_prefixlen_t len;
  cicp_rowid_t id;

  /* INADDR_ANY has special meaning in many contexts.  Assume that
   * 0.0.0.0/32 is the first entry in any list.
   *
   * For example, 1.2.3.4 can be inserted as 1.0.0.0/8, but it should not
   * be inserted as 0.0.0.0/7.  1.2.3.4 should not be converted to
   * INADDR_ANY.
   */
  if( CI_IPX_ADDR_IS_ANY(addr) )
    return CI_IPX_MAX_PREFIX_LEN(af);
  len = cp_ipx_clz(af, addr) + 1;

  for( id = 0; id < list->used; id++ ) {
    struct cp_ip_with_prefix* ipp = cp_ippl_entry(list, id);
    cicp_prefixlen_t l;
    if( cp_ipx_ippl_pfx_match(af, addr, ipp->addr, ipp->prefix) )
      l = ipp->prefix;
    else
      l = cp_ipx_ippl_pfx_get(af, addr, ipp->addr) + 1;
    if( l > len )
      len = l;
    if( len >= ipp->prefix && id < list->sorted )
      /* We can skip sorted part of the table as no further entry will have
       * longer prefix, however we still need to go through unsorted bit */
      id = list->sorted - 1; /* - 1 is due to following id++ */
  }

  return len;
}

#endif /*__TOOLS_CPLANE_IP_PREFIX_LIST_H__*/
