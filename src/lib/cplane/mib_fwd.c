/* SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* mib worker functions for fwd operations in the server.
 * i.e. these functions should not assume that the fwd_table required is in the
 * mib.
 * Client code requiring the same functions should wrap the functions here in
 * a wrapper function that passes in mib->fwd_table.
 */

#include <ci/tools.h>

#define CI_CFG_IPV6 1
#include <onload/hash.h>
#include <cplane/hash.h>
#include <cplane/mib.h>


cicp_mac_rowid_t
cp_fwd_find_row_iterate(struct cp_fwd_table* fwd_table,
                        struct cp_fwd_key* key, struct cp_fwd_key* match,
                        cp_fwd_find_hook_fn hook, void* hook_arg)
{
  cicp_mac_rowid_t hash1, hash2, hash;
  int iter = 0;

  cp_calc_fwd_hash(fwd_table, key, &hash1, NULL);
  hash = hash1;
  /* Note that hash2 is always odd, so using zero as value to indicate
   * invalidity is legitimate. */
  hash2 = 0;

  do {
    struct cp_fwd_row* fwd = cp_get_fwd_by_id(fwd_table, hash);
    if( fwd->use == 0 )
      return CICP_MAC_ROWID_BAD;
    if( cp_fwd_key_match(fwd, match) &&
        hook(fwd_table, hash, hook_arg) )
      return hash;
    if( hash2 == 0 )
      cp_calc_fwd_hash(fwd_table, key, NULL, &hash2);
    hash = (hash + hash2) & fwd_table->mask;
  } while( ++iter < (fwd_table->mask >> 2) );

  return CICP_MAC_ROWID_BAD;
}


static int
weight_check_match(struct cp_fwd_table* fwd_table,
                   cicp_mac_rowid_t fwd_id, void* arg)
{
  struct cp_fwd_row* fwd = cp_get_fwd_by_id(fwd_table, fwd_id);
  ci_uint32 val = *(ci_uint32*)arg;
  return cp_fwd_weight_match(val, &fwd->data->weight);
}


cicp_mac_rowid_t
__cp_fwd_find_row(struct cp_fwd_table* fwd_table, struct cp_fwd_key* key,
                  struct cp_fwd_key* match, ci_uint32 weight)
{
  return cp_fwd_find_row_iterate(fwd_table, key, match,
                                 weight_check_match, &weight);
}

static void
ci_fwd_pfx_next(ci_ipx_pfx_t* mask, ci_uint8 pfx)
{
  uint64_t x[3];
  bw_shift_bit_192(x, pfx);
  bw_not_192(x);
  bw_and_192((uint64_t*)mask->ip6, x);
}

cicp_mac_rowid_t
__cp_fwd_find_match(struct cp_fwd_table* fwd_table, struct cp_fwd_key* key,
                    ci_uint32 weight,
                    ci_ipx_pfx_t src_prefs_in, ci_ipx_pfx_t dst_prefs)
{
  ci_ipx_pfx_t src_prefs, zero_prefs = {};
  ci_uint8 src_pref, dst_pref;
  struct cp_fwd_key k = *key;

  /* We must check entries with large destination prefixes (/32 for IPv4)
   * first to ensure we get correct PMTU information.  All other prefixes
   * are equally good.
   */
  while( cp_get_fwd_pfx_cmp(&dst_prefs, &zero_prefs) ) {
    dst_pref = cp_get_largest_prefix(dst_prefs);
    k.dst = key->dst;
    cp_addr_apply_pfx(&k.dst, dst_pref);

    src_prefs = src_prefs_in;
    while( cp_get_fwd_pfx_cmp(&src_prefs, &zero_prefs) ) {
      cicp_mac_rowid_t id;

      src_pref = cp_get_largest_prefix(src_prefs);
      k.src = key->src;
      cp_addr_apply_pfx(&k.src, src_pref);

      id = __cp_fwd_find_row(fwd_table, &k, key, weight);
      if( id != CICP_ROWID_BAD )
        return id;
      ci_fwd_pfx_next(&src_prefs, src_pref);
    }
    ci_fwd_pfx_next(&dst_prefs, dst_pref);
  }

  return CICP_ROWID_BAD;
}
