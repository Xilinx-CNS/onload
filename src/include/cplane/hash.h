/* SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __CPLANE_HASH_H__
#define __CPLANE_HASH_H__

#include <cplane/mib.h>

/* Consider using cp_calc_fwd_hash() or cp_calc_mac_hash() rather than calling
 * this function directly. */
static inline void
cp_calc_hash(unsigned size_mask, ci_addr_t const *laddr,
             ci_addr_t const *raddr, unsigned ifindex, cicp_ip_tos_t tos,
             unsigned iif_ifindex, cicp_mac_rowid_t* hash1,
             cicp_mac_rowid_t* hash2)
{
  if( hash1 != NULL )
    *hash1 = onload_hash1(size_mask, *laddr, ifindex, *raddr, tos,
                          iif_ifindex);
  if( hash2 != NULL )
    *hash2 = cplane_hash2(*laddr, ifindex, *raddr, tos, iif_ifindex);
}

/* Calculate primary and secondary hash values for a fwd key.  If only one or
 * other hash is required, hash1 or hash2 may be NULL, in which case the
 * inlining will allow the compiler to emit efficient code. */
static inline void
cp_calc_fwd_hash(struct cp_fwd_table* fwd_table, struct cp_fwd_key* key,
                 cicp_mac_rowid_t* hash1, cicp_mac_rowid_t* hash2)
{
  cp_calc_hash(fwd_table->mask, &key->src, &key->dst, key->ifindex, key->tos,
               key->iif_ifindex, hash1, hash2);
}

static inline void
cp_calc_svc_hash(unsigned size_mask, const ci_addr_t *addr, unsigned port,
                 cicp_mac_rowid_t* hash1, cicp_mac_rowid_t* hash2)
{
  cp_calc_hash(size_mask, addr, &addr_any, port, 0, 0, hash1, hash2);
}

#endif /* defined(__CPLANE_HASH_H__) */
