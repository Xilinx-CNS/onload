/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: Copyright (C) 2024, Advanced Micro Devices, Inc. */
#include "uapi_private.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <endian.h>
#include <immintrin.h>

#define VLAN_HLEN 4

static unsigned ip_ver(const void *ip_hdr)
{
  return *(const uint8_t*)ip_hdr >> 4;
}

static unsigned swizzle_hashify(uint32_t x, unsigned nports)
{
  /* Take an input with its bits not-especially-well distributed and return a
   * value in [0,nports) which is reasonably even. The magic number is picked
   * by experimentation to give decent results for 2-4 ports even when the only
   * variation is in the low-order bits of x
   *
   * Onload uses a different formula in cicp_user_bond_hash_get_hwport() which
   * is less performant, but it matches that implemented in the kernel */
  return ((uint64_t)(x * 0xc1c1c1c1) * nports) >> 32;
}

static int bond_hash_route(struct ef_cp_handle *cp, const void *ip_hdr,
                           const struct cp_fwd_data *data,
                           cicp_hwport_mask_t hwports)
{
  unsigned nports = __builtin_popcount(hwports);
  unsigned hash_input;
  unsigned index;
  int hwport;

  assert(nports >= 1);
  if( data->encap.type & CICP_LLAP_TYPE_XMIT_HASH_LAYER34 ) {
    if( ip_ver(ip_hdr) == 4 ) {
      int hlen = *(const uint8_t*)ip_hdr & 0x0f;
      /* We should be checking the ipproto here, but let's save a couple of
       * cycles by not doing so */
      hash_input = data->base.src.ip4 ^ ((uint32_t*)ip_hdr)[4] ^
                   ((uint16_t*)ip_hdr)[hlen * 2] ^
                   ((uint16_t*)ip_hdr)[hlen * 2 + 1];
    }
    else {
      unsigned l4off = 40;
      uint8_t next_hdr = ((const uint8_t*)ip_hdr)[6];

      hash_input = data->base.src.u32[3] ^ ((uint32_t*)ip_hdr)[9];
      /* Very shoddy header chain parsing */
      while( next_hdr == 0 || next_hdr == 60 || next_hdr == 43 ) {
        next_hdr = ((const uint8_t*)ip_hdr)[l4off];
        l4off += 8 + 8 * ((const uint8_t*)ip_hdr)[l4off + 1];
      }
      if( next_hdr == IPPROTO_TCP || next_hdr == IPPROTO_UDP )
        hash_input ^= ((uint16_t*)ip_hdr)[l4off / 2] ^
                      ((uint16_t*)ip_hdr)[l4off / 2 + 1];
    }
  }
  else if( data->encap.type & CICP_LLAP_TYPE_XMIT_HASH_LAYER23 ) {
    if( ip_ver(ip_hdr) == 4 ) {
      hash_input = data->src_mac[5] ^ data->dst_mac[5] ^
                   data->base.src.ip4 ^ ((uint32_t*)ip_hdr)[4];
    }
    else {
      hash_input = data->src_mac[5] ^ data->dst_mac[5] ^
                   data->base.src.u32[3] ^ ((uint32_t*)ip_hdr)[9];
    }
  }
  else {
    assert(data->encap.type & CICP_LLAP_TYPE_XMIT_HASH_LAYER2);
    hash_input = data->src_mac[5] ^ data->dst_mac[5];
  }
  index = swizzle_hashify(hash_input, nports);
  assert(index < nports);
  /* Cunning use of rarely-encountered CPU instructions: we have an input mask
   * of (e.g.) 0b0010'1100, nports will be 3 (using the popcount opcode). We
   * generate a number in [0,3) by multiplying a well-distributed 32-bit hash
   * value by 3 and taking the top 32-bits.
   * So given a value in [0,3) we need to find the index of the nth set bit of
   * that original hwports mask. The pdep opcode is exactly what we want: it
   * 'expands out' a dense value in to a sparse set of bits, for example given
   * an input of 0bABC and a mask of 0b0010'1100 it'll produce 0b00A0'BC00. The
   * way to use this then becomes clear: set the nth bit of the input, expand
   * that using the mask, then count the trailing zeros. 5 cycles latency. */
  hwport = ffs(_pdep_u32(1 << index, hwports));
  return cp->hwport_ifindex[hwport];
}

static int64_t apply_fwd_result(struct ef_cp_handle *cp, void *ip_hdr,
                                size_t *prefix_space,
                                struct ef_cp_fwd_meta *meta,
                                const struct cp_fwd_data *data, uint64_t flags)
{
  size_t space_needed = ETH_HLEN;
  uint16_t ethertype;
  struct llap_extra *extra;
  int64_t rc = 0;
  int ifindex = data->base.ifindex;

  if( ! (data->flags & CICP_FWD_DATA_FLAG_ARP_VALID) ) {
    if( data->flags & CICP_FWD_DATA_FLAG_ARP_FAILED )
      return -EHOSTUNREACH;
    if( ! (flags & EF_CP_RESOLVE_F_NO_ARP) )
      return -EAGAIN;
    rc |= EF_CP_RESOLVE_S_ARP_INVALID;
  }
  if( data->encap.type & CICP_LLAP_TYPE_VLAN )
    space_needed += VLAN_HLEN;
  if( *prefix_space < space_needed )
    return -E2BIG;
  if( data->encap.type & CICP_LLAP_TYPE_USES_HASH ) {
    if( ! (flags & EF_CP_RESOLVE_F_UNREGISTERED) ) {
      cicp_hwport_mask_t hwports = data->hwports & cp->registered_hwports;
      if( ! hwports )
        return -EADDRNOTAVAIL;
      ifindex = bond_hash_route(cp, ip_hdr, data, hwports);
    }
  }
  extra = cp_uapi_lookup_ifindex(cp, ifindex);
  if( extra && extra->is_registered )
    meta->intf_cookie = extra->cookie;
  else if( flags & EF_CP_RESOLVE_F_UNREGISTERED ) {
    meta->intf_cookie = NULL;
    rc |= EF_CP_RESOLVE_S_UNREGISTERED;
  }
  else {
    cicp_hwport_mask_t hwports = data->hwports & cp->registered_hwports;
    if( ! hwports ) {
      meta->ifindex = ifindex;  /* Undocumented feature, used by TCPDirect for
                                 * better error reporting */
      return -EADDRNOTAVAIL;
    }
    ifindex = cp->hwport_ifindex[ffs(hwports)];
    extra = cp_uapi_lookup_ifindex(cp, ifindex);
    meta->intf_cookie = extra->cookie;
  }
  meta->ifindex = ifindex;
  meta->mtu = data->base.mtu;
  if( ip_ver(ip_hdr) == 4 ) {
    ((uint8_t*)ip_hdr)[8] = data->base.hop_limit;
    memcpy((char*)ip_hdr + 12, &data->base.src.ip4, 4);
    ethertype = htons(ETH_P_IP);
  }
  else {
    assert(ip_ver(ip_hdr) == 6);
    ((uint8_t*)ip_hdr)[7] = data->base.hop_limit;
    memcpy((char*)ip_hdr + 8, data->base.src.ip6, 16);
    ethertype = htons(ETH_P_IPV6);
  }
  if( data->encap.type & CICP_LLAP_TYPE_VLAN ) {
    ip_hdr = (char*)ip_hdr - VLAN_HLEN;
    ((uint16_t*)ip_hdr)[0] = htons(data->encap.vlan_id);
    ((uint16_t*)ip_hdr)[1] = ethertype;
    ethertype = htons(ETH_P_8021Q);
  }
  if( data->encap.type & CICP_LLAP_TYPE_LOOP )
    rc |= EF_CP_RESOLVE_S_LOOPBACK;
  ip_hdr = (char*)ip_hdr - ETH_HLEN;
  memcpy(ip_hdr, data->dst_mac, ETH_ALEN);
  memcpy((char*)ip_hdr + ETH_ALEN, data->src_mac, ETH_ALEN);
  memcpy((char*)ip_hdr + ETH_ALEN * 2, &ethertype, 2);
  *prefix_space = space_needed;
  return rc;
}

static struct cp_fwd_key build_key(const void *ip_hdr,
                                   const struct ef_cp_fwd_meta *meta,
                                   uint64_t flags)
{
  struct cp_fwd_key key;

  if( ip_ver(ip_hdr) == 4 ) {
    const struct iphdr *ip4 = ip_hdr;
    key.dst = CI_ADDR_SH_FROM_IP4(ip4->daddr);
    key.tos = ip4->tos;
    if( flags & EF_CP_RESOLVE_F_BIND_SRC )
      key.src = CI_ADDR_SH_FROM_IP4(ip4->saddr);
    else
      key.src = CI_ADDR_SH_FROM_IP4(0);
  }
  else {
    const struct ip6_hdr *ip6 = ip_hdr;
    assert(ip_ver(ip_hdr) == 6);
    memcpy(&key.dst, &ip6->ip6_dst, sizeof(struct in6_addr));
    /* Pass 0 IPv6 tclass value into cp_fwd_key tos field because Linux policy
     * based routing doesn't consider tclass when performing route lookup
     * for TCP and UDP connected send. Though, tclass is considered for UDP
     * unconnected send. As a result, there would be a single fwd entry for all
     * IPv6 tclass values. */
    key.tos = 0;
    if( flags & EF_CP_RESOLVE_F_BIND_SRC )
      memcpy(&key.src, &ip6->ip6_src, sizeof(struct in6_addr));
    else
      memset(&key.src, 0, sizeof(key.src));
  }
  key.iif_ifindex = meta->iif_ifindex >= 0 ? meta->iif_ifindex : CI_IFID_BAD;
  key.flag = CP_FWD_KEY_REQ_WAIT;
  if( flags & EF_CP_RESOLVE_F_TRANSPARENT )
    key.flag |= CP_FWD_KEY_TRANSPARENT;
  key.ifindex = meta->ifindex >= 0 ? meta->ifindex : CI_IFID_BAD;
  return key;
}

EF_CP_PUBLIC_API
int64_t ef_cp_resolve(struct ef_cp_handle *cp, void *ip_hdr,
                      size_t *prefix_space, struct ef_cp_fwd_meta *meta,
                      struct ef_cp_route_verinfo *ver, uint64_t flags)
{
  /* The fwd-table ID is meaningless at UL, but we have to pass something. */
  const cp_fwd_table_id fwd_table_id = CP_FWD_TABLE_ID_INVALID;
  /* evil cast, for API boundary reasons. ef_cp_verinfo::generation is not
   * currently used */
  cicp_verinfo_t *verinfo = (cicp_verinfo_t*)ver;
  int64_t rc;

  /* for performance, not checking for invalid flags here */
  assert(*prefix_space >= ETH_HLEN);
  assert(ip_ver(ip_hdr) == 4 || ip_ver(ip_hdr) == 6);

  /* Are we lucky?  Is the verlock valid? */
  if( ver->generation != 0 &&
      oo_cp_verinfo_is_valid(&cp->cp, verinfo, fwd_table_id) ) {
    struct cp_mibs *mib = &cp->cp.mib[0];
    cp_get_fwd_rw(&mib->fwd_table, verinfo)->frc_used = ci_frc64_get();
    rc = apply_fwd_result(cp, ip_hdr, prefix_space, meta,
                          cp_get_fwd_data(&mib->fwd_table, verinfo), flags);
    if( rc < 0 ) {
      /* It's convenient for callers if we invalidate the verinfo when we
       * return an error, since it makes the application's dispatch loop
       * naturally retry routing. */
      ver->generation = 0;
    }
    ci_rmb();
    if( cp_fwd_version_matches(&mib->fwd_table, verinfo) )
      return rc;
  }

  /* We are unlucky. Let's go via slow path. */
  {
    struct cp_fwd_key key = build_key(ip_hdr, meta, flags);
    struct cp_fwd_data data;

    rc = __oo_cp_route_resolve(&cp->cp, verinfo, &key,
                               (flags & EF_CP_RESOLVE_F_NO_CTXT_SW) == 0,
                               &data, fwd_table_id);
    if( rc >= 0 ) {
      /* verinfo::generation is intended to be used to support cplane server
       * restarts. That's not currently implemented, but we still use it to
       * allow a zero-initialized verinfo to be classed as invalid (thus making
       * the API harder to misuse). */
      ver->generation = 1;
      rc = apply_fwd_result(cp, ip_hdr, prefix_space, meta, &data, flags);
    }
    if( rc < 0 )
      ver->generation = 0;
    return rc;
  }
}

EF_CP_PUBLIC_API
bool ef_cp_route_verify(struct ef_cp_handle *cp,
                        const struct ef_cp_route_verinfo *ver)
{
  cicp_verinfo_t *verinfo = (cicp_verinfo_t*)ver;
  const cp_fwd_table_id fwd_table_id = CP_FWD_TABLE_ID_INVALID;
  return ver->generation != 0 &&
         oo_cp_verinfo_is_valid(&cp->cp, verinfo, fwd_table_id);
}
