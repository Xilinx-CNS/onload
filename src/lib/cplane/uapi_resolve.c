#include "uapi_private.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#define VLAN_HLEN 4

static unsigned ip_ver(const void *ip_hdr)
{
  return *(const uint8_t*)ip_hdr >> 4;
}

static int64_t apply_fwd_result(struct ef_cp_handle *cp, void *ip_hdr,
                                size_t *prefix_space,
                                struct ef_cp_fwd_meta *meta,
                                const struct cp_fwd_data *data)
{
  size_t space_needed = ETH_HLEN;
  uint16_t ethertype;

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
  meta->ifindex = data->base.ifindex;
  meta->intf_cookie = NULL /*FIXME todo*/;
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
  ip_hdr = (char*)ip_hdr - ETH_HLEN;
  memcpy(ip_hdr, data->dst_mac, ETH_ALEN);
  memcpy((char*)ip_hdr + ETH_ALEN, data->src_mac, ETH_ALEN);
  memcpy((char*)ip_hdr + ETH_ALEN * 2, &ethertype, 2);
  *prefix_space = space_needed;
  return data->encap.type & CICP_LLAP_TYPE_LOOP ? EF_CP_RESOLVE_S_LOOPBACK : 0;
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
                          cp_get_fwd_data(&mib->fwd_table, verinfo));
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
      rc = apply_fwd_result(cp, ip_hdr, prefix_space, meta, &data);
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
