#include "uapi_private.h"
#include <errno.h>
#include <endian.h>

EF_CP_PUBLIC_API
struct ef_cp_intf_verinfo ef_cp_intf_version_get(struct ef_cp_handle *cp)
{
  struct ef_cp_intf_verinfo ver = {
    .generation = 1,
    .version = *cp->cp.mib[0].llap_version,
  };
  return ver;
}

EF_CP_PUBLIC_API
bool ef_cp_intf_version_verify(struct ef_cp_handle *cp,
                               const struct ef_cp_intf_verinfo *ver)
{
  /* cplane server restarts not currently supported, so no need to check
   * generation */
  return ver->version == *cp->cp.mib[0].llap_version;
}

static bool llap_matches_filter_flags(const cicp_llap_row_t *row,
                                      unsigned flags)
{
  unsigned clas = 0;
  if( flags & EF_CP_GET_INTFS_F_UP_ONLY && ! (row->flags & CP_LLAP_UP) )
    return false;
  if( row->xdp_prog_id )
    clas |= EF_CP_GET_INTFS_F_GENERIC;
  else if( row->flags & CP_LLAP_ALIEN || ! row->rx_hwports )
    clas |= EF_CP_GET_INTFS_F_OTHER;
  else
    clas |= EF_CP_GET_INTFS_F_NATIVE;
  return (flags & clas) != 0;
}

static int ef_cp_get_filtered_intfs(struct ef_cp_handle *cp, int self,
                                    int *ifindices, size_t n, unsigned flags,
                                    bool (*filter)(const cicp_llap_row_t *row,
                                                   const cicp_llap_row_t *self_row))
{
  struct cp_mibs* mib;
  cp_version_t version;
  int rowid;
  int rc;
  cicp_llap_row_t *self_row = NULL;

  if( flags & ~(EF_CP_GET_INTFS_F_NATIVE | EF_CP_GET_INTFS_F_GENERIC |
                EF_CP_GET_INTFS_F_OTHER | EF_CP_GET_INTFS_F_UP_ONLY) )
    return -EINVAL;
  CP_VERLOCK_START(version, mib, &cp->cp)
  rc = 0;
  if( self >= 0 ) {
    for( rowid = 0; rowid < mib->dim->llap_max; ++rowid ) {
      if( ! cicp_llap_row_is_free(&mib->llap[rowid]) &&
          mib->llap[rowid].ifindex == self ) {
        self_row = &mib->llap[rowid];
        break;
      }
    }
    if( ! self_row )
      return -ENOENT;
  }
  for( rowid = 0; rowid < mib->dim->llap_max; ++rowid ) {
    if( cicp_llap_row_is_free(&mib->llap[rowid]) )
      break;
    if( filter && ! filter(&mib->llap[rowid], self_row) )
      continue;
    if( llap_matches_filter_flags(&mib->llap[rowid], flags) ) {
      if( rc < n )
        ifindices[rc] = mib->llap[rowid].ifindex;
      ++rc;
    }
  }
  CP_VERLOCK_STOP(version, mib)
  return rc;
}

EF_CP_PUBLIC_API
int ef_cp_get_all_intfs(struct ef_cp_handle *cp, int *ifindices, size_t n,
                        unsigned flags)
{
  return ef_cp_get_filtered_intfs(cp, -1, ifindices, n, flags, NULL);
}

static bool filter_lower(const cicp_llap_row_t *row,
                         const cicp_llap_row_t *self_row)
{
  if( row == self_row )
    return false;
  return row->encap.master_ifindex == self_row->ifindex ||
         self_row->encap.link_ifindex == row->ifindex;
}

static bool filter_lowest(const cicp_llap_row_t *row,
                          const cicp_llap_row_t *self_row)
{
  return row->rx_hwports & self_row->rx_hwports &&
         (row->encap.type == CICP_LLAP_TYPE_NONE ||
          row->encap.type == CICP_LLAP_TYPE_SLAVE);
}

EF_CP_PUBLIC_API
int ef_cp_get_lower_intfs(struct ef_cp_handle *cp, int child,
                          int *ifindices, size_t n, unsigned flags)
{
  if( flags & EF_CP_GET_INTFS_F_MOST_DERIVED ) {
    /* The documentation implies that this mode is done by walking the tree
     * downwards, but it's simpler if we do it using the hwports */
    return ef_cp_get_filtered_intfs(cp, child, ifindices, n,
                                    flags & ~EF_CP_GET_INTFS_F_MOST_DERIVED,
                                    filter_lowest);
  }
  return ef_cp_get_filtered_intfs(cp, child, ifindices, n, flags, filter_lower);
}

static bool filter_upper(const cicp_llap_row_t *row,
                         const cicp_llap_row_t *self_row)
{
  if( row == self_row )
    return false;
  return row->encap.link_ifindex == self_row->ifindex ||
         self_row->encap.master_ifindex == row->ifindex;
}

EF_CP_PUBLIC_API
int ef_cp_get_upper_intfs(struct ef_cp_handle *cp, int parent,
                          int *ifindices, size_t n, unsigned flags)
{
  return ef_cp_get_filtered_intfs(cp, parent, ifindices, n, flags, filter_upper);
}

static void cp_intf_to_ef(const cicp_llap_row_t *row,
                          const struct llap_extra *extra,
                          struct ef_cp_intf *intf)
{
  intf->ifindex = row->ifindex;
  CI_BUILD_ASSERT(EF_CP_INTF_F_UP == CP_LLAP_UP);
  CI_BUILD_ASSERT(EF_CP_INTF_F_ALIEN == CP_LLAP_ALIEN);
  intf->flags = row->flags;
  intf->mtu = row->mtu;
  intf->registered_cookie = extra->is_registered ? extra->cookie : NULL;
  CI_BUILD_ASSERT(EF_CP_ENCAP_F_VLAN == CICP_LLAP_TYPE_VLAN);
  CI_BUILD_ASSERT(EF_CP_ENCAP_F_BOND == CICP_LLAP_TYPE_BOND);
  CI_BUILD_ASSERT(EF_CP_ENCAP_F_BOND_PORT == CICP_LLAP_TYPE_SLAVE);
  CI_BUILD_ASSERT(EF_CP_ENCAP_F_LOOP == CICP_LLAP_TYPE_LOOP);
  CI_BUILD_ASSERT(EF_CP_ENCAP_F_MACVLAN == CICP_LLAP_TYPE_MACVLAN);
  CI_BUILD_ASSERT(EF_CP_ENCAP_F_VETH == CICP_LLAP_TYPE_VETH);
  CI_BUILD_ASSERT(EF_CP_ENCAP_F_IPVLAN == CICP_LLAP_TYPE_IPVLAN);
  intf->encap = row->encap.type;
  intf->encap_data[0] = row->encap.vlan_id;
  memcpy(intf->mac, row->mac, sizeof(intf->mac));
  strncpy(intf->name, row->name, sizeof(intf->name));
}

EF_CP_PUBLIC_API
int ef_cp_get_intf(struct ef_cp_handle *cp, int ifindex,
                   struct ef_cp_intf *intf, unsigned flags)
{
  struct cp_mibs* mib;
  cp_version_t version;
  int rowid;
  int rc;

  if( flags )
    return -EINVAL;
  CP_VERLOCK_START(version, mib, &cp->cp)
  rc = -ENOENT;
  for( rowid = 0; rowid < mib->dim->llap_max; ++rowid ) {
    if( cicp_llap_row_is_free(&mib->llap[rowid]) )
      break;
    if( mib->llap[rowid].ifindex == ifindex ) {
      cp_intf_to_ef(&mib->llap[rowid], &cp->llap_extra[rowid], intf);
      rc = 0;
      break;
    }
  }
  CP_VERLOCK_STOP(version, mib)
  return rc;
}

EF_CP_PUBLIC_API
int ef_cp_get_intf_by_name(struct ef_cp_handle *cp, const char* name,
                           struct ef_cp_intf *intf, unsigned flags)
{
  struct cp_mibs* mib;
  cp_version_t version;
  int rowid;
  int rc;

  if( flags )
    return -EINVAL;
  if( strlen(name) > IFNAMSIZ )
    return -EINVAL;
  CP_VERLOCK_START(version, mib, &cp->cp)
  rc = -ENOENT;
  for( rowid = 0; rowid < mib->dim->llap_max; ++rowid ) {
    if( cicp_llap_row_is_free(&mib->llap[rowid]) )
      break;
    if( ! strncmp(mib->llap[rowid].name, name, sizeof(mib->llap[rowid].name)) ) {
      cp_intf_to_ef(&mib->llap[rowid], &cp->llap_extra[rowid], intf);
      rc = 0;
      break;
    }
  }
  CP_VERLOCK_STOP(version, mib)
  return rc;
}

static ef_cp_ipaddr ip4_to_ipaddr(ci_ip_addr_t ip)
{
  return (ef_cp_ipaddr){{0, 0, htobe32(0xffff), ip}};
}

static ef_cp_ipaddr ip6_to_ipaddr(ci_ip6_addr_t ip)
{
  ef_cp_ipaddr r;
  memcpy(&r, &ip, sizeof(r));
  return r;
}

EF_CP_PUBLIC_API
int ef_cp_get_intf_addrs(struct ef_cp_handle *cp, int ifindex,
                         struct ef_cp_ifaddr* addrs, size_t n, unsigned flags)
{
  struct cp_mibs* mib;
  cp_version_t version;
  int rowid;
  int rc;
  const ef_cp_ipaddr ip6_local_broadcast_ip = {{
    htobe32(0xff02), 0, 0, htobe32(1)
  }};

  if( flags )
    return -EINVAL;
  CP_VERLOCK_START(version, mib, &cp->cp)
  rc = 0;
  for( rowid = 0; rowid < mib->dim->ipif_max; ++rowid ) {
    if( cicp_ipif_row_is_free(&mib->ipif[rowid]) )
      break;
    if( mib->ipif[rowid].ifindex == ifindex ) {
      if( rc < n ) {
        addrs[rc] = (struct ef_cp_ifaddr){
          .ifindex = mib->ipif[rowid].ifindex,
          .scope = mib->ipif[rowid].scope,
          .flags = 0,
          .ip = ip4_to_ipaddr(mib->ipif[rowid].net_ip),
          .prefix_len = mib->ipif[rowid].net_ipset,
          .bcast = ip4_to_ipaddr(mib->ipif[rowid].bcast_ip),
        };
      }
      ++rc;
    }
  }
  for( rowid = 0; rowid < mib->dim->ip6if_max; ++rowid ) {
    if( cicp_ip6if_row_is_free(&mib->ip6if[rowid]) )
      break;
    if( mib->ip6if[rowid].ifindex == ifindex ) {
      if( rc < n ) {
        addrs[rc] = (struct ef_cp_ifaddr){
          .ifindex = mib->ip6if[rowid].ifindex,
          .scope = mib->ip6if[rowid].scope,
          .flags = 0,
          .ip = ip6_to_ipaddr(mib->ip6if[rowid].net_ip6),
          .prefix_len = mib->ip6if[rowid].net_ipset,
          .bcast = ip6_local_broadcast_ip,
        };
      }
      ++rc;
    }
  }
  CP_VERLOCK_STOP(version, mib)
  return rc;
}

EF_CP_PUBLIC_API
int ef_cp_register_intf(struct ef_cp_handle *cp, int ifindex, void *user_cookie,
                        unsigned flags)
{
  struct cp_mibs* mib;
  cp_version_t version;
  int rowid;
  int rc;

  if( flags )
    return -EINVAL;
  CP_VERLOCK_START(version, mib, &cp->cp)
  rc = -ENOENT;
  for( rowid = 0; rowid < mib->dim->llap_max; ++rowid ) {
    if( cicp_llap_row_is_free(&mib->llap[rowid]) )
      break;
    if( mib->llap[rowid].ifindex == ifindex ) {
      cp->llap_extra[rowid].cookie = user_cookie;
      ci_wmb();
      cp->llap_extra[rowid].is_registered = true;
      rc = 0;
      break;
    }
  }
  CP_VERLOCK_STOP(version, mib)
  return rc;
}

EF_CP_PUBLIC_API
int ef_cp_unregister_intf(struct ef_cp_handle *cp, int ifindex, unsigned flags)
{
  struct cp_mibs* mib;
  cp_version_t version;
  int rowid;
  int rc;

  if( flags )
    return -EINVAL;
  CP_VERLOCK_START(version, mib, &cp->cp)
  rc = -ENOENT;
  for( rowid = 0; rowid < mib->dim->llap_max; ++rowid ) {
    if( cicp_llap_row_is_free(&mib->llap[rowid]) )
      break;
    if( mib->llap[rowid].ifindex == ifindex ) {
      cp->llap_extra[rowid].is_registered = false;
      rc = 0;
      break;
    }
  }
  CP_VERLOCK_STOP(version, mib)
  return rc;
}
