/* SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* This header describes the interface between the open source parts
 * of Onload and the binary-only control plane server.
 *
 * We use an md5sum over certain headers to ensure that userland and
 * kernel drivers are built against a compatible interface. The
 * control plane server and its clients will verify this hash against
 * the kernel module and refuse to start if there is a version
 * mismatch.
 *
 * Users should therefore not modify these headers because the
 * supplied control plane server will refuse to operate with the
 * resulting module.
 */

/* Cplane interface to be used from Onload */
#ifndef __TOOLS_CPLANE_ONLOAD_H__
#define __TOOLS_CPLANE_ONLOAD_H__

#include <cplane/mib.h>
#include <cplane/ioctl.h>
#include <ci/tools.h>

#ifdef __KERNEL__
#include <onload/cplane_driver.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __KERNEL__
#ifndef __CI_UL_SYSCALL_UNIX_H__
/* libonload provides this; cp_client provides this in another way */
extern int (* ci_sys_ioctl)(int, long unsigned int, ...);
#endif

static inline int cp_ioctl(int fd, long unsigned int op, void* arg)
{
  int saved_errno = errno;
  int rc = ci_sys_ioctl(fd, op, arg);
  if( rc == 0 )
    return 0;
  rc = -errno;
  errno = saved_errno;
  return rc;
}
#endif


#define CP_VERLOCK_START(var_, mib_, cp_) \
 _verlock_again: \
  (var_) = OO_ACCESS_ONCE(*(cp_)->mib[0].version);    \
  (mib_) = &(cp_)->mib[(var_) & 1]; \

#define CP_VERLOCK_STOP(var_, mib_) \
  if( (var_) != OO_ACCESS_ONCE(*(mib_)->version)) \
    goto _verlock_again;

enum { CP_CHSUM_STR_LEN  = 32 };

typedef struct oo_cp_version_check_s {
  char                    in_cp_intf_ver[CP_CHSUM_STR_LEN + 1];
} oo_cp_version_check_t;

extern oo_cp_version_check_t oo_cplane_api_version;

enum cp_sync_mode {
  CP_SYNC_NONE  = 0,
  CP_SYNC_LIGHT = 1,
  CP_SYNC_DUMP  = 2
};

#ifndef __KERNEL__
struct oo_cplane_handle {
  struct cp_mibs mib[2];
  int fd;
  uint32_t bytes;
};

#else

#include <onload/cplane_driver_handle.h>

extern int
__oo_cp_arp_confirm(struct oo_cplane_handle* cp, cicp_verinfo_t* verinfo,
                    cp_fwd_table_id fwd_table_id);
extern int
__oo_cp_arp_resolve(struct oo_cplane_handle* cp, cicp_verinfo_t* verinfo,
                    cp_fwd_table_id fwd_table_id);
extern cicp_hwport_mask_t
oo_cp_get_hwports(struct oo_cplane_handle*);
extern int oo_cp_get_acceleratable_llap_count(struct oo_cplane_handle*);
extern int oo_cp_get_acceleratable_ifindices(struct oo_cplane_handle*,
                                             ci_ifid_t* ifindices,
                                             int max_count);
#endif


extern int
cp_svc_check_dnat(struct oo_cplane_handle* cp,
                  ci_addr_sh_t* dst_addr, ci_uint16* dst_port);


extern ci_ifid_t
oo_cp_get_hwport_ifindex(struct oo_cplane_handle* cp, ci_hwport_id_t hwport);

extern int
oo_cp_get_hwport_properties(struct oo_cplane_handle*, ci_hwport_id_t hwport,
                            cp_hwport_flags_t* out_mib_flags);


/* Initialize verinfo before the first use */
static inline void oo_cp_verinfo_init(cicp_verinfo_t* verinfo)
{
  verinfo->id = CICP_MAC_ROWID_BAD;
}

static inline struct cp_fwd_table*
oo_cp_get_fwd_table(struct oo_cplane_handle* cp, cp_fwd_table_id fwd_table_id)
{
  /* At UL, each cplane handle maps the local fwd table.  This is not true in
   * the kernel, where there is precisely one handle per cplane instance, but
   * in the kernel we can get straight at each table by ID. */
#ifdef __KERNEL__
  struct cp_fwd_table* fwd_table = &cp->fwd_tables[fwd_table_id];
  ci_assert_lt(fwd_table_id, CP_MAX_INSTANCES);
  ci_assert(fwd_table->rows);
  ci_assert(fwd_table->prefix);
  ci_assert(fwd_table->rw_rows);
  return fwd_table;
#else
  return &cp->mib[0].fwd_table;
#endif
}

/* Confirm that the given ARP entry is valid (to be used with MSG_CONFIRM
 * or when TCP received a new ACK).
 * Fast exit of the inline function if the ARP entry is already fresh and
 * valid.
 * Fixme: do we want to pass current frc value as a parameter?  All the
 * callers probably have it.
 */
static inline void
oo_cp_arp_confirm(struct oo_cplane_handle* cp,
                  cicp_verinfo_t* verinfo,
                  cp_fwd_table_id fwd_table_id)
{
  struct cp_fwd_table* fwd_table = oo_cp_get_fwd_table(cp, fwd_table_id);
  struct cp_fwd_rw_row* fwd_rw;

  if( ! CICP_MAC_ROWID_IS_VALID(verinfo->id) ||
      ! cp_fwd_version_matches(fwd_table, verinfo) )
    return;

  fwd_rw = cp_get_fwd_rw(fwd_table, verinfo);
  if( ! (fwd_rw->flags & CICP_FWD_RW_FLAG_ARP_NEED_REFRESH) )
    return;
  ci_atomic32_and(&fwd_rw->flags, ~CICP_FWD_RW_FLAG_ARP_NEED_REFRESH);

#ifndef __KERNEL__
  cp_ioctl(cp->fd, OO_IOC_CP_ARP_CONFIRM, verinfo);
#else
  __oo_cp_arp_confirm(cp, verinfo, fwd_table_id);
#endif
}

/* Resolve an ARP entry.  In many cases it is not necessary, because ARP is
 * resolved when we send via OS.  However, it is always good to resolve ARP
 * at connect() time without waiting for send(). */
static inline void
oo_cp_arp_resolve(struct oo_cplane_handle* cp, cicp_verinfo_t* verinfo,
                  cp_fwd_table_id fwd_table_id)
{
  struct cp_fwd_table* fwd_table = oo_cp_get_fwd_table(cp, fwd_table_id);
  struct cp_fwd_data* data;

  ci_assert(CICP_MAC_ROWID_IS_VALID(verinfo->id));
  data = cp_get_fwd_data(fwd_table, verinfo);

#ifndef NDEBUG
  /* It was
   * ci_assert_nequal(data->base.ifindex, CI_IFID_(LOOP|BAD))
   * but it fired when the fwd entry is under change. */
  if( data->base.ifindex == CI_IFID_BAD ||
      data->base.ifindex == CI_IFID_LOOP ) {
    ci_rmb();
    ci_assert_nequal(verinfo->version,
                     *cp_fwd_version(cp_get_fwd(fwd_table, verinfo)) );
  }
#endif

  /* The most probable reason for verinfo to be invalid is ARP resolution.
   * If ARP is really resolved, then there is no need to go further. */
  if( (data->flags & CICP_FWD_DATA_FLAG_ARP_VALID) ||
      ! cp_fwd_version_matches(fwd_table, verinfo) )
    return;

#ifndef __KERNEL__
  {
    struct oo_op_cplane_arp_resolve op = {
      .verinfo = *verinfo,
      /* fwd_table_id in this structure is not respected when the ioctl comes
       * from a cplane client.  The kernel will assert that it's set to
       * CP_FWD_TABLE_ID_INVALID. */
      .fwd_table_id = CP_FWD_TABLE_ID_INVALID,
    };
    cp_ioctl(cp->fd, OO_IOC_CP_ARP_RESOLVE, &op);
  }
#else
  __oo_cp_arp_resolve(cp, verinfo, fwd_table_id);
#endif
}

extern int
__oo_cp_route_resolve(struct oo_cplane_handle* cp,
                    cicp_verinfo_t* verinfo,
                    struct cp_fwd_key* req,
                    int/*bool*/ ask_server,
                    struct cp_fwd_data* data,
                    cp_fwd_table_id fwd_table_id);

static inline int
oo_cp_verinfo_is_valid(struct oo_cplane_handle* cp,
                       cicp_verinfo_t* verinfo,
                       cp_fwd_table_id fwd_table_id)
{
  struct cp_fwd_table* fwd_table = oo_cp_get_fwd_table(cp, fwd_table_id);
  return CICP_MAC_ROWID_IS_VALID(verinfo->id) &&
         cp_fwd_version_matches(fwd_table, verinfo);
}

#if defined(__KERNEL__)
int oo_op_route_resolve(struct oo_cplane_handle* cp, struct cp_fwd_key* key,
                        cp_fwd_table_id fwd_table_id);
#endif

#ifndef __KERNEL__
/* Resolve the route, update the version info.
 *
 * Returns:
 *  1 if verinfo is valid;
 *  0 if route is resolved, new data and verinfo are filled in;
 *  -errno in case of error.
 */
static inline int
oo_cp_route_resolve(struct oo_cplane_handle* cp,
                    cicp_verinfo_t* verinfo,
                    struct cp_fwd_key* key,
                    struct cp_fwd_data* data)
{
  /* The fwd-table ID is meaningless at UL, but we have to pass something. */
  const cp_fwd_table_id fwd_table_id = CP_FWD_TABLE_ID_INVALID;

  /* Are we lucky?  Is the verlock valid? */
  if( oo_cp_verinfo_is_valid(cp, verinfo, fwd_table_id) ) {
    struct cp_mibs* mib = &cp->mib[0];
    cp_get_fwd_rw(&mib->fwd_table, verinfo)->frc_used = ci_frc64_get();
    memcpy(data, cp_get_fwd_data(&mib->fwd_table, verinfo), sizeof(*data));
    ci_rmb();
    if( cp_fwd_version_matches(&mib->fwd_table, verinfo) )
      return 1;
  }

  /* We are unlucky. Let's go via slow path. */
  return __oo_cp_route_resolve(cp, verinfo, key, 1, data, fwd_table_id);
}
#endif

static inline int/*bool*/
oo_cp_llap_params_check(cicp_llap_row_t* llap,
                        ci_hwport_id_t hwport, ci_uint16 vlan_id,
                        const uint8_t* mac)
{
  return (llap->rx_hwports & cp_hwport_make_mask(hwport)) &&
         ! (llap->encap.type & CICP_LLAP_TYPE_SLAVE) &&
         (llap->encap.type & CICP_LLAP_TYPE_VLAN) == (vlan_id != 0) &&
         ( ! (llap->encap.type & CICP_LLAP_TYPE_VLAN) ||
           llap->encap.vlan_id == vlan_id ) &&
         (mac == NULL || memcmp(mac, llap->mac, 6) == 0);
}

/* Find the network interface by the incoming packet:
 * hwport + vlan => ifindex. */
static inline ci_ifid_t
oo_cp_hwport_vlan_to_ifindex(struct oo_cplane_handle* cp,
                             ci_hwport_id_t hwport, ci_uint16 vlan_id,
                             const uint8_t* mac)
{
  struct cp_mibs* mib = &cp->mib[0];
  cp_version_t version;
  ci_ifid_t ifindex = 0;
  cicp_rowid_t i;

  ci_assert_nequal(hwport, CI_HWPORT_ID_BAD);
  ci_assert_lt(hwport, mib->dim->hwport_max);

  CP_VERLOCK_START(version, mib, cp)

  for( i = 0; i < mib->dim->llap_max; i++ ) {
    if( oo_cp_llap_params_check(&mib->llap[i], hwport, vlan_id, mac) ) {
      ifindex = mib->llap[i].ifindex;
      break;
    }
    if( cicp_llap_row_is_free(&mib->llap[i]) )
      break;
  }

  CP_VERLOCK_STOP(version, mib)

  return ifindex;

}


typedef int/*bool*/ (*oo_cp_ifindex_check)(
        struct oo_cplane_handle* cp,
        ci_ifid_t ifindex, void* data);

/* Find the network interface by an IP address.  Returns 1 if found,
 * 0 otherwise.  The "check" parameter is the local function which checks if
 * the interface parameters fulfil the caller requirements and saves any
 * additional ipif parameters if necessary.
 *
 * The "data" parameter is passed to the "check" callback.  It can be used
 * ot pass Onload stack handle or to store ipif row parameters ti make them
 * available to the caller.
 */
static inline int/*bool*/
oo_cp_find_ipif_by_ip(struct oo_cplane_handle* cp, ci_ip_addr_t ip,
                      oo_cp_ifindex_check check, void* data)
{
  struct cp_mibs* mib;
  cicp_rowid_t id;
  cp_version_t version;
  int rc = 0;

  CP_VERLOCK_START(version, mib, cp)

  for( id = 0; id < mib->dim->ipif_max; id++ ) {
    if( cicp_ipif_row_is_free(&mib->ipif[id]) )
      break;

    if( mib->ipif[id].net_ip == ip ) {
      if( check(cp, mib->ipif[id].ifindex, data) ) {
        rc = 1;
        break;
      }
    }
  }
  CP_VERLOCK_STOP(version, mib)
  return rc;
}

static inline int/*bool*/
oo_cp_find_ipif_by_ip6(struct oo_cplane_handle* cp, ci_ip6_addr_t ip,
                      oo_cp_ifindex_check check, void* data)
{
  struct cp_mibs* mib;
  cicp_rowid_t id;
  cp_version_t version;
  int rc = 0;

  CP_VERLOCK_START(version, mib, cp)

  for( id = 0; id < mib->dim->ip6if_max; id++ ) {
    if( cicp_ip6if_row_is_free(&mib->ip6if[id]) )
      break;

    if( CI_IP6_ADDR_CMP(mib->ip6if[id].net_ip6, ip) == 0 ) {
      if( check(cp, mib->ip6if[id].ifindex, data) ) {
        rc = 1;
        break;
      }
    }
  }
  CP_VERLOCK_STOP(version, mib)
  return rc;
}


typedef int/*bool*/ (*oo_cp_llap_check)(
        struct oo_cplane_handle* cp,
        cicp_llap_row_t* llap,
        void* data);
/* Same as oo_cp_find_ipif_by_ip(), but also looks up a llap row. */
static inline int
oo_cp_find_llap_by_ip(struct oo_cplane_handle* cp, ci_ip_addr_t ip,
                      oo_cp_llap_check check, void* data)
{
  struct cp_mibs* mib;
  cicp_rowid_t id;
  cp_version_t version;
  int rc = 0;

  CP_VERLOCK_START(version, mib, cp)

  for( id = 0; id < mib->dim->ipif_max; id++ ) {
    if( cicp_ipif_row_is_free(&mib->ipif[id]) )
      break;

    if( mib->ipif[id].net_ip == ip ) {
      cicp_rowid_t llap_id = cp_llap_find_row(mib, mib->ipif[id].ifindex);
      if( llap_id == CICP_ROWID_BAD )
        continue;
      if( check(cp, &mib->llap[llap_id], data) ) {
        rc = 1;
        break;
      }
    }
  }

  CP_VERLOCK_STOP(version, mib)
  return rc;
}

static inline int
oo_cp_find_llap_by_ip6(struct oo_cplane_handle* cp, ci_ip6_addr_t ip6,
                       oo_cp_llap_check check, void* data)
{
  struct cp_mibs* mib;
  cicp_rowid_t id;
  cp_version_t version;
  int rc = 0;

  CP_VERLOCK_START(version, mib, cp)

  for( id = 0; id < mib->dim->ip6if_max; id++ ) {
    if( cicp_ip6if_row_is_free(&mib->ip6if[id]) )
      break;

    if( !CI_IP6_ADDR_CMP(mib->ip6if[id].net_ip6, ip6) ) {
      cicp_rowid_t llap_id = cp_llap_find_row(mib, mib->ip6if[id].ifindex);
      if( llap_id == CICP_ROWID_BAD )
        continue;
      if( check(cp, &mib->llap[llap_id], data) ) {
        rc = 1;
        break;
      }
    }
  }

  CP_VERLOCK_STOP(version, mib)
  return rc;
}

/* Keep this function inline to guarantee that it is properly optimized
 * when the most of the parameters are NULL. */
static inline int
oo_cp_find_llap(struct oo_cplane_handle* cp, ci_ifid_t ifindex,
                ci_mtu_t *out_mtu, cicp_hwport_mask_t *out_hwports,
                cicp_hwport_mask_t *out_rx_hwports,
                ci_mac_addr_t *out_mac,
                cicp_encap_t *out_encap)
{
  struct cp_mibs* mib;
  cicp_rowid_t id;
  cp_version_t version;
  int rc = 0;

  CP_VERLOCK_START(version, mib, cp)

  id = cp_llap_find_row(mib, ifindex);
  if( id == CICP_ROWID_BAD ) {
    rc = -ENOENT;
    goto out;
  }

  if( out_mtu != NULL )
    *out_mtu = mib->llap[id].mtu;
  if( out_hwports != NULL )
    *out_hwports = mib->llap[id].tx_hwports;
  if( out_rx_hwports != NULL )
    *out_rx_hwports = mib->llap[id].rx_hwports;
  if( out_mac != NULL )
    memcpy(out_mac, mib->llap[id].mac, sizeof(*out_mac));
  if( out_encap != NULL )
    *out_encap = mib->llap[id].encap;

 out:
  CP_VERLOCK_STOP(version, mib)
  return rc;
}

static inline ci_ip_addr_t
oo_cp_ifindex_to_ip(struct oo_cplane_handle* cp, ci_ifid_t ifindex)
{
  struct cp_mibs* mib;
  cicp_rowid_t id;
  cp_version_t version;
  ci_ip_addr_t ip = INADDR_ANY;

  CP_VERLOCK_START(version, mib, cp)

  for( id = 0; id < mib->dim->ipif_max; id++ ) {
    if( cicp_ipif_row_is_free(&mib->ipif[id]) )
      break;
    /* Fixme: check IFA_F_SECONDARY flag, get a primary address */
    if( mib->ipif[id].ifindex == ifindex ) {
      ip = mib->ipif[id].net_ip;
      break;
    }
  }

  CP_VERLOCK_STOP(version, mib)
  return ip;
}



/*
 * Bonding support
 */


#define CICP_HASH_STATE_FLAGS_IS_IP      0x1
#define CICP_HASH_STATE_FLAGS_IS_TCP_UDP 0x2
#define CICP_HASH_STATE_FLAGS_IS_FRAG    0x4

struct cicp_hash_state {
  int flags;
  ci_mac_addr_t src_mac;
  ci_mac_addr_t dst_mac;
  ci_ip_addr_t src_addr_be32;
  ci_ip_addr_t dst_addr_be32;
  ci_uint16 src_port_be16;
  ci_uint16 dst_port_be16;
};

ci_inline int cicp_layer2_hash(struct cicp_hash_state *hs, int num_slaves)
{
  return (hs->src_mac[5] ^ hs->dst_mac[5]) % num_slaves;
}

ci_inline int cicp_layer23_hash(struct cicp_hash_state *hs, int num_slaves)
{
  /* TODO do we ever call this with non-IP traffic */
  if( hs->flags & CICP_HASH_STATE_FLAGS_IS_IP ) {
    return
      ((CI_BSWAP_BE32(hs->src_addr_be32 ^ hs->dst_addr_be32) & 0xffff) ^ 
       (hs->src_mac[5] ^ hs->dst_mac[5])) % num_slaves;
  }
  else
    return cicp_layer2_hash(hs, num_slaves);
}

ci_inline int cicp_layer34_hash(struct cicp_hash_state *hs, int num_slaves)
{
  /* TODO do we ever call this with non-IP traffic */
  if( hs->flags & CICP_HASH_STATE_FLAGS_IS_IP ) {
    ci_uint32 addrs = CI_BSWAP_BE32(hs->src_addr_be32 ^ hs->dst_addr_be32);
    if( !(hs->flags & CICP_HASH_STATE_FLAGS_IS_FRAG) &&
        (hs->flags & CICP_HASH_STATE_FLAGS_IS_TCP_UDP) ) {
      /* The factors in the design of this hash function are mostly obvious
       * (speed, distribution, etc.) with the added caveat that the kernel's
       * port allocation algorithm prefers odd/even numbers (depending on the
       * caller - see inet_csk_find_open_port()), so for the common case where
       * num_slaves==2 we want to avoid predictable output.
       * The hash here is a mutation of FNV-1.
       * Cast to 16-bit is because 16-bit division is slightly lower-latency
       * than 32-bit */
      ci_uint16 ports = CI_BSWAP_BE16(hs->src_port_be16 ^ hs->dst_port_be16);
      return (ci_uint16)(((ports * 16777619) >> 8) ^ addrs)
               % (ci_uint16)num_slaves;
    } else {
      return (ci_uint16)addrs % (ci_uint16)num_slaves;
    }
  }
  else {
    return cicp_layer2_hash(hs, num_slaves);
  }
}

static inline int
oo_cp_hwport_hash(cicp_llap_type_t encap, struct cicp_hash_state* hs,
                  int slaves)
{
  /* There should be exactly one hash mode selected */
  ci_assert(CI_IS_POW2(encap & CICP_LLAP_TYPE_USES_HASH));

  if( encap & CICP_LLAP_TYPE_XMIT_HASH_LAYER34 )
    return cicp_layer34_hash(hs, slaves);
  else if( encap & CICP_LLAP_TYPE_XMIT_HASH_LAYER23 )
    return cicp_layer23_hash(hs, slaves);
  else
    return cicp_layer2_hash(hs, slaves);
}

static inline ci_hwport_id_t
oo_cp_hwport_bond_get(cicp_llap_type_t encap, cicp_hwport_mask_t hwports,
                      struct cicp_hash_state* hs)
{
  ci_hwport_id_t hwport[sizeof(cicp_hwport_mask_t) * 8];
  int i;

  if( hwports == 0 )
    return CI_HWPORT_ID_BAD;

  hwport[0] = CI_HWPORT_ID_BAD; /* appease gcc */

  for( i = 0; hwports != 0 ; hwports &= (hwports-1), i++ )
    hwport[i] = cp_hwport_mask_first(hwports);

  return hwport[oo_cp_hwport_hash(encap, hs, i)];
}

#ifdef __cplusplus
}
#endif

#endif /* __TOOLS_CPLANE_ONLOAD_H__ */
