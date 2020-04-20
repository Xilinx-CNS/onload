/* SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <ci/tools.h>

#define CI_CFG_IPV6 1
#include <onload/hash.h>
#include <cplane/hash.h>
#include <cplane/mib.h>

const ci_addr_sh_t addr_sh_any;
const ci_addr_sh_t ip4_addr_sh_any = {{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}}}};


/* The memory that backs the tables collected in struct cp_mibs is shared by
 * the control plane server and its clients and is allocated and mapped as a
 * single contiguous region of memory.  This region is subdivided into separate
 * areas for the different structures, some of which are double-buffered.
 * Furthermore, there is a boundary within the region that is used to enforce
 * security policy: all clients can map the region before this boundary, but
 * only "local" clients (i.e. those in the server's namespace) can map the
 * region after the boundary.
 *   The array of structures defined here encodes the layout of this region of
 * memory.  It is used to build up a set of pointers to the various sub-
 * regions, and by the driver in enforcing access beyond the local-client
 * boundary. */
struct cp_mib_region {
  size_t length;
  size_t alignment;

  /* Offset with struct cp_mibs of the pointer to this region. */
  off_t mib_struct_member_offset;

  /* Offset within struct cp_tables_dim to the number of entries in the table
   * stored in this region.  Only valid if MIBRG_TABLE is set. */
  off_t dim_count_offset;

#define MIBRG_TABLE           0x00000001u
#define MIBRG_DOUBLE_BUFFERED 0x00000002u
#define MIBRG_NO_MIB_MEMBER   0x00000004u
#define MIBRG_PUBLIC_END      0x00000008u
  unsigned flags;
};

#define REGION(type, mbr_offset, dim_offset, _flags) { \
    .length = sizeof(type), \
    .alignment = __alignof__(type), \
    .mib_struct_member_offset = (mbr_offset), \
    .dim_count_offset = (dim_offset), \
    .flags = (_flags), \
  }

#define MIB_MEMBER_REGION(type, mbr, dim_offset, flags) \
  REGION(type, CI_MEMBER_OFFSET(struct cp_mibs, mbr), dim_offset, flags)

#define SB_MEMBER(type, mbr) MIB_MEMBER_REGION(type, mbr, 0, 0)
#define DB_MEMBER(type, mbr) MIB_MEMBER_REGION(type, mbr, 0, \
                                               MIBRG_DOUBLE_BUFFERED)
#define DB_TABLE(type, mbr, dim_mbr) \
  MIB_MEMBER_REGION(type, mbr, \
                    CI_MEMBER_OFFSET(struct cp_tables_dim, dim_mbr), \
                    MIBRG_TABLE | MIBRG_DOUBLE_BUFFERED)

#define END_PUBLIC_REGION()  { .flags = MIBRG_PUBLIC_END, }

static const struct cp_mib_region cp_mib_regions[] = {
  /* N.B. dim members specifying table sizes must be ci_int32, as
   * process_mib_layout() constructs pointers to those elements and makes that
   * assumption about the type. */

  /* mib->dim is special, as the kernel has a separate copy that is not in
   * the mib region mapped by UL, so we don't use the generic mechanism to
   * initialise it. */
  REGION(struct cp_tables_dim, 0, 0, MIBRG_NO_MIB_MEMBER),

  SB_MEMBER(cp_version_t, version),

  DB_TABLE(struct cp_svc_ep_dllist, svc_ep_table, svc_ep_max),
  DB_TABLE(struct cp_svc_ep_array, svc_arrays, svc_arrays_max),

  END_PUBLIC_REGION(),

  SB_MEMBER(cp_version_t, dump_version),
  SB_MEMBER(cp_version_t, idle_version),
  SB_MEMBER(cp_version_t, oof_version),

  DB_MEMBER(cp_string_t, sku),

  DB_MEMBER(cp_version_t, llap_version),
  DB_TABLE(struct cp_hwport_row, hwport, hwport_max),
  DB_TABLE(cicp_llap_row_t, llap, llap_max),
  DB_TABLE(cicp_ipif_row_t, ipif, ipif_max),
  DB_TABLE(cicp_ip6if_row_t, ip6if, ip6if_max),
};

#undef END_PUBLIC_REGION
#undef DB_TABLE
#undef DB_MEMBER
#undef SB_MEMBER
#undef TABLE
#undef REGION


static size_t
process_mib_layout(void* mib_start, struct cp_mibs* mibs,
                   const struct cp_tables_dim* dim,
                   off_t* local_client_boundary_out)
{
  uintptr_t ptr = (uintptr_t) mib_start;
  int i;

  ci_assert_equal(CI_PTR_ALIGN_NEEDED(ptr, CI_PAGE_SIZE), 0);

  for( i = 0; i < sizeof(cp_mib_regions) / sizeof(cp_mib_regions[0]); ++i ) {
    const struct cp_mib_region* region = &cp_mib_regions[i];
    int mib_i;
    size_t length;

    /* A region flagged with MIBRG_PUBLIC_END is a meta-region that marks the
     * end of the portion of the mib that can be accessed by non-local clients.
     * It has to be page aligned so that it can be enforced by the mmap
     * implementation. */
    if( region->flags & MIBRG_PUBLIC_END ) {
      ptr = CI_ALIGN_FWD(ptr, CI_PAGE_SIZE);
      if( local_client_boundary_out != NULL )
        *local_client_boundary_out = ptr - (uintptr_t) mib_start;
      continue;
    }

    ci_assert(region->length);
    ci_assert(region->alignment);

    /* Find the length of this region.  If the region is a table, the length is
     * the length of all entries in the table.  For double-buffered regions,
     * we need the length of one of the two buffers, so no adjustment needs to
     * be made. */
    length = region->length;
    ci_assert_equal(CI_PTR_ALIGN_NEEDED(length, region->alignment), 0);
    if( region->flags & MIBRG_TABLE ) {
      /* Find the member of the dim that specifies the size of this table. */
      ci_int32* dim_member = (ci_int32*) ((char*) dim +
                                          region->dim_count_offset);
      length *= *dim_member;
    }

    for( mib_i = 0; mib_i < 2; ++mib_i ) {
      /* Find the address of the member of the mib struct that holds the
       * address of the start of this region. */
      void** mib_member = (void**) ((char*) &mibs[mib_i] +
                                    region->mib_struct_member_offset);

      /* Currently, ptr sits immediately after the end of the previous region,
       * but the current region might start a little bit later in order to have
       * the correct alignment. */
      ptr = CI_ALIGN_FWD(ptr, region->alignment);

      /* Store the address of the start of the region in the mib structure. */
      if( mibs != NULL && ~region->flags & MIBRG_NO_MIB_MEMBER )
        *mib_member = (void*) ptr;

      /* Double-buffered regions consist of two contiguous buffers of the
       * length declared in cp_mib_regions, and so we advance the pointer after
       * populating each mib frame.  For single-buffered regions, both frames
       * should be populated with the same address, and so we advance the
       * pointer only after the second frame. */
      if( region->flags & MIBRG_DOUBLE_BUFFERED || mib_i == 1 )
        ptr += length;
    }
  }

  return ptr - (uintptr_t) mib_start;
}


size_t cp_init_mibs(void* mib_start, struct cp_mibs* mibs)
{
  return process_mib_layout(mib_start, mibs, mibs->dim, NULL);
}


size_t cp_calc_mib_size(const struct cp_tables_dim* dim)
{
  return process_mib_layout(NULL, NULL, dim, NULL);
}


off_t cp_find_public_mib_end(const struct cp_tables_dim* dim)
{
  off_t end = -1;
  size_t mib_length = process_mib_layout(NULL, NULL, dim, &end);
  return end >= 0 ? end : mib_length;
}


#ifndef __KERNEL__
void cp_init_mibs_fwd_blob(void* romem, struct cp_mibs* mibs)
{
  struct cp_fwd_row* fwd_table = cp_fwd_table_within_blob(romem);
  ci_ipx_pfx_t* fwd_prefix = cp_fwd_prefix_within_blob(romem, mibs->dim);

  mibs[0].fwd_table.rows = mibs[1].fwd_table.rows = fwd_table;
  mibs[0].fwd_table.prefix = mibs[1].fwd_table.prefix = fwd_prefix;
}
#endif


static inline int ci_rot_r(ci_uint32 i, int n)
{
  n = n & 0x1f;
  /* gcc-4.8 recognizes it and converts to the "roll" instruction,
   * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=57157 .
   * "i << (32-n)" has undefinded behaviour for n==0. */
  return (i >> n) | (i << ((-n) & 31));
}


int cp_get_acceleratable_llap_count(struct cp_mibs* mib)
{
  int count = 0;
  int rowid;

  for( rowid = 0; rowid < mib->dim->llap_max; ++rowid ) {
    if( cicp_llap_row_is_free(&mib->llap[rowid]) )
      break;
    if( mib->llap[rowid].rx_hwports != 0 )
      ++count;
  }

  return count;
}


int cp_get_acceleratable_ifindices(struct cp_mibs* mib, ci_ifid_t* ifindices,
                                   int max_count)
{
  int count = 0;
  int rowid;

  for( rowid = 0; rowid < mib->dim->llap_max && count < max_count; ++rowid ) {
    if( cicp_llap_row_is_free(&mib->llap[rowid]) )
      break;
    if( mib->llap[rowid].rx_hwports != 0 )
      ifindices[count++] = mib->llap[rowid].ifindex;
  }

  return count;
}


/* Returns the row index in the llap of a row with the matching ifindex and
 * hwports values. -1 if none is found. This is a helper for
 * cp_get_hwport_ifindex() */
static int
ci_find_ifindex_hwports(struct cp_mibs* mib, ci_ifid_t ifindex,
                        cicp_hwport_mask_t hwports)
{
  int rowid;
  for( rowid = 0; rowid < mib->dim->llap_max; ++rowid ) {
    if( cicp_llap_row_is_free(&mib->llap[rowid]) )
      break;
    if( mib->llap[rowid].ifindex == ifindex
        && mib->llap[rowid].rx_hwports == hwports )
      return rowid;
  }
  return -1;
}


/* Returns the ifindex of the 'best' interface for using hwport. Used by zf
 * to find the interface to use for ef_vi underneath bonds, vlans, etc.
 * The caller is responsible for performing a version-check before and after
 * this function is called; see oo_cp_get_hwport_ifindex(). */
ci_ifid_t cp_get_hwport_ifindex(struct cp_mibs* mib, ci_hwport_id_t hwport)
{
  int rowid;
  cicp_hwport_mask_t hwports = cp_hwport_make_mask(hwport);
  ci_ifid_t id = CI_IFID_BAD;

  for( rowid = 0; rowid < mib->dim->llap_max; ++rowid ) {
    if( cicp_llap_row_is_free(&mib->llap[rowid]) )
      break;
    /* The mapping of interfaces to hwport is complicated by the existence of
     * bonds, VLANs, MACVLANs and so on.  But we can define "the" interface for
     * an hwport to be the one that maps to precisely that hwport and that is
     * not a higher-level interface (i.e. ifindex == encap.link_ifindex).
     * This fails when a bond contains only one interface; we fix that by
     * avoiding bond masters explicitly. It is also possible to create a
     * container with no access to the underlying interface; we choose a
     * somewhat-arbitrary 'next-best' in that case since we have no information
     * on what the true underlying interface would be. */
    if( mib->llap[rowid].rx_hwports == hwports
        && ! (mib->llap[rowid].encap.type & CICP_LLAP_TYPE_BOND) ) {
      if( mib->llap[rowid].ifindex == mib->llap[rowid].encap.link_ifindex )
        return mib->llap[rowid].ifindex;

      /* This row might be a second-best match, but if we can also see a row
       * which is definitely less-derived than this one then we should prefer
       * that row. */
      if( ci_find_ifindex_hwports(mib, mib->llap[rowid].encap.link_ifindex,
                                  hwports) < 0 )
        id = mib->llap[rowid].ifindex;
    }
  }

  return id;
}


/* Iterates over all matches in the service table, calling the provided
 * callback.  Iteration terminates when the callback returns true, and the
 * ID of the table-entry at that point is returned.  The callback may be NULL,
 * in which case the ID of the first matching entry is returned. */
cicp_mac_rowid_t
cp_svc_iterate_matches(const struct cp_mibs* mib, const ci_addr_sh_t addr,
                       ci_uint16 port, cp_svc_iterator_callback_t callback,
                       void* opaque)
{
  /* svc_ep_max is guaranteed to be 2^n, see cfg_svc_ep_max in server.c */
  unsigned svc_table_mask = mib->dim->svc_ep_max - 1;
  cicp_mac_rowid_t hash1, hash2, hash;
  int iter = 0;

  cp_calc_svc_hash(svc_table_mask, &addr, port, &hash1, NULL);
  hash = hash1;
  hash2 = 0;

  do {
    struct cp_svc_ep_dllist* svc = &mib->svc_ep_table[hash];

    if( svc->use == 0 )
      return CICP_MAC_ROWID_BAD;
    if( svc->row_type != CP_SVC_EMPTY && svc->ep.port == port &&
        CI_IPX_ADDR_EQ(svc->ep.addr, addr) &&
        (callback == NULL || callback(mib, hash, opaque)) )
      return hash;

    if( hash2 == 0 ) /* After initial zero hash2 is always odd. */
      cp_calc_svc_hash(svc_table_mask, &addr, port, NULL, &hash2);
    hash = (hash + hash2) & svc_table_mask;
  } while( ++iter < (svc_table_mask >> 2) );

  return CICP_MAC_ROWID_BAD;
}


/* Returns the hash table id of a service or backend that matches the address
 * and port provided.  Returns CICP_MAC_ROWID_BAD if a match cannot be found */
cicp_mac_rowid_t
cp_svc_find_match(const struct cp_mibs* mib, const ci_addr_sh_t addr,
                  ci_uint16 port)
{
  /* Pass no callback to return the first match. */
  return cp_svc_iterate_matches(mib, addr, port, NULL, NULL);
}


/* Walk the array chain to find the array and index corresponding to the
 * element_id */
void
cp_svc_walk_array_chain(const struct cp_mibs* mib,
                        cicp_rowid_t array_id, cicp_rowid_t element_id,
                        struct cp_svc_ep_array** arr, cicp_rowid_t* index)
{
  while( element_id >= CP_SVC_BACKENDS_PER_ARRAY ) {
    element_id -= CP_SVC_BACKENDS_PER_ARRAY;
    array_id = mib->svc_arrays[array_id].next;
    ci_assert( CICP_ROWID_IS_VALID(array_id) );
  }
  *arr = &mib->svc_arrays[array_id];
  *index = element_id;
}
