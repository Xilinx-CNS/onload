/* SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __CPLANE_MMAP_H__
#define __CPLANE_MMAP_H__

#include <onload/mmap_base.h>
#include <cplane/mib.h>


/* OO_MMAP_TYPE_CPLANE */
#define OO_MMAP_CPLANE_ID_MIB       0
#define OO_MMAP_CPLANE_ID_FWD       1
#define OO_MMAP_CPLANE_ID_FWD_RW    2

/* The control plane subdivides the mmap ID as reported by
 * OO_MMAP_OFFSET_TO_MAP_ID() into two fields of the following widths. */
#define CP_MMAP_TYPE_WIDTH          4
#define CP_MMAP_PARAM_WIDTH        32

#define CP_MMAP_PARAM_SHIFT        CP_MMAP_TYPE_WIDTH

#define CP_MMAP_TYPE_MASK          ((1ull << CP_MMAP_TYPE_WIDTH) - 1)
#define CP_MMAP_PARAM_MASK         ((1ull << CP_MMAP_PARAM_WIDTH) - 1)

typedef oo_mmap_id_t cp_mmap_type_t;
typedef uint32_t cp_mmap_param_t;

static inline cp_mmap_type_t CP_MMAP_TYPE(uint64_t oo_mmap_type)
{
  return oo_mmap_type & CP_MMAP_TYPE_MASK;
}

static inline cp_mmap_param_t CP_MMAP_PARAM(uint64_t oo_mmap_type)
{
  return (oo_mmap_type >> CP_MMAP_PARAM_SHIFT) & CP_MMAP_PARAM_MASK;
}

static inline oo_mmap_id_t
CP_MAKE_MMAP_ID(cp_mmap_type_t map_type, cp_mmap_param_t param)
{
  return map_type | ((oo_mmap_id_t) param << CP_MMAP_PARAM_SHIFT);
}


#ifdef CP_SYSUNIT
static const size_t CP_SHIM_MIB_BYTES = (1024 * 1024);
static const size_t CP_SHIM_FWD_BYTES = (1024 * 1024);
static const size_t CP_SHIM_FWD_RW_BYTES = (1024 * 1024);
#endif


static inline off_t
CP_MMAP_MAKE_FWD_OFFSET(cp_fwd_table_id fwd_table_id)
{
#ifdef CP_SYSUNIT
  /* With the shimmed control plane server, the address space of the mmap-ed
   * file is contiguous, and overlaps with the rest of the mib must be
   * prevented. */
  return CP_SHIM_MIB_BYTES;
#else
  oo_mmap_id_t oo_id = CP_MAKE_MMAP_ID(OO_MMAP_CPLANE_ID_FWD, fwd_table_id);
  return (OO_MMAP_TYPE_CPLANE << OO_MMAP_TYPE_SHIFT) |
         (oo_id << OO_MMAP_ID_SHIFT);
#endif
}

static inline off_t
CP_MMAP_MAKE_FWD_RW_OFFSET(cp_fwd_table_id fwd_table_id)
{
#ifdef CP_SYSUNIT
  /* With the shimmed control plane server, the address space of the mmap-ed
   * file is contiguous, and overlaps with the rest of the mib must be
   * prevented. */
  return CP_SHIM_MIB_BYTES + CP_SHIM_FWD_BYTES;
#else
  oo_mmap_id_t oo_id = CP_MAKE_MMAP_ID(OO_MMAP_CPLANE_ID_FWD_RW, fwd_table_id);
  return (OO_MMAP_TYPE_CPLANE << OO_MMAP_TYPE_SHIFT) |
         (oo_id << OO_MMAP_ID_SHIFT);
#endif
}

/* To request the local fwd table, an ID of CP_FWD_TABLE_ID_INVALID must be
 * encoded in the mmap offset.  These macros hide away this implementation
 * detail.  Clients are _only_ permitted to map their local table, and this is
 * enforced in the kernel. */
#define CP_MMAP_LOCAL_FWD_OFFSET() \
  CP_MMAP_MAKE_FWD_OFFSET(CP_FWD_TABLE_ID_INVALID)
#define CP_MMAP_LOCAL_FWD_RW_OFFSET() \
  CP_MMAP_MAKE_FWD_RW_OFFSET(CP_FWD_TABLE_ID_INVALID)

/* 32-bit clients have to be able to encode CP_FWD_TABLE_ID_INVALID, so it
 * mustn't be too wide. */
CI_BUILD_ASSERT(CP_FWD_TABLE_ID_INVALID <=
                ((uint32_t) -1) >> (CP_MMAP_PARAM_SHIFT + OO_MMAP_ID_SHIFT));


#endif /* __CPLANE_MMAP_H__ */
