/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

/* Test replacement for lib/efthrm/oo_nics_deps.h.  The symlinked oo_nics.c
 * includes "oo_nics_deps.h", which resolves to this file in the test build.
 * It provides stub versions of every type and constant oo_nics.c needs,
 * consolidated in one place rather than shadowing a tree of system headers. */

#ifndef __OO_NICS_TEST_DEPS_H__
#define __OO_NICS_TEST_DEPS_H__

#include <stdbool.h>
#include <stdint.h>

#include "onload_kernel_compat.h"

#include <ci/internal/transport_config_opt.h>
#include <ci/tools.h>


/* --- cplane/mib.h: hwport mask types and helpers --- */

typedef ci_uint32 cicp_hwport_mask_t;
typedef ci_int16  ci_hwport_id_t;
typedef ci_int16  ci_ifid_t;
typedef ci_uint16 ci_mtu_t;
typedef unsigned char ci_mac_addr_t[6];

typedef struct {
  ci_uint16 type;
} cicp_encap_t;

static inline ci_hwport_id_t cp_hwport_mask_first(cicp_hwport_mask_t mask)
{
  return (ci_hwport_id_t)(__builtin_ffs(mask) - 1);
}

static inline cicp_hwport_mask_t cp_hwport_make_mask(ci_hwport_id_t hwport)
{
  if( hwport >= (ci_hwport_id_t)(sizeof(cicp_hwport_mask_t) * 8) )
    return 0;
  return (cicp_hwport_mask_t)1u << hwport;
}


/* --- ci/efrm/nic_set.h: NIC set --- */

typedef struct {
  uint64_t nics;
} efrm_nic_set_t;

static inline void efrm_nic_set_clear(efrm_nic_set_t *nic_set)
{
  nic_set->nics = 0;
}

static inline void
efrm_nic_set_write(efrm_nic_set_t *nic_set, unsigned index, int value)
{
  nic_set->nics = (nic_set->nics & (~(1ULL << index))) |
                  ((uint64_t)value << index);
}


/* --- ci/efhw/common.h: NIC flags --- */

#define NIC_FLAG_LLCT            0x100000000000000LL
#define NIC_FLAG_PACKED_STREAM   0x400


/* --- ci/efrm/efrm_client.h: efhw_nic and client --- */

struct efrm_client;

struct efhw_device_type {
  int function;
};

#define EFHW_FUNCTION_PF  0
#define EFHW_FUNCTION_VF  1

struct efhw_nic {
  int index;
  struct net_device *net_dev;
  uint64_t flags;
  struct efhw_device_type devtype;
};

typedef bool (*nic_match_func)(const struct efhw_nic *nic,
                               const void *opaque_data);

extern struct efhw_nic *efrm_client_get_nic(struct efrm_client *);
extern int efrm_client_accel_allowed(struct efrm_client *client);
extern struct efhw_nic* efhw_nic_find_by_foo(nic_match_func match,
                                             const void *match_data);


/* --- onload/nic.h: oo_nic --- */

#define OO_NIC_UP         0x00000001u
#define OO_NIC_UNPLUGGED  0x00000002u
#define OO_NIC_LL         0x00000004u
#define OO_NIC_FALLBACK   0x00000008u

struct oo_nic {
  struct efrm_client* efrm_client;
  unsigned            oo_nic_flags;
  int                 alternate_hwport;
};

extern struct oo_nic oo_nics[];

extern struct oo_nic* oo_nic_find(const struct efhw_nic* nic);
extern int oo_check_nic_suitable_for_onload(struct oo_nic* onic);
extern int oo_check_nic_llct(struct oo_nic* onic);


/* --- onload/tcp_helper.h: ci_netif and tcp_helper_resource_t --- */

struct oo_cplane_handle;

/* Type used by opts_netif_def.h */
typedef ci_uint32 ci_iptime_t;

/* Generate ci_netif_config_opts from the option definitions.
 * The X-macro include also produces the #define constants
 * (e.g. EF_MULTIARCH_DATAPATH_FF) as a side effect. */
typedef struct {
#define CI_CFG_OPTFILE_VERSION(version)
#define CI_CFG_OPTGROUP(group, category, expertise)
#define CI_CFG_OPT(env, name, type, doc, bits, group, dflt, min, max, pres) \
  type name;
#define CI_CFG_STR_OPT CI_CFG_OPT
#include <ci/internal/opts_netif_def.h>
#undef CI_CFG_OPTFILE_VERSION
#undef CI_CFG_OPT
#undef CI_CFG_STR_OPT
#undef CI_CFG_OPTGROUP
} ci_netif_config_opts;

typedef struct ci_netif_s {
  efrm_nic_set_t       nic_set;
  int                  nic_n;

  cicp_hwport_mask_t   tx_hwport_mask;
  cicp_hwport_mask_t   rx_hwport_mask;
  cicp_hwport_mask_t   multiarch_hwport_mask;
  ci_int8              hwport_to_intf_i[CI_CFG_MAX_HWPORTS];
  ci_int8              intf_i_to_hwport[CI_CFG_MAX_INTERFACES];

  struct oo_cplane_handle *cplane;
  ci_netif_config_opts opts;
} ci_netif;

#define NI_OPTS(ni)  ((ni)->opts)

struct tcp_helper_nic {
  int           thn_intf_i;
  struct oo_nic* thn_oo_nic;
};

typedef struct tcp_helper_resource_s {
  ci_netif               netif;
  struct tcp_helper_nic  nic[CI_CFG_MAX_INTERFACES];
} tcp_helper_resource_t;


/* --- cplane/cplane.h: cplane handle and lookups --- */

struct oo_cplane_handle {
  struct net* cp_netns;
};

extern cicp_hwport_mask_t oo_cp_get_hwports(struct oo_cplane_handle*);

extern int
oo_cp_find_llap(struct oo_cplane_handle* cp, ci_ifid_t ifindex,
                ci_mtu_t *out_mtu, cicp_hwport_mask_t *out_hwports,
                cicp_hwport_mask_t *out_rx_hwports,
                ci_mac_addr_t *out_mac,
                cicp_encap_t *out_encap);

#endif /* __OO_NICS_TEST_DEPS_H__ */
