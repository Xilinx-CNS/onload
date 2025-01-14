/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2019 Xilinx, Inc. */

#ifndef __OOF_TEST_CPLANE_H__
#define __OOF_TEST_CPLANE_H__

#include <ci/tools.h>
#include "efrm.h"
#include "oof_test.h"

struct ooft_cplane {
  ci_dllist hwports;
  ci_dllist idxs;
  ci_dllist namespaces;

  int hwport_ids;
  int idx_ids;
  int namespace_ids;
};

struct net {
  int id;
  int refcount;

  unsigned hwport_mask;

  ci_dllist idxs;

  ci_dllink cplane_link;
};


/* We don't use the efhw arch here because we care about the capabilities
 * which are different between fw variants on ef10. */
enum ooft_hwport_type {
  OOFT_HWPORT_EF10_FF,
  OOFT_HWPORT_EF10_LL,
  OOFT_HWPORT_EF10CT,
  OOFT_HWPORT_AFXDP,
  OOFT_HWPORT_NONE,
};

struct ooft_hwport {
  int id;
  int active;
  unsigned flags;
  bool hidden_by_ll;

  struct efrm_client client;
  enum ooft_hwport_type type;

  ci_dllink cplane_link;
};

struct ooft_addr {
  unsigned laddr_be;

  ci_dllink idx_link;
};

struct ooft_ifindex {
  int id;
  int up;

  int vlan_id;
  unsigned char mac[6];
  unsigned hwport_mask;
  unsigned hwport_mask_ff;
  unsigned hwport_mask_ll;

  ci_dllist addrs;

  /* For associating an ifindex with an hwport.  For ifindexes using more
   * than one hwport it is associated with the master.
   */
  ci_dllink hwport_link;

  /* For associating an ifindex with a namespace */
  ci_dllink ns_link;

  /* We also associate the ifindex with the cplane directly */
  ci_dllink cplane_link;
};

struct ooft_proxy {
  struct net* net_ns;
};

struct ooft_task {
  struct ooft_proxy* nsproxy;
};


#define IDX_FROM_CP_LINK(lnk) \
  CI_CONTAINER(struct ooft_ifindex, cplane_link, (lnk))
#define HWPORT_FROM_CP_LINK(lnk) \
  CI_CONTAINER(struct ooft_hwport, cplane_link, (lnk))
#define HWPORT_FROM_CLIENT(ptr) \
  CI_CONTAINER(struct ooft_hwport, client, (ptr))


extern struct ooft_cplane* ooft_alloc_cplane(void);
extern void ooft_free_cplane(struct ooft_cplane* cp);

extern struct net* ooft_alloc_namespace(struct ooft_cplane* cp);
extern void ooft_free_namespace(struct net* ns);
extern void ooft_namespace_put(struct net* ns);
extern void ooft_namespace_get(struct net* ns);

extern int ooft_ns_check_hw_filters(struct net*);
extern void ooft_cplane_claim_added_hw_filters(struct ooft_cplane* cp,
                                               ci_dllist* list);
extern void ooft_cplane_expect_hw_remove_all(struct ooft_cplane* cp);

/* Allocs cplane data representing a "boring" setup with 2 X2 NICs, each
 * with a single base interface in the the same namespace.  It adds a single
 * IP address to each interface and brings the interface up.
 */
extern int ooft_default_cplane_init(struct net* ns);
extern int ooft_cplane_init(struct net* net_ns, enum ooft_nic_type type);

extern struct ooft_hwport* ooft_alloc_hwport(struct ooft_cplane* cp,
                                             struct net* ns,
                                             enum ooft_hwport_type type);
extern void ooft_hwport_up_down(struct ooft_hwport* hw, int up);

extern struct ooft_ifindex* ooft_alloc_ifindex(struct ooft_cplane* cp,
                                               struct net* ns, int vlan_id,
                                               unsigned char mac[6]);
extern void ooft_add_hwport_to_ifindex(struct ooft_ifindex* idx,
                                       struct ooft_hwport* hw, struct net* ns);
extern void ooft_add_ll_hwport(struct net* net_ns, int id);
extern void ooft_move_ifindex(struct ooft_cplane* cp, struct ooft_ifindex* idx,
                              struct net* old_ns, struct net* new_ns);
extern struct ooft_ifindex* ooft_idx_from_id(int id);
extern struct ooft_hwport* ooft_hwport_from_id(int id);
extern struct ooft_hwport* ooft_hwport_from_idx(struct ooft_ifindex* idx);

extern struct ooft_addr* ooft_alloc_addr(struct net* net_ns,
                                         struct ooft_ifindex* idx,
                                         unsigned laddr_be);
extern void ooft_del_addr(struct net* net_ns, struct ooft_ifindex* idx,
                          struct ooft_addr* addr);
#endif /* __OOF_TEST_CPLANE_H__ */
