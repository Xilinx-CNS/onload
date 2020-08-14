/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017 Xilinx, Inc. */

#ifndef __OOF_TEST_EFRM_H__
#define __OOF_TEST_EFRM_H__

#include "onload_kernel_compat.h"
#include <ci/tools.h>
#include <onload/nic.h>
#include <ci/internal/transport_config_opt.h>

#include "driverlink_interface.h"


struct ooft_hw_filter {
  int filter_id;
  int hwport;
  struct efx_filter_spec spec;
  ci_dllink client_link;
};

struct efrm_client {
  int hwport;
  int filter_id;

  ci_dllist hw_filters_to_add;
  ci_dllist hw_filters_to_remove;

  ci_dllist hw_filters_added;
  ci_dllist hw_filters_removed;

  ci_dllist hw_filters_bad_add;
};

#define HW_FILTER_FROM_LINK(link) \
  CI_CONTAINER(struct ooft_hw_filter, client_link, (link))

extern struct oo_nic oo_nics[CI_CFG_MAX_HWPORTS];

extern void ooft_init_efrm_client(struct efrm_client* client, int hwport);
extern int ooft_client_check_hw_filters(struct efrm_client* client);

extern void ooft_client_expect_hw_add_ip(struct efrm_client* client,
                                         int dmaq_id, int stack_id,
                                         int vlan, int proto,
                                         unsigned laddr_be, int lport_be,
                                         unsigned raddr_be, int rport_be);
extern void ooft_client_expect_hw_remove(struct efrm_client* client,
                                         struct ooft_hw_filter* filter);
extern void ooft_client_expect_hw_remove_all(struct efrm_client* client);

extern void ooft_client_claim_added_hw_filters(struct efrm_client* client,
                                               ci_dllist* list);

extern struct ooft_hw_filter* ooft_client_add_hw_filter(ci_dllist* list,
                                                 struct efx_filter_spec* spec);

extern int ooft_hw_filter_match(struct efx_filter_spec* spec,
                                struct ooft_hw_filter* filter);
extern void ooft_hw_filter_expect_remove_list(ci_dllist* list);

extern void ooft_log_hw_filter_op(struct efrm_client* client,
                                  struct efx_filter_spec* spec,
                                  int expect, const char* op);
extern void ooft_dump_hw_filter_list(ci_dllist* list);

extern void ooft_client_hw_filter_matches(ci_dllist* in,
                                          ci_dllist* out_matches,
                                          struct efx_filter_spec* match_spec,
                                          unsigned match_flags);
struct ooft_hwport;
extern void ooft_client_hw_filter_matches_hwport(ci_dllist* in,
                                                 ci_dllist* out_matches,
                                                 struct ooft_hwport* hwport);

#endif /* __OOF_TEST_EFRM_H__ */
