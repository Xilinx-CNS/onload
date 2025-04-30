/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2017 Xilinx, Inc. */

#ifndef __OOF_TEST_STACK_H__
#define __OOF_TEST_STACK_H__

#include <ci/tools.h>
#include <onload/oof_hw_filter.h>
#include <onload/oof_socket.h>

#include "onload_kernel_compat.h"
#include "oof_onload_types.h"
#include "oof_test.h"

typedef enum {
  OOFT_EP_FREE = 0,
  OOFT_EP_IN_USE,
} ooft_endpoint_state;

struct ooft_sw_filter {
  int proto;

  uint32_t laddr_be;
  uint16_t lport_be;
  uint32_t raddr_be;
  uint16_t rport_be;

  ci_dllink socket_link;
};

struct ooft_endpoint;
struct ooft_ifindex;
struct tcp_helper_cluster_s;
struct oo_filter_ns;
typedef struct tcp_helper_resource_s {
  int stack_id;
  struct net* ns;
  struct oo_filter_ns* ofn;

  struct ooft_endpoint* eps;
  int n_eps;

  struct tcp_helper_cluster_s* thc;
  struct cpumask filter_irqmask;

  enum ooft_rx_mode mode;
} tcp_helper_resource_t;

struct ooft_endpoint {
  struct oof_socket skf;
  tcp_helper_resource_t* thr;

  ooft_endpoint_state state;
  int proto;

  uint32_t laddr_be;
  uint16_t lport_be;
  uint32_t raddr_be;
  uint16_t rport_be;

  ci_dllist sw_filters_to_add;
  ci_dllist sw_filters_to_remove;

  ci_dllist sw_filters_added;
  ci_dllist sw_filters_removed;

  ci_dllist sw_filters_bad_add;
  ci_dllist sw_filters_bad_remove;
};

typedef struct tcp_helper_cluster_s {
  int cluster_id;
  struct efrm_vi_set* thc_vi_set[CI_CFG_MAX_HWPORTS];
  int thc_refs;
  char thc_name[32];
  int thc_cluster_size;
} tcp_helper_cluster_t;

/* ---------------------------------------
 * Test data structure management
 * --------------------------------------- */
extern tcp_helper_resource_t* ooft_alloc_stack(int n_eps);
extern tcp_helper_resource_t* ooft_alloc_stack_mode(int n_eps,
                                                    enum ooft_rx_mode mode);
extern void ooft_free_stack(tcp_helper_resource_t* thr);
extern struct ooft_endpoint* ooft_alloc_endpoint(tcp_helper_resource_t* thr,
                            int proto, uint32_t laddr_be, uint16_t lport_be,
                            uint32_t raddr_be, uint32_t rport_be);
extern void ooft_free_endpoint(struct ooft_endpoint* ep);
extern int ooft_endpoint_id(struct ooft_endpoint* ep);

/* ---------------------------------------
 * Utility functions to add sockets to oof
 * --------------------------------------- */
extern int ooft_endpoint_add(struct ooft_endpoint* ep, int flags);
extern int ooft_endpoint_add_wild(struct ooft_endpoint* ep, int flags);
extern int ooft_endpoint_mcast_add(struct ooft_endpoint* ep, unsigned group,
                                   struct ooft_ifindex* idx);
int ooft_endpoint_udp_connect(struct ooft_endpoint* ep, int flags);

/* ---------------------------------------
 * Functions to handle test SW filters
 * --------------------------------------- */
extern struct ooft_sw_filter* ooft_endpoint_add_sw_filter(ci_dllist* list,
                                              int proto,
                                              unsigned laddr_be, int lport_be,
                                              unsigned raddr_be, int rport_be);
extern int ooft_sw_filter_match(struct ooft_sw_filter* filter,
                                unsigned laddr_be, int lport_be,
                                unsigned raddr_be, int rport_be, int protocol);
extern void ooft_dump_sw_filter_list(ci_dllist* list);
extern void ooft_log_sw_filter_op(struct ooft_endpoint* ep,
                                  struct ooft_sw_filter* filter, int expect,
                                  const char* op);

/* ---------------------------------------
 * Utility functions to handle expected filter operations
 * --------------------------------------- */
extern void ooft_endpoint_expect_sw_add(struct ooft_endpoint* ep, int proto,
                                        unsigned laddr_be, int lport_be,
                                        unsigned raddr_be, int rport_be);
extern void ooft_endpoint_expect_sw_remove(struct ooft_endpoint* ep,
                                           struct ooft_sw_filter* filter);
extern void ooft_endpoint_expect_sw_remove_all(struct ooft_endpoint* ep);
extern void ooft_endpoint_expect_hw_unicast(struct ooft_endpoint* ep,
                                            unsigned laddr_be, int flags);
extern void ooft_endpoint_expect_sw_remove_addr(struct ooft_endpoint* ep,
                                                unsigned laddr_be);

#define OOFT_EXPECT_FLAG_HW 1
#define OOFT_EXPECT_FLAG_WILD 2
extern void ooft_endpoint_expect_unicast_filters(struct ooft_endpoint* ep,
                                                 int flags);
extern void ooft_endpoint_expect_multicast_filters(struct ooft_endpoint* ep,
                                                   struct ooft_ifindex* idx,
                                                   unsigned hwport_mask,
                                                   unsigned laddr_be);
extern void ooft_endpoint_expect_multicast_filters_remove(
                                                   struct ooft_endpoint* ep,
                                                   struct ooft_ifindex* idx,
                                                   unsigned hwport_mask,
                                                   unsigned laddr_be);

extern int ooft_endpoint_check_sw_filters(struct ooft_endpoint* ep);
extern int ooft_stack_check_sw_filters(tcp_helper_resource_t* thr);


#endif /* __OOF_TEST_STACK_H__ */
