/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */

#ifndef __OOF_TEST_STACK_INTERFACE_H__
#define __OOF_TEST_STACK_INTERFACE_H__

#include "efrm_interface.h"
#include "stack.h"

struct efx_filter_spec;

/* Return the instance number of the VI associated with the named hwport,
 * or -1 if we don't have a VI for that hwport.
 */
extern int tcp_helper_rx_vi_id(tcp_helper_resource_t*, int hwport);

/* Return the hw stack id of the VI associated with the named hwport,
 * or -1 if we don't have a VI for that hwport.
 */
extern int tcp_helper_vi_hw_stack_id(tcp_helper_resource_t* trs, int hwport);

/* Return the hw stack id of the VI associated with the named hwport on
 * given cluster, or -1 if we don't have a VI for that hwport.
 */
extern int tcp_helper_cluster_vi_hw_stack_id(tcp_helper_cluster_t* thc, int hwport);

/* Return VI base of the VI set instantiated on the given hwport for the
 * given cluster, or -1 if cluster does not have VI set for that hwport */
extern int tcp_helper_cluster_vi_base(tcp_helper_cluster_t* thc, int hwport);

/* Return whether receiving of looped back traffic is enabled on
 * the named hwport, or -1 if we don't have a VI for that hwport.
 */
extern int tcp_helper_vi_hw_rx_loopback_supported(tcp_helper_resource_t* trs,
                                                  int hwport);

extern int tcp_helper_vi_hw_drop_filter_supported(tcp_helper_resource_t* trs,
                                                  int hwport);

extern void tcp_helper_get_filter_params(tcp_helper_resource_t* trs,
                                         int hwport, int* vi_id, int* rxq,
                                         unsigned *flags,
                                         unsigned *exclusive_rxq_token);

int tcp_helper_post_filter_add(tcp_helper_resource_t* trs, int hwport,
                               const struct efx_filter_spec* spec, int rxq,
                               bool replace);

int tcp_helper_cluster_post_filter_add(tcp_helper_cluster_t* thc, int hwport,
                                       const struct efx_filter_spec* spec,
                                       int rxq, bool replace);

#endif /* __OOF_TEST_STACK_INTERFACE_H__ */
