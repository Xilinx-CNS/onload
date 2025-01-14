/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */

#include "efrm.h"
#include "stack_interface.h"


int tcp_helper_hwport_to_stack_id(tcp_helper_resource_t* trs, int hwport)
{
  switch( trs->mode ) {
  case OOFT_RX_BOTH:
    return trs->stack_id;
  case OOFT_RX_LL:
    return oo_nics[hwport].oo_nic_flags & OO_NIC_LL ? trs->stack_id : -1;
  case OOFT_RX_FF:
    return oo_nics[hwport].oo_nic_flags & OO_NIC_LL ? -1 : trs->stack_id;
  default:
    /* Unknown mode */
    ci_assert(false);
  };

  return -1;
}

int tcp_helper_rx_vi_id(tcp_helper_resource_t* trs, int hwport)
{
  return tcp_helper_hwport_to_stack_id(trs, hwport);
}

int tcp_helper_vi_hw_stack_id(tcp_helper_resource_t* trs, int hwport)
{
  return tcp_helper_hwport_to_stack_id(trs, hwport);
}

int tcp_helper_cluster_vi_hw_stack_id(tcp_helper_cluster_t* thc, int hwport)
{
  return 1;
}

int tcp_helper_cluster_vi_base(tcp_helper_cluster_t* thc, int hwport)
{
  return 1;
}

int tcp_helper_vi_hw_rx_loopback_supported(tcp_helper_resource_t* trs,
                                                  int hwport)
{
  return 0;
}

int tcp_helper_vi_hw_drop_filter_supported(tcp_helper_resource_t* trs,
                                           int hwport)
{
  return 1;
}

void tcp_helper_get_filter_params(tcp_helper_resource_t* trs,
                                  int hwport, int* vi_id, int* rxq,
                                  unsigned *flags)
{
  *vi_id = tcp_helper_hwport_to_stack_id(trs, hwport);
}

int tcp_helper_post_filter_add(tcp_helper_resource_t* trs, int hwport,
                               const struct efx_filter_spec* spec, int rxq,
                               bool replace)
{
  return 0;
}

int tcp_helper_cluster_post_filter_add(tcp_helper_cluster_t* thc, int hwport,
                                       const struct efx_filter_spec* spec,
                                       int rxq, bool replace)
{
  return 0;
}
