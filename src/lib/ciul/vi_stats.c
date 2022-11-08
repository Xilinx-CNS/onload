/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2014-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  Akhi Singhania <asinghania@solarflare.com>
**  \brief  Layout of RX data.
**   \date  2013/11
**    \cop  (c) Solarflare Communications, Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <etherfabric/vi.h>
#include "ef_vi_internal.h"
#include "driver_access.h"
#include "logging.h"


int
ef10_query_layout(ef_vi* vi, const ef_vi_stats_layout**const layout_out)
{
/* Layout is imposed by ef10_get_rx_error_stats in ef10.c
 * The layout should be either derived dynamically or come from a
 * common header.
 */
  static const ef_vi_stats_layout layout = {
#define EF10_RX_STATS_SIZE 16
    .evsl_data_size = EF10_RX_STATS_SIZE,
    .evsl_fields_num = 4,
    .evsl_fields = {
      {
        .evsfl_name = "RX CRC errors",
        .evsfl_offset = 0,
        .evsfl_size = 4,
      },
      {
        .evsfl_name = "RX trunk errors",
        .evsfl_offset = 4,
        .evsfl_size = 4,
      },
      {
        .evsfl_name = "RX no descriptor errors",
        .evsfl_offset = 8,
        .evsfl_size = 4,
      },
      {
        .evsfl_name = "RX abort errors",
        .evsfl_offset = 12,
        .evsfl_size = 4,
      },
    }
  };
  *layout_out = &layout;
  return 0;
}

int
ef_vi_stats_query_layout(ef_vi* vi,
                         const ef_vi_stats_layout**const layout_out)
{
  switch( vi->nic_type.arch ) {
  case EF_VI_ARCH_EF10:
    return ef10_query_layout(vi, layout_out);
  default:
    return -EINVAL;
  }
}

int
ef10_query(ef_vi* vi, ef_driver_handle dh, void* data, int do_reset)
{
  ci_resource_op_t  op;

  op.op = CI_RSOP_VI_GET_RX_ERROR_STATS;
  op.id = efch_make_resource_id(vi->vi_resource_id);
  op.u.vi_stats.data_ptr = (uintptr_t)data;
  op.u.vi_stats.data_len = EF10_RX_STATS_SIZE;
  op.u.vi_stats.do_reset = do_reset;
  return ci_resource_op(dh, &op);
}

int
ef_vi_stats_query(ef_vi* vi, ef_driver_handle dh, void* data, int do_reset)
{
  switch( vi->nic_type.arch ) {
  case EF_VI_ARCH_EF10:
    return ef10_query(vi, dh, data, do_reset);
  default:
    EF_VI_BUG_ON(1);
    return -EINVAL;
  }
}

