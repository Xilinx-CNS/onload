/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2013-2020 Xilinx, Inc. */
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

#include "ef_vi_internal.h"


#define FRAME_DESCRIPTION			\
  "Ethernet frame"

#define TICKS_DESCRIPTION			\
  "Hardware timestamp (minor ticks)"

#define PKTLEN_DESCRIPTION			\
  "Packet length"

#define COMPAT_TS_DESCRIPTION			\
  "Hardware timestamp (compat)"


static const ef_vi_layout_entry frame_entry_no_prefix = {
  .evle_type = EF_VI_LAYOUT_FRAME,
  .evle_offset = 0,
  .evle_description = FRAME_DESCRIPTION,
};
static const ef_vi_layout_entry frame_entry = {
  .evle_type = EF_VI_LAYOUT_FRAME,
  .evle_offset = ES_DZ_RX_PREFIX_SIZE,
  .evle_description = FRAME_DESCRIPTION,
};
static const ef_vi_layout_entry packet_length_entry = {
  .evle_type = EF_VI_LAYOUT_PACKET_LENGTH,
  .evle_offset = ES_DZ_RX_PREFIX_PKTLEN_OFST,
  .evle_description = PKTLEN_DESCRIPTION,
};
static const ef_vi_layout_entry timestamp_entry = {
  .evle_type = EF_VI_LAYOUT_MINOR_TICKS,
  .evle_offset = ES_DZ_RX_PREFIX_TSTAMP_OFST,
  .evle_description = TICKS_DESCRIPTION,
};
static const ef_vi_layout_entry compat_timestamp_entry = {
  .evle_type = EF_VI_LAYOUT_COMPAT_TS,
  .evle_offset = 0,
  .evle_description = COMPAT_TS_DESCRIPTION,
};
static const ef_vi_layout_entry layout_prefix_none[] = {
  frame_entry_no_prefix
};
static const ef_vi_layout_entry layout_prefix_full[] = {
  frame_entry, packet_length_entry, timestamp_entry
};
static const ef_vi_layout_entry compat_layout_prefix[] = {
  frame_entry, compat_timestamp_entry
};


static int
ef10_query_layout(ef_vi* vi, const ef_vi_layout_entry**const ef_vi_layout_out,
                  int* len_out)
{
  bool rx_ts;

  /* We have no prefix, so the packet immediately starts here */
  if( ! vi->rx_prefix_len ) {
    *ef_vi_layout_out = layout_prefix_none;
    *len_out = 1;
    return 0;
  }

  /* We are in the ef10 compat layer */
  if( vi->compat_data != NULL ) {
    *ef_vi_layout_out = compat_layout_prefix;
    *len_out = 2;
    return 0;
  }

  rx_ts = !!(vi->vi_flags & EF_VI_RX_TIMESTAMPS);

  if( rx_ts ) {
    /* frame, length, timestamp */
    *ef_vi_layout_out = layout_prefix_full;
    *len_out = 3;
  }
  else {
    /* frame, length */
    *ef_vi_layout_out = layout_prefix_full;
    *len_out = 2;
  }

  return 0;
}


int ef_vi_receive_query_layout(ef_vi* vi,
                               const ef_vi_layout_entry**const ef_vi_layout_out,
                               int* len_out)
{
  switch( vi->nic_type.arch ) {
  case EF_VI_ARCH_EF10:
    return ef10_query_layout(vi, ef_vi_layout_out, len_out);
  default:
    EF_VI_BUG_ON(1);
    return -EINVAL;
  }
}
