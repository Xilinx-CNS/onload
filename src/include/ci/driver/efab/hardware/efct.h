/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2012-2020 Xilinx, Inc. */

#ifndef __CI_DRIVER_EFAB_HARDWARE_EFCT_H__
#define __CI_DRIVER_EFAB_HARDWARE_EFCT_H__

/* TODO many of these should be generated from hardware defs when possible */

/* tx header bit field definitions */
#define EFCT_TX_HEADER_PACKET_LENGTH_LBN 0
#define EFCT_TX_HEADER_PACKET_LENGTH_WIDTH 14

#define EFCT_TX_HEADER_CT_THRESH_LBN 14
#define EFCT_TX_HEADER_CT_THRESH_WIDTH 8

#define EFCT_TX_HEADER_TIMESTAMP_FLAG_LBN 22
#define EFCT_TX_HEADER_TIMESTAMP_FLAG_WIDTH 1

#define EFCT_TX_HEADER_WARM_FLAG_LBN 23
#define EFCT_TX_HEADER_WARM_FLAG_WIDTH 1

#define EFCT_TX_HEADER_ACTION_LBN 24
#define EFCT_TX_HEADER_ACTION_WIDTH 3

/* rx header bit field definitions */
#define EFCT_RX_HEADER_PACKET_LENGTH_LBN 0
#define EFCT_RX_HEADER_PACKET_LENGTH_WIDTH 14

#define EFCT_RX_HEADER_NEXT_FRAME_LOC_LBN 14
#define EFCT_RX_HEADER_NEXT_FRAME_LOC_WIDTH 2

#define EFCT_RX_HEADER_CSUM_LBN 16
#define EFCT_RX_HEADER_CSUM_WIDTH 16

#define EFCT_RX_HEADER_L2_CLASS_LBN 32
#define EFCT_RX_HEADER_L2_CLASS_WIDTH 2

#define EFCT_RX_HEADER_L3_CLASS_LBN 34
#define EFCT_RX_HEADER_L3_CLASS_WIDTH 2

#define EFCT_RX_HEADER_L4_CLASS_LBN 36
#define EFCT_RX_HEADER_L4_CLASS_WIDTH 2

#define EFCT_RX_HEADER_L2_STATUS_LBN 38
#define EFCT_RX_HEADER_L2_STATUS_WIDTH 2

#define EFCT_RX_HEADER_L3_STATUS_LBN 40
#define EFCT_RX_HEADER_L3_STATUS_WIDTH 1

#define EFCT_RX_HEADER_L4_STATUS_LBN 41
#define EFCT_RX_HEADER_L4_STATUS_WIDTH 1

#define EFCT_RX_HEADER_ROLLOVER_LBN 42
#define EFCT_RX_HEADER_ROLLOVER_WIDTH 1

#define EFCT_RX_HEADER_SENTINEL_LBN 43
#define EFCT_RX_HEADER_SENTINEL_WIDTH 1

#define EFCT_RX_HEADER_TIMESTAMP_STATUS_LBN 44
#define EFCT_RX_HEADER_TIMESTAMP_STATUS_WIDTH 2

#define EFCT_RX_HEADER_FILTER_LBN 46
#define EFCT_RX_HEADER_FILTER_WIDTH 10

#define EFCT_RX_HEADER_PARTIAL_TIMESTAMP_LBN 64
#define EFCT_RX_HEADER_PARTIAL_TIMESTAMP_WIDTH 40

#define EFCT_RX_HEADER_USER_LBN 104
#define EFCT_RX_HEADER_USER_WIDTH 24

/* data offsets corresponding to NEXT_FRAME_LOC values */
#define EFCT_RX_HEADER_NEXT_FRAME_LOC_0 18
#define EFCT_RX_HEADER_NEXT_FRAME_LOC_1 66

/* generic event bit field definitions */
#define EFCT_EVENT_PHASE_LBN 59
#define EFCT_EVENT_PHASE_WIDTH 1

#define EFCT_EVENT_TYPE_LBN 60
#define EFCT_EVENT_TYPE_WIDTH 4

/* event types */
#define EFCT_EVENT_TYPE_RX 0
#define EFCT_EVENT_TYPE_TX 1
#define EFCT_EVENT_TYPE_CONTROL 2

/* tx event bit field definitions */
#define EFCT_TX_EVENT_PARTIAL_TSTAMP_LBN 0
#define EFCT_TX_EVENT_PARTIAL_TSTAMP_WIDTH 40

#define EFCT_TX_EVENT_SEQUENCE_LBN 40
#define EFCT_TX_EVENT_SEQUENCE_WIDTH 8

#define EFCT_TX_EVENT_TIMESTAMP_STATUS_LBN 48
#define EFCT_TX_EVENT_TIMESTAMP_STATUS_WIDTH 2

#define EFCT_TX_EVENT_LABEL_LBN 50
#define EFCT_TX_EVENT_LABEL_WIDTH 6

/* size of a transmit header in bytes */
#define EFCT_TX_HEADER_BYTES 8

/* size of a transmit descriptor in bytes */
#define EFCT_TX_DESCRIPTOR_BYTES 2

/* size of the transmit FIFO in bytes */
#define EFCT_TX_FIFO_BYTES 32768

/* size of the transmit aperture in bytes */
#define EFCT_TX_APERTURE 4096

/* alignment requirement for tx packets written to the aperture */
#define EFCT_TX_ALIGNMENT 64

/* magic value of ct_thresh to disable cut-through */
#define EFCT_TX_CT_DISABLE 0xff

/* size of a receive header in bytes */
#define EFCT_RX_HEADER_BYTES 16

/* size of a transmit descriptor in bytes */
#define EFCT_RX_DESCRIPTOR_BYTES 2

/* size of each receive buffer posted to RX_BUFFER_POST (DP_RX_BUFFER_SIZE) */
#define EFCT_RX_SUPERBUF_BYTES  1048576

#endif

