/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2012-2020 Xilinx, Inc. */

#ifndef __CI_DRIVER_EFAB_HARDWARE_EFCT_H__
#define __CI_DRIVER_EFAB_HARDWARE_EFCT_H__

/* tx header bit field definitions. TODO: should come from hardware defs */
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

/* tx event bit field definitions. TODO: should come from hardware defs */
#define EFCT_TX_EVENT_PARTIAL_TSTAMP_LBN 0
#define EFCT_TX_EVENT_PARTIAL_TSTAMP_WIDTH 40

#define EFCT_TX_EVENT_SEQUENCE_LBN 40
#define EFCT_TX_EVENT_SEQUENCE_WIDTH 8

#define EFCT_TX_EVENT_TIMESTAMP_STATUS_LBN 48
#define EFCT_TX_EVENT_TIMESTAMP_STATUS_WIDTH 2

#define EFCT_TX_EVENT_LABEL_LBN 50
#define EFCT_TX_EVENT_LABEL_WIDTH 6

#define EFCT_TX_EVENT_PHASE_LBN 59
#define EFCT_TX_EVENT_PHASE_WIDTH 1

#define EFCT_TX_EVENT_TYPE_LBN 60
#define EFCT_TX_EVENT_TYPE_WIDTH 4

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

#endif
