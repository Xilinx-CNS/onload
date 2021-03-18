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

/* size of the transmit aperture in bytes */
#define EFCT_TX_APERTURE 4096

/* alignment requirement for tx packets written to the aperture */
#define EFCT_TX_ALIGNMENT 64

/* magic value of ct_thresh to disable cut-through */
#define EFCT_TX_CT_DISABLE 0xff

#endif

