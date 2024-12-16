/* SPDX-License-Identifier: GPL-2.0-only */
/****************************************************************************
 * Driver for AMD network controllers and boards
 *
 * Copyright 2024, Advanced Micro Devices, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_LLCT_REGS_H
#define EFX_LLCT_REGS_H

/* LLCT hardware architecture definitions have a name prefix following
 * the format:
 *
 *     E<type>_<min-rev><max-rev>_
 *
 * The following <type> strings are used:
 *
 *             MMIO register  Host memory structure
 * -------------------------------------------------------------
 * Address     R
 * Bitfield    RF             SF
 * Enumerator  FE             SE
 *
 * <min-rev> is the first revision to which the definition applies:
 *
 *     I: Medford 4
 *
 * If the definition has been changed or removed in later revisions
 * then <max-rev> is the last revision to which the definition applies;
 * otherwise it is "Z".
 */

/**************************************************************************
 *
 * LLCT registers and descriptors
 *
 **************************************************************************
 */

/* PARAMS_TLV_LEN: Size of design parameters area in bytes */
#define	ER_IZ_LLCT_PARAMS_TLV_LEN 0x00000020

/* PARAMS_TLV: Design parameters */
#define	ER_IZ_LLCT_PARAMS_TLV 0x00000024

/* EVQ_INT_PRIME: Prime Event Queue */
#define ER_IZ_LLCT_EVQ_INT_PRIME 0x808

#define ERF_IZ_LLCT_READ_IDX_LBN 16
#define ERF_IZ_LLCT_READ_IDX_WIDTH 16
#define ERF_IZ_LLCT_EVQ_ID_LBN 0
#define ERF_IZ_LLCT_EVQ_ID_WIDTH 16

/* RX_BUFFER_POST: Pages of memory to use for received packets RXQ */
#define ER_IZ_LLCT_RX_BUFFER_POST 0x2000
#define ER_IZ_LLCT_RX_BUFFER_POST_STEP 0x1000
#define ER_IZ_LLCT_RX_BUFFER_POST_ROWS 256

#define ERF_IZ_LLCT_ROLLOVER_LBN 53
#define ERF_IZ_LLCT_ROLLOVER_WIDTH 1
#define ERF_IZ_LLCT_SENTINEL_VALUE_LBN 52
#define ERF_IZ_LLCT_SENTINEL_VALUE_WIDTH 1
#define ERF_IZ_LLCT_PAGE_ADDRESS_LBN 0
#define ERF_IZ_LLCT_PAGE_ADDRES_WIDTH 52

/* EVQ_UNSOL_CREDIT_GRANT: Unsolicited credit grant for events for EVQ */
#define ER_IZ_LLCT_EVQ_UNSOL_CREDIT_GRANT 0x102000
#define ER_IZ_LLCT_EVQ_UNSOL_CREDIT_GRANT_STEP 0x1000
#define ER_IZ_LLCT_EVQ_UNSOL_CREDIT_GRANT_ROWS 512

#define ERF_IZ_LLCT_CLEAR_OVERFLOW_LBN 16
#define ERF_IZ_LLCT_CLEAR_OVERFLOW_WIDTH 1
#define ERF_IZ_LLCT_GRANT_SEQ_LBN 0
#define ERF_IZ_LLCT_GRANT_SEQ_WIDTH 16

#define ER_IZ_LLCT_CTPIO_REGION 0x302000

/* Enum DESIGN_PARAMS */
#define	ESE_IZ_LLCT_DP_ROLLOVER_ZEROS_PKT 24
#define	ESE_IZ_LLCT_DP_MD_LOCATION 23
#define	ESE_IZ_LLCT_DP_EV_LABEL_WIDTH 22
#define	ESE_IZ_LLCT_DP_MD_TIMESTAMP_SET_SYNC 21
#define	ESE_IZ_LLCT_DP_MD_USER_BITS_WIDTH 20
#define	ESE_IZ_LLCT_DP_NUM_FILTERS 19
#define	ESE_IZ_LLCT_DP_EV_QUEUES 18
#define	ESE_IZ_LLCT_DP_EVQ_SIZES 17
#define	ESE_IZ_LLCT_DP_RX_MAX_RUNT 16
#define	ESE_IZ_LLCT_DP_RX_L4_CSUM_PROTOCOLS 15
#define	ESE_IZ_LLCT_DP_EVQ_UNSOL_CREDIT_SEQ_BITS 14
#define	ESE_IZ_LLCT_DP_PARTIAL_TSTAMP_SUB_NANO_BITS 13
#define	ESE_IZ_LLCT_DP_TX_PACKET_FIFO_SIZE 12
#define	ESE_IZ_LLCT_DP_TX_CTPIO_APERTURE_SIZE 11
#define	ESE_IZ_LLCT_DP_TX_MAXIMUM_REORDER 10
#define	ESE_IZ_LLCT_DP_RX_METADATA_LENGTH 9
#define	ESE_IZ_LLCT_DP_FRAME_OFFSET_FIXED 8
#define	ESE_IZ_LLCT_DP_RX_BUFFER_FIFO_SIZE 7
#define	ESE_IZ_LLCT_DP_TX_CTPIO_APERTURES 6
#define	ESE_IZ_LLCT_DP_RX_QUEUES 5
#define	ESE_IZ_LLCT_DP_RX_BUFFER_SIZE 4
#define	ESE_IZ_LLCT_DP_CTPIO_STRIDE 3
#define	ESE_IZ_LLCT_DP_EVQ_STRIDE 2
#define	ESE_IZ_LLCT_DP_RX_STRIDE 1
#define	ESE_IZ_LLCT_DP_PAD 0

#endif /* EFX_LLCT_REGS_H */
