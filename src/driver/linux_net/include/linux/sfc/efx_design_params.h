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

#ifndef EFX_DESIGN_PARAMS_H
#define EFX_DESIGN_PARAMS_H

/**
 * struct efx_design_params - Design parameters.
 *
 * @rx_stride: stride between entries in receive window.
 * @rx_buffer_len: Length of each receive buffer.
 * @rx_queues: Maximum Rx queues available.
 * @tx_apertures: Maximum Tx apertures available.
 * @rx_buf_fifo_size: Maximum number of receive buffers can be posted.
 * @frame_offset_fixed: Fixed offset to the frame.
 * @rx_metadata_len: Receive metadata length.
 * @tx_max_reorder: Largest window of reordered writes to the CTPIO.
 * @tx_aperture_size: CTPIO aperture length.
 * @tx_fifo_size: Size of packet FIFO per CTPIO aperture.
 * @ts_subnano_bit: partial time stamp in sub nano seconds.
 * @unsol_credit_seq_mask: Width of sequence number in EVQ_UNSOL_CREDIT_GRANT
 *	register.
 * @l4_csum_proto: L4 csum fields.
 * @max_runt: Max length of frame data when LEN_ERR indicates runt.
 * @ev_queues: Maximum Ev queues available.
 * @evq_sizes: Event queue sizes.
 * @evq_stride: Stride between entries in evq window.
 * @num_filters: Number of filters.
 * @user_bits_width: Width of USER in RX meta.
 * @timestamp_set_sync: Timestamp contains clock status.
 * @ev_label_width: Width of LABEL in event.
 * @meta_location: Meta is at start of current packet.
 * @rollover_zeros_pkt: Rollover meta delivers zeroes.
 */
struct efx_design_params {
	u32 rx_stride;
	u32 rx_buffer_len;
	u32 rx_queues;
	u32 tx_apertures;
	u32 rx_buf_fifo_size;
	u32 frame_offset_fixed;
	u32 rx_metadata_len;
	u32 tx_max_reorder;
	u32 tx_aperture_size;
	u32 tx_fifo_size;
	u32 ts_subnano_bit;
	u32 unsol_credit_seq_mask;
	u32 l4_csum_proto;
	u32 max_runt;
	u32 ev_queues;
	u32 evq_sizes;
	u32 evq_stride;
	u32 num_filters;
	u32 user_bits_width;
	u32 timestamp_set_sync;
	u32 ev_label_width;
	u32 meta_location;
	u32 rollover_zeros_pkt;
};

#endif /* EFX_DESIGN_PARAMS_H */
