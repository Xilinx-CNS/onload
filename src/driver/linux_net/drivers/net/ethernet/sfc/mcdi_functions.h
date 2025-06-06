/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_MCDI_FUNCTIONS_H
#define EFX_MCDI_FUNCTIONS_H

#ifdef EFX_NOT_UPSTREAM
enum efx_ll_queue_type {
	EFX_LL_QUEUE_TXQ,
	EFX_LL_QUEUE_RXQ,
	EFX_LL_QUEUE_EVQ,
};
#endif

int efx_mcdi_alloc_vis(struct efx_nic *efx,
                       unsigned int min_vis, unsigned int max_vis,
                       unsigned int *vi_base, unsigned int *vi_shift,
                       unsigned int *allocated_vis);
int efx_mcdi_free_vis(struct efx_nic *efx);

int efx_mcdi_ev_probe(struct efx_channel *channel);
int efx_mcdi_ev_init(struct efx_channel *channel, bool v1_cut_thru, bool v2);
void efx_mcdi_ev_remove(struct efx_channel *channel);
void efx_mcdi_ev_fini(struct efx_channel *channel);
int efx_mcdi_tx_init(struct efx_tx_queue *tx_queue, bool *tso_v2);
void efx_mcdi_tx_fini(struct efx_tx_queue *tx_queue);
int efx_mcdi_rx_probe(struct efx_rx_queue *rx_queue);
int efx_mcdi_rx_init(struct efx_rx_queue *rx_queue, bool want_outer_classes);
void efx_mcdi_rx_remove(struct efx_rx_queue *rx_queue);
void efx_mcdi_rx_fini(struct efx_rx_queue *rx_queue);
int efx_fini_dmaq(struct efx_nic *efx);
int efx_mcdi_window_mode_to_stride(struct efx_nic *efx, u8 vi_window_mode);
int efx_get_fn_info(struct efx_nic *efx, unsigned int *pf_index,
		    unsigned int *vf_index);
#ifdef EFX_NOT_UPSTREAM
int efx_mcdi_alloc_ll_queue(struct efx_nic *efx, enum efx_ll_queue_type type);
int efx_mcdi_free_ll_queue(struct efx_nic *efx, u32 queue);
int efx_mcdi_client_alloc(struct efx_nic *efx, u32 parent, u32 *client_id);
void efx_mcdi_client_free(struct efx_nic *efx, u32 client_id);
#endif

#ifdef CONFIG_SFC_TPH
int efx_set_tlp_tph(struct efx_nic *efx, u32 channel, u16 tag);
#else
static inline int efx_set_tlp_tph(struct efx_nic *efx, u32 channel, u16 tag)
{
	return 0;
}
#endif

#endif
