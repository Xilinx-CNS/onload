/* SPDX-License-Identifier: GPL-2.0 */
/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "net_driver.h"

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP)
unsigned int efx_xdp_max_mtu(struct efx_nic *efx);
int efx_xdp_setup_prog(struct efx_nic *efx, struct bpf_prog *prog);
int efx_xdp(struct net_device *dev, struct netdev_bpf *xdp);
bool efx_xdp_rx(struct efx_nic *efx, struct efx_channel *channel,
		struct efx_rx_buffer *rx_buf, u8 **ehp);
#else
static inline bool efx_xdp_rx(struct efx_nic *efx, struct efx_channel *channel,
			      struct efx_rx_buffer *rx_buf, u8 **ehp)
{
	return true;
}
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_REDIR)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_TX_FLAGS)
int efx_xdp_xmit(struct net_device *dev, int n, struct xdp_frame **xdpfs,
		 u32 flags);
#else
int efx_xdp_xmit(struct net_device *dev, struct xdp_frame *xdpf);
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_XDP_FLUSH)
void efx_xdp_flush(struct net_device *dev);
#endif
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_TX)
int efx_xdp_tx_buffers(struct efx_nic *efx, int n, struct xdp_frame **xdpfs,
		       bool flush);
#endif

