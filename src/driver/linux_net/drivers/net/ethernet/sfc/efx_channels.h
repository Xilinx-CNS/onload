/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_CHANNELS_H
#define EFX_CHANNELS_H

extern unsigned int efx_interrupt_mode;
#if !defined(EFX_NOT_UPSTREAM)
extern unsigned int rss_cpus;
#endif

int efx_channel_dummy_op_int(struct efx_channel *channel);
void efx_channel_dummy_op_void(struct efx_channel *channel);

int efx_channels_init_module(void);
void efx_channels_fini_module(void);

int efx_init_interrupts(struct efx_nic *efx);
void efx_fini_interrupts(struct efx_nic *efx);
int efx_probe_interrupts(struct efx_nic *efx);
void efx_remove_interrupts(struct efx_nic *efx);
int efx_enable_interrupts(struct efx_nic *efx);
void efx_disable_interrupts(struct efx_nic *efx);

void efx_register_irq_notifiers(struct efx_nic *efx);
void efx_unregister_irq_notifiers(struct efx_nic *efx);

void efx_set_interrupt_affinity(struct efx_nic *efx);
void efx_clear_interrupt_affinity(struct efx_nic *efx);

int efx_init_channels(struct efx_nic *efx);
int efx_probe_channels(struct efx_nic *efx);
int efx_set_channels(struct efx_nic *efx);
void efx_unset_channels(struct efx_nic *efx);
void efx_remove_channels(struct efx_nic *efx);
void efx_fini_channels(struct efx_nic *efx);

void efx_set_channel_names(struct efx_nic *efx);

int efx_init_napi(struct efx_nic *efx);
void efx_fini_napi(struct efx_nic *efx);
#ifdef EFX_NOT_UPSTREAM
/* Only used from driverlink. */
void efx_pause_napi(struct efx_nic *efx);
int efx_resume_napi(struct efx_nic *efx);
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
int efx_channel_start_xsk_queue(struct efx_channel *channel);
int efx_channel_stop_xsk_queue(struct efx_channel *channel);
#endif
#endif
int efx_start_channels(struct efx_nic *efx);
void efx_stop_channels(struct efx_nic *efx);
void efx_start_eventq(struct efx_channel *channel);
void efx_stop_eventq(struct efx_channel *channel);

#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_NDO_POLL_CONTROLLER)
#ifdef CONFIG_NET_POLL_CONTROLLER
void efx_netpoll(struct net_device *net_dev);
#endif
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_DRIVER_BUSY_POLL)
#ifdef CONFIG_NET_RX_BUSY_POLL
int efx_busy_poll(struct napi_struct *napi);
#endif
#endif

#endif

