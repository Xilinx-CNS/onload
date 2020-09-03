/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides EtherFabric NIC hardware interface.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 * Certain parts of the driver were implemented by
 *          Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 *          OKTET Labs Ltd, Russia,
 *          http://oktetlabs.ru, <info@oktetlabs.ru>
 *          by request of Solarflare Communications
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */
#ifdef __CI_DRIVER_EFAB_HARDWARE_H__
# error This header should only be included directly in .c files
#endif
#define __CI_DRIVER_EFAB_HARDWARE_H__

#include <ci/efhw/hardware_sysdep.h>


/*----------------------------------------------------------------------------
 *
 * Common EtherFabric definitions
 *
 *---------------------------------------------------------------------------*/

#include <ci/efhw/debug.h>
#include <ci/efhw/common.h>
#include <ci/driver/efab/hardware/common.h>

/*----------------------------------------------------------------------------
 *
 * EtherFabric variants
 *
 *---------------------------------------------------------------------------*/

#include <ci/driver/efab/hardware/ef10.h>
#include <ci/driver/efab/hardware/ef100.h>
#include <ci/driver/efab/hardware/af_xdp.h>

/*----------------------------------------------------------------------------
 *
 * EtherFabric Portable Hardware Layer defines
 *
 *---------------------------------------------------------------------------*/

  /*-------------- Initialisation ------------ */
#define efhw_nic_init_hardware(nic, ev_handlers, mac_addr)      \
	((nic)->efhw_func->init_hardware((nic), (ev_handlers), (mac_addr)))
#define efhw_nic_post_reset(nic) \
	((nic)->efhw_func->post_reset((nic)))
#define efhw_nic_release_hardware(nic)      \
	((nic)->efhw_func->release_hardware((nic)))

/*-------------- Event support  ------------ */

#define efhw_nic_event_queue_enable(nic, evq, size, dma_addrs, \
				    n_pages, interrupting, dos_p, wakeup_evq, \
                                    flags, flags_out)                   \
  ((nic)->efhw_func->event_queue_enable((nic), (evq), (size),           \
                                        (dma_addrs),        \
                                        (n_pages), (interrupting),      \
                                        (dos_p), (wakeup_evq),          \
                                        (flags), (flags_out)))

#define efhw_nic_event_queue_disable(nic, evq, time_sync_events_enabled) \
	((nic)->efhw_func->event_queue_disable(nic, evq,		\
					       time_sync_events_enabled))

#define efhw_nic_wakeup_request(nic, iopage, vi_id, rd_ptr)                   \
	((nic)->efhw_func->wakeup_request((nic), (iopage), (vi_id), (rd_ptr)))

#define efhw_nic_wakeup_mask_set(nic, mask)                       \
	((nic)->efhw_func->wakeup_mask_set((nic), (mask)))

#define efhw_nic_sw_event(nic, data, ev) \
	((nic)->efhw_func->sw_event(nic, data, ev))

#define efhw_nic_handle_event(nic, handler, ev, budget) \
	((nic)->efhw_func->handle_event((nic), (handler), (ev), (budget)))

/*-------------- DMA support  ------------ */
#define efhw_nic_dmaq_tx_q_init(nic, dmaq, evq, owner, tag,		\
				dmaq_size, dma_addrs, n_dma_addrs, \
                                vport_id, stack_id, flags)              \
	((nic)->efhw_func->dmaq_tx_q_init(nic, dmaq, evq, owner, tag,	\
					  dmaq_size, dma_addrs,  \
                                          n_dma_addrs, vport_id, stack_id, \
                                          flags))

#define efhw_nic_dmaq_rx_q_init(nic, dmaq, evq, owner, tag,		\
				dmaq_size, dma_addrs, n_dma_addrs, \
                                vport_id, stack_id, ps_buf_size, flags) \
	((nic)->efhw_func->dmaq_rx_q_init(nic, dmaq, evq, owner, tag,	\
					  dmaq_size, dma_addrs,  \
                                          n_dma_addrs, vport_id, stack_id, \
                                          ps_buf_size, flags))

#define efhw_nic_dmaq_tx_q_disable(nic, dmaq) \
	((nic)->efhw_func->dmaq_tx_q_disable(nic, dmaq))

#define efhw_nic_dmaq_rx_q_disable(nic, dmaq) \
	((nic)->efhw_func->dmaq_rx_q_disable(nic, dmaq))

#define efhw_nic_flush_tx_dma_channel(nic, dmaq) \
	((nic)->efhw_func->flush_tx_dma_channel(nic, dmaq))

#define efhw_nic_flush_rx_dma_channel(nic, dmaq) \
	((nic)->efhw_func->flush_rx_dma_channel(nic, dmaq))

/* xdp specific */
#define efhw_nic_dmaq_kick(nic,instance) \
	((nic)->efhw_func->dmaq_kick((nic), (instance)))

/*-------------- MAC Low level interface ---- */
#define efhw_gmac_get_mac_addr(nic) \
	((nic)->gmac->get_mac_addr((nic)->gmac))

/*-------------- Buffer table -------------- */
#define efhw_nic_buffer_table_orders(nic)                               \
	((nic)->efhw_func->buffer_table_orders)
#define efhw_nic_buffer_table_orders_num(nic)                           \
	((nic)->efhw_func->buffer_table_orders_num)
#define efhw_nic_buffer_table_alloc(nic, owner, order, block_out,	    \
				    reset_pending)			    \
	((nic)->efhw_func->buffer_table_alloc(nic, owner, order, block_out, \
					      reset_pending))
#define efhw_nic_buffer_table_realloc(nic, owner, order, block)         \
	((nic)->efhw_func->buffer_table_realloc(nic, owner, order, block))
#define efhw_nic_buffer_table_free(nic, block, reset_pending)		\
	((nic)->efhw_func->buffer_table_free(nic, block, reset_pending))
#define efhw_nic_buffer_table_set(nic, block, first_entry, n_entries,   \
				  addrs)                                \
	((nic)->efhw_func->buffer_table_set(nic, block, first_entry,    \
					    n_entries, addrs))
#define efhw_nic_buffer_table_clear(nic, block, first_entry, n_entries) \
	((nic)->efhw_func->buffer_table_clear(nic, block, first_entry,  \
					      n_entries))
/*-------------- Sniff ------------ */
#define efhw_nic_set_port_sniff(nic, instance, enable, promiscuous, handle) \
	((nic)->efhw_func->set_port_sniff((nic), (instance), (enable),      \
					  (promiscuous), (handle)))

#define efhw_nic_set_tx_port_sniff(nic, instance, enable, handle)         \
	((nic)->efhw_func->set_tx_port_sniff((nic), (instance), (enable), \
					     (handle)))

/*-------------- RSS ------------ */
#define efhw_nic_rss_context_alloc(nic, vport_id, num_qs, shared, handle_out) \
  ((nic)->efhw_func->rss_context_alloc((nic), (vport_id), (num_qs), (shared), \
                                             (handle_out)))

#define efhw_nic_rss_context_free(nic, handle)                          \
        ((nic)->efhw_func->rss_context_free((nic), (handle)))

#define efhw_nic_rss_context_set_table(nic, handle, table)              \
	((nic)->efhw_func->rss_context_set_table((nic), (handle), (table)))

#define efhw_nic_rss_context_set_key(nic, handle, key)                  \
	((nic)->efhw_func->rss_context_set_key((nic), (handle), (key)))

#define efhw_nic_rss_context_set_flags(nic, handle, flags)              \
	((nic)->efhw_func->rss_context_set_flags((nic), (handle), (flags)))

/*-------------- Licensing ---------------- */
#define efhw_nic_license_challenge(nic, feature, challenge, expiry, signature) \
	((nic)->efhw_func->license_challenge(nic, feature, challenge, expiry,  \
                                             signature))

#define efhw_nic_license_check(nic, feature, licensed) \
	((nic)->efhw_func->license_check(nic, feature, licensed))

#define efhw_nic_v3_license_challenge(nic, app_id, challenge, expiry, \
					days, signature, base_mac, v_mac) \
	((nic)->efhw_func->v3_license_challenge(nic, app_id, \
						challenge, expiry, days, \
						signature, base_mac, v_mac))
#define efhw_nic_v3_license_check(nic, feature, licensed) \
	((nic)->efhw_func->v3_license_check(nic, feature, licensed))

/*-------------- Stats ---------------- */
#define efhw_nic_get_rx_error_stats(nic, instance, data, data_len, do_reset) \
	((nic)->efhw_func->get_rx_error_stats(nic, instance, data, data_len, \
                                              do_reset))
