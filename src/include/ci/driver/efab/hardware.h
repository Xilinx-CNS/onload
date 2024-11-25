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
#include <ci/driver/efab/hardware/efct.h>
#include <ci/driver/efab/hardware/ef10ct.h>
#include <ci/driver/efab/hardware/af_xdp.h>

/*----------------------------------------------------------------------------
 *
 * EtherFabric Portable Hardware Layer defines
 *
 *---------------------------------------------------------------------------*/

  /*-------------- Initialisation ------------ */
#define efhw_nic_sw_ctor(nic, res)      \
	((nic)->efhw_func->sw_ctor((nic), (res)))
#define efhw_nic_sw_dtor(nic) ((nic)->efhw_func->sw_dtor ? \
	 (nic)->efhw_func->sw_dtor((nic)) : (void) 0)
#define efhw_nic_init_hardware(nic, ev_handlers, mac_addr)      \
	((nic)->efhw_func->init_hardware((nic), (ev_handlers), (mac_addr)))
#define efhw_nic_post_reset(nic) \
	((nic)->efhw_func->post_reset((nic)))
#define efhw_nic_release_hardware(nic)      \
	((nic)->efhw_func->release_hardware((nic)))

/*-------------- Event support  ------------ */

#define efhw_nic_event_queue_enable(nic, params) \
  ((nic)->efhw_func->event_queue_enable((nic), (params)))

#define efhw_nic_event_queue_disable(nic, evq, time_sync_events_enabled) \
	((nic)->efhw_func->event_queue_disable(nic, evq,		\
					       time_sync_events_enabled))

#define efhw_nic_wakeup_request(nic, iopage, vi_id, rd_ptr)                   \
	((nic)->efhw_func->wakeup_request((nic), (iopage), (vi_id), (rd_ptr)))

#define efhw_nic_wakeup_mask_set(nic, mask)                       \
	((nic)->efhw_func->wakeup_mask_set((nic), (mask)))

#define efhw_nic_sw_event(nic, data, ev) \
	((nic)->efhw_func->sw_event ? \
	 (nic)->efhw_func->sw_event(nic, data, ev) : (void) 0)

#define efhw_nic_handle_event(nic, ev, budget) \
	((nic)->efhw_func->handle_event ? \
	 (nic)->efhw_func->handle_event((nic), (ev), (budget)) : -EOPNOTSUPP)

#define efhw_nic_vi_alloc(nic, evc, n_vis) \
	((nic)->efhw_func->vi_alloc((nic), (evc), (n_vis)))

#define efhw_nic_vi_free(nic, instance, n_vis) \
	((nic)->efhw_func->vi_free((nic), (instance), (n_vis)))

/*-------------- DMA support  ------------ */
#define efhw_nic_dmaq_tx_q_init(nic, params) \
	((nic)->efhw_func->dmaq_tx_q_init((nic), (params)))

#define efhw_nic_dmaq_rx_q_init(nic, params) \
	((nic)->efhw_func->dmaq_rx_q_init((nic), (params)))

#define efhw_nic_flush_tx_dma_channel(nic, dmaq, evq) \
	((nic)->efhw_func->flush_tx_dma_channel((nic), (dmaq), (evq)))

#define efhw_nic_flush_rx_dma_channel(nic, dmaq) \
	((nic)->efhw_func->flush_rx_dma_channel(nic, dmaq))

#define efhw_nic_max_shared_rxqs(nic) \
	((nic)->efhw_func->max_shared_rxqs ? \
	 (nic)->efhw_func->max_shared_rxqs((nic)) : 0)

#define efhw_nic_queue_map_type(nic) \
	((nic)->efhw_func->queue_map_type ? \
	 (nic)->efhw_func->queue_map_type((nic)) : EFHW_PAGE_MAP_DMA)

/* xdp specific */
#define efhw_nic_dmaq_kick(nic,instance) \
	((nic)->efhw_func->dmaq_kick ? \
	 (nic)->efhw_func->dmaq_kick((nic), (instance)) : 0)

#define efhw_nic_af_xdp_mem(nic, instance) \
	((nic)->efhw_func->af_xdp_mem ? \
	 (nic)->efhw_func->af_xdp_mem((nic), (instance)) : NULL)

#define efhw_nic_af_xdp_init(nic, instance, chunk_size, headroom, pages_out) \
	((nic)->efhw_func->af_xdp_init ? \
	 (nic)->efhw_func->af_xdp_init((nic), (instance), (chunk_size), \
	 (headroom), (pages_out)) : 0)

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
	((nic)->efhw_func->buffer_table_alloc ? \
	 (nic)->efhw_func->buffer_table_alloc(nic, owner, order, block_out, \
					      reset_pending) : -EOPNOTSUPP)
#define efhw_nic_buffer_table_realloc(nic, owner, order, block)         \
	((nic)->efhw_func->buffer_table_realloc ? \
	 (nic)->efhw_func->buffer_table_realloc(nic, owner, order, block) : \
	 -EOPNOTSUPP)
#define efhw_nic_buffer_table_free(nic, block, reset_pending)		\
	((nic)->efhw_func->buffer_table_free ? \
	 (nic)->efhw_func->buffer_table_free(nic, block, reset_pending) : \
	 (void) 0)
#define efhw_nic_buffer_table_set(nic, block, first_entry, n_entries,   \
				  addrs)                                \
	((nic)->efhw_func->buffer_table_set ? \
	 (nic)->efhw_func->buffer_table_set(nic, block, first_entry,    \
					    n_entries, addrs) : -EOPNOTSUPP)
#define efhw_nic_buffer_table_clear(nic, block, first_entry, n_entries) \
	((nic)->efhw_func->buffer_table_clear ? \
	 (nic)->efhw_func->buffer_table_clear(nic, block, first_entry,  \
					      n_entries) : (void) 0)
#define efhw_nic_buffer_map_type(nic) \
	((nic)->efhw_func->buffer_map_type ? \
	 (nic)->efhw_func->buffer_map_type((nic)) : EFHW_PAGE_MAP_DMA)

/*-------------- Sniff ------------ */
#define efhw_nic_set_port_sniff(nic, instance, enable, promiscuous, handle) \
	((nic)->efhw_func->set_port_sniff ? \
	 (nic)->efhw_func->set_port_sniff((nic), (instance), (enable),      \
					  (promiscuous), (handle)) : \
	 -EOPNOTSUPP)

#define efhw_nic_set_tx_port_sniff(nic, instance, enable, handle)         \
	((nic)->efhw_func->set_tx_port_sniff ? \
	 (nic)->efhw_func->set_tx_port_sniff((nic), (instance), (enable), \
					     (handle)) : -EOPNOTSUPP)

/*-------------- Stats ---------------- */
#define efhw_nic_get_rx_error_stats(nic, instance, data, data_len, do_reset) \
	((nic)->efhw_func->get_rx_error_stats ? \
	 (nic)->efhw_func->get_rx_error_stats(nic, instance, data, data_len, \
                                              do_reset) : -EOPNOTSUPP)

/*-------------- filtering --------------------- */
#define efhw_nic_rss_alloc(nic, indir, key, efhw_rss_mode, num_qs, context) \
        ((nic)->efhw_func->rss_alloc ? \
         (nic)->efhw_func->rss_alloc((nic), (indir), (key), (efhw_rss_mode), \
				     (num_qs), (context)) : -EOPNOTSUPP)
#define efhw_nic_rss_free(nic, rss_context) \
	((nic)->efhw_func->rss_free ? \
	 (nic)->efhw_func->rss_free((nic), (rss_context)) : -EOPNOTSUPP)

#define efhw_nic_filter_insert(nic, spec, rxq, exclusive_rxq_token, mask, flags) \
	((nic)->efhw_func->filter_insert((nic), (spec), (rxq), (exclusive_rxq_token), (mask), (flags)))
#define efhw_nic_filter_remove(nic, filter_id) \
	((nic)->efhw_func->filter_remove((nic), (filter_id)))
#define efhw_nic_filter_redirect(nic, filter_id, spec) \
	((nic)->efhw_func->filter_redirect ? \
	 (nic)->efhw_func->filter_redirect((nic), (filter_id), (spec)) : \
	 -EOPNOTSUPP)
#define efhw_nic_filter_query(nic, filter_id, info) \
	((nic)->efhw_func->filter_query ? \
	 (nic)->efhw_func->filter_query((nic), (filter_id), (info)) : \
         -EOPNOTSUPP)

#define efhw_nic_multicast_block(nic, block) \
	((nic)->efhw_func->multicast_block ? \
	 (nic)->efhw_func->multicast_block((nic), (block)) : -ENOSYS)
#define efhw_nic_unicast_block(nic, block) \
	((nic)->efhw_func->unicast_block ? \
	 (nic)->efhw_func->unicast_block((nic), (block)) : -ENOSYS)

/*-------------- vports ------------------------ */
#define efhw_nic_vport_alloc(nic, vlan_id, vport_handle_out) \
	((nic)->efhw_func->vport_alloc ? \
	 (nic)->efhw_func->vport_alloc((nic), (vlan_id), (vport_handle_out)) : \
	 -EOPNOTSUPP)
#define efhw_nic_vport_free(nic, vport_handle) \
	((nic)->efhw_func->vport_free ? \
	 (nic)->efhw_func->vport_free((nic), (vport_handle)) : -EOPNOTSUPP)

/*-------------- device ------------------------ */
#define efhw_nic_get_pci_dev(nic) \
	((nic)->efhw_func->get_pci_dev ? \
	 (nic)->efhw_func->get_pci_dev(nic) : NULL)
#define efhw_nic_vi_io_region(nic, instance, size_out, addr_out) \
	((nic)->efhw_func->vi_io_region((nic), (instance), (size_out), \
					(addr_out)))
#define efhw_nic_inject_reset_ev(nic, base, capacity, evq_ptr) \
	((nic)->efhw_func->inject_reset_ev ? \
	 (nic)->efhw_func->inject_reset_ev((nic), (base), (capacity), \
	 (evq_ptr)) : -EOPNOTSUPP)

/*-------------- ctpio ------------------------ */
#define efhw_nic_ctpio_addr(nic, instance, addr) \
	((nic)->efhw_func->ctpio_addr ? \
	 (nic)->efhw_func->ctpio_addr((nic), (instance), (addr)) : -ENOSYS)

/*-------------- superbufs ------------------------ */
#define efhw_nic_rxq_window(nic, instance, addr_out) \
	((nic)->efhw_func->rxq_window ? \
	 (nic)->efhw_func->rxq_window((nic), (instance), (addr_out)) : \
	 -EOPNOTSUPP)

#define efhw_nic_post_superbuf(nic, instance, addr, sentinel, rollover, owner_id) \
	((nic)->efhw_func->post_superbuf ? \
	 (nic)->efhw_func->post_superbuf((nic), (instance), (addr), \
					 (sentinel), (rollover), (owner_id)) : \
	 -EOPNOTSUPP)
#define efhw_nic_shared_rxq_bind(nic, params) \
	((nic)->efhw_func->shared_rxq_bind ? \
	 (nic)->efhw_func->shared_rxq_bind((nic), (params)) : -EOPNOTSUPP)
#define efhw_nic_shared_rxq_unbind(nic, rxq, freer) \
	((nic)->efhw_func->shared_rxq_unbind ? \
	 (nic)->efhw_func->shared_rxq_unbind((nic), (rxq), (freer)) : (void)0)
#define efhw_nic_shared_rxq_refresh(nic, hwqid, superbufs, user, max) \
	((nic)->efhw_func->shared_rxq_refresh ? \
	 (nic)->efhw_func->shared_rxq_refresh((nic), (hwqid), (superbufs), \
                                              (user), (max)) : -EOPNOTSUPP)
#define efhw_nic_shared_rxq_refresh_kernel(nic, hwqid, sbufs) \
	((nic)->efhw_func->shared_rxq_refresh_kernel ? \
	 (nic)->efhw_func->shared_rxq_refresh_kernel((nic), (hwqid), \
                                                     (sbufs)) : -EOPNOTSUPP)
#define efhw_nic_shared_rxq_request_wakeup(nic, rxq, sbseq, pktix, rec) \
	((nic)->efhw_func->shared_rxq_request_wakeup ? \
	 (nic)->efhw_func->shared_rxq_request_wakeup((nic), (rxq), (sbseq), \
                                              (pktix), (rec)) : -ENOSYS)

/*-------------- design parameters ------------ */
#define efhw_nic_design_parameters(nic, dp) \
	((nic)->efhw_func->design_parameters ? \
	 (nic)->efhw_func->design_parameters((nic), (dp)) : 0)

/*-------------- TX Alternatives ------------ */
#define efhw_nic_tx_alt_alloc(nic, tx_q_id, num_alt, num_32b_words, \
                              cp_id_out, alt_ids_out) \
	((nic)->efhw_func->tx_alt_alloc ? \
	 (nic)->efhw_func->tx_alt_alloc((nic), (tx_q_id), (num_alt), \
                                        (num_32b_words), (cp_id_out), \
                                        (alt_ids_out)) : \
         -EOPNOTSUPP)

#define efhw_nic_tx_alt_free(nic, num_alt, cp_id, alt_ids) \
	((nic)->efhw_func->tx_alt_free ? \
	 (nic)->efhw_func->tx_alt_free((nic), (num_alt), (cp_id), \
                                       (alt_ids)) : \
	 -EOPNOTSUPP)

/*-------------- pio ------------ */
#define efhw_nic_piobuf_alloc(nic, handle_out) \
	((nic)->efhw_func->piobuf_alloc ? \
	 (nic)->efhw_func->piobuf_alloc((nic), (handle_out)) : -EPERM)
#define efhw_nic_piobuf_free(nic, handle) \
	((nic)->efhw_func->piobuf_free ? \
	 (nic)->efhw_func->piobuf_free((nic), (handle)) : -EINVAL)
#define efhw_nic_piobuf_link(nic, txq, handle) \
	((nic)->efhw_func->piobuf_link ? \
	 (nic)->efhw_func->piobuf_link((nic), (txq), (handle)) : -EINVAL)
#define efhw_nic_piobuf_unlink(nic, txq) \
	((nic)->efhw_func->piobuf_unlink ? \
	 (nic)->efhw_func->piobuf_unlink((nic), (txq)) : -EINVAL)
