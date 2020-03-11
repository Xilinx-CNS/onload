/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains private API for VI resource.  The API is not designed
 * to be used outside of the SFC resource driver.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
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

#ifndef __CI_EFRM_VI_RESOURCE_PRIVATE_H__
#define __CI_EFRM_VI_RESOURCE_PRIVATE_H__

#include <ci/efhw/common.h>
#include <ci/efrm/vi_resource_manager.h>

extern struct vi_resource_manager *efrm_vi_manager;

/*************************************************************************/

extern void efrm_vi_rm_delayed_free(struct work_struct *data);

extern void efrm_vi_rm_salvage_flushed_vis(struct efhw_nic *);

extern void efrm_vi_rm_free_flushed_resource(struct efrm_vi *virs);

/*! Wakeup handler */
extern int efrm_handle_wakeup_event(struct efhw_nic *nic,
				    unsigned id, int budget);

/*! Timeout handler */
extern int efrm_handle_timeout_event(struct efhw_nic *nic,
				     unsigned id, int budget);

/*! DMA flush handler */
extern int efrm_handle_dmaq_flushed_schedule(struct efhw_nic *nic,
					      unsigned id,
					      int rx_flush, int failed);

/*! SRAM update handler */
extern void efrm_handle_sram_event(struct efhw_nic *nic);

extern unsigned
efrm_vi_shut_down_flag(enum efhw_q_type queue);

extern int
efrm_vi_q_init_common(struct efrm_vi *, enum efhw_q_type, int n_q_entries,
		   const dma_addr_t *dma_addrs, int dma_addrs_n,
		   int q_tag, unsigned q_flags);

#endif /* __CI_EFRM_VI_RESOURCE_PRIVATE_H__ */
