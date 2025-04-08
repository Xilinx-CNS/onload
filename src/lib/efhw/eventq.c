/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains event queue support.
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

#include <ci/efhw/debug.h>
#include <ci/efhw/iopage.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efhw/eventq.h>
#include <ci/efhw/nic.h>

/**********************************************************************
 * Kernel event queue management.
 */

int
efhw_handle_txdmaq_flushed(struct efhw_nic *nic, unsigned instance)
{
	EFHW_TRACE("%s: instance=%d", __FUNCTION__, instance);

	if (!nic->ev_handlers->dmaq_flushed_fn) {
		EFHW_WARN("%s: no handler registered", __FUNCTION__);
		return 0;
	}

	return nic->ev_handlers->dmaq_flushed_fn(nic, instance, false, false);
}

int
efhw_handle_rxdmaq_flushed(struct efhw_nic *nic, unsigned instance, int failed)
{
	EFHW_TRACE("%s: instance=%d", __FUNCTION__, instance);

	if (!nic->ev_handlers->dmaq_flushed_fn) {
		EFHW_WARN("%s: no handler registered", __FUNCTION__);
		return 0;
	}

	return nic->ev_handlers->dmaq_flushed_fn(nic, instance, true, failed);
}

int
efhw_handle_wakeup_event(struct efhw_nic *nic, unsigned instance, int budget)
{
	if (!nic->ev_handlers->wakeup_fn) {
		EFHW_WARN("%s: no handler registered", __FUNCTION__);
		return 0;
	}

	return nic->ev_handlers->wakeup_fn(nic, instance, budget);
}

int
efhw_handle_timeout_event(struct efhw_nic *nic, unsigned instance, int budget)
{
	if (!nic->ev_handlers->timeout_fn) {
		EFHW_WARN("%s: no handler registered", __FUNCTION__);
		return 0;
	}

	return nic->ev_handlers->timeout_fn(nic, instance, budget);
}

int
efhw_handle_efct_rxq_flushed(struct efhw_nic *nic, unsigned instance)
{
	if (!nic->ev_handlers->efct_rxq_flushed_fn) {
		EFHW_WARN("%s: no handler registered", __func__);
		return 0;
	}

	return nic->ev_handlers->efct_rxq_flushed_fn(nic, instance);
}

/**********************************************************************
 * Kernel event queue event handling.
 */
