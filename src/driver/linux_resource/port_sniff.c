/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2019 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides port sniff functionality.
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

#include "linux_resource_internal.h"
#include "efrm_internal.h"
#include <ci/tools/sysdep.h>


int efrm_port_sniff(struct efrm_resource *rs, int enable, int promiscuous,
		    int rss_context)
{
	int rc;
	ci_int32 owner;
	struct efhw_nic *nic = rs->rs_client->nic;

	if( enable && !capable(CAP_NET_ADMIN) )
		return -EPERM;

	/* Check that the current sniff owner is valid for the operation we're
	 * doing, and mark the op as in progress.
	 */
	if( enable ) {
		if( ci_cas32_fail(&efrm_nic(nic)->rx_sniff_rxq,
				  EFRM_PORT_SNIFF_NO_OWNER,
				  EFRM_PORT_SNIFF_OP_IN_PROGRESS) )
			return -EBUSY;
	}
	else {
		if( ci_cas32_fail(&efrm_nic(nic)->rx_sniff_rxq,
				  rs->rs_instance,
				  EFRM_PORT_SNIFF_OP_IN_PROGRESS) )
			return -EBUSY;
	}

	EFRM_RESOURCE_ASSERT_VALID(rs, 0);
	rc = efhw_nic_set_port_sniff(nic, rs->rs_instance, enable,
				     promiscuous, rss_context);

	if( (enable && rc == 0) || (!enable && rc != 0) )
		owner = rs->rs_instance;
	else
		owner = EFRM_PORT_SNIFF_NO_OWNER;

	EFRM_VERIFY_EQ(ci_cas32_fail(&efrm_nic(nic)->rx_sniff_rxq,
				     EFRM_PORT_SNIFF_OP_IN_PROGRESS,
				     owner), 0);

	return rc;
}
EXPORT_SYMBOL(efrm_port_sniff);

int efrm_tx_port_sniff(struct efrm_resource *rs, int enable, int rss_context)
{
	int rc;
	ci_int32 owner;
	struct efhw_nic *nic = rs->rs_client->nic;

	if( enable && !capable(CAP_NET_ADMIN) )
		return -EPERM;

	/* Check that the current sniff owner is valid for the operation we're
	 * doing, and mark the op as in progress.
	 */
	if( enable ) {
		if( ci_cas32_fail(&efrm_nic(nic)->tx_sniff_rxq,
				  EFRM_PORT_SNIFF_NO_OWNER,
				  EFRM_PORT_SNIFF_OP_IN_PROGRESS) )
			return -EBUSY;
	}
	else {
		if( ci_cas32_fail(&efrm_nic(nic)->tx_sniff_rxq,
				  rs->rs_instance,
				  EFRM_PORT_SNIFF_OP_IN_PROGRESS) )
			return -EBUSY;
	}

	EFRM_RESOURCE_ASSERT_VALID(rs, 0);
	rc = efhw_nic_set_tx_port_sniff(nic, rs->rs_instance, enable,
					rss_context);

	if( (enable && rc == 0) || (!enable && rc != 0) )
		owner = rs->rs_instance;
	else
		owner = EFRM_PORT_SNIFF_NO_OWNER;

	EFRM_VERIFY_EQ(ci_cas32_fail(&efrm_nic(nic)->tx_sniff_rxq,
				     EFRM_PORT_SNIFF_OP_IN_PROGRESS,
				     owner), 0);

	return rc;
}
EXPORT_SYMBOL(efrm_tx_port_sniff);

