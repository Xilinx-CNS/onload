/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides public API for port sniffing.
 *
 * Copyright 2005-2012: Solarflare Communications Inc,
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

#ifndef __CI_EFRM_PORT_SNIFF_H__
#define __CI_EFRM_PORT_SNIFF_H__

struct efrm_resource;

/*!
 * Set port sniff.
 *
 * \param rs          Resource to receive sniffed traffic.
 * \param enable      Whether to enable or disable port sniff.
 * \param promiscuous Whether to sniff all traffic arriving at the port
 *                    (promiscuous) or only traffic arriving at the host (not
 *                    promiscuous)
 * \param rss         The RSS context to use for sniffed traffic.  If this is
 *                    -1 then the resource is treated as a single VI.  If not
 *                    then the value is used as an RSS context handle, accross
 *                    which the sniffed traffic should be spread.
 */
extern int efrm_port_sniff(struct efrm_resource *rs, int enable,
                           int promiscuous, int rss_context);

/*!
 * Set tx port sniff.
 *
 * \param rs          Resource to receive sniffed traffic.
 * \param enable      Whether to enable or disable tx port sniff.
 * \param rss         The RSS context to use for sniffed traffic.  If this is
 *                    -1 then the resource is treated as a single VI.  If not
 *                    then the value is used as an RSS context handle, accross
 *                    which the sniffed traffic should be spread.
 */
extern int efrm_tx_port_sniff(struct efrm_resource *rs, int enable,
                              int rss_context);

#endif /* __CI_EFRM_PORT_SNIFF_H__ */
