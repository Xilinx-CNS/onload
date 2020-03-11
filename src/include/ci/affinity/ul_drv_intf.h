/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          sfc_affinity: flow steering
 *
 * This file defines the interface exported by the sfc_affinity driver to
 * user-level processes.
 *
 * Copyright 2009-2011: Solarflare Communications, Inc.,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <onload-dev@solarflare.com>
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

#ifndef __CI_AFFINITY_UL_DRV_INTF_H__
#define __CI_AFFINITY_UL_DRV_INTF_H__


/* Further error info returned when SFC_AFF_SET and SFC_AFF_CLEAR fail.  If
 * value is [sfc_aff_no_error] then [errno] may point to the cause.
 */
enum sfc_aff_err {
	sfc_aff_no_error,
	sfc_aff_bad_protocol,
	sfc_aff_bad_saddr,
	sfc_aff_bad_daddr,
	sfc_aff_bad_rxq,
	sfc_aff_bad_cpu,
	sfc_aff_intf_not_supported,
	sfc_aff_intf_not_configured,
	sfc_aff_filter_exists,
	sfc_aff_filter_set_fail,
	sfc_aff_not_found,
	sfc_aff_table_full,
	sfc_aff_cannot_replace,
};


static inline const char* sfc_aff_err_msg(enum sfc_aff_err err)
{
	switch (err) {
	case sfc_aff_no_error:
		return "No error";
	case sfc_aff_bad_protocol:
		return "Bad protocol";
	case sfc_aff_bad_saddr:
		return "Bad remote address and/or port";
	case sfc_aff_bad_daddr:
		return "Bad local address and/or port";
	case sfc_aff_bad_rxq:
		return "Bad receive queue (RXQ)";
	case sfc_aff_bad_cpu:
		return "Bad CPU";
	case sfc_aff_intf_not_supported:
		return "Interface not supported";
	case sfc_aff_intf_not_configured:
		return "Interface not configured";
	case sfc_aff_filter_exists:
		return "Filter already exists";
	case sfc_aff_filter_set_fail:
		return "Failed to set filter";
	case sfc_aff_not_found:
		return "Filter not found";
	case sfc_aff_table_full:
		return "Filter table is full";
	case sfc_aff_cannot_replace:
		return "Cannot replace existing filter";
	default:
		return "<Unknown error code>";
	}
}


struct sfc_aff_set {
	int cpu;
	int rxq;
	int ifindex;
	int protocol;
	unsigned daddr, dport;
	unsigned saddr, sport;
	enum sfc_aff_err err_out;
};


struct sfc_aff_clear {
	int ifindex;
	int protocol;
	unsigned daddr, dport;
	unsigned saddr, sport;
	enum sfc_aff_err err_out;
};


#define SFC_AFF_SET      _IOWR('a', 0, struct sfc_aff_set)
#define SFC_AFF_CLEAR    _IOWR('a', 1, struct sfc_aff_clear)


#endif  /* __CI_AFFINITY_UL_DRV_INTF_H__ */
