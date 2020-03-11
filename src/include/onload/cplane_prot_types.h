/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* Data types for cppl subsystem - driver only */
#ifndef __CPLANE_PROT_TYPES_H__
#define __CPLANE_PROT_TYPES_H__

/*! This file provides definitions are specific to given address resolution
 *  scenario.  For example two versions of this header may be used to deal
 *  with explicit ARP protocols and with "raw" socket ARP use.
 *
 *  In the (distant?) future ICMPv6 support may be added here.
 *
 *  The prefix cicppl is used for definitions in this header:
 *       ci - our main prefix
 *       cp - control plane
 *       pl - protocols
 */

/*----------------------------------------------------------------------------
 * O/S-specific Address Resolution MIB Data types
 *---------------------------------------------------------------------------*/


struct cicppl_instance {
  struct socket *bindtodev_raw_sock;
  struct socket *bindtodev_raw_sock_ip6;
  ci_ifid_t bindtodevice_ifindex;
  struct oo_cplane_handle *cp;
};


#endif /* __CPLANE_PROT_TYPES_H__ */
