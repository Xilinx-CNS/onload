/****************************************************************************
* Driverlink client for testing filter handling
* Copyright 2013 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
*/

/* This will never be upstreamable, put it here rather than in the Makefile */
#define EFX_NOT_UPSTREAM    1

#ifndef __KERNEL__
/* Hackery so that filter.h will work */
#define EFX_WANT_KERNEL_TYPES
#include "efx_linux_types.h"
#define __aligned(x)                    __attribute__((aligned(x)))
#include <arpa/inet.h>
#include <errno.h>

#define EFX_NEED_ETHER_ADDR_COPY	1
#endif /* !__KERNEL__ */

#include <linux/ioctl.h>
#include "filter.h"

struct sfc_aftm_redirect {
	int filter_id;
	int rxq_id;
};

struct sfc_aftm_vport_add {
	u16 vlan;
	bool vlan_restrict;
};

#define SFC_AFTM_IOC_MAGIC	0xef

/* Insert a filter, with replace_equal=false */
#define SFC_AFTM_IOCSINSERT	_IOW(SFC_AFTM_IOC_MAGIC, 0, \
				     struct efx_filter_spec)
/* Insert a filter, with replace_equal=true */
#define SFC_AFTM_IOCSREINSERT	_IOW(SFC_AFTM_IOC_MAGIC, 1, \
				     struct efx_filter_spec)
/* Remove filter with the given filter_id */
#define SFC_AFTM_IOCSREMOVE	_IO(SFC_AFTM_IOC_MAGIC, 2)
/* Redirect a filter, by filter_id, to a given rxq */
#define SFC_AFTM_IOCSREDIRECT	_IOW(SFC_AFTM_IOC_MAGIC, 3, \
				     struct sfc_aftm_redirect)
/* Add (SFC_AFTM_BLOCK_ADD) or remove (SFC_AFTM_BLOCK_RM) a kernel block for
 * unicast filters (IOCSUCBLK), multicast filters (IOCSMCBLK), or both
 * (IOCSBLOCK)
 * Other values fail EINVAL
 */
#define SFC_AFTM_IOCSBLOCK	_IO(SFC_AFTM_IOC_MAGIC, 4)
#define SFC_AFTM_IOCSUCBLK	_IO(SFC_AFTM_IOC_MAGIC, 5)
#define SFC_AFTM_IOCSMCBLK	_IO(SFC_AFTM_IOC_MAGIC, 6)
#define SFC_AFTM_BLOCK_ADD	1
#define SFC_AFTM_BLOCK_RM	0
/* Add a vport */
#define SFC_AFTM_IOCSVPORT_ADD	_IOW(SFC_AFTM_IOC_MAGIC, 7, \
				     struct sfc_aftm_vport_add)
/* Remove a vport */
#define SFC_AFTM_IOCSVPORT_DEL	_IO(SFC_AFTM_IOC_MAGIC, 8)
