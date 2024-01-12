/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */

#ifndef LINUX_RESOURCE_DRIVERLINK_H
#define LINUX_RESOURCE_DRIVERLINK_H

struct efhw_nic;

extern void efrm_driverlink_desist(struct efhw_nic* nic,
				   unsigned failure_generation);
extern void efrm_driverlink_resume(struct efhw_nic* nic);
extern unsigned efrm_driverlink_generation(struct efhw_nic* nic);
extern int enable_legacy_driverlink;
extern int enable_driverlink;

#endif  /* LINUX_RESOURCE_DRIVERLINK_H */
