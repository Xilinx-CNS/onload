/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2008-2020 Xilinx, Inc. */

#ifndef LINUX_RESOURCE_SFCAFFINITY_H
#define LINUX_RESOURCE_SFCAFFINITY_H


struct net_device;
struct linux_efhw_nic;

extern int efrm_affinity_install_proc_entries(void);
extern void efrm_affinity_remove_proc_entries(void);

extern void efrm_affinity_interface_up(struct linux_efhw_nic* nic);
extern void efrm_affinity_interface_down(struct linux_efhw_nic* nic);

/* Access core-to-queue mapping.  Returns -1 if cpu is out of range, or if the
 * ifindex is not known to sfc_affinity, or if the core-to-queue mapping has
 * not been initialised.
 */
extern int efrm_affinity_cpu_to_channel_dev(const struct net_device* dev,
                                            int cpu);


#endif /* LINUX_RESOURCE_SFCAFFINITY_H */
