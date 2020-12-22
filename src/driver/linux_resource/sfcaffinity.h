/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2008-2020 Xilinx, Inc. */

#ifndef LINUX_RESOURCE_SFCAFFINITY_H
#define LINUX_RESOURCE_SFCAFFINITY_H


struct linux_efhw_nic;


int efrm_affinity_interface_probe(struct linux_efhw_nic* nic);
extern void efrm_affinity_interface_remove(struct linux_efhw_nic* nic);

extern int efrm_affinity_show_cpu2rxq(struct linux_efhw_nic* nic, char* buf);
extern ssize_t efrm_affinity_store_cpu2rxq(struct linux_efhw_nic* nic,
					   const char* buf,
					   size_t count);

/* Access core-to-queue mapping.  Returns -1 if cpu is out of range, or if the
 * ifindex is not known to sfc_affinity, or if the core-to-queue mapping has
 * not been initialised.
 */
extern int efrm_affinity_cpu_to_channel_dev(const struct linux_efhw_nic* nic, int cpu);


#endif /* LINUX_RESOURCE_SFCAFFINITY_H */
