/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#ifndef LINUX_RESOURCE_SFCAFFINITY_H
#define LINUX_RESOURCE_SFCAFFINITY_H


struct net_device;

/* Access core-to-queue mapping.  Returns -1 if cpu is out of range, or if the
 * ifindex is not known to sfc_affinity, or if the core-to-queue mapping has
 * not been initialised.
 */
extern int sfc_affinity_cpu_to_channel_dev(const struct net_device* dev,
                                           int cpu);


#endif /* LINUX_RESOURCE_SFCAFFINITY_H */
