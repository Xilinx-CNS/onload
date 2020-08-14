/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */

#ifndef __ONLOAD_NETIF_DTOR_H__
#define __ONLOAD_NETIF_DTOR_H__

#include <ci/internal/ip.h>

#if (CI_CFG_UL_INTERRUPT_HELPER && ! defined(__KERNEL__)) || ( ! CI_CFG_UL_INTERRUPT_HELPER && defined(__KERNEL__))

#define OO_DO_STACK_DTOR 1


#if CI_CFG_UL_INTERRUPT_HELPER
/* n_ep_orphaned is protected by the shared stack lock */
#define n_ep_orphaned(ni) (ni)->state->n_ep_orphaned
#else
/* n_ep_orphaned must be changed atomically */
#define n_ep_orphaned(ni) (ni)->n_ep_orphaned
#endif

/* Release all the deferred packets */
void oo_deferred_free(ci_netif *ni);

/* Get all RX and TX complete events and check for packet leaks. */
void oo_netif_dtor_pkts(ci_netif* ni);

ci_uint32 oo_netif_apps_gone(ci_netif* netif);

#else
#define OO_DO_STACK_DTOR 0
#endif

#if CI_CFG_UL_INTERRUPT_HELPER || defined(__KERNEL__)
#define OO_N_EP_ORPHANED_INIT ((ci_uint32)-1)
#endif

#endif /* __ONLOAD_NETIF_DTOR_H__ */
