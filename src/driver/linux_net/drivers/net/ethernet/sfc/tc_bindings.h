/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2022 Xilinx Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_TC_BINDINGS_H
#define EFX_TC_BINDINGS_H
#include "net_driver.h"

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
#include <net/sch_generic.h>
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_FLOW_BLOCK_OFFLOAD)
#include <net/pkt_cls.h> /* for struct tc_block_offload */
#endif

struct efx_rep;

int efx_tc_setup_block(struct net_device *net_dev, struct efx_nic *efx,
		       struct flow_block_offload *tcb, struct efx_rep *efv);
int efx_setup_tc(struct net_device *net_dev, enum tc_setup_type type,
		 void *type_data);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_BLOCK_OFFLOAD)
void efx_tc_block_unbind(void *cb_priv);
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_INDR_QDISC)
int efx_tc_indr_setup_cb(struct net_device *net_dev, struct Qdisc *sch,
#else
int efx_tc_indr_setup_cb(struct net_device *net_dev,
#endif
			 void *cb_priv, enum tc_setup_type type,
			 void *type_data, void *data,
			 void (*cleanup)(struct flow_block_cb *block_cb));
#elif defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER)
int efx_tc_indr_setup_cb(struct net_device *net_dev, void *cb_priv,
			 enum tc_setup_type type, void *type_data);
#endif

int efx_tc_netdev_event(struct efx_nic *efx, unsigned long event,
			struct net_device *net_dev);
#else /* EFX_TC_OFFLOAD */
static inline int efx_tc_netdev_event(struct efx_nic *efx, unsigned long event,
				      struct net_device *net_dev)
{
	return NOTIFY_OK;
}
#endif /* EFX_TC_OFFLOAD */

#endif /* EFX_TC_BINDINGS_H */
