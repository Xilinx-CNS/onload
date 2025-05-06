/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */
/* Driver-specific shrub interface. */
#ifndef __ONLOAD_SHRUB_SPAWNER_H__
#define __ONLOAD_SHRUB_SPAWNER_H__

#include <linux/mm.h>
#include <linux/poll.h>
#include <onload/fd_private.h>

extern int oo_shrub_spawn_server(ci_private_t *priv, void *arg);
extern int oo_shrub_set_sockets(ci_private_t * priv, void* arg);

#endif
