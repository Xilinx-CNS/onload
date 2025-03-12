/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#ifndef __CI_CIUL_SHRUB_ADAPTER_H__
#define __CI_CIUL_SHRUB_ADAPTER_H__

#include <cplane/mib.h>
#include <etherfabric/shrub_shared.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef int (*shrub_request_sender_t)(int, shrub_controller_request_t *);

/* Shared Readable User Buffers, Controller API*/
int shrub_adapter_send_request(int controller_id,
                               shrub_controller_request_t *request);

/* Programmatic API for dynamically adding an interface to a shrub controller.
 */
int shrub_adapter_send_ifindex(shrub_request_sender_t send_request_func,
                               int controller_id, int ifindex,
                               uint32_t buffers);
int shrub_adapter_send_hwport(shrub_request_sender_t send_request_func,
                              int controller_id, cicp_hwport_mask_t hw_port,
                              uint32_t buffers);
int shrub_adapter_send_ifname(shrub_request_sender_t send_request_func,
                              int controller_id, const char *ifname,
                              uint32_t buffers);

/* Dump the given state of the shrub controller */
int shrub_adapter_send_dump(shrub_request_sender_t send_request_func,
                            int controller_id, const char *filename);

/* Programmatic API for killing a shrub server. */
int shrub_adapter_stop_server(shrub_request_sender_t send_request_func,
                              int controller_id, int shrub_token);

#endif
