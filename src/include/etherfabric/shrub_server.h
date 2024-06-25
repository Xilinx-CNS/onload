/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

/* Shared Readable User Buffers, Server API
 *
 * The server manages a poll of buffers, accepting connections from multiple
 * clients and providing the buffers in an ordered stream. It tracks buffer
 * usage by the clients, freeing them for reuse once all clients have
 * released them.
 */

#ifndef __CI_CIUL_SHRUB_SERVER_H__
#define __CI_CIUL_SHRUB_SERVER_H__

#include <stddef.h>

/* Opaque structure used to manage a server */
struct ef_shrub_server;

/* Create a server and make it available to accept incoming client connections.
 *
 * vi:           initialized pointer to a EtherFabric Virtual Interface
 * server:       provides a pointer to the structure for managing the server
 * server_addr:  the address for the server, typically a filesystem path;
 *               clients will use this to connect
 * buffer_bytes: the size of each buffer that the server will provide
 * buffer_count: the total number of buffers to allocate
 * qid:          Queue to attach onto.
 * 
 * Returns zero on success, or a negative error code including
 *  -ENOMEM memory allocation failed
 *  -EPERM  user does not have permission to bind to the address
 */
int ef_shrub_server_open(struct ef_vi* vi,
                         struct ef_shrub_server** server,
                         const char* server_addr,
                         size_t buffer_bytes,
                         size_t buffer_count,
                         int qid);

/* Shut down the server and destroy the opaque structure. This will close
 * all client connections, although shared buffers and other resources may
 * remain allocated until the clients release them.
 *
 * server: server to close; the pointer will be invalidated
 */
void ef_shrub_server_close(struct ef_shrub_server* server);

/* Perform server operations:
 *  post new buffers as required
 *  harvest buffers that clients have released
 *  check for incoming or closing client connections
 *
 * This should be called frequently.
 */
void ef_shrub_server_poll(struct ef_vi* vi, struct ef_shrub_server* server, int qid);

#endif

