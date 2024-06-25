/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

/* Shared Readable User Buffers, Client API
 *
 * Multiple clients may connect to a server to receive an ordered stream
 * of shared buffers. They may read incoming data from these buffers, and
 * release them for reuse once all data has been extracted.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

/* Opaque structure used to manage a client connection to a server. */
struct ef_shrub_client;

/* Create a client and open a connection to a server.
 *
 * client:      provides a pointer to the structure for managing the connection
 * buffer_addrs: TODO fill out.
 * server_addr: the address for the server, typically a filesystem path
 *
 * Returns zero on success, or negative error codes including
 *  -ENOMEM       memory allocation failed
 *  -ECONNREFUSED server is not listening
 *  -EPERM        user does not have permission to connect to the address
 *
 * This function will block while communicating with the server.
 */
int ef_shrub_client_open(struct ef_shrub_client** client,
                         void* buffer_addrs,
                         const char* server_addr);

/* Close the client connection and destroy the opaque structure.
 * This will implicitly release all buffers acquired from the connection.
 *
 * client: connection to close; the pointer will be invalidated
 */
void ef_shrub_client_close(struct ef_shrub_client* client);

/* Acquire the next buffer to be read.
 *
 * client:    connection providing the buffer
 * buffer_id: provides an identifier to be used when releasing the buffer
 *
 * Returns zero on success, or negative error codes including
 *  -EAGAIN no buffers available
 */
int ef_shrub_client_acquire_buffer(struct ef_shrub_client* client,
                                   uint32_t* buffer_id,
                                   bool* sentinel);

/* Indicate that the buffer is no longer needed.
 *
 * client: connection which provided the buffer
 * buffer_id: identifier provided when acquiring the buffer
 *
 * The buffer memory should not be accessed after calling this function.
 * Failure to release buffers (either explicitly with this function, or
 * implicitly by closing the connection) could result in the server
 * running out of buffers. */
void ef_shrub_client_release_buffer(struct ef_shrub_client* client,
                                    uint32_t buffer_id);

/* Returns the size in bytes of each buffer provided by the connection. */
size_t ef_shrub_client_buffer_bytes(const struct ef_shrub_client* client);

/* Returns the total number of buffers available for the connection.
 *
 * Identifiers provided by ef_shrub_client_acquire_buffer are in the range
 * [0, buffer_count) and so can be used as indexes into an array of this
 * size, if such a thing is desirable.
 */
size_t ef_shrub_client_buffer_count(const struct ef_shrub_client* client);

/* Returns whether it is possible to acquire a new buffer. */
bool ef_shrub_client_buffer_available(const struct ef_shrub_client* client);
