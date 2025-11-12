/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

/* Shared Readable User Buffers, Client API
 *
 * Multiple clients may connect to a server to receive an ordered stream
 * of shared buffers. They may read incoming data from these buffers, and
 * release them for reuse once all data has been extracted.
 */

#ifndef __CI_CIUL_SHRUB_CLIENT_H__
#define __CI_CIUL_SHRUB_CLIENT_H__

#include <etherfabric/internal/shrub_shared.h>

/* Structure for managing a client instance */
struct ef_shrub_client
{
  uintptr_t socket;
  uintptr_t files[EF_SHRUB_FD_COUNT];
  uint64_t  mappings[EF_SHRUB_FD_COUNT + 1];
};

/* Request shared rxq token from shrub server
 *
 * server_addr: The address for the server, typically a filesystem path
 * response:    Response from the server containing shared rxq token
 *
 * Returns zero on success, or negative error codes including
 *  -ECONNREFUSED server is not listening
 *  -EPERM        user does not have permission to connect to the address
 *
 * This function will block while communicating with the server.
 */
int ef_shrub_client_request_token(const char *server_addr,
                                  struct ef_shrub_token_response *response);

/* Open a connection to a server.
 *
 * client:      pointer to the structure for managing the connection
 * buffers:     location to map the buffer memory, NULL for arbitrary location
 * server_addr: the address for the server, typically a filesystem path
 * qid:         hardware QID to attach to
 * use_irqs:    whether we expect to use interrupts
 *
 * Returns zero on success, or negative error codes including
 *  -ENOMEM       memory allocation failed
 *  -ECONNREFUSED server is not listening
 *  -EPERM        user does not have permission to connect to the address
 *
 * This function will block while communicating with the server.
 */
int ef_shrub_client_open(struct ef_shrub_client* client,
                         void* buffers,
                         const char* server_addr,
                         int qid,
                         bool use_irqs);

/* Close the client connection.
 * This will implicitly release all buffers acquired from the connection.
 */
void ef_shrub_client_close(struct ef_shrub_client* client);

/* Acquire the next buffer to be read.
 *
 * client:    connection providing the buffer
 * buffer_id: provides an identifier to be used when releasing the buffer
 * sentinel:  sentinel value for the buffer
 * sbseq:     superbuf sequence number associated with the buffer
 *
 * Returns zero on success, or negative error codes including
 *  -EAGAIN no buffers available
 */
int ef_shrub_client_acquire_buffer(struct ef_shrub_client* client,
                                   uint32_t* buffer_id,
                                   bool* sentinel,
                                   uint32_t* sbseq);

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

/* Returns whether it is possible to acquire a new buffer. */
bool ef_shrub_client_buffer_available(const struct ef_shrub_client* client);

/* Access the client's shared state */
static inline const struct ef_shrub_client_state*
ef_shrub_client_get_state(const struct ef_shrub_client* client)
{
  return (void*)(client->mappings[EF_SHRUB_FD_COUNT]);
}

#endif
