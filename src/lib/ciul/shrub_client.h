/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

/* Shared Readable User Buffers, Client API
 *
 * Multiple clients may connect to a server to receive an ordered stream
 * of shared buffers. They may read incoming data from these buffers, and
 * release them for reuse once all data has been extracted.
 */

#include <etherfabric/shrub_shared.h>

/* Structure containing connection state sharable between instances */
struct ef_shrub_client_state
{
  int server_fifo_index;
  int client_fifo_index;
  struct ef_shrub_shared_metrics metrics;
};

/* Structure for managing a client instance */
struct ef_shrub_client
{
  int socket;
  void* buffers;
  ef_shrub_buffer_id* server_fifo;
  ef_shrub_buffer_id* client_fifo;
  struct ef_shrub_client_state* state;
};

/* Open a connection to a server.
 *
 * client:      pointer to the structure for managing the connection
 * state:       location to store connection state
 * buffers:     location to map the buffer memory, NULL for arbitrary location
 * server_addr: the address for the server, typically a filesystem path
 *
 * Returns zero on success, or negative error codes including
 *  -ENOMEM       memory allocation failed
 *  -ECONNREFUSED server is not listening
 *  -EPERM        user does not have permission to connect to the address
 *
 * This function will block while communicating with the server.
 */
int ef_shrub_client_open(struct ef_shrub_client* client,
                         struct ef_shrub_client_state* state,
                         void* buffers,
                         const char* server_addr,
                         int qid);

/* Close the client connection.
 * This will implicitly release all buffers acquired from the connection.
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

/* Returns whether it is possible to acquire a new buffer. */
bool ef_shrub_client_buffer_available(const struct ef_shrub_client* client);

