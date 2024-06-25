/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

/* Shared Readable User Buffers, shared data structures
 *
 * Once a client connection has been established, it is managed via three
 * shared data structures:
 *
 * The buffers themselves
 * A "server" FIFO, to which the server posts buffers for consumption by clients
 * A "client" FIFO, to which the client posts buffers to release after use
 *
 * The FIFOs are implemented as circularly-addressed arrays sufficiently large
 * to contain all available buffers with at least one empty slot, so that
 * readers can detect newly posted buffers with no further shared state.
 */

#ifndef __CI_CIUL_SHRUB_SHARED_H__
#define __CI_CIUL_SHRUB_SHARED_H__

#include <stdint.h>

/* Identifier for a buffer, an index into the shared buffer memory.
 * The MSB for the id corresponds to the sentinel for the buffer. */
typedef uint32_t ef_shrub_buffer_id;

/* Protocol version, to check compatibility between client and server */
#define EF_SHRUB_VERSION 1

/* An identifier that does not represent a buffer, used to indicate empty
 * slots in the FIFOs.
 */
#define EF_SHRUB_INVALID_BUFFER ((ef_shrub_buffer_id)(-1))
#define EF_SHRUB_BUFFER_ID_LBN 0
#define EF_SHRUB_BUFFER_ID_WIDTH 31
#define EF_SHRUB_SENTINEL_LBN 31
#define EF_SHRUB_SENTINEL_WIDTH 1

/* Memory is shared via an array of file descriptors passed as ancilliary
 * data alongside the metrics. These are the indexes and size for the array.
 */
#define EF_SHRUB_FD_BUFFERS     0
#define EF_SHRUB_FD_SERVER_FIFO 1
#define EF_SHRUB_FD_CLIENT_FIFO 2
#define EF_SHRUB_FD_COUNT       3

/* This structure is sent to each client immediately after accepting a
 * connection, providing the information needed to access shared data.
 */ 
struct ef_shrub_shared_metrics {
  /* Server's protocol version, to check compatibility */
  uint64_t server_version;

  /* Mapping information for shared buffer memory.
   * Read only for clients.
   * Offset is zero, length is buffer_bytes * buffer_count */
  uint64_t buffer_bytes;
  uint64_t buffer_count;

  /* Mapping information for the FIFO for the server to post buffers to clients.
   * Read only for clients.
   * Offset is zero, length is sizeof(ef_shrub_buffer_id) * size */
  uint64_t server_fifo_size;

  /* Mapping information for the FIFO for clients to release buffers to server.
   * Write only for clients.
   * Offset is provided, length is sizeof(ef_shrub_buffer_id) * size */
  uint64_t client_fifo_offset;
  uint64_t client_fifo_size;
};

#endif

