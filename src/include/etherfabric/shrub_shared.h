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

#include <cplane/mib.h>

/* Identifier for a buffer, an index into the shared buffer memory.
 * The MSB for the id corresponds to the sentinel for the buffer. */
typedef uint32_t ef_shrub_buffer_id;

/* Protocol version, to check compatibility between client and server */
#define EF_SHRUB_VERSION 3
#define SHRUB_ERR_INCOMPATIBLE_VERSION -1000

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

/* Shrub unix socket address information */
#define EF_SHRUB_DUMP_LOG_SIZE 40
#define EF_SHRUB_SOCK_DIR_PATH "/run/onload/"
#define EF_SHRUB_DUMP_LOG_DIR "/var/log/"
#define EF_SHRUB_CONTROLLER_PATH_FORMAT "%scontroller-%d/"
#define EF_SHRUB_SHRUB_FORMAT "shrub-%d"
#define EF_SHRUB_MAX_CONTROLLER 9999
#define EF_SHRUB_MAX_SHRUB 9999
#define EF_SHRUB_MAX_DIGITS 4
#define EF_SHRUB_CONTROLLER_LEN (sizeof("controller-") + EF_SHRUB_MAX_DIGITS)
#define EF_SHRUB_SHRUB_LEN (sizeof("shrub-") + EF_SHRUB_MAX_DIGITS)
#define EF_SHRUB_NEGOTIATION_SOCKET "shrub_config"
#define EF_SHRUB_SOCKET_DIR_LEN                                                \
  (sizeof(EF_SHRUB_SOCK_DIR_PATH) + EF_SHRUB_CONTROLLER_LEN + sizeof("/"))
#define EF_SHRUB_NEGOTIATION_SOCKET_LEN                                        \
  (EF_SHRUB_SOCKET_DIR_LEN + sizeof(EF_SHRUB_NEGOTIATION_SOCKET))
#define EF_SHRUB_SERVER_SOCKET_LEN                                             \
  (EF_SHRUB_SOCKET_DIR_LEN + EF_SHRUB_SHRUB_LEN)
#define EF_SHRUB_LOG_LEN                                                       \
  (sizeof(EF_SHRUB_DUMP_LOG_DIR) + EF_SHRUB_CONTROLLER_LEN +                   \
   EF_SHRUB_DUMP_LOG_SIZE + sizeof("/"))

enum shrub_controller_command {
  EF_SHRUB_CONTROLLER_DESTROY,
  EF_SHRUB_CONTROLLER_CREATE_HWPORT,
  EF_SHRUB_CONTROLLER_CREATE_IFINDEX,
  EF_SHRUB_CONTROLLER_DUMP,
};

#define EF_SHRUB_DEFAULT_BUFFER_COUNT 4

/* This enum specifies the type of request being made to the shrub server. */
enum ef_shrub_request_type {
  EF_SHRUB_REQUEST_TOKEN,
  EF_SHRUB_REQUEST_QUEUE,
};

/* This struct is sent with EF_SHRUB_REQUEST_TOKEN requests. */
struct ef_shrub_token_request {
};

/* This struct contains the server response to EF_SHRUB_REQUEST_TOKEN. */
struct ef_shrub_token_response {
  /* Exclusive rxq token of the shrub server pd. */
  uint64_t shared_rxq_token;
};

/* This structure is sent to the shrub server to request a queue. After which,
 * the server will send an ef_shrub_shared_metrics.
 */
struct ef_shrub_queue_request {
  /* Queue ID that the client intends to connect to */
  uint64_t qid;
};

/* This struct is sent to the shrub server to make various requests. */
struct ef_shrub_request {
  /* Client's protocol version, to check compatibility */
  uint64_t server_version;
  /* Tag to specify request type */
  enum ef_shrub_request_type type;
  /* Data required to be sent corresponding to a request type. */
  union {
    /* Shared rxq token request tagged by EF_SHRUB_REQUEST_TOKEN */
    struct ef_shrub_token_request rxq_token;
    /* Queue request tagged by EF_SHRUB_REQUEST_QUEUE. */
    struct ef_shrub_queue_request queue;
  } requests;
};

/* This structure is sent to each client immediately after accepting a
 * connection and receiving an ef_shrub_queue_request, providing the
 * information needed to access shared data.
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

  /* Mapping information for the FIFO for clients to release buffers to server,
   * followed by the client's FIFO access state.
   * Readable and writable for clients.
   * Offset is provided, length is
   *   sizeof(ef_shrub_buffer_id) * size + sizeof(struct ef_shrub_client_state) */
  uint64_t client_fifo_offset;
  uint64_t client_fifo_size;
};

/* Structure containing connection state sharable between instances */
struct ef_shrub_client_state
{
  uint64_t server_fifo_index;
  uint64_t client_fifo_index;
  struct ef_shrub_shared_metrics metrics;
};

typedef struct {
  uint8_t controller_version;
  uint8_t command;
  union {
    struct {
      uint32_t buffer_count;
      int ifindex;
    } create_ifindex; /* EF_SHRUB_CONTROLLER_CREATE_IFINDEX */
    struct {
      uint32_t buffer_count;
      cicp_hwport_mask_t hw_port;
    } create_hwport; /* EF_SHRUB_CONTROLLER_CREATE_HWPORT */
    struct {
      int shrub_token_id;
    } destroy; /* EF_SHRUB_CONTROLLER_DESTROY */
    struct {
      char file_name[EF_SHRUB_DUMP_LOG_SIZE];
    } dump; /* EF_SHRUB_CONTROLLER_DUMP */
  };
} shrub_controller_request_t;
#endif

