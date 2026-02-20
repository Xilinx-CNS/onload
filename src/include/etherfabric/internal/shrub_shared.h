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

/* Identifier for a buffer, an index into the shared buffer memory.
 * Format (64-bit):
 *   Bits [0:30]   - buffer index (31 bits, supports up to 2^31 buffers)
 *   Bit  [31]     - sentinel (1 bit)
 *   Bits [32:63]  - sbseq (32 bits, superbuf sequence number)
 */
typedef uint64_t ef_shrub_buffer_id;

/* The index of a buffer id */
static inline uint32_t ef_shrub_buffer_index(ef_shrub_buffer_id id)
{
  return id & 0x7fffffff;
}

/* The sentinel value of a buffer id */
static inline uint32_t ef_shrub_buffer_sentinel(ef_shrub_buffer_id id)
{
  return (id >> 31) & 1;
}

/* The sbseq value of a buffer id */
static inline uint32_t ef_shrub_buffer_sbseq(ef_shrub_buffer_id id)
{
  return id >> 32;
}

/* Protocol version, to check compatibility between client and server */
#define EF_SHRUB_VERSION 6
#define SHRUB_ERR_INCOMPATIBLE_VERSION -1000

/* An identifier that does not represent a buffer, used to indicate empty
 * slots in the FIFOs.
 */
#define EF_SHRUB_INVALID_BUFFER ((ef_shrub_buffer_id)(-1))

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
#define EF_SHRUB_CONTROLLER_PREFIX "controller-"
#define EF_SHRUB_SHRUB_PREFIX "shrub-"
#define EF_SHRUB_NEGOTIATION_SOCKET "shrub_config"
#define EF_SHRUB_CONFIG_SOCKET_LOCK EF_SHRUB_NEGOTIATION_SOCKET "_lock"
#define EF_SHRUB_CONTROLLER_PATH_FORMAT "%s" EF_SHRUB_CONTROLLER_PREFIX "%d/"
#define EF_SHRUB_SHRUB_FORMAT EF_SHRUB_SHRUB_PREFIX "%d"
#define EF_SHRUB_MAX_CONTROLLER 9999
#define EF_SHRUB_MAX_SHRUB 9999
#define EF_SHRUB_NO_SHRUB -1
#define EF_SHRUB_MAX_DIGITS 4

/* Lengths of path snippets without string terminator.
 * Only used in other length calculations.
 */
#define _SHRUB_SOCK_DIR_PATH_LEN (sizeof(EF_SHRUB_SOCK_DIR_PATH)-1)
#define _SHRUB_DUMP_LOG_DIR_LEN (sizeof(EF_SHRUB_DUMP_LOG_DIR)-1)
#define _SHRUB_CONTROLLER_PREFIX_LEN (sizeof(EF_SHRUB_CONTROLLER_PREFIX)-1)
#define _SHRUB_SHRUB_PREFIX_LEN (sizeof(EF_SHRUB_SHRUB_PREFIX)-1)
#define _SHRUB_NEGOTIATION_SOCKET_LEN (sizeof(EF_SHRUB_NEGOTIATION_SOCKET)-1)
#define _SHRUB_CONFIG_SOCKET_LOCK_LEN (sizeof(EF_SHRUB_CONFIG_SOCKET_LOCK)-1)
#define _SHRUB_PATH_SEP_LEN (sizeof("/")-1)
#define _SHRUB_CONTROLLER_LEN                                                  \
  (_SHRUB_CONTROLLER_PREFIX_LEN + EF_SHRUB_MAX_DIGITS)
#define _SHRUB_SHRUB_LEN                                                       \
  (_SHRUB_SHRUB_PREFIX_LEN + EF_SHRUB_MAX_DIGITS)
#define _SHRUB_SOCKET_DIR_LEN                                                  \
  (_SHRUB_SOCK_DIR_PATH_LEN + _SHRUB_CONTROLLER_LEN + _SHRUB_PATH_SEP_LEN)

/* Lengths of paths including string terminator */
#define EF_SHRUB_SOCKET_DIR_LEN (_SHRUB_SOCKET_DIR_LEN + 1)
#define EF_SHRUB_NEGOTIATION_SOCKET_LEN                                        \
  (_SHRUB_SOCKET_DIR_LEN + _SHRUB_NEGOTIATION_SOCKET_LEN + 1)
#define EF_SHRUB_SERVER_SOCKET_LEN                                             \
  (_SHRUB_SOCKET_DIR_LEN + _SHRUB_SHRUB_LEN + 1)
#define EF_SHRUB_LOG_LEN                                                       \
  (_SHRUB_DUMP_LOG_DIR_LEN + _SHRUB_CONTROLLER_LEN +                           \
   EF_SHRUB_DUMP_LOG_SIZE + _SHRUB_PATH_SEP_LEN + 1)
#define EF_SHRUB_CONFIG_SOCKET_LOCK_LEN                                        \
  (_SHRUB_SOCKET_DIR_LEN + _SHRUB_CONFIG_SOCKET_LOCK_LEN + 1)

enum ef_shrub_controller_command {
  EF_SHRUB_CONTROLLER_DESTROY,
  EF_SHRUB_CONTROLLER_CREATE_HWPORT,
  EF_SHRUB_CONTROLLER_CREATE_IFINDEX,
  EF_SHRUB_CONTROLLER_DUMP_TO_FILE,
  EF_SHRUB_CONTROLLER_SHRUB_DUMP,
};

#define EF_SHRUB_DEFAULT_BUFFER_COUNT 4
#define EF_SHRUB_MAX_BUFFER_COUNT 100000

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
  /* Whether we expect to use interrupts */
  uint64_t use_interrupts;
};

/* This structure is sent to the shrub server to make various requests. */
struct ef_shrub_request {
  /* Client's protocol version, to check compatibility */
  uint64_t server_version;
  /* Tag to specify request type, ef_shrub_request_type */
  uint64_t type;
  /* Data required to be sent corresponding to a request type. */
  union {
    /* Shared rxq token request tagged by EF_SHRUB_REQUEST_TOKEN */
    struct ef_shrub_token_request rxq_token;
    /* Queue request tagged by EF_SHRUB_REQUEST_QUEUE. */
    struct ef_shrub_queue_request queue;
  };
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
   * Offset is provided, length is sizeof(ef_shrub_buffer_id) * size */
  uint64_t server_fifo_offset;
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
struct ef_shrub_client_state {
  uint64_t server_fifo_index;
  uint64_t client_fifo_index;
  struct ef_shrub_shared_metrics metrics;
};

struct ef_shrub_controller_request {
  uint64_t controller_version;
  uint64_t command;
  union {
    struct {
      uint64_t buffer_count;
      uint64_t ifindex;
    } create_ifindex; /* EF_SHRUB_CONTROLLER_CREATE_IFINDEX */
    struct {
      uint64_t buffer_count;
      uint64_t hw_port;
    } create_hwport; /* EF_SHRUB_CONTROLLER_CREATE_HWPORT */
    struct {
      uint64_t shrub_token_id;
    } destroy; /* EF_SHRUB_CONTROLLER_DESTROY */
    struct {
      char file_name[EF_SHRUB_DUMP_LOG_SIZE];
    } dump; /* EF_SHRUB_CONTROLLER_DUMP_TO_FILE */
    struct {
      size_t logbuf_size;
    } shrub_dump; /* EF_SHRUB_CONTROLLER_SHRUB_DUMP */
  };
};

#define SHRUB_DUMP_SECTION_SEPARATOR \
  "---------------------------------------------------------"

void shrub_log_to_fd(int fd, char* buf, size_t buflen, const char* fmt, ...);

#endif
