/* SPDX-License-Identifier: Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __ONLOAD_CPLANE_AGENT_H__
#define __ONLOAD_CPLANE_AGENT_H__

#include <inttypes.h>

/* The control plane server accepts connections from external agents on
 * a unix domain socket.
 *
 * When an agent connects it sends a client_hello message. This
 * identifies the type of the agent and the version of the message
 * protocol that it expects to use.
 *
 * If the server is happy with the agent type and protocol version, it
 * responds with a server_hello message.
 *
 * This completes the handshake. From this point the control plane server
 * sends no further messages. The agent may send status messages of
 * various types depending on the agent type.
 *
 * If at any point the agent sends an invalid message, the control plane
 * server logs an error and closes the connection.
 */

/* We need to allocate this much space for every connected agent, so it
 * is desirable to keep the max message length short. 256 is much larger
 * than any of the currently defined messages, so gives us plenty of
 * room for growth.
 */
#define CP_AGENT_MAX_MSG_LEN 256

#define CP_AGENT_MSG_TYPE_CLIENT_HELLO 1
#define CP_AGENT_MSG_TYPE_SERVER_HELLO 2

/* OCKA protocol versions:
 *  1:  Initial version.
 *  2:  Allows backends to belong to multiple services.
 */
#define CP_AGENT_OCKA_MIN_PROTO_VER 1
#define CP_AGENT_OCKA_MAX_PROTO_VER 2

#define CP_AGENT_MSG_TYPE_OCKA_SERVICE_ADD 3
#define CP_AGENT_MSG_TYPE_OCKA_SERVICE_DEL 4
#define CP_AGENT_MSG_TYPE_OCKA_ENDPOINT_ADD 5
#define CP_AGENT_MSG_TYPE_OCKA_ENDPOINT_DEL 6

#define CP_AGENT_KDP_MIN_PROTO_VER 1
#define CP_AGENT_KDP_MAX_PROTO_VER 1


/* These are part of the protocol, so we give them explicit values. */
enum cp_agent_type {
  CP_AGENT_TYPE_UNBOUND             = 0,
  CP_AGENT_TYPE_OCKA                = 1,
  CP_AGENT_TYPE_K8S_DEVICE_PLUGIN   = 2,
  CP_AGENT_TYPE_COUNT,
};


struct cp_agent_msg_hdr {
  uint32_t len; /* Total message length including this field */
  uint32_t type; /* One of the MSG_TYPE values above */
} __attribute__((packed));


struct cp_agent_client_hello {
  struct cp_agent_msg_hdr hdr;
  uint32_t proto_ver;
  uint32_t agent_type; /* One of the AGENT_TYPE values above */
} __attribute__((packed));


struct cp_agent_server_hello {
  struct cp_agent_msg_hdr hdr;
  uint32_t proto_ver;
} __attribute__((packed));


struct cp_agent_ocka_service_update {
  struct cp_agent_msg_hdr hdr;
  uint32_t service_ip_be;
  uint16_t service_port_be;
} __attribute__((packed));


struct cp_agent_ocka_endpoint_update {
  struct cp_agent_msg_hdr hdr;
  uint32_t service_ip_be;
  uint16_t service_port_be;
  uint32_t endpoint_ip_be;
  uint16_t endpoint_port_be;
} __attribute__((packed));


#endif /* __ONLOAD_CPLANE_AGENT_H__ */
