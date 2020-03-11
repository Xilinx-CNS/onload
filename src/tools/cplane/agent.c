/* SPDX-License-Identifier: Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>

#include <cplane/agent.h>
#include "private.h"

#define AGENT_SOCK_PATH "/var/run/onload_cp_server_agent"


enum process_result {
  OK,
  BAD_AGENT,
  BUF_EMPTY,
};


struct agent_state {
  int      fd;
  char     buf[CP_AGENT_MAX_MSG_LEN];
  unsigned buf_fill;
  enum cp_agent_type type;
  uint32_t proto_ver;
};


void cp_agent_sock_init(struct cp_session* s)
{
  struct sockaddr_un addr;
  int rc;

  /* NOTE: We use SOCK_STREAM here as we need to handle multiple
   * connected clients, each with their own state.
   */
  s->agent_sock = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if( s->agent_sock < 0 )
    init_failed("failed to create agent socket: %s", strerror(errno));

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof(addr.sun_path) - 1, AGENT_SOCK_PATH);

  rc = unlink(addr.sun_path);
  if( rc < 0 && errno != ENOENT )
    init_failed("Faield to delete existing agent socket %s: %s",
                addr.sun_path, strerror(errno));

  rc = bind(s->agent_sock, &addr, sizeof(addr));
  if( rc < 0 )
    init_failed("Failed to bind agent socket to %s: %s",
                addr.sun_path, strerror(errno));

  rc = listen(s->agent_sock, 5);
  if( rc < 0 )
    init_failed("Failed to listen on agent socket: %s", strerror(errno));
}


static inline enum process_result bad_agent(char* reason, ...)
{
  va_list args;
  va_start(args, reason);
  ci_vlog(reason, args);
  va_end(args);
  return BAD_AGENT;
}


static inline enum process_result
process_ocka_service_update(struct cp_session* s, struct agent_state* agent)
{
  struct cp_agent_ocka_service_update* msg = (void*) agent->buf;
  if( msg->hdr.len != sizeof(*msg) )
    return bad_agent("Bad service msg len %d from agent(%d)",
                     msg->hdr.len, agent->fd);

  ci_addr_sh_t addr = CI_ADDR_SH_FROM_IP4( msg->service_ip_be );
  ci_uint16 port = msg->service_port_be;

  /* TODO: Handle assert cases less abruptly after OCKA testing complete. */
  struct cp_mibs* mib = cp_get_active_mib(s);
  if( msg->hdr.type == CP_AGENT_MSG_TYPE_OCKA_SERVICE_ADD ) {
    ci_assert_gt(mib->dim->svc_ep_max, 0);

    cicp_mac_rowid_t id = cp_svc_add(s, addr, port);
    ci_assert( CICP_MAC_ROWID_IS_VALID(id) );
    /* Ignore failure to add services in production */
    (void) id;
  }
  else if( msg->hdr.type == CP_AGENT_MSG_TYPE_OCKA_SERVICE_DEL ) {
    ci_assert_gt(mib->dim->svc_ep_max, 0);

    cicp_mac_rowid_t id = cp_svc_find_match(mib, addr, port);
    ci_assert( CICP_MAC_ROWID_IS_VALID(id) );
    if( !CICP_MAC_ROWID_IS_VALID(id) )
      return OK; /* Ignore failure to find service to delete in production */

    if( cp_svc_del(s, id) < 0 )
      return bad_agent("Encountered table corruption while deleting service");
  }
  else {
    ci_fail(("Unrecognised message type."));
  }

  return OK;
}


static inline enum process_result
process_ocka_endpoint_update(struct cp_session* s, struct agent_state* agent)
{
  struct cp_agent_ocka_endpoint_update* msg = (void*) agent->buf;
  if( msg->hdr.len != sizeof(*msg) )
    return bad_agent("Bad endpoint msg len %d from agent(%d)",
                     msg->hdr.len, agent->fd);

  ci_addr_sh_t svc_addr = CI_ADDR_SH_FROM_IP4( msg->service_ip_be );
  ci_uint16 svc_port = msg->service_port_be;
  ci_addr_sh_t ep_addr = CI_ADDR_SH_FROM_IP4( msg->endpoint_ip_be );
  ci_uint16 ep_port = msg->endpoint_port_be;

  /* TODO: Handle assert cases less abruptly after OCKA testing complete. */
  struct cp_mibs* mib = cp_get_active_mib(s);

  cicp_mac_rowid_t svc_id = cp_svc_find_match(mib, svc_addr, svc_port);
  ci_assert(CICP_MAC_ROWID_IS_VALID(svc_id));
  if( ! CICP_MAC_ROWID_IS_VALID(svc_id) )
    return OK; /* Ignore failure to find backend's service in production */

  if( msg->hdr.type == CP_AGENT_MSG_TYPE_OCKA_ENDPOINT_ADD ) {
    ci_assert_gt(mib->dim->svc_arrays_max, 0);

    cicp_mac_rowid_t ep_id = cp_svc_backend_add(s, svc_id, ep_addr, ep_port);
    ci_assert( CICP_MAC_ROWID_IS_VALID(ep_id) );
    if( ep_id == CICP_MAC_ROWID_ERROR )
      return bad_agent("Encountered table corruption while adding backend");
  }
  else if( msg->hdr.type == CP_AGENT_MSG_TYPE_OCKA_ENDPOINT_DEL ) {
    ci_assert_gt(mib->dim->svc_arrays_max, 0);

    if( cp_svc_backend_del(s, svc_id, ep_addr, ep_port) < 0 )
      return bad_agent("Encountered table corruption while deleting backend");
  }
  else {
    ci_fail(("Unrecognised message type."));
  }

  return OK;
}


static enum process_result
process_ocka_agent_hello(struct cp_session* s, struct agent_state* agent,
                         uint32_t proto_ver)
{
  if( proto_ver < CP_AGENT_OCKA_MIN_PROTO_VER ||
      proto_ver > CP_AGENT_OCKA_MAX_PROTO_VER )
    return bad_agent("Unsupported OCKA proto_ver %d from agent(%d)",
                     proto_ver, agent->fd);
  if( s->mib[0].dim->svc_arrays_max <= 0 || s->mib[0].dim->svc_ep_max <= 0 )
    return bad_agent("OCKA agent attempted to connect, but cplane service "
                     "limits are max_services=%d, max_endpoints=%d",
                     s->mib[0].dim->svc_arrays_max, s->mib[0].dim->svc_ep_max);
  cp_svc_erase_all(s);
  return OK;
}


static enum process_result
process_kdp_agent_hello(struct cp_session* s, struct agent_state* agent,
                        uint32_t proto_ver)
{
  if( proto_ver < CP_AGENT_KDP_MIN_PROTO_VER ||
      proto_ver > CP_AGENT_KDP_MAX_PROTO_VER )
    return bad_agent("Unsupported K8s device plugin proto_ver %d from "
                     "agent(%d)", proto_ver, agent->fd);
  return OK;
}


/* Handling for the "hello" messages that is specific to the agent-type is
 * entered by calling through this array of function pointers that is indexed
 * by agent-type. */
static enum process_result
(*hello_handlers[])(struct cp_session*, struct agent_state*,
                    uint32_t proto_ver) = {
  [CP_AGENT_TYPE_OCKA] = process_ocka_agent_hello,
  [CP_AGENT_TYPE_K8S_DEVICE_PLUGIN] = process_kdp_agent_hello,
};


static inline enum process_result
send_server_hello(struct cp_session* s, struct agent_state* agent,
                  uint32_t proto_ver)
{
  enum process_result rc;
  struct cp_agent_server_hello resp;
  resp.hdr.len = sizeof(resp);
  resp.hdr.type = CP_AGENT_MSG_TYPE_SERVER_HELLO;
  resp.proto_ver = proto_ver;
  /* NOTE: strictly we should check that the socket is writable before
   * sending this, but it's the only message we'll ever send and only a
   * few bytes, so in practice it will succeed.
   */
  rc = send(agent->fd, &resp, sizeof(resp), MSG_DONTWAIT | MSG_NOSIGNAL);
  if( rc != sizeof(resp) )
    return bad_agent("Failed to send server hello to agent(%d) "
                     "(rc=%d errno=%d)", agent->fd, rc, errno);
  return OK;
}


static inline enum process_result
process_agent_hello(struct cp_session* s, struct agent_state* agent)
{
  struct cp_agent_client_hello* msg = (void*) agent->buf;
  if( msg->hdr.len != sizeof(*msg) )
    return bad_agent("Bad hello msg len %d from agent(%d)",
                     msg->hdr.len, agent->fd);

  if( msg->agent_type <= CP_AGENT_TYPE_UNBOUND ||
      msg->agent_type >= CP_AGENT_TYPE_COUNT )
    return bad_agent("Unsupported agent_type %d from agent(%d)",
                     msg->agent_type, agent->fd);

  int rc = hello_handlers[msg->agent_type](s, agent, msg->proto_ver);
  if( rc != OK )
    return rc;

  rc = send_server_hello(s, agent, msg->proto_ver);
  if( rc != OK )
    return rc;

  agent->type = msg->agent_type;
  agent->proto_ver = msg->proto_ver;
#ifndef NDEBUG
  ci_log("agent(%d) handshake complete (agent_type=%d proto_ver=%d)",
         agent->fd, msg->agent_type, msg->proto_ver);
#endif
  return OK;
}


/* Handles a messages received from an agent before we've decided which sort
 * of agent we're talking to. */
static enum process_result
process_unbound_agent_msg(struct cp_session* s, struct agent_state* agent,
                          const struct cp_agent_msg_hdr* hdr)
{
  ci_assert_equal(agent->type, CP_AGENT_TYPE_UNBOUND);

  switch( hdr->type ) {
  case CP_AGENT_MSG_TYPE_CLIENT_HELLO:
    return process_agent_hello(s, agent);
  default:
    return bad_agent("Bad msg_type %d from unbound agent(%d)", hdr->type,
                     agent->fd);
  }
}


static enum process_result
process_ocka_agent_msg(struct cp_session* s, struct agent_state* agent,
                       const struct cp_agent_msg_hdr* hdr)
{
  ci_assert_equal(agent->type, CP_AGENT_TYPE_OCKA);

  switch( hdr->type ) {
  case CP_AGENT_MSG_TYPE_OCKA_SERVICE_ADD:
  case CP_AGENT_MSG_TYPE_OCKA_SERVICE_DEL:
    return process_ocka_service_update(s, agent);
  case CP_AGENT_MSG_TYPE_OCKA_ENDPOINT_ADD:
  case CP_AGENT_MSG_TYPE_OCKA_ENDPOINT_DEL:
    return process_ocka_endpoint_update(s, agent);
  default:
    return bad_agent("Bad msg_type %d from OCKA agent(%d)", hdr->type,
                     agent->fd);
  }
}


/* Message-handling for each type of agent is dispatched through this array of
 * function pointers that is indexed by agent-type. */
static enum process_result
process_kdp_agent_msg(struct cp_session* s, struct agent_state* agent,
                      const struct cp_agent_msg_hdr* hdr)
{
  ci_assert_equal(agent->type, CP_AGENT_TYPE_K8S_DEVICE_PLUGIN);

  /* The device plugin agent doesn't currently do anything other than say
   * hello, so any message at this point is unexpected. */
  return bad_agent("Bad msg_type %d from Kubernetes device plugin agent(%d)",
                   hdr->type, agent->fd);
}


static enum process_result
(*message_handlers[])(struct cp_session*, struct agent_state*,
                      const struct cp_agent_msg_hdr*) = {
  [CP_AGENT_TYPE_UNBOUND] = process_unbound_agent_msg,
  [CP_AGENT_TYPE_OCKA] = process_ocka_agent_msg,
  [CP_AGENT_TYPE_K8S_DEVICE_PLUGIN] = process_kdp_agent_msg,
};


static inline enum process_result
process_agent_msg(struct cp_session* s, struct agent_state* agent)
{
  struct cp_agent_msg_hdr* hdr = (void*) agent->buf;
  if( agent->buf_fill < sizeof(*hdr) )
    return BUF_EMPTY;

  if( hdr->len > sizeof(agent->buf) )
    return bad_agent("Bad msg_len %d (max=%d) from agent(%d)",
                     hdr->len, sizeof(agent->buf), agent->fd);

  if( agent->buf_fill < hdr->len )
    return BUF_EMPTY;

  ci_assert_ge(agent->type, 0);
  ci_assert_lt(agent->type, CP_AGENT_TYPE_COUNT);
  enum process_result rc = message_handlers[agent->type](s, agent, hdr);
  if( rc == OK ) {
    agent->buf_fill -= hdr->len;
    memmove(agent->buf, agent->buf + hdr->len, agent->buf_fill);
  }

  return rc;
}


#ifndef NDEBUG
static inline char* hexdump_buffer(char* buf, unsigned buf_len)
{
  static char str[1024];
  unsigned i;
  ci_assert( buf_len * 3 < sizeof(str) );
  memset(str, 0, sizeof(str));
  for(i = 0; i < buf_len; ++i) {
    sprintf(str + i * 3, "%02x ", (uint8_t)buf[i]);
  }
  return str;
}
#endif


void cp_agent_client_handle(struct cp_session* s, struct cp_epoll_state* state)
{
  struct agent_state* agent = state->private;
  unsigned recv_len = sizeof(agent->buf) - agent->buf_fill;
  char* recv_buf = agent->buf + agent->buf_fill;
  int rc = recv(state->fd, recv_buf, recv_len, MSG_DONTWAIT);
  if( rc <= 0 ) {
    if( rc < 0 )
      ci_log("WARNING: failed recv from agent(%d): %s", state->fd, strerror(errno));
#ifndef NDEBUG
    else
      ci_log("agent(%d) disconnected", state->fd);
#endif
    close(state->fd);
    cp_epoll_unregister(s, state);
    return;
  }
  agent->buf_fill += rc;
#ifndef NDEBUG
  ci_log("agent(%d) received %d bytes", state->fd, rc);
  ci_log("%s", hexdump_buffer(recv_buf, rc));
#endif

  while( true ) {
    switch( process_agent_msg(s, agent) ) {
    case BUF_EMPTY:
      return;
    case BAD_AGENT:
      close(state->fd);
      cp_epoll_unregister(s, state);
      return;
    case OK:
      break;
    default:
      ci_assert( 0 );
    }
  }
}


void cp_agent_sock_handle(struct cp_session* s, struct cp_epoll_state* state)
{
  int client_fd = accept(state->fd, NULL, NULL);
  if( client_fd < 0 ) {
    ci_log("WARNING: failed to accept on agent socket: %s", strerror(errno));
    return;
  }
#ifndef NDEBUG
  ci_log("agent(%d) connected", client_fd);
#endif
  struct cp_epoll_state* client_state;
  client_state = cp_epoll_register(s, client_fd, cp_agent_client_handle,
                                   sizeof(struct agent_state));
  struct agent_state* agent = client_state->private;
  agent->fd = client_fd;
  agent->buf_fill = 0;
  agent->type = CP_AGENT_TYPE_UNBOUND;
}
