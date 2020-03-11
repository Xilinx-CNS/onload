/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include "rtt.h"

#include <netdb.h>
#include <netinet/tcp.h>


#define SOCKET_ENDPOINT(pep)                            \
  CONTAINER_OF(struct socket_endpoint, ep, (pep))


struct socket_endpoint {
  struct rtt_endpoint  ep;
  int                  sock;
  char*                msg_buf;
  ssize_t              ping_len;
  ssize_t              pong_len;
};


static void socket_ping(struct rtt_endpoint* ep)
{
  struct socket_endpoint* sep = SOCKET_ENDPOINT(ep);
  RTT_TEST( send(sep->sock, sep->msg_buf, sep->ping_len, 0) == sep->ping_len );
}


static void socket_pong(struct rtt_endpoint* ep)
{
  struct socket_endpoint* sep = SOCKET_ENDPOINT(ep);
  RTT_TEST( recv(sep->sock, sep->msg_buf, sep->pong_len, MSG_WAITALL)
            == sep->pong_len );
}


static int lsplit_string(const char* str, char sep,
                         int* key_len_out, const char** val_out)
{
  char* p_sep = strchr(str, sep);
  if( p_sep == NULL || p_sep == str )
    return -1;
  *key_len_out = p_sep - str;
  *val_out = p_sep + 1;
  return 0;
}


static int keyprefixcmp(const char* cmp, const char* key, int key_len)
{
  if( key_len == strlen(cmp) )
    return strncmp(key, cmp, key_len);
  else
    return 1;
}


static int lookup_and(int (*op)(int, const struct sockaddr*, socklen_t),
                      const char* op_s,  int sock, int socktype,
                      const char* node, const char* service)
{
  struct addrinfo hints, *ai;
  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = AI_PASSIVE;
  hints.ai_family = AF_INET;
  hints.ai_socktype = socktype;
  int rc = getaddrinfo(node, service, &hints, &ai);
  if( rc != 0 )
    return rtt_err("ERROR: getaddrinfo(%s, %s) failed: %s\n",
                   node, service, gai_strerror(rc));

  rc = op(sock, ai->ai_addr, ai->ai_addrlen);
  freeaddrinfo(ai);
  if( rc < 0 )
    return rtt_err("ERROR: %s(%s, %s) failed: %s\n",
                   op_s, node, service, strerror(errno));
  return 0;
}


static int socket_build_endpoint(struct rtt_endpoint** ep_out,
                                 const struct rtt_options* opts,
                                 const char** args, int n_args,
                                 int socktype)
{
  const char* bind_port = NULL;
  const char* bind_host = NULL;
  const char* connect_port = NULL;
  const char* connect_host = NULL;

  int arg_i;
  for( arg_i = 0; arg_i < n_args; ++arg_i ) {
    const char *val, *key = args[arg_i];
    int key_len;
    if( lsplit_string(key, '=', &key_len, &val) < 0 )
      return rtt_err("ERROR: bad arg: %s\n", args[arg_i]);
    if( ! keyprefixcmp("bind_port", key, key_len) )
      bind_port = val;
    else if( ! keyprefixcmp("bind_host", key, key_len) )
      bind_host = val;
    else if( ! keyprefixcmp("connect_port", key, key_len) )
      connect_port = val;
    else if( ! keyprefixcmp("connect_host", key, key_len) )
      connect_host = val;
    else
      return rtt_err("ERROR: unknown arg: %s\n", args[arg_i]);
  }

  int sock = socket(AF_INET, socktype, 0);
  if( sock < 0 )
    return rtt_err("ERROR: socket() failed: %s\n", strerror(errno));

  if( socktype == SOCK_STREAM ) {
    int one = 1;
    RTT_TRY( setsockopt(sock, SOL_TCP, TCP_NODELAY, &one, sizeof(one)) );
  }

  if( bind_port || bind_host )
    if( lookup_and(bind, "bind", sock, socktype, bind_host, bind_port) < 0 )
      return -1;

  if( connect_port ) {
    if( lookup_and(connect, "connect", sock, socktype,
                   connect_host, connect_port) < 0 )
      return -1;
  }
  else if( socktype == SOCK_STREAM ) {
    RTT_TRY( listen(sock, 1) );
    int conn;
    RTT_TRY( conn = accept(sock, NULL, NULL) );
    close(sock);
    sock = conn;
  }

  struct socket_endpoint* sep = calloc(1, sizeof(*sep));
  sep->ep.ping = socket_ping;
  sep->ep.pong = socket_pong;
  sep->ep.cleanup = NULL;
  sep->ep.reset_stats = NULL;
  sep->ep.dump_info = NULL;
  sep->sock = sock;
  const ssize_t headers = 14 + 20 + 8;
  RTT_TEST( opts->ping_frame_len >= headers );
  RTT_TEST( opts->pong_frame_len >= headers );
  sep->ping_len = opts->ping_frame_len - headers;
  sep->pong_len = opts->pong_frame_len - headers;
  int max_len = sep->ping_len > sep->pong_len ? sep->ping_len : sep->pong_len;
  RTT_TEST( (sep->msg_buf = malloc(max_len)) != NULL );

  *ep_out = &(sep->ep);
  return 0;
}


int rtt_tcp_build_endpoint(struct rtt_endpoint** ep_out,
                           const struct rtt_options* opts, unsigned dirs,
                           const char** args, int n_args)
{
  return socket_build_endpoint(ep_out, opts, args, n_args, SOCK_STREAM);
}


int rtt_udp_build_endpoint(struct rtt_endpoint** ep_out,
                           const struct rtt_options* opts, unsigned dirs,
                           const char** args, int n_args)
{
  return socket_build_endpoint(ep_out, opts, args, n_args, SOCK_DGRAM);
}
