/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_unix */
 
#include <internal.h>

#include <netinet/in.h>
#include <sys/socket.h>

#if CI_CFG_LOG_SOCKET_USERS
/* configuration: */
#define PM_CFG_LOG_FILE "/var/log/etherfabric_users"
#endif



static CI_DLLIST_DECLARE(stream_protocols);
static CI_DLLIST_DECLARE(dgram_protocols);


void citp_protocol_impl_assert_valid(citp_protocol_impl* p)
{
#ifndef NDEBUG
  citp_fdops* o;
  ci_assert(p);

  o = citp_protocol_impl_get_ops(p);
  ci_assert(o->socket);
  ci_assert(o->dtor);
  ci_assert(o->bind);
  ci_assert(o->listen);
  ci_assert(o->accept);
  ci_assert(o->connect);
  ci_assert(o->shutdown);
  ci_assert(o->getsockname);
  ci_assert(o->getpeername);
  ci_assert(o->getsockopt);
  ci_assert(o->setsockopt);
  ci_assert(o->recv);
  ci_assert(o->send);
#endif
}


void citp_protocol_manager_add(citp_protocol_impl* p, int is_stream)
{
  ci_dllist* proto_list;

  CITP_PROTOCOL_IMPL_ASSERT_VALID(p);

  Log_V(log("%s: %p %s", __FUNCTION__, p, is_stream ? "stream":"dgram"));

  proto_list = is_stream ? &stream_protocols : &dgram_protocols;
  ci_dllist_push(proto_list, &p->link);
}


#if CI_CFG_LOG_SOCKET_USERS
static void citp_log_socket_user(int domain, int type, int protocol)
{
  static int stream_done, dgram_done;
  char buf[128];
  int* done;
  int n, fd;
  time_t t;
  char* ts;

  if( type == SOCK_STREAM )  done = &stream_done;
  else                       done = &dgram_done;
  if( *done )  return;
  *done = 1;

  t = time(0);
  ts = ctime(&t);
  ts[strlen(ts)-1] = '\0';  /* strip '\n' */
  n = sprintf(buf, "%-20s %-6s %5d %5d %38s\n", citp.process_name,
	      type == SOCK_STREAM ? "stream" : "dgram",
	      (int) getuid(), (int) getpid(), ts);
  fd = ci_sys_open(PM_CFG_LOG_FILE, O_WRONLY | O_APPEND);
  if( fd >= 0 ) {
    ci_sys_write(fd, buf, n);
    ci_sys_close(fd);
  }
  /* else ci_log("Can't open '%s' for append - rc %d",
                 PM_CFG_LOG_FILE, -fd); */
}
#endif




int citp_protocol_manager_create_socket(int domain, int type, int protocol)
{
  ci_dllist* proto_list;
  citp_protocol_impl* p;
  int rc;
  int type_no_flags = type;

#if CI_CFG_FAKE_IPV6
  if( domain != PF_INET && domain != PF_INET6 )  return CITP_NOT_HANDLED;
#else
  if( domain != PF_INET )  return CITP_NOT_HANDLED;
#endif

  /* If flags bits have anything but SOCK_NONBLOCK or SOCK_CLOEXEC (when
   * defined) then don't try to handle it as we haven't implemented
   * support.
   */
  if( type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC | SOCK_TYPE_MASK) )
    return CITP_NOT_HANDLED;
  type_no_flags = type & SOCK_TYPE_MASK;

  if( type_no_flags == SOCK_STREAM && 
      (protocol == 0 || protocol == IPPROTO_TCP) )
    proto_list = &stream_protocols;
  else if( type_no_flags == SOCK_DGRAM && 
           (protocol == 0 || protocol == IPPROTO_UDP))
    proto_list = &dgram_protocols;
  else
    return CITP_NOT_HANDLED;

#if CI_CFG_LOG_SOCKET_USERS
  citp_log_socket_user(domain, type, protocol);
#endif
  
  CI_DLLIST_FOR_EACH2(citp_protocol_impl, p, link, proto_list) {
    rc = citp_protocol_impl_get_ops(p)->socket(domain, type, protocol);
    if( rc >= 0 || rc == -1 )
      return rc;
  }
  /* We'll get here if the protocol op returned CI_SOCKET_HANDOVER.
   * It should already have checked CITP_OPTS.no_fail and acted
   * accordingly, so we can just map it to CITP_NOT_HANDLED
   */
  return CITP_NOT_HANDLED;
}


/*! \cidoxg_end */

