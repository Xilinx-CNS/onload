/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */
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

/*! \cidoxg_lib_ciapp */

#include <ci/app.h>

#include <fcntl.h>
#include <ctype.h>


#define MAX_HOSTNAME_LEN  100


int sockaddr_set_port(struct sockaddr_storage* sa, int port)
{
  if( port < 0 || port > 65535 )
    return -1;
  switch( sa->ss_family ) {
  case AF_INET:
    ((struct sockaddr_in*)sa)->sin_port = htons((unsigned short)port);
    return 0;
  case AF_INET6:
    ((struct sockaddr_in6*)sa)->sin6_port = htons((unsigned short)port);
    return 0;
  }
  return -1;
}


int sockaddr_get_port(const struct sockaddr_storage* sa)
{
  switch( sa->ss_family ) {
  case AF_INET:
    return ntohs(((struct sockaddr_in*)sa)->sin_port);
  case AF_INET6:
    return ntohs(((struct sockaddr_in6*)sa)->sin6_port);
  }
  return -1;
}


static int sockaddr_set_special(struct sockaddr_storage* sa, uint32_t v4,
                                const struct in6_addr* v6)
{
  switch( sa->ss_family ) {
  case AF_INET:
    ((struct sockaddr_in*)sa)->sin_addr.s_addr = htonl(v4);
    return 0;
  case AF_INET6:
    memcpy(&((struct sockaddr_in6*)sa)->sin6_addr, v6, sizeof(*v6));
    return 0;
  }
  return -1;
}


int sockaddr_set_any(struct sockaddr_storage* sa)
{
  static const struct in6_addr v6any = IN6ADDR_ANY_INIT;
  return sockaddr_set_special(sa, INADDR_ANY, &v6any);
}


int sockaddr_set_loopback(struct sockaddr_storage* sa)
{
  static const struct in6_addr v6loopback = IN6ADDR_LOOPBACK_INIT;
  return sockaddr_set_special(sa, INADDR_LOOPBACK, &v6loopback);
}


int ci_host_port_to_sockaddr_in(const char* host, int port,
			     struct sockaddr_in* sa_out)
{
  if( host && host[0] == '\0' )  host = 0;

  /* clobber! */
  sa_out->sin_family = 0;

  if( host == 0 ) {  /* port number only */
    sa_out->sin_addr.s_addr = CI_BSWAPC_BE32(INADDR_ANY);
  }
  else {
    /* try dotted quad format first */
    /* note that winsock doesn't have inet_aton */
    sa_out->sin_addr.s_addr = inet_addr(host);

    if( sa_out->sin_addr.s_addr == INADDR_NONE ) {
      /* no? then try looking up name */
      struct hostent* he;
      if( (he = gethostbyname(host)) == 0 )
	return -ENOENT;
      memcpy(&sa_out->sin_addr, he->h_addr_list[0], sizeof(sa_out->sin_addr));
    }
  }

  sa_out->sin_family = AF_INET;
  sa_out->sin_port = CI_BSWAP_BE16(port);
  return 0;
}


int ci_hostport_to_sockaddr_in(const char* hp, struct sockaddr_in* sa_out)
{
  char host[MAX_HOSTNAME_LEN];
  const char* s;
  char* d;
  int all_num = 1;
  unsigned port = 0;

  /* clobber! */
  sa_out->sin_family = 0;

  /* copy out host bit, and find port bit (if any) */
  d = host;
  s = hp;
  while( *s && *s != ':' && d - host < MAX_HOSTNAME_LEN - 1 ) {
    if( !isdigit(*s) )  all_num = 0;
    *d++ = *s++;
  }
  *d = 0;

  if( d - host >= MAX_HOSTNAME_LEN )
    return -ENAMETOOLONG;

  if( *s != ':' && all_num ) {  /* port number only */
    if( sscanf(hp, "%u", &port) != 1 )
      return -ENOENT;
    sa_out->sin_addr.s_addr = CI_BSWAPC_BE32(INADDR_ANY);
  }
  else {
    /* try dotted quad format first */
    /* note that winsock doesn't have inet_aton */
    sa_out->sin_addr.s_addr = inet_addr(host);

    if( sa_out->sin_addr.s_addr == INADDR_NONE ) {
      /* no? then try looking up name */
      struct hostent* he;
      if( (he = gethostbyname(host)) == 0 )
	return -ENOENT;
      memcpy(&sa_out->sin_addr, he->h_addr_list[0], sizeof(sa_out->sin_addr));
    }

    if( *s == ':' )  /* port specified? */
      if( sscanf(s + 1, "%u", &port) != 1 )
	return -ENOENT;
  }

  sa_out->sin_family = AF_INET;
  sa_out->sin_port = htons((unsigned short) port);
  return 0;
}


/* Returns true if 'str' is pure numeric (and non-empty) */
static int/*bool*/ all_digits(const char* str)
{
  if( ! *str )
    return 0;
  for( ; *str; ++str )
    if( ! isdigit(*str & 0xff) )
      return 0;
  return 1;
}


/* Decode browser-style host and port specifiers, along with a port-only
 * style which is allowed by most of our test tools.
 * On return populates supplied pointers with bare host and port strings
 * or NULL where not specified in input. Uses the supplied buffer if
 * necessary, which must survive use of the returned strings.
 */
static int decode_hostport(char *str, size_t str_sz,
                           const char *host,
                           const char **host_found, const char **port_found)
{
  const char* port = NULL;
  const char* firstcolon = strchr(host, ':');
  const char* lastcolon = strrchr(host, ':');
  const char* percent = strchr(host, '%');
  const char* closesquare = strchr(host, ']');

  /* strings we want to parse:
   * 1234 (port-only)
   * 1.2.3.4
   * 1.2.3.4:1234
   * ffff::ffff
   * ffff::ffff%eth0
   * ffff::ffff%eth0:1234
   * [ffff::ffff]:1234
   * dellr630a
   * dellr630a:1234
   */

  if( all_digits(host) ) {
    *host_found = NULL;
    *port_found = host;
    return 0;
  }

  /* Handle a specified port */
  if( lastcolon &&
      (firstcolon == lastcolon ||
       (percent && lastcolon > percent) ||
       (closesquare && closesquare < lastcolon)) ) {
    int hostlen = lastcolon - host;
    if( hostlen >= str_sz )
      return -ENAMETOOLONG;
    strncpy(str, host, hostlen);
    str[hostlen] = '\0';
    host = str;
    port = lastcolon + 1;
  }

  /* Strip square brackets */
  if( host && host[0] == '[' && host[strlen(host) - 1] == ']' ) {
    if( host != str ) {
      if( strlen(host) >= str_sz )
        return -ENAMETOOLONG;
      strcpy(str, host);
    }
    str[strlen(str) - 1] = '\0';
    host = str + 1;
  }

  *port_found = port;
  *host_found = host;
  return 0;
}


int ci_hostport_to_sockaddr(int hint_af, const char* hp,
                            struct sockaddr_storage* addr_out)
{
  struct addrinfo hints;
  struct addrinfo* ai;
  char temp_str[256];
  const char* host;
  const char* port;
  int rc;
  size_t size;

  rc = decode_hostport(temp_str, sizeof(temp_str), hp, &host, &port);
  if (rc != 0)
    return rc;

  hints.ai_flags = AI_PASSIVE; 
  hints.ai_family = hint_af;
  hints.ai_socktype = 0;
  hints.ai_protocol = IPPROTO_TCP;  /* Solaris compatability */
  hints.ai_addrlen = 0;
  hints.ai_addr = NULL;
  hints.ai_canonname = NULL;
  hints.ai_next = NULL;
  if( getaddrinfo(host, port, &hints, &ai) )
    return -EINVAL;

  size = sockaddr_size((struct sockaddr_storage*)ai->ai_addr);
  if( ! size )
    rc = -EPFNOSUPPORT;
  else
    memcpy(addr_out, ai->ai_addr, size);

  freeaddrinfo(ai);
  return rc;
}


int ci_setfdblocking(int s, int blocking)
{
  int nonb = !blocking;
  return ioctl(s, FIONBIO, &nonb);
}

/*! \cidoxg_end */
