/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2018-2019 Xilinx, Inc. */
#define _GNU_SOURCE 1

#include "utils.h"

#include <net/if.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <stddef.h>


void sock_put_int(int sock, int i)
{
  i = htonl(i);
  TEST( send(sock, &i, sizeof(i), 0) == sizeof(i) );
}


int sock_get_int(int sock)
{
  int i;
  TEST( recv(sock, &i, sizeof(i), MSG_WAITALL) == sizeof(i) );
  return ntohl(i);
}


int sock_get_ifindex(int sock, int* ifindex_out)
{
  int rc = -1;

  struct sockaddr_storage sas;
  socklen_t len = sizeof(sas);
  TRY( getsockname(sock, (void*) &sas, &len) );

  int addr_off, addr_len;
  switch( sas.ss_family ) {
  case AF_INET:;
    addr_off = offsetof(struct sockaddr_in, sin_addr);
    addr_len = sizeof(((struct sockaddr_in*) 0)->sin_addr);
    break;
  case AF_INET6:
    addr_off = offsetof(struct sockaddr_in6, sin6_addr);
    addr_len = sizeof(((struct sockaddr_in6*) 0)->sin6_addr);
    break;
  default:
    return -1;
  }

  struct ifaddrs *addrs, *iap;
  TRY( getifaddrs(&addrs) );
  for( iap = addrs; iap != NULL; iap = iap->ifa_next )
    if( (iap->ifa_flags & IFF_UP) && iap->ifa_addr &&
        iap->ifa_addr->sa_family == sas.ss_family &&
        memcmp((char*) &sas + addr_off,
               (char*) iap->ifa_addr + addr_off, addr_len) == 0 ) {
      TEST( (*ifindex_out = if_nametoindex(iap->ifa_name)) != 0 );
      rc = 0;
      break;
    }

  freeifaddrs(addrs);
  return rc;
}


int getaddrinfo_storage(int family, const char* host, const char* port,
                        struct sockaddr_storage* sas)
{
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = AI_PASSIVE;
  hints.ai_family = family;
  struct addrinfo* ai;
  int rc = getaddrinfo(host, port, &hints, &ai);
  if( rc != 0 ) {
    fprintf(stderr, "ERROR: could not resolve '%s:%s' (%s)\n",
            host ? host : "", port, gai_strerror(rc));
    return -1;
  }
  TEST( ai->ai_addrlen <= sizeof(*sas) );
  memcpy(sas, ai->ai_addr, ai->ai_addrlen);
  return 0;
}


int mk_socket(int family, int socktype,
              int op(int sockfd, const struct sockaddr *addr,
                     socklen_t addrlen),
              const char* host, const char* port)
{
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = AI_PASSIVE;
  hints.ai_family = family;
  hints.ai_socktype = socktype;
  struct addrinfo* ai;
  int rc = getaddrinfo(host, port, &hints, &ai);
  if( rc != 0 ) {
    fprintf(stderr, "ERROR: could not resolve '%s:%s' (%s)\n",
            (host) ? host : "", (port) ? port : "", gai_strerror(rc));
    return -1;
  }
  int sock;
  if( (sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0 ) {
    fprintf(stderr, "ERROR: socket(%d, %d, %d) failed (%s)\n",
            ai->ai_family, ai->ai_socktype, ai->ai_protocol, strerror(errno));
    return -1;
  }
  if( op != NULL && op(sock, ai->ai_addr, ai->ai_addrlen) < 0 ) {
    fprintf(stderr, "ERROR: op(%s, %s) failed (%s)\n",
            host, port, strerror(errno));
    close(sock);
    return -1;
  }
  freeaddrinfo(ai);
  return sock;
}


void get_ipaddr_of_intf(const char* intf, char** ipaddr_out)
{
  struct ifaddrs *ifaddrs, *ifa;
  char* ipaddr = calloc(NI_MAXHOST, sizeof(char));
  TEST(ipaddr);
  TRY(getifaddrs(&ifaddrs));
  for( ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next ) {
    if( ifa->ifa_addr == NULL )
      continue;
    if( strcmp(ifa->ifa_name, intf) != 0 )
      continue;
    if( ifa->ifa_addr->sa_family != AF_INET )
      continue;
    TRY(getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), ipaddr,
                    NI_MAXHOST, NULL, 0, NI_NUMERICHOST));
    break;
  }
  freeifaddrs(ifaddrs);
  *ipaddr_out = ipaddr;
}


/* Handles both vlan and non-vlan interfaces, set vlan negative to skip vlan */
void get_ipaddr_of_vlan_intf(const char* intf, int vlan, char** ipaddr_out)
{
  char full_intf[NI_MAXHOST];
  if ( vlan < 0 ) {
    get_ipaddr_of_intf(intf, ipaddr_out);
  }
  else {
    TRY(snprintf(full_intf, NI_MAXHOST, "%s.%d", intf, vlan));
    get_ipaddr_of_intf(full_intf, ipaddr_out);
  }
}

int my_getaddrinfo(const char* host, const char* port,
                          struct addrinfo**ai_out)
{
  struct addrinfo hints;
  hints.ai_flags = 0;
  hints.ai_family = AF_INET;
  hints.ai_socktype = 0;
  hints.ai_protocol = 0;
  hints.ai_addrlen = 0;
  hints.ai_addr = NULL;
  hints.ai_canonname = NULL;
  hints.ai_next = NULL;
  return getaddrinfo(host, port, &hints, ai_out);
}


int parse_host(const char* s, struct in_addr* ip_out)
{
  const struct sockaddr_in* sin;
  struct addrinfo* ai;
  if( my_getaddrinfo(s, 0, &ai) < 0 )
    return 0;
  sin = (const struct sockaddr_in*) ai->ai_addr;
  *ip_out = sin->sin_addr;
  return 1;
}


int parse_interface(const char* s, int* ifindex_out)
{
  char dummy;
  if( (*ifindex_out = if_nametoindex(s)) == 0 )
    if( sscanf(s, "%d%c", ifindex_out, &dummy) != 1 )
      return 0;
  return 1;
}
