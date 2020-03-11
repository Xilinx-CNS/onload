/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#define _GNU_SOURCE 1

#include <etherfabric/vi.h>
#include "utils.h"
#include <ci/app.h>

#include <net/if.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <stddef.h>


/* Parses a parameter of the form "param=val,", advancing *arg beyond the comma
 * and returning the integer value of val.  If nothing follows the comma, or
 * the argument is otherwise invalid, *arg will be NULL on return.  N.B.: This
 * function resets the strtok() state, and the portion of *arg that is consumed
 * will be altered. */
static int consume_parameter(char **arg)
{
  int val;
  char *param = strtok(*arg, ",");
  param = strchr(param, '=');
  ++param;
  if( ! strlen(param) ) {
    /* Nothing after the comma, so return an error.  The return value itself is
     * insignificant. */
    *arg = NULL;
    return 0;
  }
  val = atoi(param);

  *arg = strtok(NULL, "");

  return val;
}


int filter_parse(ef_filter_spec* fs, const char* s_in)
{
  union {
    struct sockaddr_storage ss;
    struct sockaddr_in s4;
    struct sockaddr_in6 s6;
  } laddr, raddr;
  const char* type;
  const char* hostport;
  char* vlan;
  char* remainder;
  char *s;
  int rc = -EINVAL;
  int protocol;
  int i;

  ef_filter_spec_init(fs, EF_FILTER_FLAG_NONE);

  s = strdup(s_in);

  if( (type = strtok(s, ":")) == NULL )
    goto out;

  if( ! strcmp("udp", type) || ! strcmp("tcp", type) ) {
    protocol = strcasecmp(type, "tcp") ? IPPROTO_UDP : IPPROTO_TCP;

    remainder = strtok(NULL, "");
    if( remainder == NULL )
      goto out;

    if( ! strncmp("mcastloop-rx,", remainder, strlen("mcastloop-rx,")) ) {
      ef_filter_spec_init(fs, EF_FILTER_FLAG_MCAST_LOOP_RECEIVE);
      strtok(remainder, ",");
      remainder = strtok(NULL, "");
      if( remainder == NULL )
        goto out;
    }
    if( ! strncmp("vid=", remainder, strlen("vid=")) ) {
      int vlan_id = consume_parameter(&remainder);
      if( remainder == NULL )
        goto out;
      TRY(ef_filter_spec_set_vlan(fs, vlan_id));
    }

    if( strchr(remainder, ',') ) {
      hostport = strtok(remainder, ",");
      remainder = strtok(NULL, "");
      TRY(ci_hostport_to_sockaddr(AF_UNSPEC, hostport, &laddr.ss));
      TRY(ci_hostport_to_sockaddr(laddr.ss.ss_family, remainder, &raddr.ss));
      if( laddr.ss.ss_family == AF_INET && raddr.ss.ss_family == AF_INET ) {
        TRY(ef_filter_spec_set_ip4_full(fs, protocol,
                                        laddr.s4.sin_addr.s_addr,
                                        laddr.s4.sin_port,
                                        raddr.s4.sin_addr.s_addr,
                                        raddr.s4.sin_port));
      } else if( laddr.ss.ss_family == AF_INET6 &&
                 raddr.ss.ss_family == AF_INET6 ) {
        TRY(ef_filter_spec_set_ip6_full(fs, protocol, &laddr.s6.sin6_addr,
                                        laddr.s6.sin6_port,
                                        &raddr.s6.sin6_addr,
                                        raddr.s6.sin6_port));
      } else {
        fprintf(stderr, "ERROR: invalid families in local/remote hosts\n");
        goto out;
      }
      rc = 0;
    }
    else {
      TRY(ci_hostport_to_sockaddr(AF_UNSPEC, strtok(remainder, ","), &laddr.ss));
      if( laddr.ss.ss_family == AF_INET ) {
        TRY(ef_filter_spec_set_ip4_local(fs, protocol,
                                         laddr.s4.sin_addr.s_addr,
                                         laddr.s4.sin_port));
      } else if( laddr.ss.ss_family == AF_INET6 ) {
        TRY(ef_filter_spec_set_ip6_local(fs, protocol, &laddr.s6.sin6_addr,
                                         laddr.s6.sin6_port));
      } else {
        fprintf(stderr, "ERROR: invalid family in local host\n");
        goto out;
      }
      rc = 0;
    }
  }

  else if( ! strcmp("eth", type) ) {
    uint8_t mac[6];
    int vlan_id = EF_FILTER_VLAN_ID_ANY;

    remainder = strtok(NULL, "");
    if( remainder == NULL )
      goto out;

    if( ! strncmp("vid=", remainder, strlen("vid=")) ) {
      vlan_id = consume_parameter(&remainder);
      if( remainder == NULL )
        goto out;
    }

    if( ! strncmp("ethertype=", remainder, strlen("ethertype=")) ) {
      uint16_t ethertype = htons(consume_parameter(&remainder));
      if( remainder == NULL )
        goto out;
      TRY(ef_filter_spec_set_eth_type(fs, ethertype));
    }
    else if( ! strncmp("ipproto=", remainder, strlen("ipproto=")) ) {
      uint8_t ipproto = consume_parameter(&remainder);
      if( remainder == NULL )
        goto out;
      TRY(ef_filter_spec_set_ip_proto(fs, ipproto));
    }

    for( i = 0; i < 6; ++i ) {
      mac[i] = strtol(remainder, &remainder, 16);
      if( i != 5 ) {
        if( *remainder != ':' )
          goto out;
        ++remainder;
        if( ! strlen(remainder) )
          goto out;
      }
    }
    if( strlen(remainder) )
      goto out;
    TRY(ef_filter_spec_set_eth_local(fs, vlan_id, mac));
    rc = 0;
  }

  else if( ! strcmp("ethertype", type) ) {
    uint16_t ethertype;

    remainder = strtok(NULL, "");
    if( remainder == NULL )
      goto out;

    if( ! strncmp("vid=", remainder, strlen("vid=")) ) {
      int vlan_id = consume_parameter(&remainder);
      if( remainder == NULL )
        goto out;
      TRY(ef_filter_spec_set_vlan(fs, vlan_id));
    }

    ethertype = htons(strtol(remainder, &remainder, 10));
    if( strlen(remainder) )
      goto out;

    TRY(ef_filter_spec_set_eth_type(fs, ethertype));
    rc = 0;
  }

  else if( ! strcmp("ipproto", type) ) {
    uint8_t ipproto;

    remainder = strtok(NULL, "");
    if( remainder == NULL )
      goto out;

    if( ! strncmp("vid=", remainder, strlen("vid=")) ) {
      int vlan_id = consume_parameter(&remainder);
      if( remainder == NULL )
        goto out;
      TRY(ef_filter_spec_set_vlan(fs, vlan_id));
    }

    ipproto = strtol(remainder, &remainder, 10);
    if( strlen(remainder) )
      goto out;

    TRY(ef_filter_spec_set_ip_proto(fs, ipproto));
    rc = 0;
  }

  else if( ! strcmp("multicast-all", type) ) {
    if( strlen(type) != strlen(s_in) )
      goto out;
    TRY(ef_filter_spec_set_multicast_all(fs));
    rc = 0;
  }

  else if( ! strcmp("unicast-all", type) ) {
    if( strlen(type) != strlen(s_in) )
      goto out;
    TRY(ef_filter_spec_set_unicast_all(fs));
    rc = 0;
  }

  else if( ! strcmp("multicast-mis", type) ) {
    TRY(ef_filter_spec_set_multicast_mismatch(fs));
    if( strlen(type) != strlen(s_in) ) {
      remainder = strtok(NULL, "");
      if( remainder == NULL || strncmp("vid=", remainder, strlen("vid=")) )
        goto out;
      vlan = strchr(remainder, '=');
      ++vlan;
      if( ! strlen(vlan) )
        goto out;
      TRY(ef_filter_spec_set_vlan(fs, atoi(vlan)));
    }
    rc = 0;
  }

  else if( ! strcmp("unicast-mis", type) ) {
    TRY(ef_filter_spec_set_unicast_mismatch(fs));
    if( strlen(type) != strlen(s_in) ) {
      remainder = strtok(NULL, "");
      if( remainder == NULL || strncmp("vid=", remainder, strlen("vid=")) )
        goto out;
      vlan = strchr(remainder, '=');
      ++vlan;
      if( ! strlen(vlan) )
        goto out;
      TRY(ef_filter_spec_set_vlan(fs, atoi(vlan)));
    }
    rc = 0;
  }

  else if( ! strcmp("sniff", type) ) {
    if( strlen(type) == strlen(s_in) ) {
      TRY(ef_filter_spec_set_port_sniff(fs, 1));
    }
    else {
      remainder = strtok(NULL, "");
      if( remainder == NULL )
        goto out;
      if( ! strcmp("promisc", remainder) )
        TRY(ef_filter_spec_set_port_sniff(fs, 1));
      else if( ! strcmp("no-promisc", remainder) )
        TRY(ef_filter_spec_set_port_sniff(fs, 0));
      else
        goto out;
    }
    rc = 0;
  }

  else if( ! strcmp("tx-sniff", type) ) {
    TRY(ef_filter_spec_set_tx_port_sniff(fs));
    rc = 0;
  }

  else if( ! strcmp("block-kernel", type) ) {
    TRY(ef_filter_spec_set_block_kernel(fs));
    rc = 0;
  }

  else if( ! strcmp("block-kernel-unicast", type) ) {
    TRY(ef_filter_spec_set_block_kernel_unicast(fs));
    rc = 0;
  }

  else if( ! strcmp("block-kernel-multicast", type) ) {
    TRY(ef_filter_spec_set_block_kernel_multicast(fs));
    rc = 0;
  }

 out:
  free(s);
  return rc;
}


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
  freeaddrinfo(ai);
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
  freeaddrinfo(ai);
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
