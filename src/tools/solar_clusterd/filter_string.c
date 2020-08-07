/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2013-2019 Xilinx, Inc. */
/****************************************************************************
 * Copyright (c) 2013, Solarflare Communications Inc,
 *
 * Maintained by Solarflare Communications
 *  <linux-xen-drivers@solarflare.com>
 *  <onload-dev@solarflare.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <etherfabric/vi.h>


#define TRY(_x)                                                         \
  do {                                                                  \
    int __rc = (_x);                                                    \
    if( __rc < 0 ) {                                                    \
      fprintf(stderr, "filter with fields=0x%X: failed %d", s->fields, -__rc); \
      return __rc;                                                      \
    }                                                                   \
  } while (0)


enum {
  SC_SF_ALL              = 0x1,
  SC_SF_ETH_DHOST        = 0x2,
  SC_SF_ETH_VLAN_ID      = 0x4,
  SC_SF_IP4_PROTOCOL     = 0x8,
  SC_SF_IP4_DEST_ADDR    = 0x10,
  SC_SF_IP4_SOURCE_ADDR  = 0x20,
  SC_SF_IP4_DEST_PORT    = 0x40,
  SC_SF_IP4_SOURCE_PORT  = 0x80,
  SC_SF_ETH_TYPE         = 0x100,
  SC_SF_ETH_SHOST        = 0x200,
  SC_SF_SNIFF            = 0x400,
};


struct sc_stream {
  /* Bit mask indicating which of the remaing fields are valid. */
  unsigned fields;
  uint8_t  eth_dhost[6];
  uint8_t  eth_shost[6];
  uint16_t eth_vlan_id;
  uint16_t eth_type;
  uint8_t  ip4_protocol;
  uint32_t ip4_dest_addr;
  uint32_t ip4_source_addr;
  uint16_t ip4_dest_port;
  uint16_t ip4_source_port;
  int      promiscuous;
};

static int sc_stream_all(struct sc_stream* stream);
static int sc_stream_sniff(struct sc_stream* s, const char* key);
static int sc_stream_reset(struct sc_stream* stream);
static int sc_stream_eth_dhost(struct sc_stream*, const uint8_t* mac_addr);
static int sc_stream_eth_vlan_id(struct sc_stream*, int vlan_id);
static int sc_stream_eth_shost(struct sc_stream*, const uint8_t* mac_addr);
static int sc_stream_eth_type(struct sc_stream*, uint16_t eth_type);
static int sc_stream_ip_dest_host(struct sc_stream*, const char* dhost);
static int sc_stream_ip_dest_port(struct sc_stream*, const char* dport);
static int sc_stream_ip_source_host(struct sc_stream*, const char* shost);
static int sc_stream_ip_source_port(struct sc_stream*, const char* sport);
static int sc_stream_ip_protocol(struct sc_stream*, int protocol);



static int my_getaddrinfo(const char* host, const char* port,
                          struct addrinfo** ai_out)
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


static int parse_ip4_host(const char* host, uint32_t* ip_out)
{
  int rc;
  struct addrinfo* ai;
  if( (rc = my_getaddrinfo(host, "0", &ai)) )
    return rc;
  const struct sockaddr_in* sin = (void*) ai->ai_addr;
  *ip_out = sin->sin_addr.s_addr;
  freeaddrinfo(ai);
  return 0;
}


static int parse_ip4_port(const char* port, uint16_t* port_out)
{
  int rc;
  struct addrinfo* ai;
  if( (rc = my_getaddrinfo("0", port, &ai)) )
    return rc;
  const struct sockaddr_in* sin = (void*) ai->ai_addr;
  *port_out = sin->sin_port;
  freeaddrinfo(ai);
  return 0;
}


static int parse_mac(const char* mac, uint8_t* mac_out)
{
  int i;
  unsigned u[6];
  if( sscanf(mac, "%x:%x:%x:%x:%x:%x", &u[0], &u[1], &u[2], &u[3], &u[4], &u[5])
      != 6 )
    return -1;
  for( i = 0; i < 6; i++ )
    mac_out[i] = u[i];
  return 0;
}


static int set_eth_type(struct sc_stream* stream, const char* value)
{
  unsigned int eth_type;
  char* end;

  if( !strcmp(value, "ip") ) {
    eth_type = ETHERTYPE_IP;
  }
  else {
    eth_type = strtoul(value, &end, 10);
    if( value == end ) {
      fprintf(stderr, "%s: ERROR: eth_type value \""
              "%s\" is not ip or an integer\n", __func__, value);
      return -EINVAL;
    }
  }

  return sc_stream_eth_type(stream, eth_type);
}


static int set_protocol(struct sc_stream* stream, const char* value)
{
  int protocol;
  char* end;

  if( !strcmp(value, "udp") ) {
    protocol = IPPROTO_UDP;
  }
  else if( !strcmp(value, "tcp") ) {
    protocol = IPPROTO_TCP;
  }
  else {
    protocol = strtol(value, &end, 10);
    if( value == end ) {
      fprintf(stderr, "%s: ERROR: protocol value \""
             "%s\" is not a recognised protocol or integer\n", __func__, value);
      return -EINVAL;
    }
  }

  return sc_stream_ip_protocol(stream, protocol);
}


static int set_vlan_id(struct sc_stream* stream, const char* value)
{
  char* end;
  int vlan_id = strtol(value, &end, 10);
  if( value == end ) {
    fprintf(stderr, "%s: ERROR: vlan_id value \"%s\" is not an integer\n",
            __func__, value);
    return -EINVAL;
  }

  return sc_stream_eth_vlan_id(stream, vlan_id);
}


static int set_general(struct sc_stream* stream, char* stream_str)
{
  int rc = 0;
  uint8_t mac[6];
  char* key;
  char* next_field = stream_str;

  /* General format is series of key=value pairs, separated by ",". */
  while( next_field && (rc == 0) ) {
    char* value;
    char* field;

    field = strsep(&next_field, ",");

    /* Split key and value */
    value = field;
    key = strsep(&value, "=");

    if( !value ) {
      /* Handle some key-only magic values */
      if( !strcmp(key, "all") )
        rc = sc_stream_all(stream);
      /* The following needs a strncmp because we pass the stream as
       * 'sniff [0,1]' */
      else if( !strncmp(key, "sniff", strlen("sniff")) )
        rc = sc_stream_sniff(stream, key);
      else if( !strcmp(key, "ip") )
        rc = set_eth_type(stream, key);
      else if( !strcmp(key, "udp") || !strcmp(key, "tcp") )
        rc = set_protocol(stream, key);
      else {
        fprintf(stderr, "%s: ERROR: No value for key %s\n", __func__, key);
        return -EINVAL;
      }
    }
    else {
      if( !strcmp(key, "dmac") ) {
        if( parse_mac(value, mac) < 0 ) {
          fprintf(stderr, "%s: ERROR: Failed to parse mac \"%s\"\n",
                  __func__, key);
          return -EINVAL;
        }
        rc = sc_stream_eth_dhost(stream, mac);
      }
      else if( !strcmp(key, "smac") ) {
        if( parse_mac(value, mac) < 0 )
          fprintf(stderr, "%s: ERROR: Failed to parse mac \"%s\"\n",
                  __func__, key);
        return -EINVAL;
        rc = sc_stream_eth_shost(stream, mac);
      }
      else if( !strcmp(key, "vid") ) {
        rc = set_vlan_id(stream, value);
      }
      else if( !strcmp(key, "eth_type") ) {
        rc = set_eth_type(stream, value);
      }
      else if( !strcmp(key, "shost") ) {
        rc = sc_stream_ip_source_host(stream, value);
      }
      else if( !strcmp(key, "dhost") ) {
        rc = sc_stream_ip_dest_host(stream, value);
      }
      else if( !strcmp(key, "ip_protocol") ) {
        rc = set_protocol(stream, value);
      }
      else if( !strcmp(key, "sport") ) {
        rc = sc_stream_ip_source_port(stream, value);
      }
      else if( !strcmp(key, "dport") ) {
        rc = sc_stream_ip_dest_port(stream, value);
      }
      else {
        fprintf(stderr, "%s: ERROR: Unrecognised key \"%s\"\n", __func__, key);
        return -EINVAL;
      }
    }
  }

  return rc;
}


static int sc_stream_reset(struct sc_stream* s)
{
  s->fields = 0;
  return 0;
}


static int sc_stream_all(struct sc_stream* s)
{
  s->fields |= SC_SF_ALL;
  return 0;
}


static int sc_stream_sniff(struct sc_stream* s, const char* key)
{
  int promiscuous;
  TRY(sscanf(key, "sniff %d", &promiscuous));
  s->fields |= SC_SF_SNIFF;
  s->promiscuous = promiscuous;
  return 0;
}


static int sc_stream_eth_dhost(struct sc_stream* s, const uint8_t* mac_addr)
{
  memcpy(s->eth_dhost, mac_addr, 6);
  s->fields |= SC_SF_ETH_DHOST;
  return 0;
}


static int sc_stream_eth_shost(struct sc_stream* s, const uint8_t* mac_addr)
{
  memcpy(s->eth_shost, mac_addr, 6);
  s->fields |= SC_SF_ETH_SHOST;
  return 0;
}


static int sc_stream_eth_vlan_id(struct sc_stream* s, int vlan_id)
{
  s->eth_vlan_id = vlan_id;
  s->fields |= SC_SF_ETH_VLAN_ID;
  return 0;
}


static int sc_stream_eth_type(struct sc_stream* s, uint16_t eth_type)
{
  s->eth_type = eth_type;
  s->fields |= SC_SF_ETH_TYPE;
  return 0;
}


static int sc_stream_ip_dest_host(struct sc_stream* s, const char* dhost)
{
  int rc;
  rc = parse_ip4_host(dhost, &s->ip4_dest_addr);
  if( rc ) {
    fprintf(stderr, "%s: ERROR: Lookup of %s failed (%d %s)\n", __func__, dhost,
            rc, gai_strerror(rc));
    return -ENOENT;
  }
  s->fields |= SC_SF_IP4_DEST_ADDR;
  sc_stream_eth_type(s, ETHERTYPE_IP);
  return 0;
}


static int sc_stream_ip_dest_port(struct sc_stream* s, const char* dport)
{
  int rc;
  rc = parse_ip4_port(dport, &s->ip4_dest_port);
  if( rc ) {
    fprintf(stderr, "%s: ERROR: Lookup of %s failed (%d %s)\n", __func__, dport,
            rc, gai_strerror(rc));
    return -ENOENT;
  }
  s->fields |= SC_SF_IP4_DEST_PORT;
  sc_stream_eth_type(s, ETHERTYPE_IP);
  return 0;
}


static int sc_stream_ip_source_host(struct sc_stream* s, const char* shost)
{
  int rc;
  rc = parse_ip4_host(shost, &s->ip4_source_addr);
  if( rc ) {
    fprintf(stderr, "%s: ERROR: Lookup of %s failed (%d %s)\n", __func__, shost,
            rc, gai_strerror(rc));
    return -ENOENT;
  }
  s->fields |= SC_SF_IP4_SOURCE_ADDR;
  sc_stream_eth_type(s, ETHERTYPE_IP);
  return 0;
}


static int sc_stream_ip_source_port(struct sc_stream* s, const char* sport)
{
  int rc;
  rc = parse_ip4_port(sport, &s->ip4_source_port);
  if( rc ) {
    fprintf(stderr, "%s: ERROR: Lookup of %s failed (%d %s)\n", __func__, sport,
            rc, gai_strerror(rc));
    return -ENOENT;
  }
  s->fields |= SC_SF_IP4_SOURCE_PORT;
  sc_stream_eth_type(s, ETHERTYPE_IP);
  return 0;
}


static int sc_stream_ip_protocol(struct sc_stream* s, int protocol)
{
  s->ip4_protocol = protocol;
  s->fields |= SC_SF_IP4_PROTOCOL;
  sc_stream_eth_type(s, ETHERTYPE_IP);
  return 0;
}


static int sc_stream_add(struct sc_stream* s, void* vi_or_set,
                         ef_driver_handle dh, ef_filter_cookie *cookie_out)
{
  ef_filter_spec spec;

  ef_filter_spec_init(&spec, EF_FILTER_FLAG_NONE);

  switch( s->fields ) {
  case SC_SF_ALL:
    TRY(ef_filter_spec_set_unicast_all(&spec));
    TRY(ef_vi_set_filter_add(vi_or_set, dh, &spec, cookie_out));
    ef_filter_spec_init(&spec, EF_FILTER_FLAG_NONE);
    TRY(ef_filter_spec_set_multicast_all(&spec));
    TRY(ef_vi_set_filter_add(vi_or_set, dh, &spec, cookie_out));
    break;
  case SC_SF_SNIFF:
    TRY(ef_filter_spec_set_port_sniff(&spec, s->promiscuous));
    TRY(ef_vi_set_filter_add(vi_or_set, dh, &spec, cookie_out));
    break;
  case SC_SF_ETH_DHOST:
    TRY(ef_filter_spec_set_eth_local(&spec, EF_FILTER_VLAN_ID_ANY,
                                     s->eth_dhost));
    TRY(ef_vi_set_filter_add(vi_or_set, dh, &spec, cookie_out));
    break;
  case SC_SF_ETH_DHOST | SC_SF_ETH_VLAN_ID:
    TRY(ef_filter_spec_set_eth_local(&spec, s->eth_vlan_id, s->eth_dhost));
    TRY(ef_vi_set_filter_add(vi_or_set, dh, &spec, cookie_out));
    break;
  case SC_SF_ETH_TYPE | SC_SF_IP4_PROTOCOL | SC_SF_IP4_DEST_ADDR |
    SC_SF_IP4_DEST_PORT:
    TRY(ef_filter_spec_set_ip4_local(&spec, s->ip4_protocol,
                                     s->ip4_dest_addr, s->ip4_dest_port));
    TRY(ef_vi_set_filter_add(vi_or_set, dh, &spec, cookie_out));
    break;
  case SC_SF_ETH_TYPE | SC_SF_IP4_PROTOCOL | SC_SF_IP4_DEST_ADDR |
    SC_SF_IP4_DEST_PORT | SC_SF_IP4_SOURCE_ADDR | SC_SF_IP4_SOURCE_PORT:
    TRY(ef_filter_spec_set_ip4_full(&spec, s->ip4_protocol,
                                    s->ip4_dest_addr, s->ip4_dest_port,
                                    s->ip4_source_addr, s->ip4_source_port));
    TRY(ef_vi_set_filter_add(vi_or_set, dh, &spec, cookie_out));
    break;
  default:
    fprintf(stderr, "ERROR: sc_vi[_set]_add_stream_string: "
            "unsupported combination of fields (0x%x)\n", s->fields);
    return -EINVAL;
  }

  return 0;
}


int ef_vi_set_filter_string_add(ef_vi_set* vi_set, ef_driver_handle dh,
                                const char* filter_str)
{
  struct sc_stream stream;
  int rc;
  char *stream_def, *stream_str;
  /* TODO: we are installing a list of filters so should allow for
   * returning a list of cookies. */
  ef_filter_cookie cookie;

  if( (stream_str = strdup(filter_str)) == NULL ) {
    fprintf(stderr, "%s: ERROR: strdup() failed\n", __func__);
    return -errno;
  }

  while( stream_str ) {
    sc_stream_reset(&stream);
    stream_def = strsep(&stream_str, ";");
    if( (rc = set_general(&stream, stream_def)) < 0 )
      goto out;
    if( (rc = sc_stream_add(&stream, vi_set, dh, &cookie)) < 0 )
      goto out;
  }

 out:
  free(stream_str);
  return rc;
}
