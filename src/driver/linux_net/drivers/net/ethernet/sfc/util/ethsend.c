/* SPDX-License-Identifier: BSD-2-Clause */
/* (c) Copyright 2005-2011 Xilinx, Inc. */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>

#define eprintf(...) fprintf ( stderr, __VA_ARGS__ )

int main ( int argc, char **argv ) {
  struct ifreq ifr;
  int sock;
  union {
    struct sockaddr sa;
    struct sockaddr_ll sll;
  } sa;
  char buffer[8192];
  ssize_t len;

  if ( argc < 2 ) {
    eprintf ( "Syntax: %s ethX\n", argv[0] );
    exit ( 1 );
  }

  sock = socket ( PF_PACKET, SOCK_RAW, htons ( ETH_P_ALL ) );
  if ( sock < 0 ) {
    eprintf ( "Could not create socket: %m\n" );
    exit ( 1 );
  }

  memset ( &ifr, 0, sizeof ( ifr ) );
  strncpy ( ifr.ifr_name, argv[1], sizeof ( ifr.ifr_name ) );
  if ( ioctl ( sock, SIOCGIFINDEX, &ifr ) < 0 ) {
    eprintf ( "Could not identify interface %s: %m\n", ifr.ifr_name );
    exit ( 1 );
  }

  memset ( &sa, 0, sizeof ( sa ) );
  sa.sll.sll_family = AF_PACKET;
  sa.sll.sll_ifindex = ifr.ifr_ifindex;

  len = read ( STDIN_FILENO, buffer, sizeof ( buffer ) );
  if ( len < 0 ) {
    eprintf ( "Could not read data to transmit: %m\n" );
    exit ( 1 );
  }

  if ( sendto ( sock, buffer, len, 0, &sa.sa, sizeof ( sa.sll ) ) < 0 ) {
    eprintf ( "Could not transmit: %m\n" );
    exit ( 1 );
  }

  return 0;
}
