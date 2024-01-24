/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2019 Xilinx, Inc. */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "cplane_unit.h"
#include <cplane/server.h>

#include "../../tap/tap.h"



#define A inet_addr

static void rand_mac(uint8_t *mac_out)
{
  int i;
  for( i = 0; i < 6; i++ )
    mac_out[i] = rand() & 0xff;
}

static int cp_mac_rows_occupied(struct cp_session* s)
{
  cicp_mac_rowid_t id;
  int occupied = 0;

  for( id = 0; id <= s->mac_mask; id++ ) {
    cicp_mac_row_t* mr = &s->mac[id];

    if( mr->ifindex != 0 )
      occupied++;
  }

  return occupied;
}

static int cp_mac_rows_used(struct cp_session* s)
{
  cicp_mac_rowid_t id;
  int occupied = 0;

  for( id = 0; id <= s->mac_mask; id++ ) {
    cicp_mac_row_t* mr = &s->mac[id];

    if( mr->use > 0 )
      occupied++;
  }

  return occupied;
}

int main(void)
{
  cp_unit_init();
  struct cp_session s;
  int i;
  int n_mac_rows;
  int n_mac_entries;

  srand(0);

  cp_unit_init_session(&s);

  /* Total size of the table in rows. */
  n_mac_rows = s.mac_mask + 1;

  /* Total number of rows we will attempt to store. This is larger
   * than the table, to test our behaviour when it overflows. */
  n_mac_entries = n_mac_rows * 4;

/* Cplane ignores neighbour entries for loopback (ifindex=1), so we use
 * different value here. */
#define ETHO0_IFINDEX 2
#define ETHO0_HWPORT 1
  const char mac1[] = {0x00, 0x0f, 0x53, 0x00, 0x00, 0x00};
  cp_unit_nl_handle_link_msg(&s, RTM_NEWLINK, ETHO0_IFINDEX, ETHO0_HWPORT,
                             "ethO0", mac1);

  /* Initially the table should be empty. */
  cmp_ok(cp_mac_rows_occupied(&s), "==", 0,
         "ARP table is empty");
  cmp_ok(cp_mac_rows_used(&s), "==", 0,
         "All ARP rows are unused");

  /* Tell the control plane about some ARP replies. */
  srand(0);
  for( i = 0; i < n_mac_entries; i++ ) {
    uint8_t macaddr[6];
    uint32_t dst_addr = i + 1;
    rand_mac(macaddr);
    cp_unit_insert_neighbour(&s, ETHO0_IFINDEX, dst_addr, macaddr);
  }

  /* Now the table should be full. */
  cmp_ok(cp_mac_rows_occupied(&s), "==", n_mac_rows,
         "ARP table is full");
  cmp_ok(cp_mac_rows_used(&s), "==", n_mac_rows,
         "All ARP rows are used");

  /* Let all the neighbours expire. */
  srand(0);
  for( i = 0; i < n_mac_entries; i++ ) {
    uint8_t macaddr[6];
    uint32_t dst_addr = i + 1;
    rand_mac(macaddr);
    cp_unit_remove_neighbour(&s, ETHO0_IFINDEX, dst_addr, macaddr);
  }

  /* Now the table should be empty again. */
  cmp_ok(cp_mac_rows_occupied(&s), "==", 0,
         "ARP table is empty");
  cmp_ok(cp_mac_rows_used(&s), "==", 0,
         "All ARP rows are unused");

  /* Neighbour entries for multicast IPs should be ignored. */
  uint32_t mcast_ip = A("239.1.2.3");
  uint8_t mcast_mac[] = {1, 0, 0x5e, 1, 2, 3};
  cp_unit_insert_neighbour(&s, ETHO0_IFINDEX, mcast_ip, mcast_mac);
  cmp_ok(cp_mac_find_row(&s, AF_INET, CI_ADDR_FROM_IP4(mcast_ip), 1), "==",
         CICP_MAC_ROWID_BAD, "Multicast entry was not inserted");

  done_testing();

  return 0;
}
