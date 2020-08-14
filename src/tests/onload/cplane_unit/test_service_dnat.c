/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

/* This test checks interactions between control plane servers in different
 * namespaces.  Currently support for this is limited to the cases where a
 * server in one namespace pulls in state from the server for init_net. */

#include "cplane_unit.h"
#include <cplane/server.h>

#include "../../tap/tap.h"


static unsigned n_svc_rows_used(struct cp_mibs* mib)
{
  int i;
  unsigned count = 0;
  for( i = 0; i < mib->dim->svc_ep_max; ++i )
    if( mib->svc_ep_table[i].use > 0 )
      count++;
  return count;
}


static unsigned n_svc_rows_occupied(struct cp_mibs* mib)
{
  int i;
  unsigned count = 0;
  for( i = 0; i < mib->dim->svc_ep_max; ++i )
    if( mib->svc_ep_table[i].row_type != CP_SVC_EMPTY )
      count++;
  return count;
}


static unsigned n_svc_dll_items(struct cp_mibs* mib, cicp_mac_rowid_t rowid)
{
  struct cp_svc_ep_dllist* svc = &mib->svc_ep_table[rowid];
  ci_assert_equal(svc->row_type, CP_SVC_SERVICE);
  ci_mib_dllist_link *lnk;
  unsigned count = 0;

  for( lnk = ci_mib_dllist_start(mib->dim, &svc->u.service.backends);
       lnk != ci_mib_dllist_end(mib->dim, &svc->u.service.backends);
       lnk = (ci_mib_dllist_link*) cp_mib_off_to_ptr(mib->dim, lnk->next) ) {
    struct cp_svc_ep_dllist* b = CP_SVC_BACKEND_FROM_LINK(lnk);
    ci_assert_equal(b->row_type, CP_SVC_BACKEND);
    (void) b;
    count++;
  }

  return count;
}


static unsigned n_svc_arrays_used(struct cp_session* s)
{
  int i;
  unsigned count = 0;
  for( i = 0; i < s->mib[0].dim->svc_arrays_max; ++i )
    if( cp_row_mask_get(s->service_used, i) )
      count++;
  return count;
}


static int find_dll_array_mismatch(struct cp_mibs* mib, cicp_mac_rowid_t rowid)
{
  struct cp_svc_ep_dllist* svc = &mib->svc_ep_table[rowid];
  struct cp_svc_ep_array* backend_array =
    &mib->svc_arrays[svc->u.service.head_array_id];
  ci_mib_dllist_link *lnk;
  int i = 0;

  /* It is a requirement that backends in a service's backend list must be in
   * the same order in the list as they are in the backend array. */
  for( lnk = ci_mib_dllist_start(mib->dim, &svc->u.service.backends);
       lnk != ci_mib_dllist_end(mib->dim, &svc->u.service.backends);
       lnk = (ci_mib_dllist_link*) cp_mib_off_to_ptr(mib->dim, lnk->next) ) {
    struct cp_svc_ep_dllist* b = CP_SVC_BACKEND_FROM_LINK(lnk);
    ci_assert_equal(b->row_type, CP_SVC_BACKEND);
    if( b->u.backend.svc_id != rowid || b->u.backend.element_id != i )
      return i;
    struct cp_svc_endpoint* array_ep = &backend_array->eps[i];
    if( !CI_IPX_ADDR_EQ(array_ep->addr, b->ep.addr) ||
        array_ep->port != b->ep.port )
      return i;
    i++;
  }

  return -1;
}


static cicp_mac_rowid_t
fill_table(struct cp_session *s, ci_addr_sh_t first_addr, ci_uint16 first_port,
           size_t svc_arrays_max, size_t per_svc_ep_max,
           cicp_mac_rowid_t max_id, int* last_id) {
  ci_addr_sh_t addr = first_addr;
  ci_uint16 port;
  cicp_mac_rowid_t id, svc_id;
  id = svc_id = CICP_MAC_ROWID_BAD;

  int i, j;
  for( i = 0; i < svc_arrays_max; ++i ) {
    port = first_port;
    id = cp_svc_add(s, addr, port++);
    if( !CICP_MAC_ROWID_IS_VALID(id) || id == max_id )
      return id;
    if( last_id != NULL )
      *last_id = id;

    svc_id = id;
    for( j = 0; j < per_svc_ep_max; ++j ) {
      id = cp_svc_backend_add(s, svc_id, addr, port++);
      if( !CICP_MAC_ROWID_IS_VALID(id) || id == max_id )
        return id;
      if( last_id != NULL )
        *last_id = id;
    }

    addr.ip4++;
  }
  return id;
}


void test_svc_not_found(void)
{
  ci_addr_sh_t addr = CI_ADDR_SH_FROM_IP4(0x01010101);
  ci_uint16 port = 80;
  struct cp_session s;
  struct cp_mibs *mib;
  cicp_mac_rowid_t id;

  cp_unit_init_session(&s);
  mib = cp_get_active_mib(&s);
  id = cp_svc_find_match(mib, addr, port);
  cmp_ok(id, "==", CICP_MAC_ROWID_BAD, "No Service");

  cp_unit_destroy_session(&s);
}


void test_svc_add_single(void)
{
  ci_addr_sh_t addr = CI_ADDR_SH_FROM_IP4(0x01010101);
  ci_uint16 port = 80;
  struct cp_session s;
  struct cp_mibs *mib;
  cicp_mac_rowid_t id1, id;

  cp_unit_init_session(&s);
  id1 = cp_svc_add(&s, addr, port);
  ok(CICP_MAC_ROWID_IS_VALID(id1), "Added service");

  mib = cp_get_active_mib(&s);
  id = cp_svc_find_match(mib, addr, port);
  cmp_ok(id, "==", id1, "Found single service");

  id = cp_svc_add(&s, addr, port);
  cmp_ok(id, "==", CICP_MAC_ROWID_BAD, "Unable to add duplicate");

  cp_unit_destroy_session(&s);
}


void test_svc_add_collision(void)
{
  ci_addr_sh_t addr1 = CI_ADDR_SH_FROM_IP4(0x01010101);
  ci_addr_sh_t addr2 = CI_ADDR_SH_FROM_IP4(0);
  ci_uint16 port = 80;
  struct cp_session s;
  struct cp_mibs *mib;
  cicp_mac_rowid_t id1, id2, id;
  unsigned i;

  cp_unit_init_session(&s);

  /* Find address that we know hash-collides on port */
  mib = cp_get_active_mib(&s);
  id2 = 0;
  cp_calc_svc_hash(mib->dim->svc_ep_max - 1, &addr1, port, &id1, NULL);
  for( i = 0; i < (mib->dim->svc_ep_max << 2); ++i ) {
    addr2.ip4 = i;
    cp_calc_svc_hash(mib->dim->svc_ep_max - 1, &addr2, port, &id2, NULL);
    if( id1 == id2 )
      break;
  }
  id = id1;
  ci_assert_equal(id1, id2);

  id1 = cp_svc_add(&s, addr1, port);
  ok(CICP_MAC_ROWID_IS_VALID(id1), "Added first service");
  cmp_ok(id1, "==", id, "Hash is as we expect");
  id2 = cp_svc_add(&s, addr2, port);
  ok(CICP_MAC_ROWID_IS_VALID(id2), "Added second service");
  cmp_ok(id1, "!=", id2, "Services collide");

  mib = cp_get_active_mib(&s);
  id = cp_svc_find_match(mib, addr1, port);
  cmp_ok(id, "==", id1, "Found first service");
  id = cp_svc_find_match(mib, addr2, port);
  cmp_ok(id, "==", id2, "Found service with collision");

  cp_unit_destroy_session(&s);
}


void test_svc_delete_single(void)
{
  ci_addr_sh_t addr = CI_ADDR_SH_FROM_IP4(0x01010101);
  ci_uint16 port = 80;
  struct cp_session s;
  struct cp_mibs *mib;
  cicp_mac_rowid_t id1, id;

  cp_unit_init_session(&s);
  id1 = cp_svc_add(&s, addr, port);
  ok(CICP_MAC_ROWID_IS_VALID(id1), "Added service");

  cp_svc_del(&s, id1);
  mib = cp_get_active_mib(&s);
  id = cp_svc_find_match(mib, addr, port);
  cmp_ok(id, "==", CICP_MAC_ROWID_BAD, "Service deleted");

  cp_unit_destroy_session(&s);
}


void test_svc_delete_collision(void)
{
  ci_addr_sh_t addr1 = CI_ADDR_SH_FROM_IP4(0x01010101);
  ci_addr_sh_t addr2 = CI_ADDR_SH_FROM_IP4(0);
  ci_uint16 port = 80;
  struct cp_session s;
  struct cp_mibs *mib;
  cicp_mac_rowid_t id1, id2, id;
  unsigned i;

  cp_unit_init_session(&s);

  /* Find address that we know hash-collides on port */
  mib = cp_get_active_mib(&s);
  id2 = 0;
  cp_calc_svc_hash(mib->dim->svc_ep_max - 1, &addr1, port, &id1, NULL);
  for( i = 0; i < (mib->dim->svc_ep_max << 2); ++i ) {
    addr2.ip4 = i;
    cp_calc_svc_hash(mib->dim->svc_ep_max - 1, &addr2, port, &id2, NULL);
    if( id1 == id2 )
      break;
  }
  id = id1;
  ci_assert_equal(id1, id2);

  id1 = cp_svc_add(&s, addr1, port);
  ok(CICP_MAC_ROWID_IS_VALID(id1), "Added first service");
  cmp_ok(id1, "==", id, "Hash is as we expect");
  id2 = cp_svc_add(&s, addr2, port);
  ok(CICP_MAC_ROWID_IS_VALID(id2), "Added second service");
  cmp_ok(id1, "!=", id2, "Second service collides");

  cp_svc_del(&s, id1);
  mib = cp_get_active_mib(&s);
  id = cp_svc_find_match(mib, addr1, port);
  cmp_ok(id, "==", CICP_MAC_ROWID_BAD, "First service deleted");
  id = cp_svc_find_match(mib, addr2, port);
  cmp_ok(id, "==", id2, "Second service can still be found");

  cp_svc_del(&s, id2);
  mib = cp_get_active_mib(&s);
  id = cp_svc_find_match(mib, addr2, port);
  cmp_ok(id, "==", CICP_MAC_ROWID_BAD, "Second service deleted");

  cmp_ok(n_svc_rows_used(mib), "==", 0, "Hash table empty");
  cmp_ok(n_svc_rows_occupied(mib), "==", 0, "Hash table empty");

  cp_unit_destroy_session(&s);
}


void test_svc_readd_single(void)
{
  ci_addr_sh_t addr = CI_ADDR_SH_FROM_IP4(0x01010101);
  ci_uint16 port = 80;
  struct cp_session s;
  struct cp_mibs *mib;
  cicp_mac_rowid_t id1, id2, id;

  cp_unit_init_session(&s);
  id1 = cp_svc_add(&s, addr, port);
  ok(CICP_MAC_ROWID_IS_VALID(id1), "Added service");

  cp_svc_del(&s, id1);
  mib = cp_get_active_mib(&s);
  id = cp_svc_find_match(mib, addr, port);
  cmp_ok(id, "==", CICP_MAC_ROWID_BAD, "Service deleted");

  id2 = cp_svc_add(&s, addr, port);
  mib = cp_get_active_mib(&s);
  ok(CICP_MAC_ROWID_IS_VALID(id2), "Re-added service");
  cmp_ok(id2, "==", id1, "Service re-added in same place");
  id = cp_svc_find_match(mib, addr, port);
  cmp_ok(id, "==", id2, "Found re-added service");

  cp_unit_destroy_session(&s);
}


void test_svc_single_backend(void)
{
  ci_addr_sh_t addr1 = CI_ADDR_SH_FROM_IP4(0x01010101);
  ci_addr_sh_t addr2 = CI_ADDR_SH_FROM_IP4(0x12121212);
  ci_uint16 port = 80;
  struct cp_session s;
  struct cp_mibs *mib;
  cicp_mac_rowid_t id1, id2, id;

  cp_unit_init_session(&s);
  id1 = cp_svc_add(&s, addr1, port);
  ok(CICP_MAC_ROWID_IS_VALID(id1), "Added service");
  id2 = cp_svc_backend_add(&s, id1, addr2, port);
  ok(CICP_MAC_ROWID_IS_VALID(id2), "Added backend");

  mib = cp_get_active_mib(&s);
  id = cp_svc_find_match(mib, addr1, port);
  cmp_ok(id, "==", id1, "Found the service");
  cmp_ok(mib->svc_ep_table[id].u.service.n_backends, "==", 1,
         "Service claims a single backend");
  cmp_ok(n_svc_dll_items(mib, id), "==", 1,
         "Service backend list has single item");

  id = cp_svc_find_match(mib, addr2, port);
  cmp_ok(id, "==", id2, "Found the backend");
  cmp_ok(mib->svc_ep_table[id].u.backend.svc_id, "==", id1,
         "Backend indexes back to service");

  cp_unit_destroy_session(&s);
}


void test_svc_delete_backend(void)
{
  ci_addr_sh_t addr1 = CI_ADDR_SH_FROM_IP4(0x01010101);
  ci_addr_sh_t addr2 = CI_ADDR_SH_FROM_IP4(0x12121212);
  ci_addr_sh_t addr3 = CI_ADDR_SH_FROM_IP4(0x13131313);
  ci_uint16 port = 80;
  struct cp_session s;
  struct cp_mibs *mib;
  cicp_mac_rowid_t id1, id2, id3, id;

  cp_unit_init_session(&s);
  id1 = cp_svc_add(&s, addr1, port);
  ok(CICP_MAC_ROWID_IS_VALID(id1), "Added service");
  id2 = cp_svc_backend_add(&s, id1, addr2, port);
  ok(CICP_MAC_ROWID_IS_VALID(id2), "Added first backend");
  id3 = cp_svc_backend_add(&s, id1, addr3, port);
  ok(CICP_MAC_ROWID_IS_VALID(id3), "Added second backend");

  mib = cp_get_active_mib(&s);
  cmp_ok(mib->svc_ep_table[id1].u.service.n_backends, "==", 2,
         "Service claims two backends");
  cmp_ok(n_svc_dll_items(mib, id1), "==", 2,
         "Service backend list has two items");

  id = cp_svc_find_match(mib, addr2, port);
  cmp_ok(id, "==", id2, "Found first backend");
  id = cp_svc_find_match(mib, addr3, port);
  cmp_ok(id, "==", id3, "Found second backend");

  cp_svc_backend_del(&s, id1, addr2, port);
  mib = cp_get_active_mib(&s);
  id = cp_svc_find_match(mib, addr2, port);
  cmp_ok(id, "==", CICP_MAC_ROWID_BAD, "First backend deleted");
  cmp_ok(mib->svc_ep_table[id1].u.service.n_backends, "==", 1,
         "Service claims one backend");
  cmp_ok(n_svc_dll_items(mib, id1), "==", 1,
         "Service backend list has one item");

  cp_unit_destroy_session(&s);
}


void test_svc_delete_svc_with_backends(void)
{
  ci_addr_sh_t addr1 = CI_ADDR_SH_FROM_IP4(0x01010101);
  ci_addr_sh_t addr2 = CI_ADDR_SH_FROM_IP4(0x12121212);
  ci_addr_sh_t addr3 = CI_ADDR_SH_FROM_IP4(0x13131313);
  ci_uint16 port = 80;
  struct cp_session s;
  struct cp_mibs *mib;
  cicp_mac_rowid_t id1, id2, id3;

  cp_unit_init_session(&s);
  id1 = cp_svc_add(&s, addr1, port);
  ok(CICP_MAC_ROWID_IS_VALID(id1), "Added service");
  id2 = cp_svc_backend_add(&s, id1, addr2, port);
  ok(CICP_MAC_ROWID_IS_VALID(id2), "Added first backend");
  id3 = cp_svc_backend_add(&s, id1, addr3, port);
  ok(CICP_MAC_ROWID_IS_VALID(id3), "Added second backend");

  mib = cp_get_active_mib(&s);
  cmp_ok(n_svc_rows_used(mib), "==", 3,
         "Three used rows in hash table.");
  cmp_ok(n_svc_rows_occupied(mib), "==", 3,
         "Three items in hash table.");

  cp_svc_del(&s, id1);
  mib = cp_get_active_mib(&s);
  cmp_ok(n_svc_rows_used(mib), "==", 0,
         "Items removed from hash table.");
  cmp_ok(n_svc_rows_occupied(mib), "==", 0,
         "Items removed from hash table.");

  cp_unit_destroy_session(&s);
}


static void test_svc_backend_in_multiple_services(void)
{
  ci_addr_sh_t svc_addr1 = CI_ADDR_SH_FROM_IP4(0x01010101);
  ci_addr_sh_t svc_addr2 = CI_ADDR_SH_FROM_IP4(0x02020202);
  ci_addr_sh_t backend_addr = CI_ADDR_SH_FROM_IP4(0x13131313);
  ci_uint16 port = 80;
  struct cp_session s;
  struct cp_mibs *mib;
  cicp_mac_rowid_t svc_id1, svc_id2, backend_id1, backend_id2;

  cp_unit_init_session(&s);

  /* Create two services and add the same backend to each. */
  svc_id1 = cp_svc_add(&s, svc_addr1, port);
  ok(CICP_MAC_ROWID_IS_VALID(svc_id1), "Added first service");
  svc_id2 = cp_svc_add(&s, svc_addr2, port);
  ok(CICP_MAC_ROWID_IS_VALID(svc_id2), "Added second service");
  backend_id1 = cp_svc_backend_add(&s, svc_id1, backend_addr, port);
  ok(CICP_MAC_ROWID_IS_VALID(backend_id1), "Added backend to first service");
  backend_id2 = cp_svc_backend_add(&s, svc_id2, backend_addr, port);
  ok(CICP_MAC_ROWID_IS_VALID(backend_id2), "Added backend to second service");

  mib = cp_get_active_mib(&s);
  cmp_ok(n_svc_rows_used(mib), "==", 4, "Four used rows in hash table.");
  cmp_ok(n_svc_rows_occupied(mib), "==", 4, "Four items in hash table.");

  /* Delete the second-added backend, which will require walking over the
   * first-added backend. */
  cp_svc_backend_del(&s, svc_id2, backend_addr, port);

  cmp_ok(n_svc_rows_used(mib), "==", 3, "Three used rows in hash table.");
  cmp_ok(n_svc_rows_occupied(mib), "==", 3, "Three items in hash table.");

  cmp_ok(mib->svc_ep_table[svc_id1].u.service.n_backends, "==", 1,
         "First service still has one backend.");
  cmp_ok(mib->svc_ep_table[svc_id2].u.service.n_backends, "==", 0,
         "Second service has no backends.");

  /* Now re-add the backend to the second service and delete it from the first.
   */
  backend_id2 = cp_svc_backend_add(&s, svc_id2, backend_addr, port);
  ok(CICP_MAC_ROWID_IS_VALID(backend_id2),
     "Re-added backend to second service");
  cp_svc_backend_del(&s, svc_id1, backend_addr, port);

  /* This time we've left a tombstone. */
  cmp_ok(n_svc_rows_used(mib), "==", 4, "Four used rows in hash table.");
  cmp_ok(n_svc_rows_occupied(mib), "==", 3, "Three items in hash table.");

  cmp_ok(mib->svc_ep_table[svc_id1].u.service.n_backends, "==", 0,
         "First service has no backends.");
  cmp_ok(mib->svc_ep_table[svc_id2].u.service.n_backends, "==", 1,
         "Second service has one backend.");

  cp_unit_destroy_session(&s);
}


void test_svc_backend_array_allocation(void)
{
  ci_addr_sh_t addr1 = CI_ADDR_SH_FROM_IP4(0x01010101);
  ci_addr_sh_t addr2 = CI_ADDR_SH_FROM_IP4(0x02020202);
  ci_addr_sh_t addr3 = CI_ADDR_SH_FROM_IP4(0x03030303);
  ci_uint16 port = 80;
  struct cp_session s;
  struct cp_mibs* mib;
  cicp_mac_rowid_t id1, id1b, id2, id2b, id3, id3b;
  cicp_rowid_t array_id1, array_id2, array_id3;

  cp_unit_init_session(&s);
  id1 = cp_svc_add(&s, addr1, port);
  id1b = cp_svc_backend_add(&s, id1, addr1, port+1);
  ok(CICP_MAC_ROWID_IS_VALID(id1), "Added first service");
  ok(CICP_MAC_ROWID_IS_VALID(id1b), "Added first service backend");
  id2 = cp_svc_add(&s, addr2, port);
  id2b = cp_svc_backend_add(&s, id2, addr2, port+1);
  ok(CICP_MAC_ROWID_IS_VALID(id2), "Added second service");
  ok(CICP_MAC_ROWID_IS_VALID(id2b), "Added second service backend");

  mib = cp_get_active_mib(&s);
  array_id1 = mib->svc_ep_table[id1].u.service.head_array_id;
  ok(CICP_ROWID_IS_VALID(array_id1), "First service reserved backend array");
  array_id2 = mib->svc_ep_table[id2].u.service.head_array_id;
  ok(CICP_ROWID_IS_VALID(array_id2), "Second service reserved backend array");
  cmp_ok(array_id1, "==", mib->svc_ep_table[id1].u.service.tail_array_id,
         "First service reserved exactly one backend array");
  cmp_ok(array_id2, "==", mib->svc_ep_table[id2].u.service.tail_array_id,
         "Second service reserved exactly one backend array");
  cmp_ok(array_id1, "!=", array_id2,
         "Services reserved different backend arrays");

  cp_svc_del(&s, id1);
  id3 = cp_svc_add(&s, addr3, port);
  id3b = cp_svc_backend_add(&s, id3, addr3, port+1);
  ok(CICP_MAC_ROWID_IS_VALID(id3), "Added third service");
  ok(CICP_MAC_ROWID_IS_VALID(id3b), "Added third service backend");

  mib = cp_get_active_mib(&s);
  array_id3 = mib->svc_ep_table[id3].u.service.head_array_id;
  cmp_ok(array_id3, "==", array_id1,
         "Third service re-used deleted service's array");

  cp_svc_backend_del(&s, id2, addr2, port+1);
  id1 = cp_svc_add(&s, addr1, port);
  id1b = cp_svc_backend_add(&s, id1, addr1, port+1);
  ok(CICP_MAC_ROWID_IS_VALID(id1), "Re-added first service");
  ok(CICP_MAC_ROWID_IS_VALID(id1b), "Re-added first service backend");

  mib = cp_get_active_mib(&s);
  array_id1 = mib->svc_ep_table[id1].u.service.head_array_id;
  cmp_ok(array_id1, "==", array_id2,
         "First services re-used service with deleted backend's array");

  cp_unit_destroy_session(&s);
}


void test_svc_backend_array_ordering(void)
{
  ci_addr_sh_t addr = CI_ADDR_SH_FROM_IP4(0x01010101);
  ci_addr_sh_t addr_b = CI_ADDR_SH_FROM_IP4(0x12121212);
  ci_uint16 port = 80;
  ci_uint16 port_b[] = {101, 102, 103, 104, 105, 106, 107, 108};
  struct cp_session s;
  struct cp_mibs *mib;
  cicp_mac_rowid_t id;
  cicp_mac_rowid_t id_b[8];
  int i;

  cp_unit_init_session(&s);
  id = cp_svc_add(&s, addr, port);
  ok(CICP_MAC_ROWID_IS_VALID(id), "Added service");
  for( i = 0; i < 8; ++i ) {
    id_b[i] = cp_svc_backend_add(&s, id, addr_b, port_b[i]);
    ok(CICP_MAC_ROWID_IS_VALID(id_b[i]), "Added backend %d", i);
  }

  mib = cp_get_active_mib(&s);
  cmp_ok(n_svc_dll_items(mib, id), "==", 8,
         "Service backend list has eight items");
  cmp_ok(find_dll_array_mismatch(mib, id), "==", -1,
         "Linked list matches array after insertion");

  cp_svc_backend_del(&s, id, addr_b, port_b[7]);
  cmp_ok(find_dll_array_mismatch(mib, id), "==", -1,
         "Linked list matches array after deleting last backend");

  cp_svc_backend_del(&s, id, addr_b, port_b[0]);
  cmp_ok(find_dll_array_mismatch(mib, id), "==", -1,
         "Linked list matches array after deleting first backend");

  cp_svc_backend_del(&s, id, addr_b, port_b[3]);
  cmp_ok(find_dll_array_mismatch(mib, id), "==", -1,
         "Linked list matches array after deleting middle backend");

  cmp_ok(n_svc_dll_items(mib, id), "==", 5,
         "Service backend list has five items");

  cp_unit_destroy_session(&s);
}


void test_svc_backend_array_chaining(void)
{
  const unsigned n_backends = 4 * CP_SVC_BACKENDS_PER_ARRAY;
  ci_addr_sh_t addr = CI_ADDR_SH_FROM_IP4(0x01010101);
  ci_addr_sh_t addr_b = CI_ADDR_SH_FROM_IP4(0x12121212);
  ci_uint16 port = 80;
  struct cp_session s;
  struct cp_mibs *mib;
  cicp_mac_rowid_t id;
  /* Used in debug builds only. */
  cicp_mac_rowid_t id_b[n_backends] __attribute__((unused));
  int i;

  cp_unit_init_session(&s);
  id = cp_svc_add(&s, addr, port);

  mib = cp_get_active_mib(&s);
  ok(CICP_MAC_ROWID_IS_VALID(id), "Added service");
  cmp_ok(n_svc_arrays_used(&s), "==", 0,
         "No service arrays used before backends added");

  for( i = 0; i < n_backends; ++i ) {
    id_b[i] = cp_svc_backend_add(&s, id, addr_b, port + i);
    ci_assert( CICP_MAC_ROWID_IS_VALID(id_b[i]) );
  }
  cmp_ok(n_svc_arrays_used(&s), "==", 4,
         "Four service arrays used after backends added");
  cmp_ok(mib->svc_ep_table[id].u.service.head_array_id, "==", 0,
         "Service array head is in expected location.");
  cmp_ok(mib->svc_ep_table[id].u.service.tail_array_id, "==", 3,
         "Service array tail is in expected location.");

  for( i = 0; i < n_backends / 2; ++i )
    cp_svc_backend_del(&s, id, addr_b, port + i);
  cmp_ok(n_svc_arrays_used(&s), "==", 2,
         "Two service arrays used after half backends delete");
  cmp_ok(mib->svc_ep_table[id].u.service.head_array_id, "==", 0,
         "Service array head is in expected location.");
  cmp_ok(mib->svc_ep_table[id].u.service.tail_array_id, "==", 1,
         "Service array tail is in expected location.");

  id_b[0] = cp_svc_backend_add(&s, id, addr_b, port + 0);
  ci_assert(CICP_MAC_ROWID_IS_VALID(id_b[0]));
  cmp_ok(n_svc_arrays_used(&s), "==", 3,
         "Three service arrays used after first backend re-added");
  cmp_ok(mib->svc_ep_table[id].u.service.head_array_id, "==", 0,
         "Service array head is in expected location.");
  cmp_ok(mib->svc_ep_table[id].u.service.tail_array_id, "==", 2,
         "Service array tail is in expected location.");

  cp_unit_destroy_session(&s);
}


void test_svc_too_many_services(void)
{
  ci_addr_sh_t addr = CI_ADDR_SH_FROM_IP4(0x01010101);
  ci_uint16 port = 80;
  struct cp_session s1, s2;
  struct cp_mibs *mib;
  cicp_mac_rowid_t id, id1 = CICP_MAC_ROWID_BAD;

  cp_unit_init_session(&s1);
  cp_unit_init_session(&s2);
  size_t table_size = sizeof(struct cp_svc_ep_dllist) *
                      s1.mib[0].dim->svc_ep_max;

  /* Add services with single backends until add fails */
  id = fill_table(&s1, addr, port, s1.mib[0].dim->svc_arrays_max + 1, 1,
                  CICP_MAC_ROWID_BAD, &id1);
  mib = cp_get_active_mib(&s1);
  ok(!CICP_MAC_ROWID_IS_VALID(id), "Got service/backend add to fail");
  cmp_ok(n_svc_rows_occupied(mib), "==", (2 * mib->dim->svc_arrays_max) + 1,
         "Confirmed that add failed due to lack of backend arrays");
  ci_assert( !CICP_MAC_ROWID_IS_VALID(id) );
  ci_assert( CICP_MAC_ROWID_IS_VALID(id1) );
  cp_mibs_verify_identical(&s1, false);

  /* Add services until just before failure */
  id = fill_table(&s2, addr, port, s2.mib[0].dim->svc_arrays_max + 1, 1,
                  id1, NULL);
  ci_assert_equal(id, id1);
  cp_mibs_verify_identical(&s2, false);

  /* Check that two has tables are identical.  This confirms that a failing
   * add operation does not alter the contents of the table */
  cmp_mem(s1.mib[0].svc_ep_table, s2.mib[0].svc_ep_table, table_size,
          "Overfilled and fully-filled sessions are identical");

  cp_unit_destroy_session(&s1);
  cp_unit_destroy_session(&s2);
}


void test_svc_hash_table_full(void)
{
  ci_addr_sh_t addr = CI_ADDR_SH_FROM_IP4(0x01010101);
  ci_uint16 port = 80;
  struct cp_session s1, s2;
  struct cp_mibs *mib;
  cicp_mac_rowid_t id, id1 = CICP_MAC_ROWID_BAD;

  cp_unit_init_session(&s1);
  cp_unit_init_session(&s2);
  size_t table_size = sizeof(struct cp_svc_ep_dllist) *
                      s1.mib[0].dim->svc_ep_max;

  /* Overfill s1's table until add fails */
  id = fill_table(&s1, addr, port, s1.mib[0].dim->svc_ep_max,
                  CP_SVC_BACKENDS_PER_ARRAY, CICP_MAC_ROWID_BAD, &id1);
  mib = cp_get_active_mib(&s1);
  ok(!CICP_MAC_ROWID_IS_VALID(id), "Got service/backend add to fail");
  cmp_ok(n_svc_rows_occupied(mib), ">", mib->dim->svc_arrays_max,
         "Confirmed that add failed due to hash table overfill");
  ci_assert( !CICP_MAC_ROWID_IS_VALID(id) );
  ci_assert( CICP_MAC_ROWID_IS_VALID(id1) );
  cp_mibs_verify_identical(&s1, false);

  /* Fill s2's table up to just before add failure */
  id = fill_table(&s2, addr, port, s2.mib[0].dim->svc_ep_max,
                  CP_SVC_BACKENDS_PER_ARRAY, id1, NULL);
  ci_assert_equal(id, id1);
  cp_mibs_verify_identical(&s2, false);

  /* Check that two has tables are identical.  This confirms that a failing
   * add operation does not alter the contents of the table */
  cmp_mem(s1.mib[0].svc_ep_table, s2.mib[0].svc_ep_table, table_size,
          "Overfilled and fully-filled sessions are identical");

  cp_unit_destroy_session(&s1);
  cp_unit_destroy_session(&s2);
}


void test_svc_erase(void)
{
  ci_addr_sh_t addr = CI_ADDR_SH_FROM_IP4(0x01010101);
  ci_uint16 port = 80;
  struct cp_session s;
  struct cp_mibs *mib;
  cicp_mac_rowid_t id;

  cp_unit_init_session(&s);

  fill_table(&s, addr, port, 32, 1, CICP_MAC_ROWID_BAD, &id);
  mib = cp_get_active_mib(&s);
  cmp_ok(n_svc_rows_occupied(mib), "==", 64, "Filled hash table");
  cmp_ok(n_svc_arrays_used(&s), "==", 32, "Claimed backend arrays");

  cp_svc_erase_all(&s);
  mib = cp_get_active_mib(&s);
  cmp_ok(n_svc_rows_occupied(mib), "==", 0, "Table is empty after erase");
  cmp_ok(n_svc_arrays_used(&s), "==", 0, "Backends arrays freed after erase");

  cp_unit_destroy_session(&s);
}


void test_svc_load_balancing(void)
{
  /* Ensure that we always use more than one backend array */
  const unsigned n_backends = CP_SVC_BACKENDS_PER_ARRAY + 1;
  ci_addr_sh_t addr = CI_ADDR_SH_FROM_IP4(0x01010101);
  ci_addr_sh_t addr_b = CI_ADDR_SH_FROM_IP4(0x12121212);
  ci_uint16 port = 80;
  struct cp_session s;
  struct oo_cplane_handle h;
  struct cp_mibs *mib;
  cicp_mac_rowid_t id, id_b;
  unsigned count_b[n_backends];
  int i;

  cp_unit_init_session(&s);
  cp_unit_init_cp_handle(&h, &s);

  id = cp_svc_add(&s, addr, port);
  ok(CICP_MAC_ROWID_IS_VALID(id), "Added service");
  for( i = 0; i < n_backends; ++i ) {
    id_b = cp_svc_backend_add(&s, id, addr_b, port + i);
    ci_assert( CICP_MAC_ROWID_IS_VALID(id_b) );
    count_b[i] = 0;
  }

  mib = cp_get_active_mib(&s);
  for( i = 0; i < 100 * n_backends; ++i ) {
    ci_addr_sh_t dnat_addr = addr;
    ci_uint16 dnat_port = port;
    cp_svc_check_dnat(&h, &dnat_addr, &dnat_port);
    id_b = cp_svc_find_match(mib, dnat_addr, dnat_port);
    ci_assert( CICP_MAC_ROWID_IS_VALID(id_b) );
    count_b[mib->svc_ep_table[id_b].u.backend.element_id]++;
  }

  for( i = 0; i < n_backends; ++i ) {
    if( count_b[i] < 60 )
      diag("WARNING: Backend %d has low selection rate %u/100", i, count_b[i]);
  }

  cp_unit_destroy_session(&s);
}



int main(void)
{
  cp_unit_init();

  test_svc_not_found();
  test_svc_add_single();
  test_svc_add_collision();
  test_svc_delete_single();
  test_svc_delete_collision();
  test_svc_readd_single();
  test_svc_single_backend();
  test_svc_delete_backend();
  test_svc_delete_svc_with_backends();
  test_svc_backend_in_multiple_services();
  test_svc_backend_array_allocation();
  test_svc_backend_array_ordering();
  test_svc_backend_array_chaining();
  test_svc_too_many_services();
  test_svc_hash_table_full();
  test_svc_erase();
  test_svc_load_balancing();

  done_testing();
}
