/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "cplane_unit.h"
#include <cplane/server.h>

/* To enable ipv6 in onload and enable tests requiring onload use make option:
  * TRANSPORT_CONFIG_OPT_HDR=ci/internal/transport_config_opt_cloud.h
  */
#include <ci/internal/transport_config_opt.h>
#if CI_CFG_IPV6
#include <ci/internal/ip.h>
#include <onload/cplane_ops.h>
#endif


#include "../../tap/tap.h"

#define A inet_addr
#define ASH(s) CI_ADDR_SH_FROM_IP4(A(s))


/* Calling into Onload from the control plane doesn't happen in the real world.
 * To do so safely, we have to make sure that Onload is built using a
 * configuration that's compatible with the control plane's build. */
#if CI_CFG_IPV6
#define CAN_TEST_ONLOAD_CPLANE_CALLS
#endif


enum {
  LOOP_IFINDEX = 1,
  ETHO0_IFINDEX,
  ETHO1_IFINDEX, /* It is a multiarch nic, i.e. with two hwports. */

  /* An interconnected pair of veth the interfaces for the cross-namespace
   * tests. */
  VETH_IFINDEX,
  VETH_XNS_IFINDEX,

  /* The following interfaces are configured in a separate namespace, but
   * bug70993 means that we need global uniqueness of ifindices, so we keep
   * them in the same enum. */
  XNSO0_IFINDEX,
  XNSO1_IFINDEX,
};

enum {
  ETHO0_HWPORTS = 0x01,
  ETHO1_HWPORTS = 0x02 | 0x04,

  XNSO0_HWPORTS = 0x08,
  XNSO1_HWPORTS = 0x10,
};

static void init_session(struct cp_session* s_local, struct cp_session* s_main)
{
  cp_unit_init_session(s_local);

  const char mac1[] = {0x00, 0x0f, 0x53, 0x00, 0x00, 0x00};
  const char mac2[] = {0x00, 0x0f, 0x53, 0x00, 0x00, 0x01};
  cp_unit_nl_handle_link_msg(s_local, RTM_NEWLINK, ETHO0_IFINDEX,
                             ETHO0_HWPORTS, "ethO0", mac1);
  cp_unit_nl_handle_link_msg(s_local, RTM_NEWLINK, ETHO1_IFINDEX,
                             ETHO1_HWPORTS, "ethO1", mac2);

  if( s_main != NULL ) {
    cp_unit_init_session(s_main);
    cp_unit_set_main_cp_handle(s_local, s_main);

    const char xns_mac1[] = {0x00, 0x0f, 0x53, 0xff, 0xff, 0x00};
    const char xns_mac2[] = {0x00, 0x0f, 0x53, 0xff, 0xff, 0x01};
    cp_unit_nl_handle_link_msg(s_main, RTM_NEWLINK, XNSO0_IFINDEX,
                               XNSO0_HWPORTS, "xnsO0", xns_mac1);
    cp_unit_nl_handle_link_msg(s_main, RTM_NEWLINK, XNSO1_IFINDEX,
                               XNSO1_HWPORTS, "xnsO1", xns_mac2);

    const char veth_main_mac[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    cp_unit_nl_handle_veth_link_msg(s_main, RTM_NEWLINK, VETH_XNS_IFINDEX,
                                    VETH_IFINDEX, "veth0_xns", veth_main_mac);
  }

  const char veth_mac[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00};
  cp_unit_nl_handle_veth_link_msg(s_local, RTM_NEWLINK, VETH_IFINDEX,
                                  VETH_XNS_IFINDEX, "veth0", veth_mac);
}


static void insert_test_routes(struct cp_session *s)
{
  /* Tell the control plane about some routes. */
  /* unit_insert_route(s, dest, dest_prefix, pref_src, ifindex) */
  cp_unit_insert_route(s, A("1.2.0.0"), 16, A("1.2.3.4"), ETHO0_IFINDEX);
  cp_unit_insert_route(s, A("9.9.9.0"), 24, A("9.9.9.1"), ETHO0_IFINDEX);
  /* unit_insert_gateway(s, gateway, dest, prefix, ifindex) */
  cp_unit_insert_gateway(s, A("9.9.9.9"), A("0.0.0.0"), 0, ETHO1_IFINDEX);
  cp_unit_insert_gateway(s, A("9.9.9.8"), A("2.0.0.0"), 8, ETHO1_IFINDEX);
  cp_unit_insert_gateway(s, A("3.0.0.0"), A("10.0.0.0"), 8, VETH_IFINDEX);
}


static void insert_test_resolutions(struct cp_session *s)
{
  /* Tell the control plane about some route-resolutions. */

  /* unit_insert_resolution(s, dest, src, pref_src, next_hop, ifindex) */
  /* Link-scoped. */
  cp_unit_insert_resolution(s, A("1.2.1.1"),  0, A("1.2.3.4"), 0,
                            ETHO0_IFINDEX);
  cp_unit_insert_resolution(s, A("1.2.1.1"),  A("1.2.3.4"), 0, 0,
                            ETHO0_IFINDEX);

  /* Via default gateway. */
  cp_unit_insert_resolution(s, A("1.1.1.1"),  0, A("9.9.9.1"), A("9.9.9.9"),
                            ETHO1_IFINDEX);
  cp_unit_insert_resolution(s, A("1.1.1.1"),  A("9.9.9.1"), 0, A("9.9.9.9"),
                            ETHO1_IFINDEX);

  cp_unit_insert_resolution(s, A("1.0.1.1"),  0, A("9.9.9.1"), A("9.9.9.9"),
                            ETHO1_IFINDEX);
  cp_unit_insert_resolution(s, A("1.0.1.1"),  A("9.9.9.1"), 0, A("9.9.9.9"),
                            ETHO1_IFINDEX);

  /* Also via default gateway. */
  cp_unit_insert_resolution(s, A("16.0.0.1"), 0, A("9.9.9.1"), A("9.9.9.9"),
                            ETHO1_IFINDEX);
  cp_unit_insert_resolution(s, A("16.0.0.1"), A("9.9.9.1"), 0, A("9.9.9.9"),
                            ETHO1_IFINDEX);

  cp_unit_insert_resolution(s, A("16.1.0.1"), 0, A("9.9.9.1"), A("9.9.9.9"),
                            ETHO1_IFINDEX);
  cp_unit_insert_resolution(s, A("16.1.0.1"), A("9.9.9.1"), 0, A("9.9.9.9"),
                            ETHO1_IFINDEX);

  /* Via gateway for 2.0.0.0/8. */
  cp_unit_insert_resolution(s, A("2.0.0.1"),  0, A("9.9.9.1"), A("9.9.9.8"),
                            ETHO1_IFINDEX);
  cp_unit_insert_resolution(s, A("2.0.0.1"),  A("9.9.9.1"), 0, A("9.9.9.8"),
                            ETHO1_IFINDEX);

  cp_unit_insert_resolution(s, A("2.0.0.2"),  0, A("9.9.9.1"), A("9.9.9.8"),
                            ETHO1_IFINDEX);
  cp_unit_insert_resolution(s, A("2.0.0.2"),  A("9.9.9.1"), 0, A("9.9.9.8"),
                            ETHO1_IFINDEX);
}


struct expected_fwd_row {
  struct cp_fwd_key     key;
  struct cp_fwd_key_ext key_ext;
  struct cp_fwd_data    data;
};


#define N_EXPECTED_ROWS 8
static void populate_expected_rows(struct expected_fwd_row *expected,
                                   size_t size)
{
  /* An exhaustive list of all cp_fwd_rows we expect to find in the session
   * after test routes and resolutions have been added to the session. */
  struct expected_fwd_row rows[] = {
    /* Link-scoped route gets a /32 entry. */
    {
      .key = { .src = ASH("0.0.0.0"), .dst = ASH("1.2.1.1"), .ifindex = 0, },
      .key_ext = { .src_prefix = 32+96, .dst_prefix = 32+96, },
      .data = {
        .base.src = ASH("1.2.3.4"),
        .base.next_hop = ASH("1.2.1.1"),
        .base.ifindex = ETHO0_IFINDEX,
        .hwports = ETHO0_HWPORTS,
      }
    },
    {
      .key = { .src = ASH("1.0.0.0"), .dst = ASH("1.2.1.1"), .ifindex = 0, },
      .key_ext = { .src_prefix = 8+96, .dst_prefix = 32+96, },
      .data = {
        .base.src = ASH("1.2.3.4"),
        .base.next_hop = ASH("1.2.1.1"),
        .base.ifindex = ETHO0_IFINDEX,
        .hwports = ETHO0_HWPORTS,
      }
    },
    /* 1.0.0.0/15 all goes via default gateway. */
    {
      .key = { .src = ASH("0.0.0.0"), .dst = ASH("1.0.0.0"), .ifindex = 0, },
      .key_ext = { .src_prefix = 32+96, .dst_prefix = 15+96, },
      .data = {
        .base.src = ASH("9.9.9.1"),
        .base.next_hop = ASH("9.9.9.9"),
        .base.ifindex = ETHO1_IFINDEX,
        .hwports = ETHO1_HWPORTS,
      }
    },
    {
      .key = { .src = ASH("8.0.0.0"), .dst = ASH("1.0.0.0"), .ifindex = 0, },
      .key_ext = { .src_prefix = 5+96, .dst_prefix = 15+96, },
      .data = {
        .base.src = ASH("9.9.9.1"),
        .base.next_hop = ASH("9.9.9.9"),
        .base.ifindex = ETHO1_IFINDEX,
        .hwports = ETHO1_HWPORTS,
      }
    },
    /* So does 16.0.0.0/4. */
    {
      .key = { .src = ASH("0.0.0.0"), .dst = ASH("16.0.0.0"), .ifindex = 0, },
      .key_ext = { .src_prefix = 32+96, .dst_prefix = 4+96, },
      .data = {
        .base.src = ASH("9.9.9.1"),
        .base.next_hop = ASH("9.9.9.9"),
        .base.ifindex = ETHO1_IFINDEX,
        .hwports = ETHO1_HWPORTS,
      }
    },
    {
      .key = { .src = ASH("8.0.0.0"), .dst = ASH("16.0.0.0"), .ifindex = 0, },
      .key_ext = { .src_prefix = 5+96, .dst_prefix = 4+96, },
      .data = {
        .base.src = ASH("9.9.9.1"),
        .base.next_hop = ASH("9.9.9.9"),
        .base.ifindex = ETHO1_IFINDEX,
        .hwports = ETHO1_HWPORTS,
      }
    },
    /* 2.0.0.0/8 goes via its own gateway. */
    {
      .key = { .src = ASH("0.0.0.0"), .dst = ASH("2.0.0.0"), .ifindex = 0, },
      .key_ext = { .src_prefix = 32+96, .dst_prefix = 8+96, },
      .data = {
        .base.src = ASH("9.9.9.1"),
        .base.next_hop = ASH("9.9.9.8"),
        .base.ifindex = ETHO1_IFINDEX,
        .hwports = ETHO1_HWPORTS,
      }
    },
    {
      .key = { .src = ASH("8.0.0.0"), .dst = ASH("2.0.0.0"), .ifindex = 0, },
      .key_ext = { .src_prefix = 5+96, .dst_prefix = 8+96, },
      .data = {
        .base.src = ASH("9.9.9.1"),
        .base.next_hop = ASH("9.9.9.8"),
        .base.ifindex = ETHO1_IFINDEX,
        .hwports = ETHO1_HWPORTS,
      }
    }
  };

  CI_BUILD_ASSERT(sizeof(rows) / sizeof(rows[0]) == N_EXPECTED_ROWS);
  ci_assert_ge(size, N_EXPECTED_ROWS);
  memcpy(expected, rows, sizeof(rows));
}


bool ci_ipx_addr_sh_eq(ci_addr_sh_t *lhs, ci_addr_sh_t *rhs)
{
  return lhs->u64[0] == rhs->u64[0] &&
         lhs->u64[1] == rhs->u64[1];
}


bool fwd_data_equal(struct cp_fwd_data *lhs, struct cp_fwd_data *rhs)
{
  return ci_ipx_addr_sh_eq(&lhs->base.src, &rhs->base.src) &&
         ci_ipx_addr_sh_eq(&lhs->base.next_hop, &rhs->base.next_hop) &&
         lhs->base.ifindex == rhs->base.ifindex &&
         lhs->hwports == rhs->hwports;
}


void test_inserts(void)
{
  struct cp_session s;
  init_session(&s, NULL);
  insert_test_routes(&s);

  cmp_ok(s.route_dst.used, "==", 4,
	 "saw all rules other than the default gateway");

  /* Control plane sorts routes by prefix: /32 first, /0 last. */
  cmp_ok(cp_ippl_entry(&s.route_dst, 0)->addr.ip4, "==", A("9.9.9.0"),
	 "route destination - longest prefix");
  cmp_ok(cp_ippl_entry(&s.route_dst, 0)->prefix, "==", 24,
	 "longest route prefix");
  cmp_ok(cp_ippl_entry(&s.route_dst, 1)->addr.ip4, "==", A("1.2.0.0"),
	 "route destination");
  cmp_ok(cp_ippl_entry(&s.route_dst, 1)->prefix, "==", 16,
	 "route prefix");
}


void test_resolutions(void)
{
  struct cp_session s;
  init_session(&s, NULL);
  insert_test_routes(&s);
  insert_test_resolutions(&s);

  struct cp_fwd_state* fwd_state = cp_fwd_state_get(&s, 0);
  struct cp_fwd_table* fwd_table = &fwd_state->fwd_table;
  int count = 0;

  bool seen[N_EXPECTED_ROWS] = {0};
  struct expected_fwd_row expected[N_EXPECTED_ROWS];
  populate_expected_rows(expected, sizeof(expected) / sizeof(expected[0]));

  cicp_mac_rowid_t id;
  int i;
  for( id = 0; id <= fwd_table->mask; ++id ) {
    struct cp_fwd_row* fwd = cp_get_fwd_by_id(fwd_table, id);
    if( fwd->flags & CICP_FWD_FLAG_OCCUPIED ) {
      ++count;
      for( i = 0; i < N_EXPECTED_ROWS; ++i ) {
        if( ci_ipx_addr_sh_eq(&expected[i].key.src, &fwd->key.src) &&
            ci_ipx_addr_sh_eq(&expected[i].key.dst, &fwd->key.dst) &&
            expected[i].key.ifindex == fwd->key.ifindex &&
            expected[i].key_ext.src_prefix == fwd->key_ext.src_prefix &&
            expected[i].key_ext.dst_prefix == fwd->key_ext.dst_prefix &&
            fwd_data_equal(&expected[i].data, &fwd->data[0]) )
          seen[i] = true;
      }
    }
  }

  for( i = 0; i < N_EXPECTED_ROWS; ++i )
    ok(seen[i], "saw expected fwd entry %d", i);
  cmp_ok(count, "==", N_EXPECTED_ROWS, "saw expected count of fwd entries");
}


void test_route_resolve(void)
{
  struct cp_session s;
  struct oo_cplane_handle h;
  init_session(&s, NULL);
  cp_unit_init_cp_handle(&h, &s);

  insert_test_routes(&s);
  insert_test_resolutions(&s);

  struct expected_fwd_row expected[N_EXPECTED_ROWS];
  populate_expected_rows(expected, sizeof(expected) / sizeof(expected[0]));

  cicp_verinfo_t verinfo;
  struct cp_fwd_data data;
  int i, rc;
  for( i = 0; i < N_EXPECTED_ROWS; ++i ) {
    oo_cp_verinfo_init(&verinfo);
    rc = oo_cp_route_resolve(&h, &verinfo, &expected[i].key, &data);
    /* rc==1 indicates a valid lookup, but from a cached entry where verinfo
     * is valid.  This is not the code path we want to test. */
    cmp_ok(rc, "==", 0, "oo_cp_route_resolve looked up fwd entry %d", i);
    ok( fwd_data_equal(&expected[i].data, &data),
        "found expected data for fwd entry %d", i );
  }
}


#ifdef CAN_TEST_ONLOAD_CPLANE_CALLS
static void cp_unit_netif_mock(ci_netif* ni,
                               struct cp_session* s_current,
                               struct cp_session* s_init_net)
{
  memset(ni, 0, sizeof(*ni));
  ni->state = malloc(sizeof(*ni->state));
  CP_TEST(ni->state);

  ni->cplane = malloc(sizeof(*ni->cplane));
  CP_TEST(ni->cplane);
  cp_unit_init_cp_handle(ni->cplane, s_current);

  if( s_init_net != NULL ) {
    ni->cplane_init_net = malloc(sizeof(*ni->cplane_init_net));
    CP_TEST(ni->cplane_init_net);
    cp_unit_init_cp_handle(ni->cplane_init_net, s_init_net);
  }

  /* All ports onloaded, good enough for test */
  ni->state->tx_hwport_mask = -1;
  ni->state->rx_hwport_mask = -1;
}


static void cp_unit_netif_mock_destroy(ci_netif* ni)
{
  free(ni->state);
  free(ni->cplane);
  free(ni->cplane_init_net);
}


void test_user_retrieve(void)
{
  struct cp_session s;
  ci_netif ni;

  init_session(&s, NULL);
  cp_unit_netif_mock(&ni, &s, NULL);

  insert_test_routes(&s);
  insert_test_resolutions(&s);

  struct expected_fwd_row expected[N_EXPECTED_ROWS];
  populate_expected_rows(expected, sizeof(expected) / sizeof(expected[0]));

  ci_ip_cached_hdrs ipcache;
  struct oo_sock_cplane sock_cp;

  ci_addr_sh_t next_hop;
  int i;
  for( i = 0; i < N_EXPECTED_ROWS; ++i ) {
    ci_ip_cache_invalidate(&ipcache);
    ipcache.ether_type = CI_ETHERTYPE_IP;
    ipcache.ipx.ip4.ip_daddr_be32 = expected[i].key.dst.ip4;

    oo_sock_cplane_init(&sock_cp);
    sock_cp.laddr = expected[i].key.src;
    sock_cp.so_bindtodevice = expected[i].key.ifindex;

    cicp_user_retrieve(&ni, &ipcache, &sock_cp);
    next_hop = CI_ADDR_SH_FROM_ADDR(ipcache.nexthop);

    cmp_ok(ipcache.status, "==", retrrc_nomac,
       "ipcache status success (but for mac) after retrieve for entry %d", i);
    cmp_ok(ipcache.intf_i, ">=", 0,
       "ipcache intf_i not invalid for entry %d", i);
    cmp_ok(ipcache.intf_i, "!=", OO_INTF_I_LOOPBACK,
       "ipcache intf_i not loopback for entry %d", i);
    ok(ci_ipx_addr_sh_eq(&next_hop, &expected[i].data.base.next_hop),
       "ipcache next_hop correct for entry %d", i);
  }

  cp_unit_netif_mock_destroy(&ni);
}


/* The routes in the local namespace include one route over a veth
 * interface.  This function inserts the routes that we are pretending are
 * configured in the main namespace. */
static void insert_cross_namespace_routes(struct cp_session* s_local,
                                          struct cp_session* s_main)
{
  cp_unit_insert_route(s_local, A("10.0.0.0"), 24, A("10.0.0.3"), VETH_IFINDEX);

  cp_unit_insert_route(s_main, A("10.0.1.0"), 24, A("10.0.1.2"), XNSO0_IFINDEX);
  cp_unit_insert_gateway(s_main, A("10.0.0.1"), 0, 0, XNSO1_IFINDEX);
}


/* This inserts the resolutions in each namespace for some lookups that
 * traverse the veth-pair. */
static void
insert_cross_namespace_resolutions(struct cp_session* s_local,
                                   struct cp_session* s_main)
{
  /* Via gateway over veth for 10.0.0.0/8. */
  cp_unit_insert_resolution(s_local, A("10.0.0.2"),  0, A("10.0.0.3"),
                            A("3.0.0.0"), VETH_IFINDEX);
  cp_unit_insert_resolution(s_local, A("10.0.0.2"), A("10.0.0.3"), 0,
                            A("3.0.0.0"), VETH_IFINDEX);
  cp_unit_insert_resolution(s_local, A("10.0.1.1"),  0, A("10.0.1.2"),
                            A("3.0.0.0"), VETH_IFINDEX);
  cp_unit_insert_resolution(s_local, A("10.0.1.1"), A("10.0.1.2"), 0,
                            A("3.0.0.0"), VETH_IFINDEX);

  /* Tell the main control plane about the cross-namespace veth interface.
   * This must be done before inserting the "xns" resolutions with the RTA_IIF
   * attribute.  Otherwise, the control plane refuses to update the fwd
   * table. */
  cp_veth_fwd_table_id_do(s_main, VETH_XNS_IFINDEX, 0);

  /* Link-scoped. */
  cp_unit_insert_resolution_xns(s_main, A("10.0.1.1"), 0, A("10.0.1.2"), 0,
                                XNSO0_IFINDEX, VETH_XNS_IFINDEX);
  cp_unit_insert_resolution_xns(s_main, A("10.0.1.1"), A("10.0.1.2"), 0, 0,
                                XNSO0_IFINDEX, VETH_XNS_IFINDEX);
  /* Via gateway. */
  cp_unit_insert_resolution_xns(s_main, A("10.0.0.2"), 0, A("10.0.0.3"),
                                A("10.0.0.1"), XNSO1_IFINDEX, VETH_XNS_IFINDEX);
  cp_unit_insert_resolution_xns(s_main, A("10.0.0.2"), A("10.0.0.3"), 0,
                                A("10.0.0.1"), XNSO1_IFINDEX, VETH_XNS_IFINDEX);
}


static ci_hwport_id_t
ifindex_to_hwport(struct cp_session* s, ci_ifid_t ifindex)
{
  cicp_rowid_t llap_id = cp_llap_find_row(&s->mib[0], ifindex);
  ci_assert_nequal(llap_id, CICP_MAC_ROWID_BAD);
  ci_assert(CI_IS_POW2(s->mib[0].llap[llap_id].rx_hwports));
  return cp_hwport_mask_first(s->mib[0].llap[llap_id].rx_hwports);
}


static void test_cross_namespace_routing(void)
{
  struct cp_session s_local, s_main;
  init_session(&s_local, &s_main);
  insert_test_routes(&s_local);
  insert_test_resolutions(&s_local);
  insert_cross_namespace_routes(&s_local, &s_main);
  insert_cross_namespace_resolutions(&s_local, &s_main);

  ci_ip_cached_hdrs ipcache;
  struct oo_sock_cplane sock_cp;
  ci_netif ni;

  cp_unit_netif_mock(&ni, &s_local, &s_main);
  ci_ip_cache_invalidate(&ipcache);
  oo_sock_cplane_init(&sock_cp);

  /* TODO: When the data structure has been finalised, iterate over the cases
   * where only one of the two versions is invalid. */

  ci_ipcache_set_daddr(&ipcache, CI_ADDR_FROM_IP4(A("10.0.0.2")));
  cicp_user_retrieve(&ni, &ipcache, &sock_cp);
  cmp_ok(ipcache.status, "==", retrrc_nomac,
         "ipcache status success (but for mac) after cross-ns gateway lookup");
  cmp_ok(ipcache.hwport, "==", ifindex_to_hwport(&s_main, XNSO1_IFINDEX),
         "cross-ns gateway lookup mapped to correct hwport");
  ok(CI_IPX_ADDR_EQ(ipcache.nexthop, CI_ADDR_FROM_IP4(A("10.0.0.1"))),
     "ipcache next_hop correct for entry");

  ci_ip_cache_invalidate(&ipcache);
  ci_ipcache_set_daddr(&ipcache, CI_ADDR_FROM_IP4(A("10.0.1.1")));

  cicp_user_retrieve(&ni, &ipcache, &sock_cp);
  cmp_ok(ipcache.status, "==", retrrc_nomac,
         "ipcache status success (but for mac) after cross-ns gateway lookup");
  cmp_ok(ipcache.hwport, "==", ifindex_to_hwport(&s_main, XNSO0_IFINDEX),
         "cross-ns gateway lookup mapped to correct hwport");
  ok(CI_IPX_ADDR_EQ(ipcache.nexthop, CI_ADDR_FROM_IP4(A("10.0.1.1"))),
     "ipcache next_hop correct for entry");

  cp_unit_netif_mock_destroy(&ni);
}

static void test_scope(void)
{
  struct cp_session s;
  init_session(&s, NULL);

  ci_netif ni;
  cp_unit_netif_mock(&ni, &s, NULL);

  const char mac1[] = {0x00, 0x0f, 0x53, 0x00, 0x00, 0x00};
  const char mac2[] = {0x00, 0x0f, 0x53, 0x00, 0x00, 0x01};

  cp_unit_nl_handle_link_msg(&s, RTM_NEWLINK, ETHO0_IFINDEX, ETHO0_HWPORTS,
                             "ethO0", mac1);
  cp_unit_nl_handle_link_msg(&s, RTM_NEWLINK, ETHO1_IFINDEX, ETHO1_HWPORTS,
                             "ethO1", mac2);

  cp_unit_nl_handle_addr_msg(&s, A("198.18.0.0"), ETHO0_IFINDEX, 16,
                             RT_SCOPE_HOST);

  cp_unit_nl_handle_addr_msg(&s, A("198.19.0.0"), ETHO1_IFINDEX, 16,
                             RT_SCOPE_UNIVERSE);

  cmp_ok(cicp_user_addr_is_local_efab(&ni, ASH("198.18.0.0")), "==", 0,
         "localhost is not acceleratable");
  cmp_ok(cicp_user_addr_is_local_efab(&ni, ASH("198.19.0.0")), "==", 1,
         "any scope larger than localhost is acceleratable");

  cp_unit_netif_mock_destroy(&ni);
}
#endif


int main(void)
{
  cp_unit_init();
  test_inserts();
  test_resolutions();
  test_route_resolve();

#ifdef CAN_TEST_ONLOAD_CPLANE_CALLS
  test_user_retrieve();
  test_cross_namespace_routing();
  test_scope();
#endif

  done_testing();

  return 0;
}
