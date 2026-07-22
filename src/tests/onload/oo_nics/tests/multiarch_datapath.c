/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include "../oo_nics_test.h"
#include "../../../tap/tap.h"
#include "../oo_nics.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

static struct oo_cplane_handle mock_cplane;

enum {
  HWPORT_PAIR_FF,
  HWPORT_PAIR_LLCT,
  HWPORT_LLCT_ONLY,
  HWPORT_FF_ONLY,
  HWPORT_TEST_NIC_PORT0_FF,
  HWPORT_TEST_NIC_PORT0_LLCT,
  HWPORT_TEST_NIC_PORT1_FF,
  HWPORT_TEST_NIC_PORT1_LLCT,
};

#define HWPORT_MASK(hwport) ((cicp_hwport_mask_t) 1u << (hwport))

#define TEST_NIC_PORT0_FF_HWPORTS   HWPORT_MASK(HWPORT_TEST_NIC_PORT0_FF)
#define TEST_NIC_PORT0_LLCT_HWPORTS HWPORT_MASK(HWPORT_TEST_NIC_PORT0_LLCT)
#define TEST_NIC_PORT1_FF_HWPORTS   HWPORT_MASK(HWPORT_TEST_NIC_PORT1_FF)
#define TEST_NIC_PORT1_LLCT_HWPORTS HWPORT_MASK(HWPORT_TEST_NIC_PORT1_LLCT)
#define TEST_NIC_FF_HWPORTS         (TEST_NIC_PORT0_FF_HWPORTS | \
                                     TEST_NIC_PORT1_FF_HWPORTS)
#define TEST_NIC_LLCT_HWPORTS       (TEST_NIC_PORT0_LLCT_HWPORTS | \
                                     TEST_NIC_PORT1_LLCT_HWPORTS)
#define TEST_NIC_HWPORTS            (TEST_NIC_FF_HWPORTS | \
                                     TEST_NIC_LLCT_HWPORTS)

/*
 * Each interface represents one supported port capability combination:
 *
 *   multiarch  has both FF and LLCT ports;
 *   llct-only  has only an LLCT port; and
 *   ff-only    has only an FF port.
 */
struct port_combination {
  const char* name;
  cicp_hwport_mask_t ff_hwports;
  cicp_hwport_mask_t llct_hwports;
};

static const struct port_combination port_combinations[] = {
  {
    .name = "multiarch",
    .ff_hwports = HWPORT_MASK(HWPORT_PAIR_FF),
    .llct_hwports = HWPORT_MASK(HWPORT_PAIR_LLCT),
  },
  {
    .name = "llct-only",
    .llct_hwports = HWPORT_MASK(HWPORT_LLCT_ONLY),
  },
  {
    .name = "ff-only",
    .ff_hwports = HWPORT_MASK(HWPORT_FF_ONLY),
  },
};

static const ci_uint32 tx_datapaths[] = {
  EF_MULTIARCH_DATAPATH_FF,
  EF_MULTIARCH_DATAPATH_LLCT,
  EF_MULTIARCH_DATAPATH_AUTO,
};

static const ci_uint32 rx_datapaths[] = {
  EF_MULTIARCH_DATAPATH_FF,
  EF_MULTIARCH_DATAPATH_LLCT,
  EF_MULTIARCH_DATAPATH_BOTH,
  EF_MULTIARCH_DATAPATH_AUTO,
};

static const char* datapath_name(ci_uint32 datapath)
{
  switch( datapath ) {
  case EF_MULTIARCH_DATAPATH_FF:
    return "ff";
  case EF_MULTIARCH_DATAPATH_LLCT:
    return "llct";
  case EF_MULTIARCH_DATAPATH_BOTH:
    return "both";
  case EF_MULTIARCH_DATAPATH_AUTO:
    return "auto";
  default:
    return "unknown";
  }
}

static cicp_hwport_mask_t all_hwports(void)
{
  return cp_hwport_make_mask(HWPORT_PAIR_FF) |
         cp_hwport_make_mask(HWPORT_PAIR_LLCT) |
         cp_hwport_make_mask(HWPORT_LLCT_ONLY) |
         cp_hwport_make_mask(HWPORT_FF_ONLY);
}

static void setup_port_combinations(tcp_helper_resource_t* trs)
{
  struct net_device* nd;

  memset(trs, 0, sizeof(*trs));
  trs->netif.cplane = &mock_cplane;
  test_set_cplane_hwports(all_hwports());

  test_add_interface("multiarch", 1,
                     cp_hwport_make_mask(HWPORT_PAIR_FF) |
                     cp_hwport_make_mask(HWPORT_PAIR_LLCT));
  test_add_interface("llct-only", 2, cp_hwport_make_mask(HWPORT_LLCT_ONLY));
  test_add_interface("ff-only", 3, cp_hwport_make_mask(HWPORT_FF_ONLY));

  /* The FF and LLCT ports of the multiarch interface share a net_device. */
  nd = dev_get_by_name(NULL, "multiarch");
  test_add_hwport(HWPORT_PAIR_FF, 0, nd);
  test_add_hwport(HWPORT_PAIR_LLCT, 1, nd);

  nd = dev_get_by_name(NULL, "llct-only");
  test_add_hwport(HWPORT_LLCT_ONLY, 1, nd);

  nd = dev_get_by_name(NULL, "ff-only");
  test_add_hwport(HWPORT_FF_ONLY, 0, nd);
}

static void setup_one_two_port_nic(tcp_helper_resource_t* trs)
{
  struct net_device* nd;

  memset(trs, 0, sizeof(*trs));
  trs->netif.cplane = &mock_cplane;
  test_set_cplane_hwports(TEST_NIC_HWPORTS);

  /*
   * The physical NIC has two network interfaces.  Each interface has an FF
   * and LLCT hwport pair, identified by the shared net_device.
   */
  test_add_interface("nicp0", 1, TEST_NIC_PORT0_FF_HWPORTS |
                     TEST_NIC_PORT0_LLCT_HWPORTS);
  test_add_interface("nicp1", 2, TEST_NIC_PORT1_FF_HWPORTS |
                     TEST_NIC_PORT1_LLCT_HWPORTS);

  nd = dev_get_by_name(NULL, "nicp0");
  test_add_hwport(HWPORT_TEST_NIC_PORT0_FF, 0, nd);
  test_add_hwport(HWPORT_TEST_NIC_PORT0_LLCT, 1, nd);

  nd = dev_get_by_name(NULL, "nicp1");
  test_add_hwport(HWPORT_TEST_NIC_PORT1_FF, 0, nd);
  test_add_hwport(HWPORT_TEST_NIC_PORT1_LLCT, 1, nd);
}

static cicp_hwport_mask_t
expected_tx_hwports(const struct port_combination* ports, ci_uint32 datapath)
{
  switch( datapath ) {
  case EF_MULTIARCH_DATAPATH_FF:
    return ports->ff_hwports;
  case EF_MULTIARCH_DATAPATH_LLCT:
    return ports->llct_hwports;
  case EF_MULTIARCH_DATAPATH_AUTO:
    return ports->llct_hwports ? ports->llct_hwports : ports->ff_hwports;
  default:
    return 0;
  }
}

static cicp_hwport_mask_t
expected_rx_hwports(const struct port_combination* ports, ci_uint32 datapath)
{
  switch( datapath ) {
  case EF_MULTIARCH_DATAPATH_FF:
    return ports->ff_hwports;
  case EF_MULTIARCH_DATAPATH_LLCT:
    return ports->llct_hwports;
  case EF_MULTIARCH_DATAPATH_BOTH:
    return ports->ff_hwports && ports->llct_hwports ?
           ports->ff_hwports | ports->llct_hwports : 0;
  case EF_MULTIARCH_DATAPATH_AUTO:
    if( ports->ff_hwports && ports->llct_hwports )
      return ports->ff_hwports | ports->llct_hwports;
    return ports->llct_hwports ? ports->llct_hwports : ports->ff_hwports;
  default:
    return 0;
  }
}

static cicp_hwport_mask_t
blacklisted_hwports(unsigned blacklist_combination)
{
  return (cicp_hwport_mask_t) blacklist_combination <<
         HWPORT_TEST_NIC_PORT0_FF;
}

static int hwport_count(cicp_hwport_mask_t hwports)
{
  int count = 0;

  while( hwports != 0 ) {
    ++count;
    hwports &= hwports - 1;
  }
  return count;
}

/* Expected selection for the two-port multiarch NIC under the presence rule.
 *
 * Each port is a pair {FF, LLCT}.  After removing the blacklisted hwports, a
 * port is "present" if it retains at least one hwport, in which case it must be
 * able to serve each requested non-auto datapath.  A port reduced to a single
 * hwport behaves as an ff-only / llct-only interface. */
struct expected_selection {
  cicp_hwport_mask_t tx_mask;
  cicp_hwport_mask_t rx_mask;
  cicp_hwport_mask_t discovered;
  int nic_n;
  int rc;
};

static struct expected_selection
compute_expected(cicp_hwport_mask_t blacklist, ci_uint32 tx, ci_uint32 rx)
{
  cicp_hwport_mask_t surviving = TEST_NIC_HWPORTS & ~blacklist;
  cicp_hwport_mask_t ff = surviving & TEST_NIC_FF_HWPORTS;
  cicp_hwport_mask_t llct = surviving & TEST_NIC_LLCT_HWPORTS;
  /* A pair survives intact only when both of its hwports remain. */
  cicp_hwport_mask_t paired_ff = 0, paired_llct = 0;
  cicp_hwport_mask_t singleton_ff, singleton_llct;
  struct expected_selection e;
  int tx_ok = 1, rx_ok = 1;

  if( (surviving & (TEST_NIC_PORT0_FF_HWPORTS | TEST_NIC_PORT0_LLCT_HWPORTS)) ==
      (TEST_NIC_PORT0_FF_HWPORTS | TEST_NIC_PORT0_LLCT_HWPORTS) ) {
    paired_ff |= TEST_NIC_PORT0_FF_HWPORTS;
    paired_llct |= TEST_NIC_PORT0_LLCT_HWPORTS;
  }
  if( (surviving & (TEST_NIC_PORT1_FF_HWPORTS | TEST_NIC_PORT1_LLCT_HWPORTS)) ==
      (TEST_NIC_PORT1_FF_HWPORTS | TEST_NIC_PORT1_LLCT_HWPORTS) ) {
    paired_ff |= TEST_NIC_PORT1_FF_HWPORTS;
    paired_llct |= TEST_NIC_PORT1_LLCT_HWPORTS;
  }
  singleton_ff = ff & ~paired_ff;
  singleton_llct = llct & ~paired_llct;

  switch( tx ) {
  case EF_MULTIARCH_DATAPATH_FF:
    e.tx_mask = ff;
    tx_ok = (singleton_llct == 0);
    break;
  case EF_MULTIARCH_DATAPATH_LLCT:
    e.tx_mask = llct;
    tx_ok = (singleton_ff == 0);
    break;
  default: /* auto */
    e.tx_mask = llct | singleton_ff;
    break;
  }

  switch( rx ) {
  case EF_MULTIARCH_DATAPATH_FF:
    e.rx_mask = ff;
    rx_ok = (singleton_llct == 0);
    break;
  case EF_MULTIARCH_DATAPATH_LLCT:
    e.rx_mask = llct;
    rx_ok = (singleton_ff == 0);
    break;
  case EF_MULTIARCH_DATAPATH_BOTH:
    e.rx_mask = paired_ff | paired_llct;
    rx_ok = (singleton_ff == 0 && singleton_llct == 0);
    break;
  default: /* auto */
    e.rx_mask = ff | llct;
    break;
  }

  e.rc = (tx_ok && rx_ok && e.tx_mask != 0 && e.rx_mask != 0) ? 0 : -ENODEV;
  e.discovered = e.tx_mask | e.rx_mask;
  e.nic_n = hwport_count(e.discovered);
  return e;
}

static cicp_hwport_mask_t discovered_hwports(const tcp_helper_resource_t* trs)
{
  cicp_hwport_mask_t hwports = 0;
  int hwport;

  for( hwport = 0; hwport < CI_CFG_MAX_HWPORTS; ++hwport ) {
    if( trs->netif.hwport_to_intf_i[hwport] != -1 )
      hwports |= cp_hwport_make_mask(hwport);
  }
  return hwports;
}

static void test_datapath_matrix(void)
{
  unsigned i, tx_i, rx_i;

  for( i = 0; i < sizeof(port_combinations) / sizeof(port_combinations[0]);
       ++i ) {
    const struct port_combination* ports = &port_combinations[i];

    for( tx_i = 0; tx_i < sizeof(tx_datapaths) / sizeof(tx_datapaths[0]);
         ++tx_i ) {
      for( rx_i = 0; rx_i < sizeof(rx_datapaths) / sizeof(rx_datapaths[0]);
           ++rx_i ) {
        tcp_helper_resource_t trs;
        cicp_hwport_mask_t expected_tx;
        cicp_hwport_mask_t expected_rx;
        int expected_rc;
        int rc;

        setup_port_combinations(&trs);
        snprintf(NI_OPTS(&trs.netif).iface_whitelist,
                 sizeof(NI_OPTS(&trs.netif).iface_whitelist), "%s",
                 ports->name);
        NI_OPTS(&trs.netif).multiarch_tx_datapath = tx_datapaths[tx_i];
        NI_OPTS(&trs.netif).multiarch_rx_datapath = rx_datapaths[rx_i];

        expected_tx = expected_tx_hwports(ports, tx_datapaths[tx_i]);
        expected_rx = expected_rx_hwports(ports, rx_datapaths[rx_i]);
        expected_rc = expected_tx != 0 && expected_rx != 0 ? 0 : -ENODEV;

        diag("%s: available hwports: ff=%#x llct=%#x; tx=%s rx=%s",
             ports->name, (unsigned) ports->ff_hwports,
             (unsigned) ports->llct_hwports,
             datapath_name(tx_datapaths[tx_i]),
             datapath_name(rx_datapaths[rx_i]));
        rc = oo_get_nics(&trs, -1);
        if( rc != expected_rc )
          diag("%s: tx=%s rx=%s: expected rc=%d, got rc=%d",
               ports->name, datapath_name(tx_datapaths[tx_i]),
               datapath_name(rx_datapaths[rx_i]), expected_rc, rc);
        ok(rc == expected_rc, "%s: tx=%s rx=%s expects rc=%d",
           ports->name, datapath_name(tx_datapaths[tx_i]),
           datapath_name(rx_datapaths[rx_i]), expected_rc);
        ok(trs.netif.tx_hwport_mask == expected_tx,
           "%s: tx=%s rx=%s selects expected TX hwports %#x",
           ports->name, datapath_name(tx_datapaths[tx_i]),
           datapath_name(rx_datapaths[rx_i]), (unsigned) expected_tx);
        ok(trs.netif.rx_hwport_mask == expected_rx,
           "%s: tx=%s rx=%s selects expected RX hwports %#x",
           ports->name, datapath_name(tx_datapaths[tx_i]),
           datapath_name(rx_datapaths[rx_i]), (unsigned) expected_rx);

        test_cleanup();
      }
    }
  }
}

static void test_module_blacklist_datapath_matrix(void)
{
  unsigned blacklist_i, tx_i, rx_i;

  for( blacklist_i = 0; blacklist_i < 1u << 4; ++blacklist_i ) {
    cicp_hwport_mask_t blacklist = blacklisted_hwports(blacklist_i);

    for( tx_i = 0; tx_i < sizeof(tx_datapaths) / sizeof(tx_datapaths[0]);
         ++tx_i ) {
      for( rx_i = 0; rx_i < sizeof(rx_datapaths) / sizeof(rx_datapaths[0]);
           ++rx_i ) {
        tcp_helper_resource_t trs;
        struct expected_selection e;
        int rc;

        setup_one_two_port_nic(&trs);
        test_clear_module_whitelist();
        test_set_module_blacklist(blacklist);
        NI_OPTS(&trs.netif).multiarch_tx_datapath = tx_datapaths[tx_i];
        NI_OPTS(&trs.netif).multiarch_rx_datapath = rx_datapaths[rx_i];

        e = compute_expected(blacklist, tx_datapaths[tx_i], rx_datapaths[rx_i]);

        diag("one two-port multiarch NIC: blacklist=%#x; tx=%s rx=%s",
             (unsigned) blacklist,
             datapath_name(tx_datapaths[tx_i]),
             datapath_name(rx_datapaths[rx_i]));
        rc = oo_get_nics(&trs, -1);
        if( rc != e.rc )
          diag("blacklist=%#x: tx=%s rx=%s: expected rc=%d, got rc=%d",
               (unsigned) blacklist, datapath_name(tx_datapaths[tx_i]),
               datapath_name(rx_datapaths[rx_i]), e.rc, rc);
        ok(rc == e.rc, "blacklist=%#x: tx=%s rx=%s expects rc=%d",
           (unsigned) blacklist, datapath_name(tx_datapaths[tx_i]),
           datapath_name(rx_datapaths[rx_i]), e.rc);
        ok(trs.netif.tx_hwport_mask == e.tx_mask,
           "blacklist=%#x: tx=%s rx=%s selects TX hwports %#x",
           (unsigned) blacklist, datapath_name(tx_datapaths[tx_i]),
           datapath_name(rx_datapaths[rx_i]), (unsigned) e.tx_mask);
        ok(trs.netif.rx_hwport_mask == e.rx_mask,
           "blacklist=%#x: tx=%s rx=%s selects RX hwports %#x",
           (unsigned) blacklist, datapath_name(tx_datapaths[tx_i]),
           datapath_name(rx_datapaths[rx_i]), (unsigned) e.rx_mask);
        ok(discovered_hwports(&trs) == e.discovered,
           "blacklist=%#x: tx=%s rx=%s discovers hwports %#x",
           (unsigned) blacklist, datapath_name(tx_datapaths[tx_i]),
           datapath_name(rx_datapaths[rx_i]),
           (unsigned) e.discovered);
        ok(trs.netif.nic_n == e.nic_n,
           "blacklist=%#x: tx=%s rx=%s discovers %d NICs",
           (unsigned) blacklist, datapath_name(tx_datapaths[tx_i]),
           datapath_name(rx_datapaths[rx_i]), e.nic_n);

        test_cleanup();
      }
    }
  }
}

static void test_module_whitelist(void)
{
  static const struct {
    const char* name;
    cicp_hwport_mask_t whitelist;
    cicp_hwport_mask_t tx_mask;
    cicp_hwport_mask_t rx_mask;
    cicp_hwport_mask_t multiarch_mask;
    int rc;
  } cases[] = {
    {
      .name = "intact pair",
      .whitelist = TEST_NIC_PORT0_FF_HWPORTS |
                   TEST_NIC_PORT0_LLCT_HWPORTS,
      .tx_mask = TEST_NIC_PORT0_LLCT_HWPORTS,
      .rx_mask = TEST_NIC_PORT0_FF_HWPORTS |
                 TEST_NIC_PORT0_LLCT_HWPORTS,
      .multiarch_mask = TEST_NIC_PORT0_FF_HWPORTS |
                        TEST_NIC_PORT0_LLCT_HWPORTS,
      .rc = 0,
    },
    {
      .name = "FF half only",
      .whitelist = TEST_NIC_PORT0_FF_HWPORTS,
      .tx_mask = TEST_NIC_PORT0_FF_HWPORTS,
      .rx_mask = TEST_NIC_PORT0_FF_HWPORTS,
      .rc = 0,
    },
    {
      .name = "LLCT half only",
      .whitelist = TEST_NIC_PORT0_LLCT_HWPORTS,
      .tx_mask = TEST_NIC_PORT0_LLCT_HWPORTS,
      .rx_mask = TEST_NIC_PORT0_LLCT_HWPORTS,
      .rc = 0,
    },
    {
      .name = "no hwports",
      .rc = -ENODEV,
    },
  };
  unsigned i;

  for( i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i ) {
    const cicp_hwport_mask_t discovered =
      cases[i].tx_mask | cases[i].rx_mask;
    tcp_helper_resource_t trs;
    int rc;

    setup_one_two_port_nic(&trs);
    test_set_module_whitelist(cases[i].whitelist);
    NI_OPTS(&trs.netif).multiarch_tx_datapath =
      EF_MULTIARCH_DATAPATH_AUTO;
    NI_OPTS(&trs.netif).multiarch_rx_datapath =
      EF_MULTIARCH_DATAPATH_AUTO;

    diag("one two-port multiarch NIC: module whitelist %s=%#x",
         cases[i].name, (unsigned) cases[i].whitelist);
    rc = oo_get_nics(&trs, -1);
    ok(rc == cases[i].rc, "whitelist %s: expects rc=%d",
       cases[i].name, cases[i].rc);
    ok(trs.netif.tx_hwport_mask == cases[i].tx_mask,
       "whitelist %s: selects TX hwports %#x",
       cases[i].name, (unsigned) cases[i].tx_mask);
    ok(trs.netif.rx_hwport_mask == cases[i].rx_mask,
       "whitelist %s: selects RX hwports %#x",
       cases[i].name, (unsigned) cases[i].rx_mask);
    ok(trs.netif.multiarch_hwport_mask == cases[i].multiarch_mask,
       "whitelist %s: identifies multiarch hwports %#x",
       cases[i].name, (unsigned) cases[i].multiarch_mask);
    ok(discovered_hwports(&trs) == discovered,
       "whitelist %s: discovers hwports %#x",
       cases[i].name, (unsigned) discovered);
    ok(trs.netif.nic_n == hwport_count(discovered),
       "whitelist %s: discovers %d NICs",
       cases[i].name, hwport_count(discovered));

    test_cleanup();
  }
}

static void test_auto_all_interfaces(void)
{
  tcp_helper_resource_t trs;
  int rc;

  setup_port_combinations(&trs);
  NI_OPTS(&trs.netif).multiarch_tx_datapath = EF_MULTIARCH_DATAPATH_AUTO;
  NI_OPTS(&trs.netif).multiarch_rx_datapath = EF_MULTIARCH_DATAPATH_AUTO;

  diag("all interfaces: available hwports: multiarch=ff:%#x,llct:%#x "
       "llct-only=llct:%#x ff-only=ff:%#x; tx=auto rx=auto",
       (unsigned) HWPORT_MASK(HWPORT_PAIR_FF),
       (unsigned) HWPORT_MASK(HWPORT_PAIR_LLCT),
       (unsigned) HWPORT_MASK(HWPORT_LLCT_ONLY),
       (unsigned) HWPORT_MASK(HWPORT_FF_ONLY));
  rc = oo_get_nics(&trs, -1);
  ok(rc == 0, "auto with all interfaces: success");
  ok(trs.netif.tx_hwport_mask ==
     (cp_hwport_make_mask(HWPORT_PAIR_LLCT) |
      cp_hwport_make_mask(HWPORT_LLCT_ONLY) |
      cp_hwport_make_mask(HWPORT_FF_ONLY)),
     "auto with all interfaces: TX prefers LLCT and falls back to FF");
  ok(trs.netif.rx_hwport_mask == all_hwports(),
     "auto with all interfaces: RX prefers both, then LLCT, then FF");

  test_cleanup();
}

static void test_auto_respects_blacklist(void)
{
  tcp_helper_resource_t trs;
  int rc;

  setup_port_combinations(&trs);
  snprintf(NI_OPTS(&trs.netif).iface_blacklist,
           sizeof(NI_OPTS(&trs.netif).iface_blacklist), "%s", "multiarch");
  NI_OPTS(&trs.netif).multiarch_tx_datapath = EF_MULTIARCH_DATAPATH_AUTO;
  NI_OPTS(&trs.netif).multiarch_rx_datapath = EF_MULTIARCH_DATAPATH_AUTO;

  diag("multiarch blacklisted: available hwports: llct-only=llct:%#x "
       "ff-only=ff:%#x; tx=auto rx=auto",
       (unsigned) HWPORT_MASK(HWPORT_LLCT_ONLY),
       (unsigned) HWPORT_MASK(HWPORT_FF_ONLY));
  rc = oo_get_nics(&trs, -1);
  ok(rc == 0, "auto with multiarch blacklisted: success");
  ok(trs.netif.tx_hwport_mask ==
     (cp_hwport_make_mask(HWPORT_LLCT_ONLY) |
      cp_hwport_make_mask(HWPORT_FF_ONLY)),
     "auto with multiarch blacklisted: TX uses remaining interfaces");
  ok(trs.netif.rx_hwport_mask ==
     (cp_hwport_make_mask(HWPORT_LLCT_ONLY) |
      cp_hwport_make_mask(HWPORT_FF_ONLY)),
     "auto with multiarch blacklisted: RX uses remaining interfaces");

  test_cleanup();
}

int test_multiarch_datapath(void)
{
  /* Three port combinations, three TX settings, four RX settings, and
   * return-code/TX-mask/RX-mask checks for every combination.  The
   * module blacklist matrix adds five checks for every mask and TX/RX pair,
   * and the four module whitelist cases add six checks each. */
  plan(3 * 3 * 4 * 3 + 3 + 3 + (1 << 4) * 3 * 4 * 5 + 4 * 6);

  test_datapath_matrix();
  test_module_blacklist_datapath_matrix();
  test_module_whitelist();
  test_auto_all_interfaces();
  test_auto_respects_blacklist();

  return exit_status();
}
