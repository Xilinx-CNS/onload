/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#include "../onload_kernel_compat.h"
#include "../stack.h"
#include "../../tap/tap.h"
#include "../oof_test.h"
#include "../cplane.h"
#include "../utils.h"
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>
#include <arpa/inet.h>

enum hwport_expected {
  HWPORT_LL_ONLY,
  HWPORT_FF_ONLY,
  HWPORT_ALL,
};

unsigned hwport_expected_to_mask(struct ooft_ifindex *idx,
                                 enum hwport_expected exp)
{
  switch( exp ) {
  case HWPORT_LL_ONLY:
    return idx->hwport_mask_ll;
  case HWPORT_FF_ONLY:
    return idx->hwport_mask_ff;
  case HWPORT_ALL:
    return idx->hwport_mask;
  };

  assert(false);
  return 0;
}

void do_test(enum ooft_nic_type nic, enum ooft_rx_mode rx_mode,
             enum hwport_expected exp)
{
  struct ooft_ifindex* idx;
  tcp_helper_resource_t *thr;
  struct ooft_endpoint *e;
  const char* group = "230.1.2.3";
  unsigned hwport_mask;
  int rc;

  test_alloc(32);

  thr = ooft_alloc_stack_mode(64, rx_mode);

  TRY(ooft_cplane_init(current_ns(), nic));
  idx = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));
  hwport_mask = hwport_expected_to_mask(idx, exp);

  TEST_DEBUG(oof_onload_manager_dump(&efab_tcp_driver, dump, "\n"));

  e = ooft_alloc_endpoint(thr, IPPROTO_UDP, inet_addr(group), htons(2000),
                          INADDR_ANY, 0);

  /* Because we're bound to a multicast address we won't get filters until
   * the group is joined. */
  rc = ooft_endpoint_add(e, 0);
  cmp_ok(rc, "==", 0, "add endpoint");

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "check no sw filters");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "check no hw filters");

  /* Now join the group, which should result in both SW and HW filters. */
  ooft_endpoint_expect_multicast_filters(e, idx, hwport_mask,
                                        inet_addr(group));
  rc = ooft_endpoint_mcast_add(e, inet_addr(group), idx);
  cmp_ok(rc, "==", 0, "mcast add endpoint");

  TEST_DEBUG(oof_onload_manager_dump(&efab_tcp_driver, dump, "\n"));

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "check sw filters added");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "check hw filters added");

  ooft_endpoint_expect_sw_remove_all(e);
  ooft_endpoint_expect_multicast_filters_remove(e, idx, hwport_mask,
                                                inet_addr(group));
  oof_socket_del(thr->ofn->ofn_filter_manager, &e->skf);

  rc = ooft_endpoint_check_sw_filters(e);
  cmp_ok(rc, "==", 0, "check sw filters removed");
  rc = ooft_ns_check_hw_filters(thr->ns);
  cmp_ok(rc, "==", 0, "check hw filters removed");

  ooft_free_stack(thr);
  test_cleanup();
}

int test_multicast_local_addr(void)
{

  new_test();
  plan(32);

  do_test(OOFT_NIC_X2_LL, OOFT_RX_NONE, HWPORT_ALL);
  do_test(OOFT_NIC_X4_LL, OOFT_RX_BOTH, HWPORT_LL_ONLY);
  do_test(OOFT_NIC_X4_LL, OOFT_RX_LL, HWPORT_LL_ONLY);
  do_test(OOFT_NIC_X4_LL, OOFT_RX_FF, HWPORT_FF_ONLY);

  done_testing();
}
