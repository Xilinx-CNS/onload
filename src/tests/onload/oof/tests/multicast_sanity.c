#include "../onload_kernel_compat.h"
#include "../stack.h"
#include "../../tap/tap.h"
#include "../oof_test.h"
#include "../cplane.h"
#include "../utils.h"
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>
#include <arpa/inet.h>


int test_multicast_sanity(void)
{
  tcp_helper_resource_t* thr1;
  struct ooft_endpoint* e1;
  struct ooft_ifindex* idx;
  const char* group = "230.1.2.3";
  int rc;

  new_test();
  plan(6);

  test_alloc(32);

  thr1 = ooft_alloc_stack(64);

  TRY(ooft_default_cplane_init(current_ns()));
  TEST_DEBUG(oof_onload_manager_dump(&efab_tcp_driver, dump, "\n"));

  e1 = ooft_alloc_endpoint(thr1, IPPROTO_UDP, INADDR_ANY, htons(2000),
                           INADDR_ANY, 0);

  ooft_endpoint_expect_unicast_filters(e1, 1);
  rc = ooft_endpoint_add(e1, 0);
  cmp_ok(rc, "==", 0, "add endpoint");

  idx = IDX_FROM_CP_LINK(ci_dllist_head(&cp->idxs));
  ooft_endpoint_expect_multicast_filters(e1, idx, inet_addr(group));
  rc = ooft_endpoint_mcast_add(e1, inet_addr(group), idx);
  cmp_ok(rc, "==", 0, "mcast add endpoint");

  TEST_DEBUG(oof_onload_manager_dump(&efab_tcp_driver, dump, "\n"));

  rc = ooft_endpoint_check_sw_filters(e1);
  cmp_ok(rc, "==", 0, "check sw filters");
  rc = ooft_ns_check_hw_filters(thr1->ns);
  cmp_ok(rc, "==", 0, "check hw filters");

  ooft_endpoint_expect_sw_remove_all(e1);
  ooft_cplane_expect_hw_remove_all(cp);
  oof_socket_del(thr1->ofn->ofn_filter_manager, &e1->skf);

  rc = ooft_endpoint_check_sw_filters(e1);
  cmp_ok(rc, "==", 0, "check sw filters");
  rc = ooft_ns_check_hw_filters(thr1->ns);
  cmp_ok(rc, "==", 0, "check hw filters");

  ooft_free_stack(thr1);
  test_cleanup();

  done_testing();
}

