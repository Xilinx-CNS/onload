#include "onload_kernel_compat.h"
#include <onload/oof_interface.h>
#include <ci/tools.h>
#include <onload/oof_hw_filter.h>
#include <onload/oof_socket.h>
#include <stdlib.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <onload/oof_onload.h>

#include "include/onload/tcp_driver.h"
#include "../../tap/tap.h"
#include "stack.h"
#include "oof_test.h"
#include "cplane.h"
#include "utils.h"

int oo_debug_bits = 0x1;
int scalable_filter_gid = -1;

struct ooft_cplane* cp;
struct efab_tcp_driver_s efab_tcp_driver;
struct ooft_task* current;

void vdump(const char* fmt, va_list args)
{
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
}

void dump(void* opaque, const char* fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  vdump(fmt, args);
  va_end(args);
}


struct net* current_ns(void)
{
  return current->nsproxy->net_ns;
}


struct ooft_task* context_alloc(struct net* ns)
{
  struct ooft_task* task = malloc(sizeof(struct ooft_task));
  TEST(task);

  task->nsproxy = malloc(sizeof(struct ooft_proxy));
  TEST(task->nsproxy);

  ooft_namespace_get(ns);
  task->nsproxy->net_ns = ns;

  return task;
}


void context_free(struct ooft_task* task)
{
  ooft_namespace_put(task->nsproxy->net_ns);
  free(task->nsproxy);
  free(task);
}


void test_alloc(int max_addrs)
{
  cp = ooft_alloc_cplane();
  TEST(cp);

  struct net* ns = ooft_alloc_namespace(cp);
  TEST(ns);

  current = context_alloc(ns);
  TEST(current);

  memset(&efab_tcp_driver, 0, sizeof(efab_tcp_driver));
  TEST(oo_filter_ns_manager_ctor(&efab_tcp_driver) == 0);
}


void test_cleanup(void)
{
  struct net* ns = current_ns();

  oo_filter_ns_manager_dtor(&efab_tcp_driver);
  context_free(current);
  ooft_free_namespace(ns);
  ooft_free_cplane(cp);
}


int main(int argc, char* argv[])
{
  int all = (argc == 1);

  if( all || !strcmp(argv[1], "sanity") )
    test_sanity();

  if( all || !strcmp(argv[1], "multicast_sanity") )
    test_multicast_sanity();

  if( all || !strcmp(argv[1], "namespace_sanity") )
    test_namespace_sanity();

  if( all || !strcmp(argv[1], "namespace_macvlan_move") )
    test_namespace_macvlan_move();

  return 0;
}
