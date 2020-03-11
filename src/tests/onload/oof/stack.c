#include "stack.h"
#include "onload_kernel_compat.h"
#include "oof_test.h"
#include "cplane.h"
#include "utils.h"
#include "tcp_filters_internal.h"
#include "../../tap/tap.h"
#include "stack_interface.h"

#include <ci/tools.h>
#include <ci/net/ipv4.h>
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>
#include <arpa/inet.h>

static int thr_id = 0;

static void ooft_free_filter_list(ci_dllist* list);

/* ---------------------------------------
 * Test data structure management
 * --------------------------------------- */
tcp_helper_resource_t* ooft_alloc_stack(int n_eps)
{
  int oof_preexisted;
  tcp_helper_resource_t* thr = calloc(1, sizeof(tcp_helper_resource_t));
  TEST(thr);

  thr->eps = calloc(n_eps, sizeof(struct ooft_endpoint));
  ci_assert(thr->eps);
  thr->n_eps = n_eps;
  thr->stack_id = thr_id++;
  thr->ns = current_ns();
  thr->ofn = oo_filter_ns_get(&efab_tcp_driver, current->nsproxy->net_ns, &oof_preexisted);

  return thr;
}


void ooft_free_stack(tcp_helper_resource_t* thr)
{
  oo_filter_ns_put(&efab_tcp_driver, thr->ofn);
  free(thr->eps);
  free(thr);
}


struct ooft_endpoint* ooft_alloc_endpoint(tcp_helper_resource_t* thr,
                                          int proto,
                                          uint32_t laddr_be, uint16_t lport_be,
                                          uint32_t raddr_be, uint32_t rport_be)
{
  int i;
  struct ooft_endpoint* ep = NULL;

  for(i = 0; i < thr->n_eps; i++) {
    if(thr->eps[i].state == OOFT_EP_FREE) {
      ep = &thr->eps[i];

      ep->state = OOFT_EP_IN_USE;
      ep->thr = thr;
      oof_socket_ctor(&ep->skf);
      ep->proto = proto;
      ep->laddr_be = laddr_be;
      ep->raddr_be = raddr_be;
      ep->lport_be = lport_be;
      ep->rport_be = rport_be;

      ci_dllist_init(&ep->sw_filters_to_add);
      ci_dllist_init(&ep->sw_filters_to_remove);

      ci_dllist_init(&ep->sw_filters_added);
      ci_dllist_init(&ep->sw_filters_removed);

      ci_dllist_init(&ep->sw_filters_bad_add);
      ci_dllist_init(&ep->sw_filters_bad_remove);
      break;
    }
  }

  return ep;
}


void ooft_free_endpoint(struct ooft_endpoint* ep)
{
  ci_assert_equal(ep->state, OOFT_EP_IN_USE);
  oof_socket_dtor(&ep->skf);

  ooft_free_filter_list(&ep->sw_filters_to_add);
  ooft_free_filter_list(&ep->sw_filters_to_remove);

  ooft_free_filter_list(&ep->sw_filters_added);
  ooft_free_filter_list(&ep->sw_filters_removed);

  ooft_free_filter_list(&ep->sw_filters_bad_add);
  ooft_free_filter_list(&ep->sw_filters_bad_remove);

  memset(ep, 0, sizeof(struct ooft_endpoint));
}


int ooft_endpoint_id(struct ooft_endpoint* ep)
{
  return (ep - ep->thr->eps);
}


/* ---------------------------------------
 * Utility functions to add sockets to oof
 * --------------------------------------- */
int ooft_endpoint_add(struct ooft_endpoint* ep, int flags)
{
  ci_addr_t laddr, raddr;

  laddr = CI_ADDR_FROM_IP4(ep->laddr_be);
  raddr = CI_ADDR_FROM_IP4(ep->raddr_be);
  return oof_socket_add(ep->thr->ofn->ofn_filter_manager, &ep->skf,
                        flags, ep->proto, AF_SPACE_FLAG_IP4, laddr,
                        ep->lport_be, raddr, ep->rport_be, NULL);
}


int ooft_endpoint_mcast_add(struct ooft_endpoint* ep, unsigned group,
                            struct ooft_ifindex* idx)
{
  return oof_socket_mcast_add(ep->thr->ofn->ofn_filter_manager, &ep->skf,
                              group, idx->id);
}


/* ---------------------------------------
 * Functions to handle test SW filters
 * --------------------------------------- */
struct ooft_sw_filter* ooft_endpoint_add_sw_filter(ci_dllist* list, int proto,
                                               unsigned laddr_be, int lport_be,
                                               unsigned raddr_be, int rport_be)
{
  struct ooft_sw_filter* filter = malloc(sizeof(struct ooft_sw_filter));
  TEST(filter);

  filter->proto = proto;
  filter->laddr_be = laddr_be;
  filter->lport_be = lport_be;
  filter->raddr_be = raddr_be;
  filter->rport_be = rport_be;

  ci_dllist_push_tail(list, &filter->socket_link);

  return filter;
}


int ooft_sw_filter_match(struct ooft_sw_filter* filter, unsigned laddr,
                         int lport, unsigned raddr, int rport, int protocol)
{
  if( (filter->proto == protocol) &&
      (filter->laddr_be == laddr) && (filter->lport_be == lport) &&
      (filter->raddr_be == raddr) && (filter->rport_be == rport) )
    return 1;
  else
    return 0;
}


void ooft_dump_sw_filter_list(ci_dllist* list)
{
  struct ooft_sw_filter* filter;
  ci_dllink* link;

  CI_DLLIST_FOR_EACH(link, list) {
    filter = CI_CONTAINER(struct ooft_sw_filter, socket_link, link);
    diag("SW FILTER: %x "IPPORT_FMT" "IPPORT_FMT"\n", filter->proto,
           IPPORT_ARG(filter->laddr_be, filter->lport_be),
           IPPORT_ARG(filter->raddr_be, filter->rport_be));
  }
}


static void ooft_free_filter_list(ci_dllist* list)
{
  struct ooft_sw_filter* filter;

  while( ci_dllist_not_empty(list) ) {
    filter = CI_CONTAINER(struct ooft_sw_filter, socket_link,
                          ci_dllist_start(list));
    ci_dllist_remove_safe(&filter->socket_link);
    free(filter);
  }
}


void ooft_log_sw_filter_op(struct ooft_endpoint* ep,
                           struct ooft_sw_filter* filter, int expect,
                           const char* op)
{
  diag("%sSW FILTER %s: %d:%d %s "IPPORT_FMT" "IPPORT_FMT"\n",
       expect ? "EXPECT " : "", op, ep->thr->stack_id, ooft_endpoint_id(ep),
       FMT_PROTOCOL(filter->proto),
       IPPORT_ARG(filter->laddr_be, filter->lport_be),
       IPPORT_ARG(filter->raddr_be, filter->rport_be));
}


/* ---------------------------------------
 * Utility functions to handle expected filter operations
 * --------------------------------------- */


/* Expect the addition of a SW filter with the specific field values */
void ooft_endpoint_expect_sw_add(struct ooft_endpoint* ep, int proto,
                                 unsigned laddr_be, int lport_be,
                                 unsigned raddr_be, int rport_be)
{
  struct ooft_sw_filter* filter;
  filter = ooft_endpoint_add_sw_filter(&ep->sw_filters_to_add, proto,
                                       laddr_be, lport_be, raddr_be, rport_be);
  LOG_FILTER_OP(ooft_log_sw_filter_op(ep, filter, 1, "INSERT"));
}


void ooft_endpoint_expect_sw_remove(struct ooft_endpoint* ep,
                                    struct ooft_sw_filter* filter)
{
  ci_dllist_remove_safe(&filter->socket_link);
  ci_dllist_push_tail(&ep->sw_filters_to_remove, &filter->socket_link);
  LOG_FILTER_OP(ooft_log_sw_filter_op(ep, filter, 1, "REMOVE"));
}


void ooft_endpoint_expect_sw_remove_all(struct ooft_endpoint* ep)
{
  struct ooft_sw_filter* filter;

  /* We walk the list here rather than transfer it wholesale so that we
   * can log the details of each filter.
   */
  while( ci_dllist_not_empty(&ep->sw_filters_added) ) {
    filter = CI_CONTAINER(struct ooft_sw_filter, socket_link,
                          ci_dllist_start(&ep->sw_filters_added));
    ooft_endpoint_expect_sw_remove(ep, filter);
  }
}

void ooft_endpoint_expect_sw_remove_addr(struct ooft_endpoint* ep,
                                         unsigned laddr_be)
{
  struct ooft_sw_filter* filter;
  struct ooft_sw_filter* filter_tmp;

  CI_DLLIST_FOR_EACH3(struct ooft_sw_filter, filter, socket_link,
                      &ep->sw_filters_added, filter_tmp) {
    if( filter->laddr_be == laddr_be )
      ooft_endpoint_expect_sw_remove(ep, filter);
  }
}


/* Adds a filter with the supplied local address on each hwport in this
 * endpoint's namespace.  Other fields are taken from the endpoint.
 */
void ooft_endpoint_expect_hw_unicast(struct ooft_endpoint* ep,
                                     unsigned laddr_be)
{
  int i;
  unsigned hwport_mask = ep->thr->ns->hwport_mask;

  for( i = 0; i < CI_CFG_MAX_HWPORTS; i++ ) {
    if( (1 << i) & hwport_mask )
      ooft_client_expect_hw_add_ip(oo_nics[i].efrm_client,
                                   tcp_helper_rx_vi_id(ep->thr, i),
                                   tcp_helper_vi_hw_stack_id(ep->thr, i),
                                   EFX_FILTER_VID_UNSPEC,
                                   ep->proto, laddr_be, ep->lport_be,
                                   ep->raddr_be, ep->rport_be);
  }
}


/* Expect the addition of appropriate unicast filters for the supplied
 * endpoint:
 * - for wild sockets a semi-wild filter for each IP address configured in
 *   the namespace of this socket
 * - for semi-wild sockets a semi-wild filter for the socket's laddr
 * - for full-match sockets a full-match filter
 */
void ooft_endpoint_expect_unicast_filters(struct ooft_endpoint* ep, int hw)
{
  if( ep->laddr_be != INADDR_ANY ) {
    ooft_endpoint_expect_sw_add(ep, ep->proto, ep->laddr_be, ep->lport_be,
                                ep->raddr_be, ep->rport_be);
    if( hw )
      ooft_endpoint_expect_hw_unicast(ep, ep->laddr_be);
  }
  else {
    ci_dllist* idxs = &ep->thr->ns->idxs;
    ci_dllink* idx_link;
    ci_dllink* addr_link;
    struct ooft_ifindex* idx;
    struct ooft_addr* addr;

    CI_DLLIST_FOR_EACH(idx_link, idxs) {
      idx = CI_CONTAINER(struct ooft_ifindex, ns_link, idx_link);
      CI_DLLIST_FOR_EACH(addr_link, &idx->addrs) {
        addr = CI_CONTAINER(struct ooft_addr, idx_link, addr_link);
        ooft_endpoint_expect_sw_add(ep, ep->proto, addr->laddr_be,
                                    ep->lport_be, ep->raddr_be, ep->rport_be);
        if( hw )
          ooft_endpoint_expect_hw_unicast(ep, addr->laddr_be);
      }
    }
  }
}


/* Expect the addition of multicast filters for the supplied endpoint,
 * populating the non-multicast laddr fields from the socket.
 */
void ooft_endpoint_expect_multicast_filters(struct ooft_endpoint* ep,
                                            struct ooft_ifindex* idx,
                                            unsigned laddr_be)
{
  ci_assert_equal(ep->proto, IPPROTO_UDP);

  ooft_endpoint_expect_sw_add(ep, ep->proto, laddr_be, ep->lport_be,
                              ep->raddr_be, ep->rport_be);

  int i;
  int vlans;
  struct ooft_hwport* hw;
  for( i = 0; i < CI_CFG_MAX_HWPORTS; i++ ) {
    if( (1 << i) & idx->hwport_mask ) {
      hw = HWPORT_FROM_CLIENT(oo_nics[i].efrm_client);
      vlans = hw->vlans;
      ooft_client_expect_hw_add_ip(oo_nics[i].efrm_client,
                                   tcp_helper_rx_vi_id(ep->thr, i),
                                   tcp_helper_vi_hw_stack_id(ep->thr, i),
                                   vlans ? idx->vlan_id:EFX_FILTER_VID_UNSPEC,
                                   ep->proto, laddr_be, ep->lport_be,
                                   vlans ? 0 : ep->raddr_be,
                                   vlans ? 0 : ep->rport_be);
    }
  }
}


/* Check that everything we expect to happen has, and that nothing that we
 * didn't expect happened for all sockets in the stack.  Returns 0 if
 * everything is ok.
 */
int ooft_stack_check_sw_filters(tcp_helper_resource_t* thr)
{
  int i;
  int rc = 0;

  for(i = 0; i < thr->n_eps; i++)
    if(thr->eps[i].state != OOFT_EP_FREE)
      rc |= ooft_endpoint_check_sw_filters(&thr->eps[i]);

  return rc;
}


/* Check that everything we expect to happen has, and that nothing that we
 * didn't expect happened.  Returns 0 if everything is ok.
 */
int ooft_endpoint_check_sw_filters(struct ooft_endpoint* ep)
{
  int rc = 0;

  if( ci_dllist_not_empty(&ep->sw_filters_to_add) ) {
    diag("Socket %d expected to have added:\n", oof_cb_socket_id(&ep->skf));
    ooft_dump_sw_filter_list(&ep->sw_filters_to_add);
    rc = 1;
  }

  if( ci_dllist_not_empty(&ep->sw_filters_to_remove) ) {
    diag("Socket %d expected to have removed:\n", oof_cb_socket_id(&ep->skf));
    ooft_dump_sw_filter_list(&ep->sw_filters_to_remove);
    rc = 1;
  }

  if( ci_dllist_not_empty(&ep->sw_filters_bad_add) ) {
    diag("Socket %d did not expect to have added:\n",
         oof_cb_socket_id(&ep->skf));
    ooft_dump_sw_filter_list(&ep->sw_filters_bad_add);
    rc = 1;
  }

  if( ci_dllist_not_empty(&ep->sw_filters_bad_remove) ) {
    diag("Socket %d did not expect to have removed:\n",
         oof_cb_socket_id(&ep->skf));
    ooft_dump_sw_filter_list(&ep->sw_filters_bad_remove);
    rc = 1;
  }

  return rc;
}

