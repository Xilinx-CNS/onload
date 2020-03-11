#include "onload_kernel_compat.h"
#include <ci/tools.h>
#include <ci/net/ipv4.h>

#include "efrm.h"
#include "../../tap/tap.h"
#include "utils.h"
#include "oof_test.h"
#include "tcp_filters_internal.h"
#include "cplane.h"

struct oo_nic oo_nics[CI_CFG_MAX_HWPORTS];

void ooft_init_efrm_client(struct efrm_client* client, int hwport)
{
  ci_dllist_init(&client->hw_filters_to_add);
  ci_dllist_init(&client->hw_filters_to_remove);

  ci_dllist_init(&client->hw_filters_added);
  ci_dllist_init(&client->hw_filters_removed);

  ci_dllist_init(&client->hw_filters_bad_add);

  client->filter_id = 0;
  client->hwport = hwport;
  oo_nics[hwport].efrm_client = client;
}


/* Check that everything we expect to happen has, and that nothing that we
 * didn't expect happened.  Returns 0 if everything is ok.
 */
int ooft_client_check_hw_filters(struct efrm_client* client)
{
  int rc = 0;

  if( ci_dllist_not_empty(&client->hw_filters_to_add) ) {
    diag("hwport %d expected to have added:\n", client->hwport);
    ooft_dump_hw_filter_list(&client->hw_filters_to_add);
    rc = 1;
  }

  if( ci_dllist_not_empty(&client->hw_filters_to_remove) ) {
    diag("hwport %d expected to have removed:\n", client->hwport);
    ooft_dump_hw_filter_list(&client->hw_filters_to_remove);
    rc = 1;
  }

  if( ci_dllist_not_empty(&client->hw_filters_bad_add) ) {
    diag("hwport %d did not expect to have added:\n", client->hwport);
    ooft_dump_hw_filter_list(&client->hw_filters_bad_add);
    rc = 1;
  }

  return rc;
}


int ooft_hw_filter_match(struct efx_filter_spec* spec,
                         struct ooft_hw_filter* filter)
{
  return !memcmp(spec, &filter->spec, sizeof(struct efx_filter_spec));
}


void ooft_hw_filter_expect_remove_list(ci_dllist* list)
{
  struct ooft_hw_filter* filter;

  while( ci_dllist_not_empty(list) ) {
    filter = HW_FILTER_FROM_LINK(ci_dllist_head(list));
    ci_dllist_remove_safe(&filter->client_link);
    ooft_client_expect_hw_remove(oo_nics[filter->hwport].efrm_client, filter);
  }
}


void ooft_log_hw_filter_op(struct efrm_client* client,
                           struct efx_filter_spec* spec,
                           int expect, const char* op)
{
  diag("%sHW FILTER %s: %d->%d %x %s [%x:%x] "IPPORT_FMT" "IPPORT_FMT"\n",
       expect ? "EXPECT ": "", op,
       client->hwport, spec->dmaq_id, spec->match_flags,
       FMT_PROTOCOL(spec->ip_proto), spec->outer_vid, spec->inner_vid,
       IPPORT_ARG(spec->loc_host, spec->loc_port),
       IPPORT_ARG(spec->rem_host, spec->rem_port));
}


void ooft_dump_hw_filter_list(ci_dllist* list)
{
  struct efx_filter_spec* spec;
  ci_dllink* link;

  CI_DLLIST_FOR_EACH(link, list) {
    spec = &(CI_CONTAINER(struct ooft_hw_filter, client_link, link)->spec);
    diag("HW FILTER: ->%d %x %s [%x:%x] "IPPORT_FMT" "IPPORT_FMT"\n",
       spec->dmaq_id, spec->match_flags,
       FMT_PROTOCOL(spec->ip_proto), spec->outer_vid, spec->inner_vid,
       IPPORT_ARG(spec->loc_host, spec->loc_port),
       IPPORT_ARG(spec->rem_host, spec->rem_port));
  }
}


void ooft_client_claim_added_hw_filters(struct efrm_client* client,
                                        ci_dllist* list)
{
  ci_dllist_join(list, &client->hw_filters_added);
}


struct ooft_hw_filter* ooft_client_add_hw_filter(ci_dllist* list,
                                                 struct efx_filter_spec* spec)
{
  struct ooft_hw_filter* filter = malloc(sizeof(struct ooft_hw_filter));
  TEST(filter);

  if( spec )
    memcpy(&filter->spec, spec, sizeof(struct efx_filter_spec));

  ci_dllist_push_tail(list, &filter->client_link);
  return filter;
}


void ooft_client_expect_hw_remove(struct efrm_client* client,
                                  struct ooft_hw_filter* filter)
{
  ci_dllist_remove_safe(&filter->client_link);
  ci_dllist_push_tail(&client->hw_filters_to_remove, &filter->client_link);
  LOG_FILTER_OP(ooft_log_hw_filter_op(client, &filter->spec, 1, "REMOVE"));
}


void ooft_client_expect_hw_remove_all(struct efrm_client* client)
{
  ooft_hw_filter_expect_remove_list(&client->hw_filters_added);
}


/* Expect the addition of a HW filter with the specific field values */
void ooft_client_expect_hw_add_ip(struct efrm_client* client, int dmaq_id,
                                  int stack_id, int vlan, int proto,
                                  unsigned laddr_be, int lport_be,
                                  unsigned raddr_be, int rport_be)
{
  struct ooft_hw_filter* filter;
  filter = ooft_client_add_hw_filter(&client->hw_filters_to_add, NULL);
  struct efx_filter_spec* spec = &filter->spec;
  int rc;

  int flags = EFX_FILTER_FLAG_RX_SCATTER;
  efx_filter_init_rx(spec, EFX_FILTER_PRI_REQUIRED, flags, dmaq_id);
  efx_filter_set_stack_id(spec, stack_id);
  if( raddr_be != 0 )
    rc = efx_filter_set_ipv4_full(spec, proto, laddr_be, lport_be,
                                  raddr_be, rport_be);
  else
    rc = efx_filter_set_ipv4_local(spec, proto, laddr_be, lport_be);
  ci_assert_equal(rc, 0);
  (void) rc;

  if( vlan != EFX_FILTER_VID_UNSPEC )
    rc = efx_filter_set_eth_local(spec, vlan, NULL);
  ci_assert_equal(rc, 0);

  LOG_FILTER_OP(ooft_log_hw_filter_op(client, spec, 1, "INSERT"));
}


int ooft_client_hw_filter_match(struct efx_filter_spec* spec1,
                                struct efx_filter_spec* spec2,
                                unsigned match_flags)
{
  if( match_flags & EFX_FILTER_MATCH_REM_HOST ) {
    if( spec1->rem_host[0] != spec2->rem_host[0] )
      return 0;
  }
  if( match_flags & EFX_FILTER_MATCH_LOC_HOST ) {
    if( spec1->loc_host[0] != spec2->loc_host[0] )
      return 0;
  }
  if( match_flags & EFX_FILTER_MATCH_REM_MAC ) {
    if( memcmp(spec1->rem_mac, spec2->rem_mac, ETH_ALEN) )
      return 0;
  }
  if( match_flags & EFX_FILTER_MATCH_REM_PORT ) {
    if( spec1->rem_port != spec2->rem_port )
      return 0;
  }
  if( match_flags & EFX_FILTER_MATCH_LOC_MAC ) {
    if( memcmp(spec1->loc_mac, spec2->loc_mac, ETH_ALEN) )
      return 0;
  }
  if( match_flags & EFX_FILTER_MATCH_LOC_PORT ) {
    if( spec1->loc_port != spec2->loc_port )
      return 0;
  }
  if( match_flags & EFX_FILTER_MATCH_ETHER_TYPE ) {
    if( spec1->ether_type != spec2->ether_type )
      return 0;
  }
  if( match_flags & EFX_FILTER_MATCH_INNER_VID ) {
    if( spec1->inner_vid != spec2->inner_vid )
      return 0;
  }
  if( match_flags & EFX_FILTER_MATCH_OUTER_VID ) {
    if( spec1->outer_vid != spec2->outer_vid )
      return 0;
  }
  if( match_flags & EFX_FILTER_MATCH_IP_PROTO ) {
    if( spec1->ip_proto != spec2->ip_proto )
      return 0;
  }
  if( match_flags & EFX_FILTER_MATCH_ENCAP_TYPE ) {
    if( spec1->encap_type != spec2->encap_type )
      return 0;
  }
  if( match_flags & EFX_FILTER_MATCH_ENCAP_TNI ) {
    if( spec1->tni != spec2->tni )
      return 0;
  }
  if( match_flags & EFX_FILTER_MATCH_OUTER_LOC_MAC ) {
    if( memcmp(spec1->outer_loc_mac, spec2->outer_loc_mac, ETH_ALEN) )
      return 0;
  }

  return 1;
}


/* This function will remove any filters from the in list where the fields
 * specified in match_flags match the match_spec.  The removed filters are
 * then placed on the out_matches list.
 */
void ooft_client_hw_filter_matches(ci_dllist* in, ci_dllist* out_matches,
                                   struct efx_filter_spec* match_spec,
                                   unsigned match_flags)
{
  struct ooft_hw_filter* filter;
  struct ooft_hw_filter* filter_tmp;

  CI_DLLIST_FOR_EACH3(struct ooft_hw_filter, filter, client_link, in,
                      filter_tmp) {
    if( ooft_client_hw_filter_match(&filter->spec, match_spec, match_flags) ) {
      ci_dllist_remove_safe(&filter->client_link);
      ci_dllist_push_tail(out_matches, &filter->client_link);
    }
  }
}


/* This function will remove any filters from the in list that are on the
 * specificed hw port.  These filters are then place on the out_matches
 * list.
 */
void ooft_client_hw_filter_matches_hwport(ci_dllist* in,
                                          ci_dllist* out_matches,
                                          struct ooft_hwport* hw)
{
  struct ooft_hw_filter* filter;
  struct ooft_hw_filter* filter_tmp;

  CI_DLLIST_FOR_EACH3(struct ooft_hw_filter, filter, client_link, in,
                      filter_tmp) {
    if( filter->hwport == hw->id ) {
      ci_dllist_remove_safe(&filter->client_link);
      ci_dllist_push_tail(out_matches, &filter->client_link);
    }
  }
}

