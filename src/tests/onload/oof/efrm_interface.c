/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017 Xilinx, Inc. */

#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>

#include "onload_kernel_compat.h"
#include "efrm_interface.h"
#include "driverlink_interface.h"
#include "efrm.h"
#include "oof_test.h"


int efrm_filter_insert_fail_count = 0;
int efrm_filter_insert_fail_after = -1;
int efrm_filter_insert_fail_proto_mac = 0;

/* Error code returned by the fail_count / fail_after injectors.  Defaults to
 * -EBUSY (HW filter table full).  Tests can set this to e.g. -ENETDOWN to
 * simulate the NIC going away, or -EACCES to simulate a firewall block. */
int efrm_filter_insert_fail_rc = -EBUSY;

/* Redirect (filter move) failure injection.  When fail_count > 0,
 * efrm_filter_redirect removes the old filter (as a real redirect would)
 * then returns fail_rc instead of installing the new one.  Defaults to
 * -ENOENT, simulating the net driver having lost the filter; -ENODEV
 * (move not supported) is also handled identically by the OOF layer. */
int efrm_filter_redirect_fail_count = 0;
int efrm_filter_redirect_fail_rc = -ENOENT;

/* Number of explicit rollback removals expected from filters inserted earlier
 * in the same OOF operation.  Redirects remove their old filter as part of the
 * normal operation and do not consume this counter. */
int efrm_filter_rollback_remove_count = 0;
static unsigned efrm_filter_op_seq;


bool efrm_filter_insert_allowed(struct efrm_client *client, int *rxq,
                                struct efx_filter_spec *spec)
{
  ci_dllink *link;
  struct ooft_hw_filter *filter;

  /* Always allow insert for non-ll nics */
  if( (oo_nics[client->hwport].oo_nic_flags & OO_NIC_LL) == 0 )
    return true;

  /* Else check that if this filter matches an existing one, the rxq requested
   * matches too. */
  CI_DLLIST_FOR_EACH(link, &client->hw_filters_all) {
    filter = CI_CONTAINER(struct ooft_hw_filter, all_link, link);
    if( ooft_client_hw_filter_match(&filter->spec, spec, 0xffffffff) &&
        filter->spec.dmaq_id != *rxq )
      return false;
  }

  return true;
}


int efrm_filter_insert_common(struct efrm_client* client,
                              struct efx_filter_spec *spec, int *rxq,
                              unsigned pd_excl_owner,
                              const struct cpumask *mask, unsigned flags,
                              int filter_id, const char *op)
{
  /* FIXME consider handling of replace_equal */
  struct ooft_hw_filter* filter;
  ci_dllink* link;
  int rc = 0;

  if( !efrm_filter_insert_allowed(client, rxq, spec) )
    return -EPERM;

  LOG_FILTER_OP(ooft_log_hw_filter_op(client, spec, 0, op));

  CI_DLLIST_FOR_EACH(link, &client->hw_filters_to_add) {
    filter = CI_CONTAINER(struct ooft_hw_filter, client_link, link);
    if( ooft_hw_filter_match(spec, filter) ) {
      filter->op_seq = ++efrm_filter_op_seq;
      ci_dllist_remove_safe(link);
      ci_dllist_push_tail(&client->hw_filters_added, &filter->client_link);
      ci_dllist_push_tail(&client->hw_filters_all, &filter->all_link);

      if( filter_id < 0 )
        filter->filter_id = client->filter_id++;
      else
        filter->filter_id = filter_id;

      filter->hwport = client->hwport;
      rc = filter->filter_id;
      break;
    }
  }

  if( !link ) {
    ooft_client_add_hw_filter(&client->hw_filters_bad_add, spec);
    rc = -EINVAL;
  }

  *rxq = 0;
  return rc;
}

int efrm_filter_insert(struct efrm_client* client,
                       struct efx_filter_spec *spec, int *rxq,
                       unsigned pd_excl_owner, const struct cpumask *mask,
                       unsigned flags)
{
  int rc;

  if( efrm_filter_insert_fail_proto_mac &&
      (spec->match_flags & (EFX_FILTER_MATCH_IP_PROTO |
                            EFX_FILTER_MATCH_LOC_MAC)) ==
      (EFX_FILTER_MATCH_IP_PROTO | EFX_FILTER_MATCH_LOC_MAC) )
    return -EPROTONOSUPPORT;

  if( efrm_filter_insert_fail_count > 0 ) {
    --efrm_filter_insert_fail_count;
    return efrm_filter_insert_fail_rc;
  }
  if( efrm_filter_insert_fail_after == 0 )
    return efrm_filter_insert_fail_rc;

  rc = efrm_filter_insert_common(client, spec, rxq, pd_excl_owner, mask,
                                 flags, -1, "INSERT");
  if( rc >= 0 && efrm_filter_insert_fail_after > 0 )
    --efrm_filter_insert_fail_after;
  return rc;
}


struct efx_filter_spec*
efrm_filter_remove_common(struct efrm_client* client, int filter_id,
                          const char* op)
{
  struct ooft_hw_filter* filter;
  struct efx_filter_spec* spec = NULL;
  ci_dllink* link;

  CI_DLLIST_FOR_EACH(link, &client->hw_filters_to_remove) {
    filter = CI_CONTAINER(struct ooft_hw_filter, client_link, link);
    if( filter_id == filter->filter_id ) {
      filter->op_seq = ++efrm_filter_op_seq;
      ci_dllist_remove_safe(link);
      ci_dllist_remove_safe(&filter->all_link);
      ci_dllist_push_tail(&client->hw_filters_removed, &filter->client_link);
      LOG_FILTER_OP(ooft_log_hw_filter_op(client, &filter->spec, 0, op));
      spec = &filter->spec;
      break;
    }
  }

  /* Handle expected rollback: filter was added and removed within the same
   * OOF call.  Redirects remove their current filter before installing the
   * replacement, so continue to accept those unconditionally. */
  if( !link && (!strcmp(op, "REDIRECT-REMOVE") ||
                efrm_filter_rollback_remove_count > 0) ) {
    CI_DLLIST_FOR_EACH(link, &client->hw_filters_added) {
      filter = CI_CONTAINER(struct ooft_hw_filter, client_link, link);
      if( filter_id == filter->filter_id ) {
        filter->op_seq = ++efrm_filter_op_seq;
        if( strcmp(op, "REDIRECT-REMOVE") )
          --efrm_filter_rollback_remove_count;
        ci_dllist_remove_safe(link);
        ci_dllist_remove_safe(&filter->all_link);
        ci_dllist_push_tail(&client->hw_filters_removed, &filter->client_link);
        LOG_FILTER_OP(ooft_log_hw_filter_op(client, &filter->spec, 0, op));
        spec = &filter->spec;
        break;
      }
    }
  }

  /* filter in question was not expected to be removed */
  ci_assert(link);

  return spec;
}


void efrm_filter_remove(struct efrm_client* client, int filter_id)
{
  efrm_filter_remove_common(client, filter_id, "REMOVE");
}

bool efrm_filter_check_is_redirect_nop(struct efrm_client *client,
                                       int filter_id,
                                       struct efx_filter_spec *spec)
{
  ci_dllink *link;
  struct ooft_hw_filter *filter;

  CI_DLLIST_FOR_EACH(link, &client->hw_filters_all) {
    filter = CI_CONTAINER(struct ooft_hw_filter, all_link, link);
    if( filter_id == filter->filter_id ) {
      if( filter->spec.dmaq_id == spec->dmaq_id )
        return true;
    }
  }

  return false;
}

int efrm_filter_redirect(struct efrm_client * client, int filter_id,
                         struct efx_filter_spec *spec, int *rxq,
                         unsigned pd_excl_token, const struct cpumask *mask)
{
  struct efx_filter_spec *old_spec;

  if( efrm_filter_check_is_redirect_nop(client, filter_id, spec) ) {
    LOG_FILTER_OP(ooft_log_hw_filter_op(client, spec, 0, "REDIRECT-NOP"));
    return filter_id;
  }

  old_spec = efrm_filter_remove_common(client, filter_id, "REDIRECT-REMOVE");
  if( !old_spec )
    return -EINVAL;

  /* Injected redirect failure: the old filter has been removed (as a real
   * redirect would), but the move does not complete.  The OOF layer reacts
   * by forgetting the old filter id and installing a fresh one. */
  if( efrm_filter_redirect_fail_count > 0 ) {
    --efrm_filter_redirect_fail_count;
    return efrm_filter_redirect_fail_rc;
  }

  return efrm_filter_insert_common(client, spec, rxq, pd_excl_token, mask, 0,
                                   filter_id, "REDIRECT-INSERT");
}


int efrm_vi_set_get_rss_context(struct efrm_vi_set *vi_set, unsigned rss_id)
{
  return 0;
}
