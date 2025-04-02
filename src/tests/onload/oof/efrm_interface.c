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

  LOG_FILTER_OP(ooft_log_hw_filter_op(client, spec, 0, op));

  CI_DLLIST_FOR_EACH(link, &client->hw_filters_to_add) {
    filter = CI_CONTAINER(struct ooft_hw_filter, client_link, link);
    if( ooft_hw_filter_match(spec, filter) ) {
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
  return efrm_filter_insert_common(client, spec, rxq, pd_excl_owner, mask,
                                   flags, -1, "INSERT");
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
      ci_dllist_remove_safe(link);
      ci_dllist_remove_safe(&filter->all_link);
      ci_dllist_push_tail(&client->hw_filters_removed, &filter->client_link);
      LOG_FILTER_OP(ooft_log_hw_filter_op(client, &filter->spec, 0, op));
      spec = &filter->spec;
      break;
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
                         struct efx_filter_spec *spec)
{
  struct efx_filter_spec *old_spec;
  int rxq_out;

  if( efrm_filter_check_is_redirect_nop(client, filter_id, spec) ) {
    LOG_FILTER_OP(ooft_log_hw_filter_op(client, spec, 0, "REDIRECT-NOP"));
    return filter_id;
  }

  old_spec = efrm_filter_remove_common(client, filter_id, "REDIRECT-REMOVE");
  if( !old_spec )
    return -EINVAL;

  return efrm_filter_insert_common(client, spec, &rxq_out, 0, NULL, 0,
                                   filter_id, "REDIRECT-INSERT");
}


int efrm_vi_set_get_rss_context(struct efrm_vi_set *vi_set, unsigned rss_id)
{
  return 0;
}

