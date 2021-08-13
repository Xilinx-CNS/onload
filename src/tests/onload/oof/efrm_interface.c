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


int efrm_filter_insert(struct efrm_client* client,
                       struct efx_filter_spec *spec, int *rxq,
                       const struct cpumask *mask, unsigned flags)
{
  /* FIXME consider handling of replace_equal */
  struct ooft_hw_filter* filter;
  ci_dllink* link;
  int rc = 0;

  LOG_FILTER_OP(ooft_log_hw_filter_op(client, spec, 0, "INSERT"));

  CI_DLLIST_FOR_EACH(link, &client->hw_filters_to_add) {
    filter = CI_CONTAINER(struct ooft_hw_filter, client_link, link);
    if( ooft_hw_filter_match(spec, filter) ) {
      ci_dllist_remove_safe(link);
      ci_dllist_push_tail(&client->hw_filters_added, &filter->client_link);

      filter->filter_id = client->filter_id++;
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


void efrm_filter_remove(struct efrm_client* client, int filter_id)
{
  struct ooft_hw_filter* filter;
  ci_dllink* link;

  CI_DLLIST_FOR_EACH(link, &client->hw_filters_to_remove) {
    filter = CI_CONTAINER(struct ooft_hw_filter, client_link, link);
    if( filter_id == filter->filter_id ) {
      ci_dllist_remove_safe(link);
      ci_dllist_push_tail(&client->hw_filters_removed, &filter->client_link);
      LOG_FILTER_OP(ooft_log_hw_filter_op(client, &filter->spec, 0, "REMOVE"));
      break;
    }
  }

  ci_assert(link);
}


int efrm_filter_redirect(struct efrm_client * client, int filter_id,
                         int rxq_i, int stack_id)
{
  return 1;
}


int efrm_vi_set_get_rss_context(struct efrm_vi_set *vi_set, unsigned rss_id)
{
  return 0;
}

