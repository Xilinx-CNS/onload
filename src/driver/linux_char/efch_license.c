/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include "efch.h"
#include <ci/efch/op_types.h>
#include <ci/efhw/efhw_types.h>
#include "linux_char_internal.h"
#include "char_internal.h"
#include <ci/efrm/resource.h>
#include <ci/efrm/licensing.h>

int
efch_license_challenge(ci_resource_table_t* rt,
                       struct ci_license_challenge_op_s* op, int* copy_out)
{
  int rc;
  struct efrm_resource *rs;
  struct efrm_license_challenge_s s;

  rc = efch_lookup_rs(op->fd, op->pd_id, EFRM_RESOURCE_PD, &rs);
  if( rc < 0 ) {
    EFCH_ERR("%s: ERROR: hwm=%d id="EFCH_RESOURCE_ID_FMT" rc=%d",
             __FUNCTION__, rt->resource_table_highwater,
             EFCH_RESOURCE_ID_PRI_ARG(op->pd_id), rc);
    goto done_no_ref;
  }

  EFCH_TRACE("%s: id="EFCH_RESOURCE_ID_FMT,
             __FUNCTION__, EFCH_RESOURCE_ID_PRI_ARG(op->pd_id));

  // Make sure that the API buffer lengths match
  if((CI_LCOP_CHALLENGE_CHALLENGE_LEN != EFRM_LICENSE_CHALLENGE_CHALLENGE_LEN) ||
     (CI_LCOP_CHALLENGE_SIGNATURE_LEN != EFRM_LICENSE_CHALLENGE_SIGNATURE_LEN)) {
    EFCH_ERR("%s: id="EFCH_RESOURCE_ID_FMT" mismatched challenge/sig "
             "lcop_chal=%d efhw_chal=%d lcop_sig=%d rfhw_sig=%d",
             __FUNCTION__, EFCH_RESOURCE_ID_PRI_ARG(op->pd_id),
             CI_LCOP_CHALLENGE_CHALLENGE_LEN,
             EFRM_LICENSE_CHALLENGE_CHALLENGE_LEN,
             CI_LCOP_CHALLENGE_SIGNATURE_LEN,
             EFRM_LICENSE_CHALLENGE_SIGNATURE_LEN);

    efrm_resource_release(rs);
    return -EFAULT;
  }

  s.feature = op->feature;
  memcpy(s.challenge, op->challenge,
         EFRM_LICENSE_CHALLENGE_CHALLENGE_LEN);

  rc = efrm_license_challenge(rs, &s);

  if(!rc) {
    op->expiry = s.expiry;
    memcpy(op->signature, s.signature,
           EFRM_LICENSE_CHALLENGE_SIGNATURE_LEN);
  }
  EFCH_TRACE("%s: id="EFCH_RESOURCE_ID_FMT" rc=%d",
             __FUNCTION__, EFCH_RESOURCE_ID_PRI_ARG(op->pd_id), rc);
  *copy_out = 1;

  efrm_resource_release(rs);
done_no_ref:
  return rc;
}


int
efch_v3_license_challenge(ci_resource_table_t* rt,
                          struct ci_v3_license_challenge_op_s* op,
                          int* copy_out)
{
  int rc;
  struct efrm_resource *rs;
  struct efrm_v3_license_challenge_s s;

  rc = efch_lookup_rs(op->fd, op->pd_id, EFRM_RESOURCE_PD, &rs);
  if( rc < 0 ) {
    EFCH_ERR("%s: ERROR: hwm=%d id="EFCH_RESOURCE_ID_FMT" rc=%d",
             __FUNCTION__, rt->resource_table_highwater,
             EFCH_RESOURCE_ID_PRI_ARG(op->pd_id), rc);
    goto done_no_ref;
  }

  EFCH_TRACE("%s: id="EFCH_RESOURCE_ID_FMT,
             __FUNCTION__, EFCH_RESOURCE_ID_PRI_ARG(op->pd_id));
  // Make sure that the API buffer lengths match
  if((CI_LCOP_V3_CHALLENGE_CHALLENGE_LEN !=
      EFRM_V3_LICENSE_CHALLENGE_CHALLENGE_LEN) ||
     (CI_LCOP_V3_CHALLENGE_SIGNATURE_LEN !=
      EFRM_V3_LICENSE_CHALLENGE_SIGNATURE_LEN)) {
    EFCH_ERR("%s: id="EFCH_RESOURCE_ID_FMT" mismatched challenge/sig "
             "lcop_chal=%d efhw_chal=%d lcop_sig=%d efhw_sig=%d",
             __FUNCTION__, EFCH_RESOURCE_ID_PRI_ARG(op->pd_id),
             CI_LCOP_V3_CHALLENGE_CHALLENGE_LEN,
             EFRM_V3_LICENSE_CHALLENGE_CHALLENGE_LEN,
             CI_LCOP_V3_CHALLENGE_SIGNATURE_LEN,
             EFRM_V3_LICENSE_CHALLENGE_SIGNATURE_LEN);

    efrm_resource_release(rs);
    return -EFAULT;
  }

  s.app_id = op->app_id;
  memcpy(s.challenge, op->challenge, EFRM_V3_LICENSE_CHALLENGE_CHALLENGE_LEN);

  rc = efrm_v3_license_challenge(rs, &s);

  if( rc == 0 ) {
    op->expiry = s.expiry;
    op->days = s.days;
    memcpy(op->signature, s.signature,
           EFRM_V3_LICENSE_CHALLENGE_SIGNATURE_LEN);
    memcpy(op->base_macaddr, s.base_macaddr,
           EFRM_V3_LICENSE_CHALLENGE_MACADDR_LEN);
    memcpy(op->current_macaddr, s.vadaptor_macaddr,
           EFRM_V3_LICENSE_CHALLENGE_MACADDR_LEN);
    *copy_out = 1;
  }
  else if( rc != -ENOENT ) {
    EFCH_ERR("%s: V3 Challenge response %d",
      __FUNCTION__, rc);
  }

  EFCH_TRACE("%s: id="EFCH_RESOURCE_ID_FMT" rc=%d",
             __FUNCTION__, EFCH_RESOURCE_ID_PRI_ARG(op->pd_id), rc);

  efrm_resource_release(rs);
done_no_ref:
  return rc;
}

