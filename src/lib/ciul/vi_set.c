/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  David Riddoch
**  \brief  Allocate / manage a set of VIs (ef_vi_set).
**   \date  2011/02/25
**    \cop  Copyright Solarflare Communications, Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include "ef_vi_internal.h"
#include "driver_access.h"
#include "logging.h"


static int __ef_vi_set_alloc(ef_vi_set* viset, ef_driver_handle dh,
			     ef_pd* pd, ef_driver_handle pd_dh,
			     int ifindex, int n_vis)
{
  ci_resource_alloc_t ra;
  int rc;

  memset(&ra, 0, sizeof(ra));
  ef_vi_set_intf_ver(ra.intf_ver, sizeof(ra.intf_ver));
  ra.ra_type = EFRM_RESOURCE_VI_SET;
  ra.u.vi_set.in_n_vis = n_vis;
  ra.u.vi_set.in_flags = 0;
  if( pd != NULL ) {
    ra.u.vi_set.in_pd_fd = pd_dh;
    ra.u.vi_set.in_pd_rs_id =
      efch_make_resource_id(pd->pd_resource_id);
  }
  else {
    ra.u.vi_set.in_pd_fd = -1;
    ra.u.vi_set.in_ifindex = ifindex;
  }
  rc = ci_resource_alloc(dh, &ra);
  if( rc < 0 ) {
    LOGVV(ef_log("%s: ci_resource_alloc failed %d",
                 __FUNCTION__, rc));
    return rc;
  }
  viset->vis_res_id = ra.out_id.index;
  viset->vis_pd = NULL;
  return rc;
}


int ef_vi_set_alloc_from_pd(ef_vi_set* viset, ef_driver_handle dh,
			    ef_pd* pd, ef_driver_handle pd_dh,
			    int n_vis)
{
  int rc;

  if( pd->pd_cluster_sock == -1 ) {
    rc = __ef_vi_set_alloc(viset, dh, pd, pd_dh, -1, n_vis);
    viset->vis_pd = pd;
    return rc;
  }
  else {
    ef_log("%s: WARNING: Cannot create a vi_set on a cluster",
           __FUNCTION__);
    return -EINVAL;
  }
}


int ef_vi_set_free(ef_vi_set* vi_set, ef_driver_handle dh)
{
  return 0;
}
