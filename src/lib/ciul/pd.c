/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2012-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  David Riddoch <driddoch@solarflare.com>
**  \brief  Registered memory.
**   \date  2012/02/06
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <etherfabric/base.h>
#include <etherfabric/pd.h>
#include <etherfabric/capabilities.h>
#include "ef_vi_internal.h"
#include "driver_access.h"
#include "logging.h"

#include <net/if.h>

static int __ef_tok_eq(const char* tok, size_t tok_len, const char* tmpl)
{
    size_t l = strlen(tmpl);
    return l == tok_len && ! strncmp(tok, tmpl, l);
}

static enum ef_pd_flags __ef_pd_flags_from_env(enum ef_pd_flags flags)
{
    const char* s = getenv("EF_VI_PD_FLAGS");
    if( s == NULL )
        return flags;

    enum ef_pd_flags new_flags = 0;
    const char* tok_end;
    do
    {
        tok_end = strchr(s, ',');
        if( ! tok_end )
            tok_end = s + strlen(s);
        if( __ef_tok_eq(s, tok_end - s, "vf") )
            new_flags |= EF_PD_VF;
        else if( __ef_tok_eq(s, tok_end - s, "phys") )
            new_flags |= EF_PD_PHYS_MODE;
        else if( __ef_tok_eq(s, tok_end - s, "default") )
            flags = 0;
        else if( __ef_tok_eq(s, tok_end - s, "mcast_loop") )
            new_flags |= EF_PD_MCAST_LOOP;
        else if( __ef_tok_eq(s, tok_end - s, "express") )
            new_flags |= EF_PD_EXPRESS;
        s = tok_end + 1;
    } while( *tok_end != '\0' );

    return new_flags != 0 ? new_flags : flags;
}

static enum ef_pd_flags ef_pd_extra_flags_for_compat(ef_driver_handle pd_dh,
                                                     int ifindex)
{
  enum ef_compat_mode mode = ef_vi_compat_mode_get_from_env();
  if( mode == EF_COMPAT_MODE_EF10 ) {
    /* For X4 we want to select Express datapath too */
    unsigned long capability_val;
    /* Directly query the hardware capabilities to avoid ending up in an
     * infinite loop due to ef_vi_capabilities_get() calling
     * ef_pd_flags_from_env(), and avoid getting the overwritten compat
     * capability value. */
    int rc = __ef_vi_capabilities_get_hw(pd_dh, ifindex, -1, -1,
                                         EF_VI_CAP_EXTRA_DATAPATHS,
                                         &capability_val);
    if( rc == 0 && (capability_val & EF_VI_EXTRA_DATAPATH_EXPRESS) )
      return EF_PD_EXPRESS;
  }
  return 0;
}

enum ef_pd_flags ef_pd_flags_from_env(enum ef_pd_flags flags,
                                        ef_driver_handle pd_dh,
                                        int ifindex)
{
  return __ef_pd_flags_from_env(flags) |
    ef_pd_extra_flags_for_compat(pd_dh, ifindex);
}

static int __ef_pd_alloc(ef_pd* pd, ef_driver_handle pd_dh,
			 int ifindex, enum ef_pd_flags flags, int vlan_id)
{
  ci_resource_alloc_t ra;
  int rc;

  flags = ef_pd_flags_from_env(flags, pd_dh, ifindex);

  if( flags & EF_PD_VF )
    flags |= EF_PD_PHYS_MODE;

  ef_vi_init_resource_alloc(&ra, EFRM_RESOURCE_PD);
  ra.u.pd.in_ifindex = ifindex;
  ra.u.pd.in_flags = 0;
  if( flags & EF_PD_VF )
    ra.u.pd.in_flags |= EFCH_PD_FLAG_VF;
  if( flags & EF_PD_PHYS_MODE )
    ra.u.pd.in_flags |= EFCH_PD_FLAG_PHYS_ADDR;
  if( flags & EF_PD_RX_PACKED_STREAM )
    ra.u.pd.in_flags |= EFCH_PD_FLAG_RX_PACKED_STREAM;
  if( flags & EF_PD_VPORT )
    ra.u.pd.in_flags |= EFCH_PD_FLAG_VPORT;
  if( flags & EF_PD_MCAST_LOOP )
    ra.u.pd.in_flags |= EFCH_PD_FLAG_MCAST_LOOP;
  if( flags & EF_PD_MEMREG_64KiB )
    /* FIXME: We're overloading the packed-stream flag here.  The only
     * effect it has is to force ef_memreg to use at least 64KiB buffer
     * table entries.  Unfortunately this won't work if the adapter is not
     * in packed-stream mode.
     */
    ra.u.pd.in_flags |= EFCH_PD_FLAG_RX_PACKED_STREAM;
  if( flags & EF_PD_IGNORE_BLACKLIST )
    ra.u.pd.in_flags |= EFCH_PD_FLAG_IGNORE_BLACKLIST;
  if( flags & EF_PD_EXPRESS )
    ra.u.pd.in_flags |= EFCH_PD_FLAG_LLCT;
  ra.u.pd.in_vlan_id = vlan_id;

  rc = ci_resource_alloc(pd_dh, &ra);
  if( rc < 0 ) {
    LOGVV(ef_log("ef_pd_alloc: ci_resource_alloc %d", rc));
    return rc;
  }

  pd->pd_resource_id = ra.out_id.index;

  pd->pd_intf_name = malloc(IF_NAMESIZE);
  if( pd->pd_intf_name == NULL ) {
    LOGVV(ef_log("ef_pd_alloc: malloc failed"));
    return -ENOMEM;
  }
  if( if_indextoname(ifindex, pd->pd_intf_name) == NULL ) {
    free(pd->pd_intf_name);
    ef_log("ef_pd_alloc: warning: if_indextoname failed %d", errno);
    pd->pd_intf_name = NULL;
    /* TODO the above is a work around
     * base interface resides in different namespace
     * allocating PD was allowed nevertheless.
     * we intend to do this for license checking only, but
     * FIXME: pd alloc() should be allowed to be done through
     * upper (MACVLAN/VLAN) interface.
     */
  }

  pd->pd_flags = flags;
  pd->pd_cluster_name = NULL;
  pd->pd_cluster_sock = -1;
  pd->pd_cluster_dh = 0;
  pd->pd_cluster_viset_resource_id = 0;

  return 0;
}


int ef_pd_alloc(ef_pd* pd, ef_driver_handle pd_dh,
		int ifindex, enum ef_pd_flags flags)
{
  return __ef_pd_alloc(pd, pd_dh, ifindex, flags, -1);
}


int ef_pd_alloc_with_vport(ef_pd* pd, ef_driver_handle pd_dh,
			   const char* intf_name,
			   enum ef_pd_flags flags, int vlan_id)
{
  int ifindex = if_nametoindex(intf_name);
  if( ifindex == 0 )
    return -errno;
  return __ef_pd_alloc(pd, pd_dh, ifindex, flags | EF_PD_VPORT, vlan_id);
}


const char* ef_pd_interface_name(ef_pd* pd)
{
  return pd->pd_intf_name;
}


int ef_pd_free(ef_pd* pd, ef_driver_handle pd_dh)
{
  free(pd->pd_intf_name);
  if( pd->pd_cluster_sock != -1 ) {
    return ef_pd_cluster_free(pd, pd_dh);
  }
  else {
    EF_VI_DEBUG(memset(pd, 0, sizeof(*pd)));
    return 0;
  }
}

unsigned ef_pd_mr_flags(ef_pd* pd)
{
  /* The public users of the LLCT datapath want a dummy memreg mapping. */
  return pd->pd_flags & EFCH_PD_FLAG_LLCT ? EFCH_MEMREG_FLAG_DUMMY : 0;
}
