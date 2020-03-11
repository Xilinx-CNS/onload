/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"


static void ci_active_wild_state_init(ci_netif* netif, ci_active_wild* aw)
{
  oo_p p;

  ci_sock_cmn_init(netif, &aw->s, 1);
  aw->s.b.state = CI_TCP_STATE_ACTIVE_WILD;
  aw->s.b.sb_aflags = 0;
#if CI_CFG_IPV6
  aw->s.pkt.ether_type = CI_ETHERTYPE_IP6;
#endif

  sock_protocol(&aw->s) = IPPROTO_TCP;
  ci_sock_set_laddr_port(&aw->s, addr_any, 0);
  ci_sock_set_raddr_port(&aw->s, addr_any, 0);

  p = TS_OFF(netif, aw);
  OO_P_ADD(p, CI_MEMBER_OFFSET(ci_active_wild, pool_link));
  ci_ni_dllist_link_init(netif, &aw->pool_link, p, "pool");
  ci_ni_dllist_self_link(netif, &aw->pool_link);

  aw->expiry = ci_ip_time_now(netif);
  aw->last_laddr = addr_any;
  aw->last_raddr = addr_any;
  aw->last_rport = 0u;
}


ci_active_wild* ci_active_wild_get_state_buf(ci_netif* netif)
{
  citp_waitable_obj* wo;

  ci_assert(netif);

  wo = citp_waitable_obj_alloc(netif);
  if( wo ) {
    ci_active_wild_state_init(netif, &wo->aw);
    return &wo->aw;
  }
  return NULL;
}


/* Calling this _all_fds_gone is a bit of a lie, as active wilds are never
 * associated with an fd.  However, it makes the naming consistent with
 * other types of waitable.
 */
void ci_active_wild_all_fds_gone(ci_netif* ni, ci_active_wild* aw, int do_free)
{
  ci_assert(ci_netif_is_locked(ni));
  ci_assert(aw->s.b.state == CI_TCP_STATE_ACTIVE_WILD);

  ci_tcp_ep_clear_filters(ni, SC_SP(&aw->s), 0);

  if( do_free )
    citp_waitable_obj_free(ni, &aw->s.b);
}


/*! \cidoxg_end */
