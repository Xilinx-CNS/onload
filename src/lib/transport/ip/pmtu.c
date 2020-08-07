/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  stg
**  \brief  Path MTU support. 
**   \date  2004/07/09
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */
  
#include "ip_internal.h"


#define LPF "ci_pmtu_"

#if OO_DO_STACK_POLL

static const ci_uint16 mtu_plateau[] = CI_PMTU_PLATEAU_ENTRIES;


extern void
ci_pmtu_state_init(ci_netif* ni, ci_sock_cmn *s, 
                   oo_p pmtu_sp, ci_pmtu_state_t* pmtus,
                   int func_code)
{
  pmtus->tid.param1 = SC_SP(s);
  pmtus->tid.fn = (ci_iptime_callback_fn_t)func_code;

  OO_P_ADD(pmtu_sp, CI_MEMBER_OFFSET(ci_ni_aux_mem, u.pmtus));
  ci_ip_timer_init(ni, &pmtus->tid, pmtu_sp, "pmtu");
}

/*! Update the PMTU value for an endpoint, range limited to valid values.
**
** NOTE: This doesn't update the effective MSS for TCP endpoints.  Call
**       ci_tcp_set_eff_mss() after calling this if you need to update the MSS.
*/
extern void ci_pmtu_set(ci_netif *ni, ci_pmtu_state_t *pmtus, unsigned pmtu)
{
  const ci_uint16 plateau[] = CI_PMTU_PLATEAU_ENTRIES;
  unsigned id = CI_PMTU_PLATEAU_ENTRY_MAX;
  ci_assert_ge(pmtu, CI_CFG_TCP_MINIMUM_MSS);

  pmtu = CI_MIN(CI_PMTU_MAX_MTU, pmtu);
  while (id && pmtu < plateau[id])
    id--;

  pmtus->pmtu = (ci_uint16)pmtu;
  pmtus->plateau_id = (ci_uint8)id;
  LOG_PMTU(ci_log("%s: req_pmtu=%d pmtu=%d id=%d(%d) max_mtu=%d",
                  __FUNCTION__, pmtu, pmtus->pmtu, pmtus->plateau_id,
                  plateau[pmtus->plateau_id], CI_PMTU_MAX_MTU));
}


ci_inline void __ci_pmtu_timeout_handler(ci_netif* ni, ci_pmtu_state_t *pmtus,
                                         ci_ip_cached_hdrs *ipcache)
{
  ci_assert_le(pmtus->pmtu, CI_PMTU_MAX_MTU);
  ci_assert_le(ipcache->mtu, CI_PMTU_MAX_MTU);

  /* go to the next plateau */
  pmtus->pmtu = mtu_plateau[++pmtus->plateau_id];

  /* If we reached the limit kill the timer, we depend on ci_ip_send() to start
   * it again if the mtu changes. If we haven't reached the upper limit keep the
   * timer running. */
  if( pmtus->pmtu > ipcache->mtu ) {
    pmtus->pmtu = ipcache->mtu;
    pmtus->plateau_id--;
    CI_PMTU_TIMER_KILL(ni, pmtus);
    LOG_PMTU(ci_log("%s: (TCP) reached interface MTU, killed timer, mtu=%d",
                    __FUNCTION__, pmtus->pmtu));
  } else {
    CI_PMTU_TIMER_SET_FAST(ni, pmtus);
    LOG_PMTU(ci_log("%s: (TCP) climbed a plateau, set fast timer, mtu=%d",
                    __FUNCTION__, pmtus->pmtu));
  }
#undef TRAFFIC_TCP
#undef TRAFFIC_UDP
}


/* Called at timeout on a Path MTU (re-)discovery timeout.
 * TCP sockets only. */
void ci_pmtu_timeout_pmtu(ci_netif* ni, ci_tcp_state *ts)
{
  __ci_pmtu_timeout_handler(ni, ci_ni_aux_p2pmtus(ni, ts->pmtus),
                            &ts->s.pkt);
  ci_tcp_tx_change_mss(ni, ts);
}


/*! Update the pmtu state to the new pmtu value and set the slow timer if
 * appropriate. The timer is set, if the pmtu value is less than
 * the outgoing interface MTU value.
 */
void ci_pmtu_update_slow(ci_netif* ni, ci_pmtu_state_t *pmtus,
                         ci_ip_cached_hdrs *ipcache,
                         unsigned pmtu)
{
  ci_assert_ge(pmtu, CI_CFG_TCP_MINIMUM_MSS);
  ci_assert_le(pmtu, CI_PMTU_MAX_MTU);
  ci_assert_le(pmtu, ipcache->mtu);

  CI_PMTU_TIMER_KILL(ni, pmtus);
  ci_pmtu_set(ni, pmtus, pmtu);

  if (pmtus->pmtu < ipcache->mtu)
    CI_PMTU_TIMER_SET_SLOW(ni, pmtus);

  LOG_PMTU(ci_log("%s: new_pmtu=%d req_pmtu=%d if_mtu=%d", __FUNCTION__,
                  pmtus->pmtu, pmtu, ipcache->mtu));
}


/*! Update the pmtu state to the new pmtu value and set the fast timer if
 * appropriate. The timer is set, if the pmtu value is less than
 * the outgoing interface MTU value.
 */
void ci_pmtu_update_fast(ci_netif* ni, ci_pmtu_state_t *pmtus,
                         ci_ip_cached_hdrs *ipcache,
                         unsigned pmtu)
{
  ci_assert_ge(pmtu, CI_CFG_TCP_MINIMUM_MSS);
  ci_assert_le(pmtu, CI_PMTU_MAX_MTU);
  ci_assert_le(pmtu, ipcache->mtu);

  CI_PMTU_TIMER_KILL(ni, pmtus);
  ci_pmtu_set(ni, pmtus, pmtu);

  if (pmtus->pmtu < ipcache->mtu)
    CI_PMTU_TIMER_SET_FAST(ni, pmtus);

  LOG_PMTU(ci_log("%s: new_pmtu=%d req_pmtu=%d if_mtu=%d", __FUNCTION__,
                  pmtus->pmtu, pmtu, ipcache->mtu));
}

#endif
/*! \cidoxg_end */
