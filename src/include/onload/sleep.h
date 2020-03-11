/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __ONLOAD_SLEEP_H__
#define __ONLOAD_SLEEP_H__


/* citp_waitable_wakeup(): This goes into the kernel to ding the waitqueue.
 * You probably don't want to invoke this directly -- see
 * citp_waitable_wake() etc. below.
 */
#ifdef __KERNEL__
ci_inline void citp_waitable_wakeup(ci_netif* ni, citp_waitable* w)
{
  tcp_helper_endpoint_wakeup(netif2tcp_helper_resource(ni),
                             ci_netif_get_valid_ep(ni, w->bufid));
}
#else
extern void citp_waitable_wakeup(ci_netif*, citp_waitable*) CI_HF;
#endif

extern void citp_waitable_wake_not_in_poll(ci_netif* ni, citp_waitable* sb,
                                           unsigned what);


ci_inline void citp_waitable_wake(ci_netif* ni, citp_waitable* sb,
				  unsigned what)
{
  ci_assert(what);
  ci_assert((what & ~(CI_SB_FLAG_WAKE_RX|CI_SB_FLAG_WAKE_TX)) == 0u);
  ci_assert(ni->state->in_poll);
  sb->sb_flags |= what;
}


ci_inline void citp_waitable_wake_possibly_not_in_poll(ci_netif* ni,
						       citp_waitable* sb,
						       unsigned what)
{
  if( ni->state->in_poll )
    citp_waitable_wake(ni, sb, what);
  else
    citp_waitable_wake_not_in_poll(ni, sb, what);
}


ci_inline void ci_tcp_wake(ci_netif* ni, ci_tcp_state* ts, unsigned what)
{ citp_waitable_wake(ni, &ts->s.b, what); }

ci_inline void ci_tcp_wake_not_in_poll(ci_netif* ni, ci_tcp_state* ts,
                                       unsigned what)
{ citp_waitable_wake_not_in_poll(ni, &ts->s.b, what); }

ci_inline void ci_tcp_wake_possibly_not_in_poll(ci_netif* ni, ci_tcp_state* ts,
                                                unsigned what)
{ citp_waitable_wake_possibly_not_in_poll(ni, &ts->s.b, what); }


ci_inline void ci_udp_wake(ci_netif* ni, ci_udp_state* us, unsigned what)
{ citp_waitable_wake(ni, &us->s.b, what); }

ci_inline void ci_udp_wake_possibly_not_in_poll(ci_netif* ni, ci_udp_state* us,
                                                unsigned what)
{ citp_waitable_wake_possibly_not_in_poll(ni, &us->s.b, what); }


#endif  /* __ONLOAD_SLEEP_H__ */
