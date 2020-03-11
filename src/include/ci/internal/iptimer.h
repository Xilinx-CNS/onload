/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#ifndef __CI_INTERNAL_IPTIMER_H__
#define __CI_INTERNAL_IPTIMER_H__

#include <ci/internal/ip_shared_types.h>
#include <ci/internal/ip_types.h>
#include <ci/internal/ni_dllist.h>

/*********************************************************************
********************** Timers and management *************************
*********************************************************************/

#define IPTIMER_STATE(ni) (&(ni)->state->iptimer_state)

#define TIME_LT(x, y)  ((ci_int32)((x)-(y)) <  0)
#define TIME_LE(x, y)  ((ci_int32)((x)-(y)) <= 0)
#define TIME_GT(x, y)  ((ci_int32)((x)-(y)) >  0)
#define TIME_GE(x, y)  ((ci_int32)((x)-(y)) >= 0)


/* gives a bucket no for a given wheelno */
#define IPTIMER_BUCKETNO(wheelno, abs)                          \
        (((abs) >> ((wheelno)*CI_IPTIME_BUCKETBITS)) & CI_IPTIME_BUCKETMASK)

/* get the bucket for a given wheelno and abs */
#define IPTIMER_BUCKET(netif, wheelno, abs)                     \
        (&(IPTIMER_STATE((netif))->warray[(wheelno)*CI_IPTIME_BUCKETS + \
                                          IPTIMER_BUCKETNO((wheelno), (abs))]))

#define IPTIMER_WHEEL2_MASK (CI_IPTIME_BUCKETMASK << (CI_IPTIME_BUCKETBITS*3))
#define IPTIMER_WHEEL1_MASK (IPTIMER_WHEEL2_MASK + \
                            (CI_IPTIME_BUCKETMASK << (CI_IPTIME_BUCKETBITS*2)))
#define IPTIMER_WHEEL0_MASK (IPTIMER_WHEEL1_MASK + \
                            (CI_IPTIME_BUCKETMASK << (CI_IPTIME_BUCKETBITS*1)))

/* Mark a wheel0 bucket as busy adding a timer with the given time */
ci_inline void __ci_timer_busy_set(ci_netif* netif, ci_iptime_t time)
{
  int b = IPTIMER_BUCKETNO(0, time);
  ci_assert_equal(IPTIMER_STATE(netif)->sched_ticks & IPTIMER_WHEEL0_MASK,
                  time & IPTIMER_WHEEL0_MASK);
  IPTIMER_STATE(netif)->busy_mask[b/64] |= 1ULL << (b%64);
}

/*  Mark a wheel0 bucket as non-busy when removing a timer */
ci_inline void __ci_timer_busy_unset(ci_netif* netif, ci_iptime_t time)
{
  int b = IPTIMER_BUCKETNO(0, time);
  ci_assert_equal(IPTIMER_STATE(netif)->sched_ticks & IPTIMER_WHEEL0_MASK,
                  time & IPTIMER_WHEEL0_MASK);
  IPTIMER_STATE(netif)->busy_mask[b/64] &=~ (1ULL << (b%64));
}

ci_inline void ci_timer_busy_maybe_unset(ci_netif* netif, ci_iptime_t time)
{
  int b;
  if( (IPTIMER_STATE(netif)->sched_ticks & IPTIMER_WHEEL0_MASK) !=
      (time & IPTIMER_WHEEL0_MASK) )
    return;
  b = IPTIMER_BUCKETNO(0, time);
  if( ci_ni_dllist_is_empty(netif, &(IPTIMER_STATE((netif))->warray[b])) )
    __ci_timer_busy_unset(netif, time);
}

/* debugging hook called if CI_IP_TIMER_DEBUG_HOOK set */
typedef void (*ci_ip_timer_debug_fn_t)(ci_netif*, int, int);
extern ci_ip_timer_debug_fn_t ci_ip_timer_debug_fn;

/*! Poll the ip timer scheduler to run the timer wheel and fire any
**  expiring timers.
**  \param netif  A pointer to the netif structure
*/
extern void ci_ip_timer_poll(ci_netif* netif) CI_HF;

/*! Initialise the ip timer management structure shared state in netif,
**  includes calibration and wheel setup.
**  \param netif  A pointer to the netif to initialise
**  \param cpu_khz CPU speed in kHz
*/
extern void ci_ip_timer_state_init(ci_netif* netif, unsigned cpu_khz) CI_HF;

/*! Dump out state of timers
**  \param netif  A pointer to the netif to initialise
*/
extern void ci_ip_timer_state_dump(ci_netif* ni) CI_HF;

CI_DEBUG(extern void ci_ip_timer_state_assert_valid(ci_netif*,
                                                    const char*, int) CI_HF;)

/*! Debug function to see if the list link behind the timer is valid */
ci_inline int ci_ip_timer_is_link_valid(ci_netif* ni, ci_ip_timer* ts)
{ return ci_ni_dllist_is_valid(ni, &ts->link); }

/*! Clear a timer (whether or not its pending).
**  \param netif  A pointer to the netif for this timer
**  \param ts     A pointer to the timer structure
*/
ci_inline void ci_ip_timer_clear(ci_netif* netif, ci_ip_timer* ts)
{
  ci_ni_dllist_remove_safe(netif, &ts->link);
  ci_timer_busy_maybe_unset(netif, ts->time);
}

/*! Check if a timer is pending 
**  \param ts     A pointer to the ip timer structure to check 
**  \return       0 if not pending, 1 if pending
*/
ci_inline int ci_ip_timer_pending(ci_netif* netif, ci_ip_timer* ts)
{ return ! ci_ni_dllist_is_self_linked(netif, &ts->link); }

/*! Set a non-pending ip timer
**  \param netif  A pointer to the netif for this timer
**  \param ts     A pointer to the timer structure
**  \param t      The time at which the timer should fire in ticks
*/
extern void __ci_ip_timer_set(ci_netif*, ci_ip_timer* ts, ci_iptime_t t) CI_HF;

ci_inline void ci_ip_timer_set(ci_netif* ni, ci_ip_timer* ts, ci_iptime_t t)
{
  ci_assert(! ci_ip_timer_pending(ni, ts));
  __ci_ip_timer_set(ni, ts, t);
}

/*! Modify a pending timer 
**  \param netif  A pointer to the netif for this timer
**  \param ts     A pointer to the timer structure
**  \param t      The time at which the timer should now fire in ticks
*/
ci_inline void ci_ip_timer_modify(ci_netif* ni, ci_ip_timer* ts, ci_iptime_t t)
{
  ci_ni_dllist_remove(ni, &ts->link);
  ci_timer_busy_maybe_unset(ni, ts->time);
  __ci_ip_timer_set(ni, ts, t);
}

/*! Initialise a new timer. */
ci_inline void ci_ip_timer_init(ci_netif* netif, ci_ip_timer* t,
                                oo_p t_sp, const char* name) {
  OO_P_ADD(t_sp, CI_MEMBER_OFFSET(ci_ip_timer, link));
  ci_assert_equal(CI_NETIF_PTR(netif, t_sp), (char*) &t->link);
  ci_ni_dllist_link_init(netif, &t->link, t_sp, name);
  ci_ni_dllist_self_link(netif, &t->link);
}




#endif /* __CI_INTERNAL_IPTIMER_H__ */
