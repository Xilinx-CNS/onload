/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

/**************************************************************************\
*//*! \file
** \author    Solarflare Communications, Inc.
** \brief     Timers for EtherFabric Virtual Interface HAL.
** \date      2018/11/06
** \copyright Copyright &copy; 2018 Solarflare Communications, Inc. All
**            rights reserved. Solarflare, OpenOnload and EnterpriseOnload
**            are trademarks of Solarflare Communications, Inc.
*//*
\**************************************************************************/

#ifndef __ETHERFABRIC_TOOLS_H__
#define __ETHERFABRIC_TOOLS_H__

#ifdef __cplusplus
extern "C" {
#endif

struct ef_vi;


/*! \brief Prime an event queue timer with a new timeout
**
** \param q Pointer to ef_vi structure for the event queue.
** \param v Initial value for timer (specified in &micro;s).
**
** \return None.
**
** Prime an event queue timer with a new timeout.
**
** The timer is stopped if it is already running, and no timeout-event is
** delivered.
**
** The specified timeout is altered slightly, to avoid lots of timers going
** off in the same tick (bug1317). The timer is then primed with this new
** timeout.
**
** The timer is then ready to run when the next event arrives on the event
** queue. When the timer-value reaches zero, a timeout-event will be
** delivered.
**
** \note This is implemented as a macro, that calls the relevant function
**       from the ef_vi::ops structure.
*/
#define ef_eventq_timer_prime(q, v) (q)->ops.eventq_timer_prime(q, v)

/*! \brief Start an event queue timer running
**
** \param q Pointer to ef_vi structure for the event queue.
** \param v Initial value for timer (specified in &micro;s).
**
** \return None.
**
** Start an event queue timer running.
**
** The timer is stopped if it is already running, and no timeout-event is
** delivered.
**
** The specified timeout is altered slightly, to avoid lots of timers going
** off in the same tick (bug1317). The timer is then primed with this new
** timeout., and starts running immediately.
**
** When the timer-value reaches zero, a timeout-event will be delivered.
**
** \note This is implemented as a macro, that calls the relevant function
**       from the ef_vi::ops structure.
*/
#define ef_eventq_timer_run(q, v) (q)->ops.eventq_timer_run(q, v)

/*! \brief Stop an event queue timer
**
** \param q Pointer to ef_vi structure for the event queue.
**
** \return None.
**
** Stop an event queue timer.
**
** The timer is stopped if it is already running, and no timeout-event is
** delivered.
**
** The timer will not run when the next event arrives on the event queue.
**
** \note This is implemented as a macro, that calls the relevant function
**       from the ef_vi::ops structure.
*/
#define ef_eventq_timer_clear(q) (q)->ops.eventq_timer_clear(q)

/*! \brief Prime an event queue timer to expire immediately
**
** \param q Pointer to ef_vi structure for the event queue.
**
** \return None.
**
** Prime an event queue timer to expire immediately.
**
** The timer is stopped if it is already running, and no timeout-event is
** delivered.
**
** The timer is then primed with a new timeout of 0.
**
** When the next event arrives on the event queue, a timeout-event will be
** delivered.
**
** \note This is implemented as a macro, that calls the relevant function
**       from the ef_vi::ops structure.
*/
#define ef_eventq_timer_zero(q) (q)->ops.eventq_timer_zero(q)

#ifdef __cplusplus
}
#endif

#endif  /* __ETHERFABRIC_TOOLS_H__ */
