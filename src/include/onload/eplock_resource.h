/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  ok_sasha
**  \brief  eplock resource internal API
**     $Id$
**   \date  2007/08
**    \cop  (c) Solaraflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_onload  */

/* This file is a part of ci/internal/ip.h or.
 * ***** Do not include it directly! Include ip.h instead! *****
 */

#ifndef __ONLOAD_EPLOCK_REOSURCE_H__
#define __ONLOAD_EPLOCK_REOSURCE_H__

/*--------------------------------------------------------------------
 *
 * eplock_resource_t
 *
 *--------------------------------------------------------------------*/

/* Set this to 1 to record which user processes waited when acquiring
** eplock.
*/
#define CI_CFG_EFAB_EPLOCK_RECORD_CONTENTIONS	0
#define EFAB_EPLOCK_MAX_NO_PIDS     40

/*! Comment? */
typedef struct {
  wait_queue_head_t     wq;

#if CI_CFG_EFAB_EPLOCK_RECORD_CONTENTIONS
  /* if asked we keep a record of who waited on this lock */
  int                   pids_who_waited[EFAB_EPLOCK_MAX_NO_PIDS];
  unsigned              pids_no_waits[EFAB_EPLOCK_MAX_NO_PIDS];
  ci_irqlock_t          pids_lock;
#endif
} eplock_helper_t;


extern int eplock_ctor(ci_netif *ni);
extern void eplock_dtor(ci_netif *ni);

#if ! CI_CFG_UL_INTERRUPT_HELPER
/*! Comment? */
extern int efab_eplock_unlock_and_wake(ci_netif *ni, int in_dl_context);
#else
extern int efab_eplock_wake_and_do(ci_netif *ni, ci_uint64 l);

#endif

/*! Comment? */
extern int efab_eplock_lock_wait(ci_netif* ni, int maybe_wedged);

/* Locks the stack.  Returns 0 in case of success. */
extern int oo_eplock_lock(ci_netif* ni, long* timeout_jiffies, int maybe_wedged);

extern int
efab_eplock_lock_timeout(ci_netif* ni, signed long timeout_jiffies);

#endif /* __ONLOAD_EPLOCK_REOSURCE_H__ */
/*! \cidoxg_end */
