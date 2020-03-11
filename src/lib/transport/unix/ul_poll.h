/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Support for user-level poll() and select().
**   \date  2009/02/22
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __UL_POLL_H__
#define __UL_POLL_H__

/* Keep kernel fds data on-stack for that many kfds. */
#define OO_POLL_KFDS_LOCAL 16

#define OO_POLL_MAX_OSP    16

#define KEEP_POLLING(what, now, start)                                  \
  (what && (((now) = ci_frc64_get()) - (start) < citp.spin_cycles))


struct oo_ul_poll_state {
  /* Timestamp for the beginning of the current poll.  Used to avoid doing
   * ci_netif_poll() on stacks too frequently.
   */
  ci_uint64             this_poll_frc;

  /* The argument to poll(). */
  struct pollfd*__restrict__ pfds;

  /* Number of entries in [pfds] with revents set. */
  int                   n_ul_ready;

  /* Number of user-level sockets in [pfds]. */
  int                   n_ul_fds;

  /* Number of entries in [kfds] and [kfd_map]. */
  int                   nkfds;

  /* Should it spin */
  unsigned              ul_poll_spin;

#if CI_CFG_SPIN_STATS
  /* Have we incremented statistics for this spin round? */
  int stat_incremented;
#endif

  /* Kernel file descriptors */

  /* Maps entry number in [kfds] onto entry number in [pfds]. */
  int                   kfd_map_local[OO_POLL_KFDS_LOCAL];
  int*                  kfd_map;

  /* Use this to do sys_poll() on non-onload fds. */
  struct pollfd         kfds_local[OO_POLL_KFDS_LOCAL];
  struct pollfd*        kfds;
};

#endif  /* __UL_POLL_H__ */
