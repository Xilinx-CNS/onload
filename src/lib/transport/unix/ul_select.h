/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Support for user-level select().
**   \date  2011/02/21
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __UL_SELECT_H__
#define __UL_SELECT_H__



/* The events that correspond to the select() sets. */
#define SELECT_RD_SET  (POLLIN | POLLRDNORM | POLLRDBAND | POLLHUP | POLLERR)
#define SELECT_WR_SET  (POLLOUT | POLLWRNORM | POLLWRBAND | POLLERR)
#define SELECT_EX_SET  (POLLPRI)


struct oo_ul_select_state {
  fd_set *rdu, *wru, *exu;
  fd_set *rdk, *wrk, *exk;
  fd_set *rdi, *wri, *exi;
  int       nfds_inited;
  int       nfds_split;
  int       is_ul_fd;
  int       is_kernel_fd;
  ci_uint64 now_frc;
  unsigned  ul_select_spin;
#if CI_CFG_SPIN_STATS
  int stat_incremented;
#endif
};


#endif  /* __UL_SELECT_H__ */
