/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_ciapp */

#include <ci/app.h>

#include <sys/select.h>


int ci_select_1(int fd, int which, int* state, const struct timeval* tmo)
{
  fd_set rfds;
  fd_set wfds;
  fd_set efds;
  int rc;
  struct timeval timeout;

  ci_assert(fd >= 0);
  ci_assert(which);

  FD_ZERO(&rfds);
  FD_ZERO(&wfds);
  FD_ZERO(&efds);
  FD_SET((unsigned) fd, &rfds);
  FD_SET((unsigned) fd, &wfds);
  FD_SET((unsigned) fd, &efds);

  if( tmo )  timeout = *tmo;

  rc = select(fd + 1,
	      (which & CI_SELECT_READABLE) ? &rfds:0,
	      (which & CI_SELECT_WRITABLE) ? &wfds:0,
	      (which & CI_SELECT_EXCEPT) ? &efds:0,
	      tmo ? &timeout : 0);
  if( rc < 0 )  return rc;

  if( state ) {
    *state = 0;
    if( FD_ISSET(fd, &rfds) )  *state |= CI_SELECT_READABLE;
    if( FD_ISSET(fd, &wfds) )  *state |= CI_SELECT_WRITABLE;
    if( FD_ISSET(fd, &efds) )  *state |= CI_SELECT_EXCEPT;
  }

  return rc > 0 ? 0 : -ETIMEDOUT;
}


int ci_select_2(int fd1, int which1, int* state1,
		int fd2, int which2, int* state2,
		const struct timeval* tmo)
{
  fd_set rfds;
  fd_set wfds;
  fd_set efds;
  int max, rc;
  struct timeval timeout;

  ci_assert(fd1 >= 0);
  ci_assert(fd2 >= 0);
  ci_assert(which1 || which2);

  FD_ZERO(&rfds);
  FD_ZERO(&wfds);
  FD_ZERO(&efds);

  if( which1 & CI_SELECT_READABLE )  FD_SET((unsigned) fd1, &rfds);
  if( which1 & CI_SELECT_WRITABLE )  FD_SET((unsigned) fd1, &wfds);
  if( which1 & CI_SELECT_EXCEPT   )  FD_SET((unsigned) fd1, &efds);

  if( which2 & CI_SELECT_READABLE )  FD_SET((unsigned) fd2, &rfds);
  if( which2 & CI_SELECT_WRITABLE )  FD_SET((unsigned) fd2, &wfds);
  if( which2 & CI_SELECT_EXCEPT   )  FD_SET((unsigned) fd2, &efds);

  if( tmo )  timeout = *tmo;

  max = fd1;
  if( fd2 > fd1 )  max = fd2;

  rc = select(max + 1, &rfds, &wfds, &efds, tmo ? &timeout : 0);
  if( rc < 0 )  return rc;

  if( state1 ) {
    *state1 = 0;
    if( FD_ISSET(fd1, &rfds) )  *state1 |= CI_SELECT_READABLE;
    if( FD_ISSET(fd1, &wfds) )  *state1 |= CI_SELECT_WRITABLE;
    if( FD_ISSET(fd1, &efds) )  *state1 |= CI_SELECT_EXCEPT;
  }
  if( state2 ) {
    *state2 = 0;
    if( FD_ISSET(fd2, &rfds) )  *state2 |= CI_SELECT_READABLE;
    if( FD_ISSET(fd2, &wfds) )  *state2 |= CI_SELECT_WRITABLE;
    if( FD_ISSET(fd2, &efds) )  *state2 |= CI_SELECT_EXCEPT;
  }

  return rc > 0 ? 0 : -ETIMEDOUT;
}

/*! \cidoxg_end */
