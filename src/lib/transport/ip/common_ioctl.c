/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file common_ioctl.c
** <L5_PRIVATE L5_SOURCE>
** \author  stg
**  \brief  Ioctl handling common to all protocols
**   \date  2005/07/25
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include <linux/sockios.h>

#include "ip_internal.h"
#include <ci/net/ioctls.h>

/* Common handler for IOCTL calls. 
 * NOTE: in the kernel version if [arg] is a pointer then it will point
 * into user space.  Use the CI_IOCTL_* macros in internal.h please. 
 */
int ci_cmn_ioctl(ci_netif* netif, ci_sock_cmn* s, int request, 
		 void* arg, int os_rc, int os_socket_exists)
{
  ci_assert(netif);
  ci_assert(s);

  /* ioctl defines are listed in `man ioctl_list` and the CI equivalent
   * CI defines are in include/ci/net/ioctls.h */

  LOG_SV( ci_log("request = %u/%#x, arg = %lu/%#lx", request, request,
                 (long) arg, (long) arg));

  switch( request ) {
  case SIOCGPGRP:
    /* get the process ID/group that is receiving signals for this fd */
    if( !CI_IOCTL_ARG_OK(int, arg) )
      goto fail_fault;
    CI_IOCTL_SETARG( ((int*)arg), s->b.sigown);
    break;

  case SIOCSPGRP:
    /* set the process ID/group that is receiving signals for this fd */
    if( !CI_IOCTL_ARG_OK(int, arg) )
      goto fail_fault;
    s->b.sigown = CI_IOCTL_GETARG(int,arg);
    if( s->b.sigown && (s->b.sb_aflags & CI_SB_AFLAG_O_ASYNC) )
      ci_bit_set(&s->b.wake_request, CI_SB_FLAG_WAKE_RX_B);
    break;

  case SIOCGSTAMP:
  case SIOCGSTAMPNS:
    RET_WITH_ERRNO(ENOENT);

  default:
    if( !CI_IOCTL_ARG_OK(int, arg) )
      goto fail_fault;
    if (!os_socket_exists)
      RET_WITH_ERRNO(ENOTTY);
    /* Assumes that errno is unchanged from the OS call, or that [os_rc] == 0 */
    return os_rc;
  }

  /* Successful conclusion */
  return 0;

 fail_fault:
  LOG_SC( ci_log("%s: "NS_FMT" req %d/%#x arg %ld/%#lx unhandled (EINVAL)", 
		 __FUNCTION__, NS_PRI_ARGS(netif, s),
		 request, request, (long)arg, (long)arg));
  RET_WITH_ERRNO(EFAULT);
}
