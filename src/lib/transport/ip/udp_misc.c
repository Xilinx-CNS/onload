/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Misc stuff for UDP sockets.
**   \date  2005/02/01
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */
#include "ip_internal.h"
#include "udp_internal.h"
#include <onload/osfile.h>

#define VERB(x)


void ci_udp_state_free(ci_netif* ni, ci_udp_state* us)
{
  ci_assert(ci_netif_is_locked(ni));
  ci_assert(us->s.b.state == CI_TCP_STATE_UDP);
  ci_assert(ci_ni_dllist_is_self_linked(ni, &us->s.b.post_poll_link));

#if CI_CFG_TIMESTAMPING
  ci_udp_recv_q_drop(ni, &us->timestamp_q);
#endif

  citp_waitable_obj_free(ni, &us->s.b);
}


int ci_udp_try_to_free_pkts(ci_netif* ni, ci_udp_state* us, int desperation)
{
  /* Reap should be called before this.  There is nothing else we can do. */
  return 0;
}

void ci_udp_perform_deferred_socket_work(ci_netif* ni, ci_udp_state* us)
{
  ci_assert(us->s.b.state == CI_TCP_STATE_UDP);

  ci_udp_sendmsg_send_async_q(ni, us);
}

/*! \cidoxg_end */
