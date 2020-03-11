/* SPDX-License-Identifier: Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* Cplane state machine to dump all MIB tables from OS to internal and
 * shared states. */

#include "private.h"


static int nl_dump(struct cp_session* s, int nlmsg_type,
                   cicp_mac_rowid_t rows_max, unsigned char family)
{
  struct {
    struct nlmsghdr nlhdr;
    struct rtgenmsg CP_NLMSG_PACKED rtm;
  } msg;
  CI_BUILD_ASSERT(sizeof(msg) == NLMSG_SPACE(sizeof(struct rtgenmsg)));

  cp_row_mask_init(s->seen, rows_max);

  msg.rtm.rtgen_family = family;
  return cp_nl_send_dump_req(s, s->sock_net, &msg.nlhdr, nlmsg_type,
                             NLM_F_ROOT, sizeof(msg));
}

CP_UNIT_EXTERN void cp_nl_dump_all_done(struct cp_session* s)
{
  /* We have to refresh fwd cache because we do not dump the route and
   * rule tables. */
  if( ! (s->flags & CP_SESSION_FLAG_FWD_REFRESHED) )
    cp_fwd_cache_refresh(s);
  s->flags &=~ CP_SESSION_FLAG_FWD_REFRESHED;
}


static void cp_dump_finish(struct cp_session* s)
{
  /* Finish the current dump. */
    switch( s->state ) {
      case CP_DUMP_IDLE:
        break;
      case CP_DUMP_LLAP:
        cp_llap_dump_done(s);
        break;
      case CP_DUMP_IPIF:
        cp_ipif_dump_done(s);
        break;
      case CP_DUMP_IP6IF:
        cp_ip6if_dump_done(s);
        break;
      case CP_DUMP_GENL:
        cp_genl_dump_done(s);
        break;
      case CP_DUMP_MAC:
      case CP_DUMP_MAC6:
        cp_mac_dump_done(s, (s->state == CP_DUMP_MAC6) ? AF_INET6 : AF_INET);
        break;
      case CP_DUMP_RULE:
      case CP_DUMP_RULE6:
        cp_rule_dump_done(s, (s->state == CP_DUMP_RULE6) ? AF_INET6 : AF_INET);
        break;
      case CP_DUMP_ROUTE:
      case CP_DUMP_ROUTE6:
      {
        int af = (s->state == CP_DUMP_ROUTE6) ? AF_INET6 : AF_INET;
        cp_route_dump_done(s, af);
        break;
      }
      default:
        break;
    }
}

void cp_dump_init(struct cp_session* s)
{
  s->prev_state = CP_DUMP_IDLE;
  s->state++;
  s->dump_one_only = false;

  /* We can get here starting a new dump or retrying after a failed one.
   * We must ensure that the version is odd now, but we must not increment
   * to the even number.  So we use '|= 1' instead of '++'. */
  *s->mib->dump_version |= 1;
  cp_dump_start(s);
}

/* Previous periodic dump went awry.  Give netlink some time to process
 * all the messages and get into a better state and call periodic dump
 * again after 1s. */
static void cp_dump_recover(struct cp_session* s, bool overlap)
{
  struct itimerspec its;
  timer_gettime(s->timer_net.t, &its);

  /* We want to restart dump after 1 second, but we have to increase
   * interval if periodic dump overlaps. */
  if( overlap )
    its.it_interval.tv_sec++;
  its.it_value.tv_sec = 1;

  timer_settime(s->timer_net.t, 0, &its, NULL);
  if( overlap ) {
    ci_log("Periodic dump when in %d state: increasing periodic dump "
           "timeout to %d seconds", s->state, (int)its.it_interval.tv_sec);
  }
  else {
    ci_log("Periodic dump failed in %d state, restart after 1 second", s->state);
    s->state = CP_DUMP_IDLE;
  }
}

static void cp_dump_fini(struct cp_session* s, bool success)
{
  ci_assert_equal((*s->mib->dump_version) & 1, 1);

  if( success ) {
    (*s->mib->dump_version)++;

    /* If we have not told kernel that we are ready, then do it now. */
    if( ! (s->flags & CP_SESSION_NETLINK_DUMPED) ) {
      s->flags |= CP_SESSION_NETLINK_DUMPED;
      if( s->flags & CP_SESSION_HWPORT_DUMPED )
        cp_ready_usable(s);
    }
  }


  /* Nothing to finalize in case of simple periodic dump. */
  if( ! (s->flags & (CP_SESSION_USER_DUMP | CP_SESSION_USER_DUMP_REFRESH)) ) {
    if( ! success )
      cp_dump_recover(s, false);
    s->state = CP_DUMP_IDLE;
    return;
  }

  s->state = CP_DUMP_IDLE;

  /* User asked us to synchronize our state with the OS, but we were busy
   * with ongoing dump.  */
  if( s->flags & CP_SESSION_USER_DUMP_REFRESH ) {
    s->flags &=~ CP_SESSION_USER_DUMP_REFRESH;
    cp_dump_start(s);
    return;
  }

  if( success ) {
    ci_wmb(); /* ensure that dump_version is updated */
    if( cp_ready_usable(s) )
      s->flags &=~ CP_SESSION_USER_DUMP;
  }
  else {
    /* Complain to log and try again */
    ci_log("ERROR: OS MIB dump failed.  Retrying...");
    cp_dump_init(s);
  }
}

void cp_dump_start(struct cp_session* s)
{
  int af;

  /* Start the new dump mode.  Reset the dump mode in case of failure - the
   * timer will fire again, and we'll re-dump everything from scratch. */
  switch( s->state ) {
    case CP_DUMP_LLAP:
      if( nl_dump(s, RTM_GETLINK, s->mib->dim->llap_max, AF_INET) != 0 )
        cp_dump_fini(s, false);
      break;

    case CP_DUMP_IPIF:
      cp_ipif_dump_start(s, AF_INET);
      if( nl_dump(s, RTM_GETADDR, s->mib->dim->ipif_max, AF_INET) != 0 )
        cp_dump_fini(s, false);
      break;

    case CP_DUMP_IP6IF:
      cp_ipif_dump_start(s, AF_INET6);
      if( nl_dump(s, RTM_GETADDR, s->mib->dim->ip6if_max, AF_INET6) != 0 )
        cp_dump_fini(s, false);
      break;

    case CP_DUMP_GENL:
      if( cp_genl_dump_start(s) != 0 )
        cp_dump_fini(s, false);
      break;

    case CP_DUMP_MAC:
    case CP_DUMP_MAC6:
      if( nl_dump(s, RTM_GETNEIGH, s->mac_mask + 1,
          (s->state == CP_DUMP_MAC6) ? AF_INET6 : AF_INET) != 0 )
        cp_dump_fini(s, false);
      break;

    case CP_DUMP_RULE:
    case CP_DUMP_RULE6:
      af = (s->state == CP_DUMP_RULE6) ? AF_INET6 : AF_INET;
      cp_rule_dump_start(s, af);
      if( nl_dump(s, RTM_GETRULE, 0, af) != 0 )
        cp_dump_fini(s, false);
      break;

    case CP_DUMP_ROUTE:
    case CP_DUMP_ROUTE6:
    {
      int af = (s->state == CP_DUMP_ROUTE6) ? AF_INET6 : AF_INET;
      cp_route_dump_start(s, af);
      if( nl_dump(s, RTM_GETROUTE, 0, af) != 0 )
        cp_dump_fini(s, false);
      break;
    }

    case CP_DUMP_COMPLETED:
      cp_nl_dump_all_done(s);
      cp_dump_fini(s, true);
      break;

    default:
      ci_assert(0);
      break;
  }
}

void cp_do_dump(struct cp_session* s)
{
  cp_dump_finish(s);

  if( s->dump_one_only ) {
    s->state = CP_DUMP_IDLE;
    cp_nl_dump_all_done(s);
    return;
  }

  /* Increment the state */
  s->state++;

  if( (s->state == CP_DUMP_IP6IF || s->state == CP_DUMP_MAC6 ||
       s->state == CP_DUMP_RULE6 || s->state == CP_DUMP_ROUTE6) &&
      (s->flags & CP_SESSION_NO_IPV6) )
    s->state++;

  /* If team dump in in progress, it will call cp_dump_start() later,
   * see team_dump_next(). */
  if( s->team_dump != NULL )
    return;

  cp_dump_start(s);
}

void cp_periodic_dump(struct cp_session* s)
{
  if( s->state != CP_DUMP_IDLE ) {
    if( s->flags & CP_SESSION_USER_DUMP )
      return;

    if( s->state != s->prev_state ) {
      /* Overlap? */
      s->prev_state = s->state;
      cp_dump_recover(s, true);
      return;
    }

    /* There is no progress from the previous timer call.  Have we missed
     * NLMSG_DONE message?  Start it over. */
    cp_dump_fini(s, false);
  }

  cp_dump_init(s);
}

