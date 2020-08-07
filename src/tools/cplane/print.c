/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2018-2020 Xilinx, Inc. */
#include "private.h"
#include "print.h"
#include "mibdump.h"

void cp_print(struct cp_session* s, const char* format, ...)
{
  va_list ap;
  va_start(ap, format);
  vdprintf(s->cp_print_fd, format, ap);
  va_end(ap);
  dprintf(s->cp_print_fd, "\n");
}

void cp_print_nonewline(struct cp_session* s, const char* format, ...)
{
  va_list ap;
  va_start(ap, format);
  vdprintf(s->cp_print_fd, format, ap);
  va_end(ap);
}

static void cp_stat_print(struct cp_session* s)
{
  cp_print(s, "Flags: 0x%x", s->flags);
  cp_print(s, "Statistics:");

#define  CP_STAT_GROUP_START(desc, name) \
  {                                                 \
    typeof(s->stats.name)* group = &s->stats.name;  \
    const char* group_name = #name;
#define CP_STAT(desc, type, name) \
    cp_print(s, "%s."#name": %d", group_name, group->name);
#define CP_STAT_GROUP_END(name) \
  }
#include "stats.h"
#undef CP_STAT_GROUP_START
#undef CP_STAT
#undef CP_STAT_GROUP_END
}

static void cp_stat_doc_print(struct cp_session* s)
{
  cp_print(s, "Statistic Fields:");

#define  CP_STAT_GROUP_START(desc, name) \
  {                                                 \
    const char* group_name = #name;                 \
    cp_print(s, #name": "#desc);
#define CP_STAT(desc, type, name) \
    cp_print(s, "  %s."#name": %s", group_name, desc);
#define CP_STAT_GROUP_END(name) \
  }
#include "stats.h"
#undef CP_STAT_GROUP_START
#undef CP_STAT
#undef CP_STAT_GROUP_END
}

#define CP_SERVER_PRINT_STATE_IPV6_BITS \
  ((1 << CP_SERVER_PRINT_STATE_MAC6) | (1 << CP_SERVER_PRINT_STATE_DST6) | \
   (1 << CP_SERVER_PRINT_STATE_SRC6) | (1 << CP_SERVER_PRINT_STATE_ROUTE6))

static void
print_route(struct cp_session* s, int i, struct cp_ip_with_prefix* ipp)
{
  struct cp_route* route = (struct cp_route*)(char*)ipp;

  cp_ippl_print_cb_ip_prefix(s, i, ipp);
  cp_print(s, "\tmetric %d tos %d scope %d type %d",
           route->metric, route->tos, route->scope, route->type);
  cp_print(s, "\t"CP_FWD_DATA_BASE_FMT,
           CP_FWD_DATA_BASE_ARG(s->mib, &route->data));
  if( route->weight.end != 0 )
    cp_print(s, "\t"CP_FWD_MULTIPATH_WEIGHT_FMT,
             CP_FWD_MULTIPATH_WEIGHT_ARG(&route->weight));
}
static void
print_route_table(struct cp_session* s, struct cp_route_table** tables)
{
  int i;
  for( i = 0; i < ROUTE_TABLE_HASH_SIZE; i++ ) {
    struct cp_route_table* table;
    for( table = tables[i];
         table != NULL; table = table->next ) {
      cp_print(s, "Route table %d:", table->id);
      cp_ippl_print(s, &table->routes, print_route);
    }
  }
}

static void cp_laddr_print_cb(struct cp_session* s, int i,
                              struct cp_ip_with_prefix* ipp)
{
  cp_print(s, "  [%d] %s %s(%d)", i, AF_IP_L3(ipp->addr),
           cp_ifindex2name(cp_get_active_mib(s), ipp->ifindex), ipp->ifindex);
}

void cp_session_print_state(struct cp_session* s, int kind)
{
  cp_print(s, "%s(0x%x):", __func__, kind);

  if( kind == 0 )
    kind = (1 << CP_SERVER_PRINT_STATE_STAT_DOC) - 1;

  if( (kind & CP_SERVER_PRINT_STATE_IPV6_BITS) &&
      (s->flags & CP_SESSION_NO_IPV6) ) {
    cp_print(s, "\nIPv6 support disabled\n");
    kind &=~ CP_SERVER_PRINT_STATE_IPV6_BITS;
  }

  if( kind & (1 << CP_SERVER_PRINT_STATE_BASE) ) {
    cp_print(s, "  flags=%x", s->flags);
    cp_print(s, "  state=%d prev_state=%d seen[0]=%016" PRIx64, s->state,
            s->prev_state, s->seen[0]);
    cp_print(s, "  user_hz=%u khz=%"PRIu64, s->user_hz, s->khz);

    if( kind != 1 << CP_SERVER_PRINT_STATE_BASE )
      cp_print(s, "");
  }

  if( kind & (1 << CP_SERVER_PRINT_STATE_DST) ) {
    cp_print(s, "Destinations in routes and rules:");
    cp_ippl_print(s, &s->route_dst, cp_ippl_print_cb_ip_prefix);
  }
  if( kind & (1 << CP_SERVER_PRINT_STATE_SRC) ) {
    cp_print(s, "Source rules:");
    cp_ippl_print(s, &s->rule_src, cp_ippl_print_cb_ip_prefix);
  }
  if( kind & (1 << CP_SERVER_PRINT_STATE_DST6) ) {
    cp_print(s, "IPv6 destinations in routes and rules:");
    cp_ippl_print(s, &s->ip6_route_dst, cp_ippl_print_cb_ip_prefix);
  }
  if( kind & (1 << CP_SERVER_PRINT_STATE_SRC6) ) {
    cp_print(s, "IPv6 source rules:");
    cp_ippl_print(s, &s->ip6_rule_src, cp_ippl_print_cb_ip_prefix);
  }

  if( kind & (1 << CP_SERVER_PRINT_STATE_LLAP) )
    cp_llap_print(s);
  if( kind & (1 << CP_SERVER_PRINT_STATE_TEAM) )
    cp_team_print(s);
  if( kind & (1 << CP_SERVER_PRINT_STATE_MAC) )
    cp_mac_print(s);
  if( kind & (1 << CP_SERVER_PRINT_STATE_MAC6) )
    cp_mac6_print(s);
  if( kind & (1 << CP_SERVER_PRINT_STATE_FWD) )
    cp_fwd_print(s);
  if( kind & (1 << CP_SERVER_PRINT_STATE_STAT) )
    cp_stat_print(s);

  if( kind & (1 << CP_SERVER_PRINT_STATE_ROUTE) )
    print_route_table(s, s->rt_table);
  if( kind & (1 << CP_SERVER_PRINT_STATE_ROUTE6) )
    print_route_table(s, s->rt6_table);

  if( kind & (1 << CP_SERVER_PRINT_STATE_LADDR) ) {
    cp_print(s, "Local addresses for accelerated interfaces:");
    cp_ippl_print(s, &s->laddr, cp_laddr_print_cb);
  }

  if( kind & (1 << CP_SERVER_PRINT_STATE_STAT_DOC) )
    cp_stat_doc_print(s);
}

