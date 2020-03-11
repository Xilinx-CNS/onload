/* SPDX-License-Identifier: Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_team.h>
#include <linux/socket.h>

#include "private.h"

/* RHEL7 does not have SOL_NETLINK defined.  But it has NETLINK_ADD_MEMBERSHIP.
 * Reasons for this are unclear. */
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

/* The array must match to enum cp_genl_group */
static const char* group_name[CP_GENL_GROUP_MAX] = {
  "nlctrl",
  TEAM_GENL_NAME
};

int cp_genl_dump_start(struct cp_session* s)
{
  struct {
    struct nlmsghdr nlhdr;
    struct genlmsghdr CP_NLMSG_PACKED gen;
  } msg;
  CI_BUILD_ASSERT(sizeof(msg) == NLMSG_SPACE(GENL_HDRLEN));

  cp_row_mask_init(s->seen, CP_GENL_GROUP_MAX);

  msg.gen.cmd = CTRL_CMD_GETFAMILY;
  return cp_nl_send_dump_req(s, s->sock_gen[CP_GENL_GROUP_CTRL],
                             &msg.nlhdr, GENL_ID_CTRL, NLM_F_DUMP,
                             sizeof(msg));
}

void genl_drop_membership(struct cp_session* s,
                          enum cp_genl_group group_type)
{
  setsockopt(s->sock_gen[group_type], SOL_NETLINK, NETLINK_DROP_MEMBERSHIP,
             &s->genl_group[group_type], sizeof(s->genl_group[group_type]));
  s->genl_family[group_type] = s->genl_group[group_type] = 0;
}

void cp_genl_dump_done(struct cp_session* s)
{
  int i;

  for( i = 0; i < CP_GENL_GROUP_MAX; i++ ) {
    if( s->genl_family[i] != 0 && ! cp_row_mask_get(s->seen, i) )
      genl_drop_membership(s, i);
  }
}

static void ctrl_handle(struct cp_session* s,
                        struct genlmsghdr* genlhdr, size_t bytes)
{
  bool add;
  enum cp_genl_group group_type = CP_GENL_GROUP_MAX;
  uint32_t family_id = 0;
  uint32_t group_id = 0;

  /* On 3.10, you'll see CTRL_CMD_NEWFAMILY without groups
   * + CTRL_CMD_NEWMCAST_GRP when team module is registered.
   * On 3.16, you'll see CTRL_CMD_NEWFAMILY with groups. */
  switch( genlhdr->cmd ) {
    case CTRL_CMD_NEWFAMILY:
    case CTRL_CMD_NEWMCAST_GRP:
      add = true;
      break;
    case CTRL_CMD_DELFAMILY:
    case CTRL_CMD_DELMCAST_GRP:
      add = false;
      break;

    default:
      /* We are not interested in any other messages */
      return;
  }

  /* We should use "struct nlattr" instead of "struct rtattr" here, but
   * they do not differ from each other, and there is no sense in writing
   * 2 copies of access macros.
   * iproute does the same thing. */
  RTA_LOOP(genlhdr, attr, bytes) {
    switch( attr->rta_type & NLA_TYPE_MASK ) {
      case CTRL_ATTR_FAMILY_NAME:
        if( group_type == CP_GENL_GROUP_MAX) {
          int i;
          for( i = 0; i < CP_GENL_GROUP_MAX; i++ ) {
            if( strcmp(group_name[i], RTA_DATA(attr)) == 0 ) {
              group_type = i;
              break;
            }
          }
          /* We are not interested in unknown groups */
          if( i == CP_GENL_GROUP_MAX )
            return;
        }
        break;

      case CTRL_ATTR_FAMILY_ID:
        family_id = *((uint32_t *)RTA_DATA(attr));
        if( family_id == GENL_ID_CTRL ) {
          ci_assert_nequal(group_type, CP_GENL_GROUP_TEAM);
          group_type = CP_GENL_GROUP_CTRL;
        }
        break;

      case CTRL_ATTR_MCAST_GROUPS:
      /* In the both cases we have one and only one multicast group:
       * "nlctrl"/"notify" and
       * TEAM_GENL_NAME/TEAM_GENL_CHANGE_EVENT_MC_GRP_NAME.  If this ever
       * changes, we'll need to check CTRL_ATTR_MCAST_GRP_NAME attribute to
       * get the right group. */
      {
        RTA_NESTED_LOOP(attr, attr1, bytes1) {
          /* attr1->rta_type is the index of this group.  In our cases it
           * is always 0, but other families may have multiple multicast
           * groups. */

          RTA_NESTED_LOOP(attr1, attr2, bytes2) {
            if( (attr2->rta_type & NLA_TYPE_MASK) == CTRL_ATTR_MCAST_GRP_ID ) {
              group_id = *((uint32_t *)RTA_DATA(attr2));
              break;
            }
          }
          ci_assert(group_id);
          if( CI_LIKELY( group_id != 0 ) )
            break;
        }
        break;
      }
    }
  }

  ci_assert_nequal(group_type, CP_GENL_GROUP_MAX);
  ci_assert_nequal(family_id, 0);
  if( CI_UNLIKELY(group_type == CP_GENL_GROUP_MAX || family_id == 0 ) ) {
    ci_log("ERROR: NETLINK_GENERIC message without valid content");
    return;
  }

  if( add ) {
    if( group_id == 0 ) {
      ci_assert_equal(genlhdr->cmd, CTRL_CMD_NEWFAMILY);
      /* we'll get CTRL_CMD_NEWMCAST_GRP later */
      return;
    }

    if( s->state == CP_DUMP_GENL)
      cp_row_mask_set(s->seen, group_type);
    if( s->genl_group[group_type] != group_id ) {
      if( s->genl_group[group_type] != 0 )
        genl_drop_membership(s, group_type);
      s->genl_family[group_type] = family_id;
      s->genl_group[group_type] = group_id;
      if( ! (s->flags & CP_SESSION_NO_LISTEN) ) {
        setsockopt(s->sock_gen[group_type], SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                   &group_id, sizeof(group_id));
      }
    }
  }
  else if( s->genl_group[group_type] != 0 ) {
    /* We unbind from the group_id even if it is not provided yet. */
    if( group_id != 0 )
      ci_assert_equal(s->genl_group[group_type], group_id);
    ci_assert_equal(s->genl_family[group_type], family_id);
    genl_drop_membership(s, group_type);
  }
}

static void
team_port_handle(struct cp_session* s,
                 struct genlmsghdr* genlhdr, ssize_t bytes, bool is_dump)
{
  ci_ifid_t team = 0, port = 0;

  RTA_LOOP(genlhdr, attr, bytes) {
    uint16_t team_attr_type = attr->rta_type & NLA_TYPE_MASK;
    switch( team_attr_type ) {
      case TEAM_ATTR_TEAM_IFINDEX:
        ci_assert_equal(team, 0);
        team = *((uint32_t *)RTA_DATA(attr));
        break;

      case TEAM_ATTR_LIST_PORT:
      {
        ci_assert_nequal(team, 0);
        if( team == 0 ) {
          ci_log("WARNING: no TEAM_ATTR_TEAM_IFINDEX attribute before "
                 "TEAM_ATTR_LIST_PORT attribute");
          break;
        }

        RTA_NESTED_LOOP(attr, attr1, bytes1) {
          uint32_t port_flags = 0;
          uint16_t list_port_type = attr1->rta_type & NLA_TYPE_MASK;

          ci_assert_equal(list_port_type, TEAM_ATTR_ITEM_PORT);
          if( list_port_type != TEAM_ATTR_ITEM_PORT ) {
            ci_log("WARNING: unexpected attribute TEAM_ATTR_LIST_PORT/%d",
                   list_port_type);
            continue;
          }

          RTA_NESTED_LOOP(attr1, attr2, bytes2) {
            uint16_t port_attr_type = attr2->rta_type & NLA_TYPE_MASK;
            switch( port_attr_type ) {
              case TEAM_ATTR_PORT_IFINDEX:
                ci_assert_equal(port, 0);
                port = *((uint32_t *)RTA_DATA(attr2));
                break;

              case TEAM_ATTR_PORT_CHANGED:
                /* TODO: Do we need the "changed" flag? it can be used to
                 * separate dump from multicast updates. */
              case TEAM_ATTR_PORT_LINKUP:
              case TEAM_ATTR_PORT_REMOVED:
                port_flags |= 1 << port_attr_type;
                break;

              case TEAM_ATTR_PORT_SPEED:
              case TEAM_ATTR_PORT_DUPLEX:
                break;

              default:
                ci_log("WARNING: unknown attribute TEAM_ATTR_ITEM_PORT/%d",
                       port_attr_type);
                break;
            }
          }

          ci_assert_nequal(port, 0);
          if( port == 0 ) {
            ci_log("WARNING: no port in TEAM_ATTR_ITEM_PORT attribute");
            continue;
          }

          /* team `team` has/had port `port`; see details in `port_flags` */
          if( port_flags & (1 << TEAM_ATTR_PORT_REMOVED) ) {
            ci_assert(!is_dump);
            cp_team_slave_del(s, team, port);
          }
          else {
            cicp_rowid_t port_id = cp_team_port_add(s, team, port);
            if( ! CICP_ROWID_IS_VALID(port_id) )
              continue;
            cp_team_slave_update_flags(s, port_id, CICP_BOND_ROW_FLAG_UP,
                                       port_flags & (1 << TEAM_ATTR_PORT_LINKUP) ?
                                       CICP_BOND_ROW_FLAG_UP : 0);
            if( is_dump ) {
              ci_assert(s->team_dump);
              cp_row_mask_set(s->team_dump->seen, port_id);
            }
          }
          CI_DEBUG(port = 0;)
        }
        break;
      }

      default:
        ci_log("WARNING: unknown attribute %d "
               "in TEAM_CMD_PORT_LIST_GET message", team_attr_type);
        break;
    }
  }
}


static void team_opt_apply_mode(struct cp_session* s, ci_ifid_t team,
                                void* val, uint32_t flags, ci_ifid_t port)
{
  int mode;

  if( strcmp(val, "activebackup") == 0 )
    mode = CICP_BOND_MODE_ACTIVE_BACKUP;
  else if( strcmp(val, "loadbalance") == 0 )
    mode = CICP_BOND_MODE_802_3AD;
  else
    mode = CICP_BOND_MODE_UNSUPPORTED;

  ci_assert_nflags(flags, 1 << TEAM_ATTR_OPTION_REMOVED);
  cp_team_set_mode(s, team, mode, 0);
}
static void team_opt_apply_enabled(struct cp_session* s, ci_ifid_t team,
                                   void* val, uint32_t flags, ci_ifid_t port)
{
  ci_assert_nequal(port, 0);
  cicp_rowid_t port_id = cp_team_port_add(s, team, port);
  if( CICP_ROWID_IS_VALID(port_id) )
    cp_team_slave_update_flags(s, port_id, CICP_BOND_ROW_FLAG_ENABLED,
                               (val == NULL ||
                                (flags & (1 << TEAM_ATTR_OPTION_REMOVED))) ?
                                0 : CICP_BOND_ROW_FLAG_ENABLED);
}

static void team_opt_apply_activeport(struct cp_session* s, ci_ifid_t team,
                                      void* val, uint32_t flags,
                                      ci_ifid_t port)
{
  /* Port value is passed in the "option value", not in the "port" */
  port = *(uint32_t*)val;

  /* TODO: Ideally, we should do both changes in one verlock loop.
   * From the other side, mode is probably already set to ACTIVE_BACKUP. */
  cp_team_set_mode(s, team, CICP_BOND_MODE_ACTIVE_BACKUP, 0);
  if( flags & (1 << TEAM_ATTR_OPTION_REMOVED) )
    cp_team_remove_master(s, team);
  else if( port == 0 )
    cp_team_no_ports(s, team);
  else
    cp_team_activebackup_set_active(s, team, port);
}

static void team_opt_apply_bpf(struct cp_session* s, ci_ifid_t team,
                               void* val, uint32_t flags, ci_ifid_t port)
{
  if( flags & (1 << TEAM_ATTR_OPTION_REMOVED) ) {
    cp_team_remove_master(s, team);
    return;
  }

  cp_team_set_mode(s, team, CICP_BOND_MODE_802_3AD, 0);
}

/* We are interested in the following options only: */
struct {
  char* name;
  void (*apply)(struct cp_session* s, ci_ifid_t team,
                void* val, uint32_t flags, ci_ifid_t port);
} team_options[] = {
  {"mode", team_opt_apply_mode},
  {"enabled", team_opt_apply_enabled},

  /* activebackup-specific */
  {"activeport", team_opt_apply_activeport},

  /* loadbalance-specific */
  {"bpf_hash_func", team_opt_apply_bpf},
};
#define CP_TEAM_OPTION_MAX (sizeof(team_options) / sizeof(team_options[0]))

static void
team_one_opt_handle(struct cp_session* s, ci_ifid_t team,
                    struct rtattr* item_option)
{
  int opt = CP_TEAM_OPTION_MAX;
  void* val = NULL;
  uint32_t flags = 0;
  ci_ifid_t port = 0;
  uint16_t item_option_type = item_option->rta_type & NLA_TYPE_MASK;

  ci_assert_equal(item_option_type, TEAM_ATTR_ITEM_OPTION);
  if( item_option_type != TEAM_ATTR_ITEM_OPTION ) {
    ci_log("WARNING: unexpected attribute TEAM_ATTR_LIST_OPTION/%d",
           item_option_type);
    return;
  }

  RTA_NESTED_LOOP(item_option, attr, bytes) {
    uint16_t subtype = attr->rta_type & NLA_TYPE_MASK;
    switch( subtype ) {
      case TEAM_ATTR_OPTION_NAME:
        ci_assert_equal(opt, CP_TEAM_OPTION_MAX);
        for( opt = 0; opt < CP_TEAM_OPTION_MAX; opt++ ) {
          if( strcmp(RTA_DATA(attr), team_options[opt].name) == 0 )
            break;
        }
        if( opt == CP_TEAM_OPTION_MAX )
          return;
        break;

      case TEAM_ATTR_OPTION_DATA:
        val = RTA_DATA(attr);
        break;

      case TEAM_ATTR_OPTION_PORT_IFINDEX:
        ci_assert_nequal(opt, CP_TEAM_OPTION_MAX);
        port = *(uint32_t*)RTA_DATA(attr);
        break;


      case TEAM_ATTR_OPTION_TYPE:
        /* we believe that we already know the type */
      case TEAM_ATTR_OPTION_ARRAY_INDEX:
        /* we do not expect to see this attribute for options we are
         * interested in */
        break;

      case TEAM_ATTR_OPTION_CHANGED:
      case TEAM_ATTR_OPTION_REMOVED:
        flags |= 1 << subtype;
        break;

      default:
        ci_log("WARNING: unknown attribute TEAM_ATTR_ITEM_OPTION/%d", subtype);
        break;
    }
  }

  team_options[opt].apply(s, team, val, flags, port);
}

static void
team_options_handle(struct cp_session* s,
                    struct genlmsghdr* genlhdr, ssize_t bytes)
{
  ci_ifid_t team = 0;

  RTA_LOOP(genlhdr, attr, bytes) {
    uint16_t team_opt_type = attr->rta_type & NLA_TYPE_MASK;
    switch( team_opt_type ) {
      case TEAM_ATTR_TEAM_IFINDEX:
        ci_assert_equal(team, 0);
        team = *((uint32_t *)RTA_DATA(attr));
        if( team == 0 ) {
          /* linux/drivers/net/team/team.c:team_init() sends initial state
           * of the team with ifindex==0.  We can't do anything with this.
           * In practice, all the important options are set (and announced)
           * later.  And even if this changes in future, we do periodic dumps.
           */
          return;
        }
        break;

      case TEAM_ATTR_LIST_OPTION:
      {
        ci_assert_nequal(team, 0);
        if( team == 0 ) {
          ci_log("WARNING: no TEAM_ATTR_TEAM_IFINDEX attribute before "
                 "TEAM_ATTR_LIST_OPTION attribute");
          break;
        }

        RTA_NESTED_LOOP(attr, attr1, bytes1)
          team_one_opt_handle(s, team, attr1);
        break;
      }

      default:
        ci_log("WARNING: unknown attribute %d "
               "in TEAM_CMD_OPTION_GET message", team_opt_type);
        break;
    }
  }
}

static void
genl_team_handle(struct cp_session* s,
                 struct nlmsghdr *nlhdr, ssize_t bytes, bool is_dump)
{
  struct genlmsghdr* genlhdr = NLMSG_DATA(nlhdr);

  /* TODO: Do we need nlhdr->nlmsg_seq and nlmsg_pid to separate dump replies
   * from new updates? */

  switch( genlhdr->cmd ) {
    case TEAM_CMD_PORT_LIST_GET:
      team_port_handle(s, genlhdr,
                       NLMSG_PAYLOAD(nlhdr, sizeof(struct genlmsghdr)),
                       is_dump);
      break;
    case TEAM_CMD_OPTIONS_GET:
      team_options_handle(s, genlhdr,
                          NLMSG_PAYLOAD(nlhdr, sizeof(struct genlmsghdr)));
      break;
    default:
      ci_log("WARNING: unknown team command %d", genlhdr->cmd);
  }
}

struct genl_dump_team {
  struct genlmsghdr CP_NLMSG_PACKED gen;
  /* struct name needed to avoid compiler error */
  struct __rt {
    struct rtattr attr;
    uint32_t CP_RTA_PACKED ifindex;
  } CP_NLMSG_PACKED rt;
};
static int team_dump_one(struct cp_session* s, struct cp_team_dump* state)
{
  struct {
    struct nlmsghdr nlhdr;
    struct genl_dump_team d;
  } msg;
  CI_BUILD_ASSERT(sizeof(msg) ==
                  NLMSG_SPACE(GENL_HDRLEN + RTA_SPACE(sizeof(msg.d.rt.ifindex))));

  msg.d.gen.cmd = state->state == CP_TEAM_DUMP_OPTS ?
                        TEAM_CMD_OPTIONS_GET : TEAM_CMD_PORT_LIST_GET;
  msg.d.rt.attr.rta_type = TEAM_ATTR_TEAM_IFINDEX;
  msg.d.rt.attr.rta_len = RTA_LENGTH(sizeof(msg.d.rt.ifindex));
  msg.d.rt.ifindex = state->ifindex;

  /* The dump request needs to be sent to CP_GENL_GROUP_CTRL socket,
   * because CP_GENL_GROUP_TEAM can receive NLMSG_DONE at any time
   * and so can mess up our state machine. */
  return cp_nl_send_dump_req(s, s->sock_gen[CP_GENL_GROUP_CTRL], &msg.nlhdr,
                           s->genl_family[CP_GENL_GROUP_TEAM], NLM_F_ROOT,
                           sizeof(msg));
}

static void team_dump_next(struct cp_session* s)
{
  while( s->team_dump != NULL ) {
    struct cp_team_dump* state = s->team_dump;

    if( state->state == CP_TEAM_DUMP_DONE ) {
      s->team_dump = state->next;
      ci_team_purge_unseen(s, state->ifindex, state->seen);
      free(state);
      continue;
    }

    int rc = team_dump_one(s, state);
    if( rc != 0 ) {
      /* If there is no luck this time, then we'll ask OS about this team
       * interface later again. */
      s->team_dump = state->next;
      free(state);
      /* Go through the team_dump list: we'll probably fail again, but
       * let's free all these states. */
      continue;
    }
    state->state++;
    return;
  }

  /* See cp_do_dump(): we should call cp_dump_start() if LLAP has finished
   * its dumping: */
  if( s->state != CP_DUMP_LLAP ) {
    ci_assert_equal(s->state, CP_DUMP_LLAP + 1);
    cp_dump_start(s);
  }
}


/* nl_gen_ctrl_handle() and nl_gen_team_handle() are similar, but they
 * can't be merged into one.  The problem is NLMSG_DONE message.  For
 * CP_GENL_GROUP_CTRL socket, this message is used to call cp_do_dump():
 * we've finished dumping all NETLINK_GENERIC families/groups.  But
 * CP_GENL_GROUP_TEAM socket receives it at any time, for example when
 * a new slave(s) have been added.
 *
 * This issue is also the reason for two sock_gen sockets: we should find
 * out what kind of NLMSG_DONE have been received. */
void nl_gen_ctrl_handle(struct cp_session* s, struct cp_epoll_state* state)
{
  ssize_t bytes;
  struct nlmsghdr *nlhdr = NULL;

  while ( (bytes = cp_sock_recv(s, s->sock_gen[CP_GENL_GROUP_CTRL])) > 0 ) {
    nlhdr = s->buf;
    while( NLMSG_OK(nlhdr, bytes) ) {
      switch( nlhdr->nlmsg_type ) {
        case NLMSG_ERROR:
        {
          struct nlmsgerr* err = NLMSG_DATA(nlhdr);
          if( err->error != -EINVAL ) {
            ci_log("%s(): NLMSG_ERROR error=%d", __func__, err->error);
            break;
          }
          if( err->msg.nlmsg_type == GENL_ID_CTRL ) {
            ci_log("%s(): NLMSG_ERROR for GENL_ID_CTRL", __func__);
            break;
          }
          if( err->msg.nlmsg_type !=
                   s->genl_family[CP_GENL_GROUP_TEAM] ) {
            ci_log("%s(): got NLMSG_ERROR type %d when expecting type %d",
                   __func__, err->msg.nlmsg_type,
                   s->genl_family[CP_GENL_GROUP_TEAM]);
            break;
          }
          if( s->team_dump == NULL ) {
            ci_log("%s(): NLMSG_ERROR out of team dump, in %d state",
                   __func__, s->state);
            break;
          }
          /* It must be a dump request for an interface which has just
           * gone away. */
          struct genl_dump_team *msg = NLMSG_DATA(&err->msg);
          cp_team_remove_master(s, msg->rt.ifindex);
          team_dump_next(s);
          break;
        }

        case NLMSG_NOOP:
          break;

        case NLMSG_DONE:
          if( s->state == CP_DUMP_GENL )
            cp_do_dump(s);
          else
            team_dump_next(s);
          break;

        case GENL_ID_CTRL:
          ctrl_handle(s, NLMSG_DATA(nlhdr),
                      NLMSG_PAYLOAD(nlhdr, sizeof(struct genlmsghdr)));
          break;

        default:
          if( nlhdr->nlmsg_type == s->genl_family[CP_GENL_GROUP_TEAM] )
            genl_team_handle(s, nlhdr, bytes, true);
      }

      nlhdr = NLMSG_NEXT(nlhdr, bytes);
    }
  }
}

void nl_gen_team_handle(struct cp_session* s, struct cp_epoll_state* state)
{
  ssize_t bytes;
  struct nlmsghdr *nlhdr = NULL;

  while ( (bytes = cp_sock_recv(s, s->sock_gen[CP_GENL_GROUP_TEAM])) > 0 ) {
    nlhdr = s->buf;
    while( NLMSG_OK(nlhdr, bytes) ) {
      switch( nlhdr->nlmsg_type ) {
        case NLMSG_ERROR:
          ci_log("%s(): ERROR", __func__);
          break;

        case NLMSG_NOOP:
          break;

        case NLMSG_DONE:
          /* We see DONE after the end of every operation.  Ignore it. */
          break;

        default:
          if( nlhdr->nlmsg_type == s->genl_family[CP_GENL_GROUP_TEAM] ) {
            genl_team_handle(s, nlhdr, bytes, false);
          }
          else {
            ci_log("WARNING: unknown message type %d "
                   "when expecting team(%d)",
                   nlhdr->nlmsg_type, s->genl_family[CP_GENL_GROUP_TEAM]);
          }
          break;
      }

      nlhdr = NLMSG_NEXT(nlhdr, bytes);
    }
  }
}

void cp_team_dump_one(struct cp_session* s, ci_ifid_t ifindex)
{
  struct cp_team_dump* state =
    calloc(sizeof(*state) + cp_row_mask_sizeof(s->bond_max), 1);
  if( state == NULL )
    return;
  state->seen = (void*)(state + 1);
  state->ifindex = ifindex;
  state->next = s->team_dump;
  s->team_dump = state;

  /* If it is the first teaming interface, then start with it. */
  if( state->next == NULL )
    team_dump_next(s);
}

