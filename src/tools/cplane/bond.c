/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_bonding.h>
#include <linux/if_link.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>

#include "private.h"
#include <cplane/server.h>


/* Keep it in match with CICP_LLAP_TYPE_XMIT_HASH_* */
int hash_policy2llap_type(int hash_policy)
{
  int type = 1 << (hash_policy + 3);
  CI_BUILD_ASSERT(CICP_LLAP_TYPE_XMIT_HASH_LAYER2 == (1<<3));

  if( type & ~CICP_LLAP_TYPE_USES_HASH ) {
    CI_RLLOG(10,
             "Bonding: unknown xmit_hash_policy %d, "
             "using BOND_XMIT_POLICY_LAYER34",
             hash_policy);
    return CICP_LLAP_TYPE_XMIT_HASH_LAYER34;
  }
  return type;
}

/* The netlink bonding interface exists in linux>=3.14 and has been backported
 * to most distros that we care about, with the exception of SLES11.  The
 * control plane blob is built on a distro that includes it, which results in
 * a binary that is suitable for all of our supported distros. */

/* Handles a bonding netlink IFLA_BOND_.* sub-attribute associated with an
 * IFLA_INFO_DATA attribute. */
void cp_bond_handle_netlink_info(struct cp_session* s, ci_ifid_t bond_ifindex,
                                 struct rtattr *attr,
                                 struct cp_bond_netlink_state* state)
{
  switch( attr->rta_type & NLA_TYPE_MASK ) {
  case IFLA_BOND_MODE:
    state->attributes_seen |= CP_BOND_NETLINK_SEEN_MODE;
    switch( *(uint8_t*) RTA_GET(attr) ) {
    case BOND_MODE_ACTIVEBACKUP:
      state->mode = CICP_BOND_MODE_ACTIVE_BACKUP;
      break;
    case BOND_MODE_8023AD:
      state->mode = CICP_BOND_MODE_802_3AD;
      break;
    default:
      state->mode = CICP_BOND_MODE_UNSUPPORTED;
      break;
    }
    break;

  case IFLA_BOND_ACTIVE_SLAVE:
    state->attributes_seen |= CP_BOND_NETLINK_SEEN_ACTIVE_SLAVE;
    state->active_slave = *(uint32_t*) RTA_GET(attr);
    break;

  case IFLA_BOND_XMIT_HASH_POLICY:
    state->attributes_seen |= CP_BOND_NETLINK_SEEN_HASH_POLICY;
    state->hash_policy = hash_policy2llap_type(*(uint32_t*) RTA_GET(attr));
    break;

  case IFLA_BOND_AD_INFO:
    if( state->mode != CICP_BOND_MODE_802_3AD ) {
      /* Linux always puts IFLA_BOND_MODE before IFLA_BOND_AD_INFO. */
      ci_log("ERROR: unexpected IFLA_BOND_AD_INFO attribute for "
             "active-backup bond interface ifindex=%d", bond_ifindex);
      break;
    }
    RTA_NESTED_LOOP(attr, attr1, bytes1) {
      switch( attr1->rta_type & NLA_TYPE_MASK ) {
        case IFLA_BOND_AD_INFO_AGGREGATOR:
          state->attributes_seen |= CP_BOND_NETLINK_SEEN_AGGREGATOR;
          state->aggregator_id = (int)*(uint16_t*) RTA_GET(attr1);
          break;
      }
    }
    break;
  }
}

/* This macro calls the function above, after preparing the netlink-like
 * agrument.  The "data" parameter must be a variable, declared with
 * appropriate type, matching the "type" parameter. */
#define CP_BOND_HANDLE_NETLINK_INFO(s, bond_ifindex, type, data, state) \
  do {                                                                  \
    struct {                                                            \
      struct rtattr attr;                                               \
      typeof(data) CP_RTA_PACKED data;                                  \
    } attr;                                                             \
    attr.attr.rta_type = type;                                          \
    attr.attr.rta_len = sizeof(data);                                   \
    attr.data = data;                                                   \
    cp_bond_handle_netlink_info(s, bond_ifindex, &attr.attr, state);    \
  } while(0)


/* Handle an active-slave notification as received via the
 * IFLA_BOND_ACTIVE_SLAVE attribute. */
static void
cp_bond_handle_active_slave(struct cp_session* s, ci_ifid_t bond_ifindex,
                            ci_ifid_t active_slave_ifindex)
{
  cicp_rowid_t bond_rowid = cp_bond_find_master(s, bond_ifindex);

  /* We needn't be a bond at all, as some properties are indicated by the
   * absence of attributes.  In that case, there's nothing to do. */
  if( ! CICP_ROWID_IS_VALID(bond_rowid) )
    return;

  cicp_bond_row_t* bond = &s->bond[bond_rowid];

  /* We only track active slaves for active-backup bonds. */
  if( bond->master.mode != CICP_BOND_MODE_ACTIVE_BACKUP )
    return;

  if( active_slave_ifindex == 0 )
    cp_team_no_ports(s, bond_ifindex);
  else
    cp_team_activebackup_set_active(s, bond_ifindex, active_slave_ifindex);
}


/* Store aggregator id of LACP bond */
void cp_bond_handle_aggregator_id(struct cp_session* s,
                                  ci_ifid_t bond_ifindex,
                                  uint16_t agg_id)
{
  cicp_rowid_t team_id = cp_team_find_or_add(s, bond_ifindex);
  if( ! CICP_ROWID_IS_VALID(team_id) )
    return;

  ci_assert_equal(s->bond[team_id].master.mode, CICP_BOND_MODE_802_3AD);

  if( s->bond[team_id].agg_id == agg_id )
    return;
  s->bond[team_id].agg_id = agg_id;

  /* For each slave, set CICP_BOND_ROW_FLAG_ACTIVE flag if agg_id matches */
  s->bond[team_id].master.n_active_slaves = 0;
  cicp_rowid_t slave_id;
  for( slave_id = s->bond[team_id].next;
       slave_id != CICP_ROWID_BAD;
       slave_id = s->bond[slave_id].next ) {
    /* We can call cp_team_slave_update_flags() for each slave, but it
     * results in expensive team_update_hwports() for each.  So we manually
     * update FLAG_ENABLED and FLAG_ACTIVE, and rely on caller for
     * team_update_hwports() call after this. */
    /* See cp_bond_slave_update() for a comment about this condition */
    if( s->bond[slave_id].agg_id == 0 ||
        s->bond[slave_id].agg_id == agg_id ) {
      s->bond[slave_id].slave.flags |= CICP_BOND_ROW_FLAG_ENABLED;
      if( s->bond[slave_id].slave.flags & CICP_BOND_ROW_FLAG_UP ) {
        s->bond[slave_id].slave.flags |=  CICP_BOND_ROW_FLAG_ACTIVE;
        ++s->bond[team_id].master.n_active_slaves;
      }
    }
    else {
      s->bond[slave_id].slave.flags &=~
                (CICP_BOND_ROW_FLAG_ACTIVE | CICP_BOND_ROW_FLAG_ENABLED);
    }
  }

  cp_team_update_hwports_bothmibs(s, team_id);
}

/* Call this when all of the bonding properties from a netlink RTM_NEWLINK
 * message have been accumulated. */
void cp_bond_master_update(struct cp_session* s, ci_ifid_t bond_ifindex,
                           const struct cp_bond_netlink_state* state)
{
  if( state->attributes_seen & CP_BOND_NETLINK_SEEN_MODE ) {
    cp_team_set_mode(s, bond_ifindex, state->mode,
                state->attributes_seen & CP_BOND_NETLINK_SEEN_HASH_POLICY ?
                state->hash_policy : 0);
  }
  else {
    if( state->attributes_seen & CP_BOND_NETLINK_SEEN_HASH_POLICY ) {
      /* Cannot get HASH_POLICY without MODE. */
      ci_log("ERROR: ignoring xmit_hash_policy without bond mode");
      ci_assert(0);
    }
    /* Cannot take further action without MODE */
    return;
  }

 /* We were using IFLA_BOND_SLAVE_MII_STATUS attribute to mark a slave as
  * active.  Now we need to to set one active slave only.  New kernels
  * provide the IFLA_BOND_ACTIVE_SLAVE attribute.
  */
  if( state->mode == CICP_BOND_MODE_ACTIVE_BACKUP &&
      ( state->attributes_seen & CP_BOND_NETLINK_SEEN_ACTIVE_SLAVE ) ) {
    ci_ifid_t active_slave =
      state->attributes_seen & CP_BOND_NETLINK_SEEN_ACTIVE_SLAVE ?
      state->active_slave : 0;
    cp_bond_handle_active_slave(s, bond_ifindex, active_slave);
  }
  else if( state->mode == CICP_BOND_MODE_802_3AD &&
           ( state->attributes_seen & CP_BOND_NETLINK_SEEN_AGGREGATOR ) ) {
    cp_bond_handle_aggregator_id(s, bond_ifindex, state->aggregator_id);
  }
}


/* Call this when netlink announces a master-slave relationship for a bond.  If
 * the slave has been removed, call with master_ifindex == CI_IFID_BAD. */
void cp_bond_slave_update(struct cp_session* s, ci_ifid_t master_ifindex,
                          ci_ifid_t slave_ifindex, bool slave_up,
                          int16_t aggregator_id)
{

  ci_assert_nequal(slave_ifindex, CI_IFID_BAD);

  if( master_ifindex != CI_IFID_BAD ) {
    cicp_rowid_t team_id = cp_team_find_or_add(s, master_ifindex);
    if( ! CICP_ROWID_IS_VALID(team_id) )
      return;
    /* aggregator_id may be 0 if an only if it is not provided by OS.
     * It happens with RHEL6 and with linux < 3.14, when
     * IFLA_BOND_SLAVE_AD_AGGREGATOR_ID is not supported.
     * Otherwise we must use aggragator id matching instead of mii status. */
    bool slave_enabled = true;
    if( s->bond[team_id].master.mode == CICP_BOND_MODE_802_3AD &&
        aggregator_id != 0 )
      slave_enabled = (aggregator_id == s->bond[team_id].agg_id);

    cicp_rowid_t port_id = cp_team_port_add(s, master_ifindex, slave_ifindex);
    if( ! CICP_ROWID_IS_VALID(port_id) )
      return;
    cp_team_slave_update_flags(s, port_id,
                               CICP_BOND_ROW_FLAG_ENABLED | CICP_BOND_ROW_FLAG_UP,
                               (slave_enabled ?
                                CICP_BOND_ROW_FLAG_ENABLED : 0) |
                               (slave_up ? CICP_BOND_ROW_FLAG_UP : 0));
  }
  else {
    cicp_rowid_t slave_id = cp_bond_find_slave(s, slave_ifindex);
    cicp_bond_row_t* master_row;

    /* This function may be called to ensure that the interface is removed
     * from all the aggregations.  If it is not a slave of any aggregation,
     * then we have nothing to do. */
    if( ! CICP_ROWID_IS_VALID(slave_id) )
      return;
    ci_assert(CICP_ROWID_IS_VALID(s->bond[slave_id].slave.master));
    master_row = &s->bond[s->bond[slave_id].slave.master];

    cp_team_slave_del(s, master_row->ifid, slave_ifindex);
  }
}
