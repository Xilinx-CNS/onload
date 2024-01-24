/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */
/* This file contains bond MIB update functions.  This file does not
 * contain the code which receives such updates from OS (netlink, read from
 * /proc, etc). */

#include "private.h"

static cicp_rowid_t
cp_team_find_free(struct cp_session* s)
{
  cicp_rowid_t id;

  for( id = 0; id < s->bond_max; id++ ) {
    if( cicp_bond_row_is_free(&s->bond[id]) )
      return id;
  }
  return CICP_ROWID_BAD;
}

cicp_rowid_t
cp_team_find_or_add(struct cp_session* s, ci_ifid_t ifindex)
{
  cicp_rowid_t id = cp_team_find_row(s, ifindex);

  if( CICP_ROWID_IS_VALID(id) ) {
    if( s->bond[id].type != CICP_BOND_ROW_TYPE_MASTER )
      return CICP_ROWID_BAD;
    return id;
  }

  id = cp_team_find_free(s);
  if( ! CICP_ROWID_IS_VALID(id) ) {
    CI_RLLOG(10, "ERROR: can not store new team ifindex %d", ifindex);
    return CICP_ROWID_BAD;
  }
  cicp_bond_row_t* bond = &s->bond[id];

  bond->ifid = ifindex;
  bond->type = CICP_BOND_ROW_TYPE_MASTER;
  bond->next = CICP_ROWID_BAD;

  bond->master.n_active_slaves = 0;

  /* Set unsupported mode to start with: */
  s->bond[id].master.mode = CICP_BOND_MODE_UNSUPPORTED;
  return id;
}

static cicp_rowid_t
port_find_or_add(struct cp_session* s, ci_ifid_t ifindex)
{
  struct cp_mibs* mib = cp_get_active_mib(s);
  cicp_rowid_t id = cp_team_find_row(s, ifindex);
  cicp_rowid_t llap_id;

  if( CICP_ROWID_IS_VALID(id) ) {
    if( s->bond[id].type != CICP_BOND_ROW_TYPE_SLAVE )
      return CICP_ROWID_BAD;
    return id;
  }

  llap_id = cp_llap_find_row(mib, ifindex);
  if( ! CICP_ROWID_IS_VALID(llap_id) )
    return CICP_ROWID_BAD;

  id = cp_team_find_free(s);
  if( ! CICP_ROWID_IS_VALID(id) ) {
    CI_RLLOG(10, "ERROR: can not store new port ifindex %d", ifindex);
    return CICP_ROWID_BAD;
  }
  cicp_bond_row_t* bond = &s->bond[id];

  /* This part of the initialisation is only done for genuinely new slaves.
   * The remainder of the initialisation, which is common to new slaves and to
   * slaves that are changing master, must be done by the caller. */
  bond->ifid = ifindex;
  bond->type = CICP_BOND_ROW_TYPE_SLAVE;

  bond->slave.master = CICP_ROWID_BAD;
  bond->slave.flags = 0;
  cp_bond_slave_set_hwports(bond, &mib->llap[llap_id]);

  return id;
}


static void
__team_slave_release(struct cp_session* s, cicp_rowid_t team_id,
                     cicp_rowid_t port_id)
{
  if( s->bond[port_id].slave.flags & CICP_BOND_ROW_FLAG_ACTIVE &&
      s->bond[team_id].master.mode == CICP_BOND_MODE_802_3AD ) {
    ci_assert_gt(s->bond[team_id].master.n_active_slaves, 0);
    s->bond[team_id].master.n_active_slaves--;
  }
  s->bond[port_id].slave.flags &=~ CICP_BOND_ROW_FLAG_ACTIVE;
}


static void
__team_slave_remove_from_list(struct cp_session* s, cicp_rowid_t team_id,
                              cicp_rowid_t port_id)
{
  cicp_rowid_t id, prev_id;

  for( id = s->bond[team_id].next, prev_id = team_id;
       id != CICP_ROWID_BAD;
       prev_id = id, id = s->bond[id].next ) {
    if( id == port_id ) {
      s->bond[prev_id].next = s->bond[id].next;
      s->bond[id].next = CICP_ROWID_BAD;
      return;
    }
  }
}


static void
team_slave_disassociate(struct cp_session* s, cicp_rowid_t port_id)
{
  cicp_rowid_t team_id = s->bond[port_id].slave.master;
  __team_slave_release(s, team_id, port_id);
  __team_slave_remove_from_list(s, team_id, port_id);
  s->bond[port_id].slave.master = CICP_ROWID_BAD;
}


/* This function ensures that "port" is recorded as a slave for "team".
 * Returns the row id of the slave "port".
 *
 * The caller must call cp_team_update_hwports_bothmibs() to ensure that the
 * just-added port is included into hwports.  In many cases, the caller
 * delegates this job to cp_team_slave_update_flags().
 */
cicp_rowid_t
cp_team_port_add(struct cp_session* s, ci_ifid_t team, ci_ifid_t port)
{
  cicp_rowid_t team_id, port_id;

  team_id = cp_team_find_or_add(s, team);
  if( ! CICP_ROWID_IS_VALID(team_id) )
    return CICP_ROWID_BAD;
  ci_assert_equal(s->bond[team_id].type, CICP_BOND_ROW_TYPE_MASTER);

  port_id = port_find_or_add(s, port);
  if( ! CICP_ROWID_IS_VALID(port_id) )
    return CICP_ROWID_BAD;
  ci_assert_equal(s->bond[port_id].type, CICP_BOND_ROW_TYPE_SLAVE);

  if( s->bond[port_id].slave.master == team_id )
    return port_id;
  /* If the slave already has a master other than the one to which we have been
   * told it now belongs, then before proceeding we need to disentangle the
   * slave from its old master. */
  else if( CICP_ROWID_IS_VALID(s->bond[port_id].slave.master) )
    team_slave_disassociate(s, port_id);

  ci_assert(! CICP_ROWID_IS_VALID(s->bond[port_id].slave.master));

  /* (Re)-initialise the slave. */
  ci_assert_nflags(s->bond[port_id].slave.flags, CICP_BOND_ROW_FLAG_ACTIVE);
  s->bond[port_id].slave.master = team_id;
  s->bond[port_id].next = s->bond[team_id].next;
  s->bond[team_id].next = port_id;

  return port_id;
}


/* Update the hwports for a bond's LLAP entry (in one MIB structure!). */
static void
team_set_hwports(struct cp_session* s, struct cp_mibs* mib,
                 cicp_rowid_t team_id,
                 cicp_hwport_mask_t rx_hwports,
                 cicp_hwport_mask_t tx_hwports,
                 bool notify)
{
  cicp_rowid_t llap_id = cp_llap_find_row(mib, s->bond[team_id].ifid);
  if( llap_id == CICP_ROWID_BAD )
    return;

  cp_llap_set_hwports(s, mib, llap_id, rx_hwports, tx_hwports,
                      (mib->llap[llap_id].encap.type & ~CICP_LLAP_TYPE_USES_HASH) |
                      s->bond[team_id].master.hash_policy, notify);
}


/* Calculate the hwport mask for this team.
 * Returns true if the team is accelerated. */
static bool
team_get_hwports(struct cp_session* s, cicp_rowid_t team_id,
                 cicp_hwport_mask_t* rx_ports, cicp_hwport_mask_t* tx_ports)
{
  cicp_rowid_t slave = s->bond[team_id].next;

  if( s->bond[team_id].master.mode == CICP_BOND_MODE_UNSUPPORTED ||
      slave == CICP_ROWID_BAD ) {
    return false;
  }

  do {
    ci_assert_nequal(slave, CICP_ROWID_BAD);
    if( s->bond[slave].slave.flags & CICP_BOND_ROW_FLAG_UNSUPPORTED ) {
      return false;
    }

    *rx_ports |= s->bond[slave].slave.hwports;
    if( s->bond[slave].slave.flags & CICP_BOND_ROW_FLAG_ACTIVE )
      *tx_ports |= s->bond[slave].slave.hwports;
  } while( (slave = s->bond[slave].next) != CICP_ROWID_BAD );

  return true;
}


/* After a change in a bond's configuration, the correct hwport mask for its
 * LLAP is not trivial to determine from its previous mask, as the presence of
 * any non-SFC slave forces the mask to zero.  This function recalculates and
 * updates the hwport mask.
 *
 * cp_team_update_hwports() must be called under MIB_UPDATE_LOOP.
 *
 * cp_team_update_hwports_bothmibs() calls MIB_UPDATE_LOOP itself. */
void cp_team_update_hwports(struct cp_session* s, struct cp_mibs* mib,
                           cicp_rowid_t team_id, bool notify)
{
  cicp_hwport_mask_t rx = 0, tx = 0;
  if( team_get_hwports(s, team_id, &rx, &tx) )
    team_set_hwports(s, mib, team_id, rx, tx, notify);
  else
    team_set_hwports(s, mib, team_id, 0, 0, notify);
}


void
cp_team_update_hwports_bothmibs(struct cp_session* s, cicp_rowid_t team_id)
{
  struct cp_mibs* mib;
  int mib_i;

  MIB_UPDATE_LOOP(mib, s, mib_i)
    cp_team_update_hwports(s, mib, team_id, mib_i == 0);
  MIB_UPDATE_LOOP_END(mib, s)
}


static void
activebackup_set_active(struct cp_session* s, cicp_rowid_t team_id,
                        cicp_rowid_t port_id)
{
  if( s->bond[port_id].slave.flags & CICP_BOND_ROW_FLAG_ACTIVE )
    return;

  s->bond[port_id].slave.flags |= CICP_BOND_ROW_FLAG_ACTIVE;

  int id = s->bond[port_id].slave.master;
  while( (id = s->bond[id].next) != CICP_ROWID_BAD ) {
    if( port_id != id )
      s->bond[id].slave.flags &=~ CICP_BOND_ROW_FLAG_ACTIVE;
  }

  cp_team_update_hwports_bothmibs(s, team_id);
}

static void
loadbalance_set_active(struct cp_session* s,
                       cicp_rowid_t team_id, cicp_rowid_t port_id,
                       bool active)
{
  /* If the flag is already correct, there's nothing to do. */
  if( ! (s->bond[port_id].slave.flags & CICP_BOND_ROW_FLAG_ACTIVE) == ! active )
    return;

  if( active ) {
    s->bond[port_id].slave.flags |= CICP_BOND_ROW_FLAG_ACTIVE;
    s->bond[team_id].master.n_active_slaves++;
  }
  else if( s->bond[port_id].slave.flags & CICP_BOND_ROW_FLAG_ACTIVE) {
    s->bond[port_id].slave.flags &=~ CICP_BOND_ROW_FLAG_ACTIVE;
    ci_assert_gt(s->bond[team_id].master.n_active_slaves, 0);
    s->bond[team_id].master.n_active_slaves--;
  }
  else {
    /* If the CICP_BOND_ROW_FLAG_ACTIVE flag is already correct, we should have
     * exited early. */
    ci_assert(0);
  }

  cp_team_update_hwports_bothmibs(s, team_id);
}

void cp_team_slave_update_flags(struct cp_session* s, cicp_rowid_t port_id,
                                ci_uint8 mask, ci_uint8 flags)
{
  cicp_rowid_t team_id = s->bond[port_id].slave.master;
  uint8_t* row_flags = &s->bond[port_id].slave.flags;

  /* Have the flags changed? */
  if( (*row_flags & mask) == flags )
    return;

  *row_flags &=~ mask;
  *row_flags |= flags;

  /* Should we change CICP_BOND_ROW_FLAG_ACTIVE? */
  if(  s->bond[team_id].master.mode != CICP_BOND_MODE_802_3AD ||
       !! (*row_flags & CICP_BOND_ROW_FLAG_ACTIVE) ==
      ( (*row_flags & (CICP_BOND_ROW_FLAG_UP | CICP_BOND_ROW_FLAG_ENABLED)) ==
        (CICP_BOND_ROW_FLAG_UP | CICP_BOND_ROW_FLAG_ENABLED) ) ) {
    /* Even if flags are not updated, the list of ports can be new - call
     * cp_team_update_hwports_bothmibs().  See also comments before
     * cp_team_port_add(). */
    cp_team_update_hwports_bothmibs(s, team_id);
    return;
  }

  loadbalance_set_active(s, team_id, port_id,
        (*row_flags & (CICP_BOND_ROW_FLAG_UP | CICP_BOND_ROW_FLAG_ENABLED)) ==
         (CICP_BOND_ROW_FLAG_UP | CICP_BOND_ROW_FLAG_ENABLED));
}

/* The caller must start MIB loop and remove the port_id from the list */
static void team_slave_free(struct cp_session* s, cicp_rowid_t team_id,
                            cicp_rowid_t port_id)
{
  __team_slave_release(s, team_id, port_id);
  s->bond[port_id].type = CICP_BOND_ROW_TYPE_FREE;

  cp_team_update_hwports_bothmibs(s, team_id);
}

static void team_compress_update_slaves(struct cp_session* s,
                                        cicp_rowid_t master)
{
  cicp_rowid_t slave;

  for( slave = s->bond[master].next;
       CICP_ROWID_IS_VALID(slave);
       slave = s->bond[slave].next ) {
    /* We only move masters to free rows, so if this slave is already
     * pointing at this row, then something's up.
     */
    ci_assert_nequal(s->bond[slave].slave.master, master);
    s->bond[slave].slave.master = master;
  }
}

/* We compress master rows only; slaves can be uncompressed. */
static bool team_compress_one(struct cp_session* s)
{
  cicp_rowid_t free, id;

  for( free = 0; free < s->bond_max; free++ ) {
    if( s->bond[free].type == CICP_BOND_ROW_TYPE_FREE )
      break;
  }

  if( free == s->bond_max )
    return false;

  for( id = free + 1; id < s->bond_max; id++ ) {
    if( s->bond[id].type == CICP_BOND_ROW_TYPE_MASTER ) {
      memcpy(&s->bond[free], &s->bond[id], sizeof(s->bond[free]));
      team_compress_update_slaves(s, free);
      s->bond[id].type = CICP_BOND_ROW_TYPE_FREE;

      /* Are there any other masters to be moved to another just-freed
       * rows?  Try to compress again. */
      return true;
    }
  }

  return false;
}
static void team_compress(struct cp_session* s)
{
  while( team_compress_one(s) )
    ;
}

void cp_team_slave_del(struct cp_session* s,
                       ci_ifid_t team, ci_ifid_t port)
{
  struct cp_mibs* mib = cp_get_active_mib(s);
  cicp_rowid_t team_id, port_id;

  team_id = cp_team_find_row(s, team);
  port_id = cp_team_find_row(s, port);
  if( ! CICP_ROWID_IS_VALID(team_id) || ! CICP_ROWID_IS_VALID(port_id) ||
      s->bond[team_id].type != CICP_BOND_ROW_TYPE_MASTER ||
      s->bond[port_id].type != CICP_BOND_ROW_TYPE_SLAVE ||
      s->bond[port_id].slave.master != team_id ) {
    /* Something is wrong; we'll fix it during the next dump. */
    return;
  }

  __team_slave_remove_from_list(s, team_id, port_id);
  team_slave_free(s, team_id, port_id);

  cicp_rowid_t llap_id = cp_llap_find_row(mib, s->bond[team_id].ifid);
  if( llap_id != CICP_ROWID_BAD )
    cp_fwd_llap_update(s, mib, llap_id, 0);

  team_compress(s);
}

static void
assert_active_slave_count_sanity(struct cp_session* s, cicp_rowid_t team_id)
{
#ifndef NDEBUG
  cicp_rowid_t slave_id;
  int n_active_slaves = 0;

  for( slave_id = s->bond[team_id].next;
       slave_id != CICP_ROWID_BAD;
       slave_id = s->bond[slave_id].next )
    if( s->bond[slave_id].slave.flags & CICP_BOND_ROW_FLAG_ACTIVE )
      ++n_active_slaves;

  switch( s->bond[team_id].master.mode ) {
  case CICP_BOND_MODE_ACTIVE_BACKUP:
    ci_assert_le(n_active_slaves, 1);
    break;
  case CICP_BOND_MODE_802_3AD:
    ci_assert_equal(n_active_slaves, s->bond[team_id].master.n_active_slaves);
    break;
  }
#endif
}

void cp_team_set_mode(struct cp_session* s, ci_ifid_t team, ci_int8 mode,
                      cicp_llap_type_t hash_policy)
{
  cicp_rowid_t team_id;

  ci_assert_nflags(hash_policy, ~CICP_LLAP_TYPE_USES_HASH);

  team_id = cp_team_find_or_add(s, team);
  if( ! CICP_ROWID_IS_VALID(team_id) )
    return;
  ci_assert_equal(s->bond[team_id].type, CICP_BOND_ROW_TYPE_MASTER);

  if( s->bond[team_id].master.mode == mode &&
      s->bond[team_id].master.hash_policy == hash_policy)
    return;

  if( s->bond[team_id].master.mode != mode ) {
    /* If this is a genuine change in mode, we need to fix up the tracking of
     * active slaves, which differs according to mode.  For AB bonds, we need
     * to ensure that at most one slave is active.  For LACP bonds, we need to
     * update [n_active_slaves], as that is only guaranteed to be valid while
     * in LACP mode. */
    int n_active_slaves = 0;
    cicp_rowid_t slave_id;
    for( slave_id = s->bond[team_id].next;
         slave_id != CICP_ROWID_BAD;
         slave_id = s->bond[slave_id].next )
      if( s->bond[slave_id].slave.flags & CICP_BOND_ROW_FLAG_ACTIVE ) {
        if( ++n_active_slaves > 1 && mode == CICP_BOND_MODE_ACTIVE_BACKUP )
          s->bond[slave_id].slave.flags &= ~CICP_BOND_ROW_FLAG_ACTIVE;
      }
    if( mode == CICP_BOND_MODE_802_3AD )
      s->bond[team_id].master.n_active_slaves = n_active_slaves;
  }

  if( mode == CICP_BOND_MODE_802_3AD ) {
    s->bond[team_id].master.hash_policy = 
              hash_policy ? hash_policy : CICP_LLAP_TYPE_XMIT_HASH_LAYER34;
  }
  else {
    s->bond[team_id].master.hash_policy = 0;
  }
  s->bond[team_id].master.mode = mode;

  assert_active_slave_count_sanity(s, team_id);

  cp_team_update_hwports_bothmibs(s, team_id);
}

void cp_team_no_ports(struct cp_session* s, ci_ifid_t team)
{
  struct cp_mibs* mib;
  int mib_i;
  cicp_rowid_t team_id, llap_id = CICP_ROWID_BAD;
  bool changed = false;

  team_id = cp_team_find_or_add(s, team);
  if( ! CICP_ROWID_IS_VALID(team_id) )
    return;
  ci_assert_equal(s->bond[team_id].master.mode,
                  CICP_BOND_MODE_ACTIVE_BACKUP);

  /* Ensure that no slave is marked as "active" */
  cicp_rowid_t slave_rowid;
  for( slave_rowid = s->bond[team_id].next;
       CICP_ROWID_IS_VALID(slave_rowid);
       slave_rowid = s->bond[slave_rowid].next ) {
    s->bond[slave_rowid].slave.flags &=~ CICP_BOND_ROW_FLAG_ACTIVE;
  }

  MIB_UPDATE_LOOP(mib, s, mib_i)
    llap_id = cp_llap_find_row(mib, team);
    if( llap_id != CICP_ROWID_BAD &&
        (mib->llap[llap_id].encap.type & CICP_LLAP_TYPE_BOND) &&
        mib->llap[llap_id].tx_hwports != 0 ) {
      cp_mibs_llap_under_change(s);
      changed = true;
      mib->llap[llap_id].tx_hwports = 0;
    }
  MIB_UPDATE_LOOP_END(mib, s)
  if( changed )
    cp_fwd_llap_update(s, cp_get_active_mib(s), llap_id, 0);
}

void cp_team_activebackup_set_active(struct cp_session* s,
                                     ci_ifid_t team, ci_ifid_t port)
{
  cicp_rowid_t team_id, port_id;

  port_id = cp_team_port_add(s, team, port);
  if( ! CICP_ROWID_IS_VALID(port_id) )
    return;
  team_id = s->bond[port_id].slave.master;
  ci_assert_equal(s->bond[team_id].master.mode, CICP_BOND_MODE_ACTIVE_BACKUP);

  activebackup_set_active(s, team_id, port_id);
}


static void team_remove_master(struct cp_session* s, cicp_rowid_t id)
{
  cicp_rowid_t old;

  while( id != CICP_ROWID_BAD ) {
    old = id;
    id = s->bond[id].next;
    s->bond[old].type = CICP_BOND_ROW_TYPE_FREE;
  }
}

void cp_team_remove_master(struct cp_session* s, ci_ifid_t team)
{
  cicp_rowid_t team_id;

  team_id = cp_team_find_row(s, team);
  if( ! CICP_ROWID_IS_VALID(team_id) ||
      s->bond[team_id].type != CICP_BOND_ROW_TYPE_MASTER ) {
    return;
  }

  team_remove_master(s, team_id);
  team_compress(s);
}

void ci_team_purge_unseen(struct cp_session* s, ci_ifid_t team,
                          cp_row_mask_t seen)
{
  cicp_rowid_t team_id, id, prev;

  team_id = cp_team_find_row(s, team);
  if( ! CICP_ROWID_IS_VALID(team_id) ||
      s->bond[team_id].type != CICP_BOND_ROW_TYPE_MASTER ) {
    return;
  }
  bool removed = false;
  prev = team_id;
  while( id = s->bond[prev].next, CICP_ROWID_IS_VALID(id) ) {
    ci_assert_equal(s->bond[id].type, CICP_BOND_ROW_TYPE_SLAVE);
    if( ! cp_row_mask_get(seen, id) ) {
      s->bond[prev].next = s->bond[id].next;
      team_slave_free(s, team_id, id);
      removed = true;
    }
    else {
      prev = s->bond[prev].next;
    }
  }

  if( removed )
    team_compress(s);
}

void cp_team_purge_unknown(struct cp_session* s, struct cp_mibs* mib)
{
  cicp_rowid_t team_id;
  bool removed = false;

  for( team_id = 0; team_id < s->bond_max; team_id++ ) {
    /* Master rows are compressed, so we can exit early. */
    if( s->bond[team_id].type == CICP_BOND_ROW_TYPE_FREE )
      break;

    if( s->bond[team_id].type == CICP_BOND_ROW_TYPE_MASTER ) {
      if( ! CICP_ROWID_IS_VALID(
              cp_llap_find_row(mib, s->bond[team_id].ifid)) ) {
        team_remove_master(s, team_id);
        removed = true;
      }
    }
  }

  if( removed )
    team_compress(s);
}

CP_UNIT_EXTERN void
__cp_team_print(struct cp_session* s, cicp_bond_row_t* bond_table)
{
  cicp_rowid_t id;

  for( id = 0; id < s->bond_max; id++ ) {
    cicp_bond_row_t *row = &bond_table[id];
    switch( row->type ) {
      case CICP_BOND_ROW_TYPE_MASTER:
        cp_print(s, "  Row %d: MST if %d, next %d, mode %d, agg_id %d "
                 "hash "CICP_ENCAP_NAME_FMT" actv_slaves %d",
                 id, row->ifid, row->next, row->master.mode, row->agg_id,
                 cicp_encap_name(row->master.hash_policy),
                 row->master.n_active_slaves);
        break;
      case CICP_BOND_ROW_TYPE_SLAVE:
        cp_print(s, "  Row %d: SLV if %d, master %d, agg_id %d, "
                 "next %d, hwports 0x%08x, flags %d (%s %s%s%s)",
                 id, row->ifid, row->slave.master, row->agg_id,
                 row->next, row->slave.hwports, row->slave.flags,
                 row->slave.flags & CICP_BOND_ROW_FLAG_ACTIVE ?
                 "Active" : "Inactive",
                 row->slave.flags & CICP_BOND_ROW_FLAG_UNSUPPORTED ?
                 "Unsupported" : "Supported",
                 row->slave.flags & CICP_BOND_ROW_FLAG_UP ?
                 ", Up" : "",
                 row->slave.flags & CICP_BOND_ROW_FLAG_ENABLED ?
                 ", Enabled" : "");
    }
  }
}

void cp_team_print(struct cp_session* s)
{
  cp_print(s, "%s:", __func__);
  __cp_team_print(s, s->bond);
}

