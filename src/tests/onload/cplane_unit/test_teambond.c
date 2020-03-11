#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "cplane_unit.h"
#include <cplane/server.h>
#include <ci/tools.h>
#include <ci/tools/dllist.h>

#include "../../tap/tap.h"



#if 0
# define diag_verbose(...) diag(__VA_ARGS__)
#else
# define diag_verbose(...) do {} while( 0 )
#endif


enum events {
  EVENT_ADD_MASTER,
  EVENT_REMOVE_MASTER,
  EVENT_SET_MODE,
  EVENT_ADD_SLAVE,
  EVENT_ADD_SLAVE_TO_ANOTHER_BOND,
  EVENT_REMOVE_SLAVE,
  EVENT_AB_SET_ACTIVE,
  EVENT_ENABLE_SLAVE,
  EVENT_DISABLE_SLAVE,
  /* There's no real-life event corresponding to EVENT_UPDATE_HWPORTS, but it's
   * an entry point to the common team/bond layer, so we treat it as an event
   * anyway. */
  EVENT_UPDATE_HWPORTS,
  EVENT_COUNT,
};

enum teambond_calls {
  CP_TEAM_UPDATE_HWPORTS,
  CP_TEAM_SLAVE_ADD,
  CP_TEAM_SLAVE_DEL,
  CP_TEAM_SET_MODE,
  CP_TEAM_ENABLE_PORT,
  CP_TEAM_DISABLE_PORT,
  CP_TEAM_ACTIVEBACKUP_SET_ACTIVE,
  CP_TEAM_REMOVE_MASTER,
  CP_TEAM_PURGE_UNSEEN,
  CP_TEAM_PURGE_UNKNOWN,
};

enum if_type {
  IF_TYPE_MASTER,
  IF_TYPE_SLAVE,
};

/* An LACP slave should be marked as active iff both of these flags are set. */
const ci_uint8 LACP_ACTIVE_FLAGS = CICP_BOND_ROW_FLAG_UP |
                                   CICP_BOND_ROW_FLAG_ENABLED;

struct test_state {
  cicp_bond_row_t* expected_table;
  int table_rows_in_use;
  int master_count;
  int active_backup_slave_count;
  ci_dllist netlink_queue;
  ci_dllist teambond_queue;
  int total_queue_length;
  ci_int_fifo2_t free_ifindices;
};

/* Describes an enqueued netlink message. */
struct netlink_message_spec {
  ci_dllink link;
  uint16_t nlmsg_type;
  ci_ifid_t ifindex;
  enum if_type if_type;
};

/* Describes an enqueued call into the teambond layer. */
struct teambond_call_spec {
  ci_dllink link;
  enum teambond_calls call;
  /* Not all fields are relevant to all calls. */
  ci_ifid_t master;
  ci_ifid_t slave;
  ci_int8 mode;
  bool up;
};


/* This function checks that the bonding table maintained by the control plane
 * is internally valid.  It does not not check that it is consistent with the
 * configured networking. */
static bool validate_bond_table(struct cp_session* s)
{
  cicp_bond_row_t* row;
  int list_slaves = 0;
  int slave_rows = 0;
  bool found_free = false;

  for( row = s->bond; row - s->bond < s->bond_max; ++row )
    if( row->type == CICP_BOND_ROW_TYPE_MASTER ) {
      if( found_free ) {
        /* Masters should not appear after a free entry. */
        diag("Masters are not compressed at index %d", row - s->bond);
        return false;
      }

      /* Iterate over this bond's slaves. */
      cicp_bond_row_t* slave = row;
      int active_slave_count = 0;
      while( CICP_ROWID_IS_VALID(slave->next) ) {
        slave = &s->bond[slave->next];
        if( slave->type != CICP_BOND_ROW_TYPE_SLAVE ) {
          diag("Row %d in slave-list for %d is of type %d", slave - s->bond,
               row - s->bond, slave->type);
          return false;
        }
        if( slave->slave.flags & CICP_BOND_ROW_FLAG_ACTIVE )
          ++active_slave_count;
        ++list_slaves;
      }
      if( row->master.mode == CICP_BOND_MODE_802_3AD &&
          active_slave_count != row->master.n_active_slaves ) {
        diag("LACP bond has %d active slaves, but n_active_slaves = %d",
             active_slave_count, row->master.n_active_slaves);
        return false;
      }
    }
    else if( row->type == CICP_BOND_ROW_TYPE_SLAVE ) {
      ++slave_rows;
    }
    else if( row->type == CICP_BOND_ROW_TYPE_FREE ) {
      found_free = true;
    }
    else {
      diag("Row %d has invalid type %d", row - s->bond, row->type);
      return false;
    }

  if( slave_rows != list_slaves ) {
    diag("Found %d orphaned slaves", slave_rows - list_slaves);
    return false;
  }

  return true;
}


static inline int ifindex_to_hwport(ci_ifid_t ifindex)
{
  return ifindex & 15;
}


static void
enqueue_netlink_message(struct test_state* state, ci_ifid_t ifindex,
                        uint16_t nlmsg_type, enum if_type if_type)
{
  struct netlink_message_spec* spec = malloc(sizeof(*spec));
  ci_assert(spec);
  spec->nlmsg_type = nlmsg_type;
  spec->if_type = if_type;
  spec->ifindex = ifindex;
  ci_dllist_push_tail(&state->netlink_queue, &spec->link);
  ++state->total_queue_length;
}


static void
enqueue_teambond_call(struct test_state* state, enum teambond_calls call,
                      ci_ifid_t master, ci_ifid_t slave, ci_int8 mode, bool up)
{
  struct teambond_call_spec* spec = malloc(sizeof(*spec));
  ci_assert(spec);
  spec->call = call;
  spec->master = master;
  spec->slave = slave;
  spec->mode = mode;
  spec->up = up;
  ci_dllist_push_tail(&state->teambond_queue, &spec->link);
  ++state->total_queue_length;
}

static cicp_bond_row_t*
alloc_bond_row(struct cp_session* s, struct test_state* state, ci_uint8 type)
{
  cicp_bond_row_t* bond;
  for( bond = state->expected_table;
       bond - state->expected_table < s->bond_max;
       ++bond ) {
    if( bond->type == CICP_BOND_ROW_TYPE_FREE ) {
      bond->type = type;
      ++state->table_rows_in_use;
      return bond;
    }
  }

  return NULL;
}


static void
free_bond_row(struct test_state* state, cicp_bond_row_t* bond)
{
  bond->type = CICP_BOND_ROW_TYPE_FREE;
  --state->table_rows_in_use;
}


static cicp_bond_row_t*
choose_random_master(struct cp_session* s, struct test_state* state)
{
  int master_index = rand() % state->master_count;
  cicp_bond_row_t* bond;
  for( bond = state->expected_table;
       bond - state->expected_table < s->bond_max;
       ++bond )
    if( bond->type == CICP_BOND_ROW_TYPE_MASTER )
      if( master_index-- == 0 )
        break;

  ci_assert_equal(master_index, -1);

  return bond;
}


static cicp_bond_row_t*
choose_random_ab_slave(struct cp_session* s, struct test_state* state)
{
  int slave_index = rand() % state->active_backup_slave_count;
  cicp_bond_row_t* bond;
  cicp_bond_row_t* slave = NULL;

  for( bond = state->expected_table;
       bond - state->expected_table < s->bond_max;
       ++bond )
    if( bond->type == CICP_BOND_ROW_TYPE_MASTER &&
        bond->master.mode == CICP_BOND_MODE_ACTIVE_BACKUP ) {
      /* Iterate over the slaves, decrementing our count as we go. */
      slave = bond;
      while( CICP_ROWID_IS_VALID(slave->next) ) {
        slave = &state->expected_table[slave->next];
        if( slave_index-- == 0 )
          goto found;
      }
    }

 found:
  ci_assert_equal(slave_index, -1);

  return slave;
}


static cicp_bond_row_t*
choose_random_slave(struct cp_session* s, struct test_state* state)
{
  int slave_index = rand() % (state->table_rows_in_use - state->master_count);
  cicp_bond_row_t* bond;
  for( bond = state->expected_table;
       bond - state->expected_table < s->bond_max;
       ++bond )
    if( bond->type == CICP_BOND_ROW_TYPE_SLAVE )
      if( slave_index-- == 0 )
        break;

  ci_assert_equal(slave_index, -1);

  return bond;
}


static ci_uint8 choose_random_bond_mode(void)
{
  const int MODE_MIN = CICP_BOND_MODE_ACTIVE_BACKUP;
  const int MODE_MAX = CICP_BOND_MODE_UNSUPPORTED;
  const int MODE_COUNT = MODE_MAX - MODE_MIN + 1;
  return MODE_MIN + rand() % MODE_COUNT;
}


/* Returns whether either the bonding or LLAP table is full. */
static inline bool
table_is_full(struct cp_session* s, struct test_state* state)
{
  return state->table_rows_in_use >=
         CI_MIN(s->bond_max, s->mib[0].dim->llap_max);
}


static int count_bond_slaves(struct test_state* state, cicp_bond_row_t* row)
{
  int slave_count = 0;

  while( CICP_ROWID_IS_VALID(row->next) ) {
    ++slave_count;
    row = &state->expected_table[row->next];
  }

  return slave_count;
}


static bool
test_has_slave(struct cp_session* s, struct test_state* state,
               ci_ifid_t ifindex)
{
  cicp_bond_row_t* row;
  for( row = &state->expected_table[0];
       row - state->expected_table < s->bond_max;
       ++row )
    if( row->ifid == ifindex && row->type == CICP_BOND_ROW_TYPE_SLAVE )
      return true;
  return false;
}


/* Enqueues netlink and teambond messages for the addition/dump of a master. */
static void
enqueue_master_messages(struct test_state* state, cicp_bond_row_t* bond)
{
  /* Enqueue the addition of the master interface. */
  enqueue_netlink_message(state, bond->ifid, RTM_NEWLINK, IF_TYPE_MASTER);

  /* There's no explicit call into the teambond layer to indicate the addition
   * of a new master.  Instead, the master is created when we first hear about
   * it.  In practice, this will be in a cp_team_set_mode() call. */
  enqueue_teambond_call(state, CP_TEAM_SET_MODE, bond->ifid, 0 /* slave */,
                        bond->master.mode, false /* up */);
}


/* Enqueues netlink and teambond messages for the addition/dump of a slave. */
static void
enqueue_slave_messages(struct test_state* state, ci_ifid_t master_ifindex,
                       cicp_bond_row_t* slave, bool up)
{
  /* Enqueue the addition of the slave interface. */
  enqueue_netlink_message(state, slave->ifid, RTM_NEWLINK, IF_TYPE_SLAVE);

  /* Enqueue the teaming slave notification. */
  enqueue_teambond_call(state, CP_TEAM_SLAVE_ADD, master_ifindex, slave->ifid,
                        0 /* mode */, up);
}


static int ifindex_comparator(const void* a, const void* b)
{
  return *((ci_ifid_t*) a) - *((ci_ifid_t*) b);
}

static void
find_sorted_slaves(struct cp_session* s, cicp_bond_row_t* base,
                   cicp_bond_row_t* row, ci_ifid_t ifindices_out[])
{
  memset(ifindices_out, 0, sizeof(ci_ifid_t) * s->bond_max);

  int i = 0;
  while( CICP_ROWID_IS_VALID(row->next) ) {
    row = &base[row->next];
    /* These assertions are valid even for the control plane's state, because
     * we've already checked that the control plane's state is internally
     * valid. */
    ci_assert_equal(row->type, CICP_BOND_ROW_TYPE_SLAVE);
    ci_assert_lt(i, s->bond_max);
    ifindices_out[i++] = row->ifid;
  }

  qsort(ifindices_out, s->bond_max, sizeof(ci_ifid_t), ifindex_comparator);
}


/* Removes a slave from its master's slave-list. */
static void
disassociate_slave_from_master(struct test_state* state,
                               cicp_bond_row_t* slave)
{
  cicp_bond_row_t* bond = &state->expected_table[slave->slave.master];
  cicp_bond_row_t* row = bond;
  cicp_rowid_t slave_id = slave - state->expected_table;

  while( CICP_ROWID_IS_VALID(row->next) ) {
    cicp_bond_row_t* next = &state->expected_table[row->next];
    if( row->next == slave_id ) {
      row->next = next->next;
      slave->slave.master = CICP_ROWID_BAD;
      return;
    }
    row = next;
  }

  /* We only reach here if the slave was not in its master's list. */
  ci_assert(0);
}


/* Check that the test and the control plane both have the same opinions about
 * the bonding state. */
static bool verify_cplane_state(struct cp_session* s, struct test_state* state)
{
  ci_assert_equal(state->total_queue_length, 0);

  int i;
  cicp_bond_row_t* row;
  for( i = 0; i < s->bond_max; ++i ) {
    row = &state->expected_table[i];
    if( row->type == CICP_BOND_ROW_TYPE_MASTER ) {
      cicp_rowid_t cplane_bond_rowid = cp_bond_find_master(s, row->ifid);
      if( ! CICP_ROWID_IS_VALID(cplane_bond_rowid) ) {
        diag("Row %d: No master for ifindex %d", i, row->ifid);
        return false;
      }
      cicp_bond_row_t* cplane_bond = &s->bond[cplane_bond_rowid];
      if( cplane_bond->master.mode != row->master.mode ) {
        diag("Row %d: Expected mode %d, found %d", i, row->master.mode,
             cplane_bond->master.mode);
        return false;
      }
      ci_ifid_t test_slave_ifindices[s->bond_max];
      ci_ifid_t cplane_slave_ifindices[s->bond_max];
      find_sorted_slaves(s, state->expected_table, row, test_slave_ifindices);
      find_sorted_slaves(s, s->bond, cplane_bond, cplane_slave_ifindices);
      if( memcmp(test_slave_ifindices, cplane_slave_ifindices,
                 sizeof(ci_ifid_t) * s->bond_max) != 0 ) {
        diag("Row %d: Slave-list mismatch", i);
        return false;
      }
    }
    else if( row->type == CICP_BOND_ROW_TYPE_SLAVE ) {
      cicp_rowid_t cplane_slave_rowid = cp_bond_find_slave(s, row->ifid);
      if( ! CICP_ROWID_IS_VALID(cplane_slave_rowid) ) {
        diag("Row %d: No slave for ifindex %d", i, row->ifid);
        return false;
      }
      cicp_bond_row_t* cplane_slave = &s->bond[cplane_slave_rowid];
      cicp_bond_row_t* test_bond = &state->expected_table[row->slave.master];
      ci_ifid_t test_bond_ifid = test_bond->ifid;
      ci_ifid_t cplane_bond_ifid = s->bond[cplane_slave->slave.master].ifid;
      if( cplane_bond_ifid != test_bond_ifid ) {
        diag("Row %d: Expected master ifindex %u, found %u", i, test_bond_ifid,
             cplane_bond_ifid);
        return false;
      }
      if( cplane_slave->slave.hwport != row->slave.hwport ) {
        diag("Row %d: Expected hwport %d, found %d", i, row->slave.hwport,
             cplane_slave->slave.hwport);
        return false;
      }
      if( test_bond->master.mode != CICP_BOND_MODE_UNSUPPORTED &&
          cplane_slave->slave.flags != row->slave.flags ) {
        diag("Row %d: Expected flags %x, found %x", i, row->slave.flags,
             cplane_slave->slave.flags);
        return false;
      }
    }
  }

  int occupied_cplane_rows = 0;
  for( row = &s->bond[0]; row - s->bond < s->bond_max; ++row )
    if( row->type != CICP_BOND_ROW_TYPE_FREE )
      ++occupied_cplane_rows;

  if( occupied_cplane_rows != state->table_rows_in_use ) {
      diag("Expected %d rows, but found %d", state->table_rows_in_use,
           occupied_cplane_rows);
      return false;
  }

  return true;
}


/* Generic handler for an event (as enumerated in [enum events]).  Returns
 * zero on success, or -EINVAL to indicate that the event does not make sense
 * given the current state. */
typedef int (*event_handler_t)(struct cp_session*, struct test_state*);


static int add_master(struct cp_session* s, struct test_state* state)
{
  if( table_is_full(s, state) )
    return -EINVAL;

  /* Add the new master to the expected bonding table. */
  cicp_bond_row_t* bond = alloc_bond_row(s, state, CICP_BOND_ROW_TYPE_MASTER);
  ci_assert(bond);
  ci_assert(ci_fifo2_not_empty(&state->free_ifindices));
  ci_fifo2_get(&state->free_ifindices, &bond->ifid);
  ci_assert_nequal(bond->ifid, CI_IFID_BAD);
  bond->next = CICP_ROWID_BAD;
  bond->master.n_active_slaves = 0;
  ++state->master_count;

  bond->master.mode = choose_random_bond_mode();

  enqueue_master_messages(state, bond);

  return 0;
}


/* Removes a master and all of its slaves. */
static int remove_master(struct cp_session* s, struct test_state* state)
{
  if( state->master_count == 0 )
    return -EINVAL;

  cicp_bond_row_t* bond = choose_random_master(s, state);

  if( bond->master.mode == CICP_BOND_MODE_ACTIVE_BACKUP ) {
    int slave_count = count_bond_slaves(state, bond);
    ci_assert_ge(state->active_backup_slave_count, slave_count);
    state->active_backup_slave_count -= slave_count;
  }

  /* Enqueue the deletion of the master interface and bond-table entry. */
  enqueue_teambond_call(state, CP_TEAM_REMOVE_MASTER, bond->ifid, 0 /* slave */,
                        0 /* mode */, false /* up */);

  do {
    enqueue_netlink_message(state, bond->ifid, RTM_DELLINK,
                            bond->type == CICP_BOND_ROW_TYPE_MASTER ?
                              IF_TYPE_MASTER : IF_TYPE_SLAVE);
    ci_fifo2_put(&state->free_ifindices, bond->ifid);
    free_bond_row(state, bond);
    /* We can still touch bond->next! */
    bond = CICP_ROWID_IS_VALID(bond->next) ?
      &state->expected_table[bond->next] : NULL;
  } while( bond != NULL );
  --state->master_count;

  return 0;
}


static int set_mode(struct cp_session* s, struct test_state* state)
{
  if( state->master_count == 0 )
    return -EINVAL;

  cicp_bond_row_t* bond = choose_random_master(s, state);
  if( bond->master.mode == CICP_BOND_MODE_ACTIVE_BACKUP ) {
    int slave_count = count_bond_slaves(state, bond);
    ci_assert_ge(state->active_backup_slave_count, slave_count);
    state->active_backup_slave_count -= slave_count;
  }

  bond->master.mode = choose_random_bond_mode();
  enqueue_teambond_call(state, CP_TEAM_SET_MODE, bond->ifid, 0 /* slave */,
                        bond->master.mode, false /* up */);

  if( bond->master.mode == CICP_BOND_MODE_ACTIVE_BACKUP ) {
    state->active_backup_slave_count += count_bond_slaves(state, bond);

    /* At most one slave should now be marked as active.  Choose the first one,
     * and tell the control plane about it. */
    bool found_active = false;
    cicp_bond_row_t* row = bond;
    while( CICP_ROWID_IS_VALID(row->next) ) {
      row = &state->expected_table[row->next];
      ci_assert_equal(row->type, CICP_BOND_ROW_TYPE_SLAVE);
      if( row->slave.flags & CICP_BOND_ROW_FLAG_ACTIVE ) {
        if( ! found_active ) {
          /* First active row: choose this one. */
          found_active = true;
          enqueue_teambond_call(state, CP_TEAM_ACTIVEBACKUP_SET_ACTIVE,
                                bond->ifid, row->ifid, 0 /* mode */,
                                false /* up */);
        }
        else {
          /* Subsequent active row: deactivate it. */
          row->slave.flags &= ~CICP_BOND_ROW_FLAG_ACTIVE;
        }
      }
    }
  }
  else if( bond->master.mode == CICP_BOND_MODE_802_3AD ) {
    cicp_bond_row_t* row = bond;
    while( CICP_ROWID_IS_VALID(row->next) ) {
      row = &state->expected_table[row->next];
      ci_assert_equal(row->type, CICP_BOND_ROW_TYPE_SLAVE);
      if( (row->slave.flags & LACP_ACTIVE_FLAGS) == LACP_ACTIVE_FLAGS )
        row->slave.flags |= CICP_BOND_ROW_FLAG_ACTIVE;
      else
        row->slave.flags &=~ CICP_BOND_ROW_FLAG_ACTIVE;
    }
  }

  return 0;
}


static int add_slave(struct cp_session* s, struct test_state* state)
{
  if( state->master_count == 0 || table_is_full(s, state) )
    return -EINVAL;

  cicp_bond_row_t* bond = choose_random_master(s, state);

  /* Add the new slave to the expected bonding table. */
  cicp_bond_row_t* slave = alloc_bond_row(s, state, CICP_BOND_ROW_TYPE_SLAVE);
  ci_assert(slave);
  ci_assert(ci_fifo2_not_empty(&state->free_ifindices));
  ci_fifo2_get(&state->free_ifindices, &slave->ifid);
  ci_assert_nequal(slave->ifid, CI_IFID_BAD);
  slave->slave.master = bond - state->expected_table;
  slave->slave.hwport = ifindex_to_hwport(slave->ifid);
  bool up = rand() & 1;
  slave->slave.flags = up ? CICP_BOND_ROW_FLAG_UP : 0;
  slave->next = bond->next;
  bond->next = slave - state->expected_table;

  if( bond->master.mode == CICP_BOND_MODE_ACTIVE_BACKUP )
    ++state->active_backup_slave_count;

  enqueue_slave_messages(state, bond->ifid, slave, up);

  return 0;
}


/* Simulates the case where a slave is added to one bond while it is already a
 * member of another.  In the real world, this is only expected in the case of
 * netlink drops. */
static int
add_slave_to_another_bond(struct cp_session* s, struct test_state* state)
{
  if( state->master_count < 2 ||
      state->master_count == state->table_rows_in_use )
    return -EINVAL;

  cicp_bond_row_t* slave = choose_random_slave(s, state);
  cicp_bond_row_t* original_bond = &state->expected_table[slave->slave.master];
  cicp_bond_row_t* new_bond;

  /* Choose a master other than the slave's current master. */
  do {
    new_bond = choose_random_master(s, state);
  } while( new_bond->ifid == original_bond->ifid );

  disassociate_slave_from_master(state, slave);
  if( original_bond->master.mode == CICP_BOND_MODE_ACTIVE_BACKUP )
    --state->active_backup_slave_count;

  /* Add the slave to its new master. */
  slave->slave.master = new_bond - state->expected_table;
  bool up = rand() & 1;
  slave->slave.flags = up ? CICP_BOND_ROW_FLAG_UP : 0;
  slave->next = new_bond->next;
  new_bond->next = slave - state->expected_table;

  if( new_bond->master.mode == CICP_BOND_MODE_ACTIVE_BACKUP )
    ++state->active_backup_slave_count;

  enqueue_slave_messages(state, new_bond->ifid, slave, up);

  return 0;
}


static int remove_slave(struct cp_session* s, struct test_state* state)
{
  if( state->master_count == state->table_rows_in_use )
    return -EINVAL;

  cicp_bond_row_t* slave = choose_random_slave(s, state);
  cicp_bond_row_t* bond = &state->expected_table[slave->slave.master];

  if( bond->master.mode == CICP_BOND_MODE_ACTIVE_BACKUP ) {
    ci_assert_gt(state->active_backup_slave_count, 0);
    --state->active_backup_slave_count;
  }

  /* Enqueue the deletion of the slave interface and bond-table entry. */
  enqueue_netlink_message(state, slave->ifid, RTM_DELLINK, IF_TYPE_SLAVE);
  enqueue_teambond_call(state, CP_TEAM_SLAVE_DEL, bond->ifid, slave->ifid,
                        0 /* mode */, false /* up */);

  ci_fifo2_put(&state->free_ifindices, slave->ifid);

  disassociate_slave_from_master(state, slave);
  free_bond_row(state, slave);

  return 0;
}


static int
activebackup_set_active(struct cp_session* s, struct test_state* state)
{
  if( state->active_backup_slave_count == 0 )
    return -EINVAL;

  cicp_bond_row_t* slave = choose_random_ab_slave(s, state);
  cicp_bond_row_t* bond = &state->expected_table[slave->slave.master];
  ci_assert_equal(bond->master.mode, CICP_BOND_MODE_ACTIVE_BACKUP);

  cicp_bond_row_t* row = bond;
  while( CICP_ROWID_IS_VALID(row->next) ) {
    row = &state->expected_table[row->next];
    ci_assert_equal(row->type, CICP_BOND_ROW_TYPE_SLAVE);
    if( row->ifid == slave->ifid )
      row->slave.flags |= (CICP_BOND_ROW_FLAG_ACTIVE |
                           CICP_BOND_ROW_FLAG_ENABLED);
    else
      row->slave.flags &= ~CICP_BOND_ROW_FLAG_ACTIVE;
  }

  enqueue_teambond_call(state, CP_TEAM_ENABLE_PORT, bond->ifid, slave->ifid,
                        0 /* mode */, false /* up */);
  enqueue_teambond_call(state, CP_TEAM_ACTIVEBACKUP_SET_ACTIVE, bond->ifid,
                        slave->ifid, 0 /* mode */, false /* up */);

  return 0;
}


static int enable_slave(struct cp_session* s, struct test_state* state)
{
  if( state->master_count == state->table_rows_in_use )
    return -EINVAL;

  cicp_bond_row_t* slave = choose_random_slave(s, state);
  cicp_bond_row_t* bond = &state->expected_table[slave->slave.master];
  /* A slave becomes active when it's enabled only if the bond is in LACP mode
   * and the slave is up.
   */
  slave->slave.flags |= CICP_BOND_ROW_FLAG_ENABLED;
  if( bond->master.mode == CICP_BOND_MODE_802_3AD &&
      (slave->slave.flags & LACP_ACTIVE_FLAGS) == LACP_ACTIVE_FLAGS )
    slave->slave.flags |= CICP_BOND_ROW_FLAG_ACTIVE;

  /* Enqueue the teaming slave notification. */
  enqueue_teambond_call(state, CP_TEAM_ENABLE_PORT, bond->ifid, slave->ifid,
                        0 /* mode */, false /* up */);

  return 0;
}


static int disable_slave(struct cp_session* s, struct test_state* state)
{
  if( state->master_count == state->table_rows_in_use )
    return -EINVAL;

  cicp_bond_row_t* slave = choose_random_slave(s, state);
  cicp_bond_row_t* bond = &state->expected_table[slave->slave.master];
  /* Disabling a slave also causes it to become inactive. */
  slave->slave.flags &= ~(CICP_BOND_ROW_FLAG_ACTIVE |
                          CICP_BOND_ROW_FLAG_ENABLED);

  /* Enqueue the teaming slave notification. */
  enqueue_teambond_call(state, CP_TEAM_DISABLE_PORT, bond->ifid, slave->ifid,
                        0 /* mode */, false /* up */);

  return 0;
}


static int update_hwports(struct cp_session* s, struct test_state* state)
{
  if( state->master_count == 0 )
    return -EINVAL;

  cicp_bond_row_t* bond = choose_random_master(s, state);

  /* Enqueue the teaming slave notification. */
  enqueue_teambond_call(state, CP_TEAM_UPDATE_HWPORTS, bond->ifid,
                        0 /* slave */, 0 /* mode */, false /* up */);

  return 0;
}


static int
handle_event(struct cp_session* s, struct test_state* state, enum events event)
{
  event_handler_t handlers[] = {
    [EVENT_ADD_MASTER]     = add_master,
    [EVENT_REMOVE_MASTER]  = remove_master,
    [EVENT_SET_MODE]       = set_mode,
    [EVENT_ADD_SLAVE]      = add_slave,
    [EVENT_ADD_SLAVE_TO_ANOTHER_BOND]
                           = add_slave_to_another_bond,
    [EVENT_REMOVE_SLAVE]   = remove_slave,
    [EVENT_AB_SET_ACTIVE]  = activebackup_set_active,
    [EVENT_ENABLE_SLAVE]   = enable_slave,
    [EVENT_DISABLE_SLAVE]  = disable_slave,
    [EVENT_UPDATE_HWPORTS] = update_hwports,
  };
  ci_assert_lt(event, sizeof(handlers) / sizeof(handlers[0]));
  return handlers[event](s, state);
}


static void
despatch_netlink_message(struct cp_session* s, struct test_state* state)
{
  ci_assert(! ci_dllist_is_empty(&state->netlink_queue));
  ci_dllink* link = ci_dllist_pop(&state->netlink_queue);
  struct netlink_message_spec* spec = CI_CONTAINER(struct netlink_message_spec,
                                                   link, link);
  bool is_master = spec->if_type == IF_TYPE_MASTER;

  diag_verbose("Netlink: msg %d for %s ifindex %d", spec->nlmsg_type,
               is_master ? "master" : "slave", spec->ifindex);

  /* Encode the ifindex in the name and MAC. */
  char mac[] = {0x00, 0x0f, 0x53, (spec->ifindex >> 16) & 0xff,
                (spec->ifindex >> 8) & 0xff, spec->ifindex & 0xff};
  char ifname[IFNAMSIZ];
  sprintf(ifname, "%s%d", is_master ? "team" : "eth", spec->ifindex);
  if( is_master ) {
    cp_unit_nl_handle_team_link_msg(s, spec->nlmsg_type, spec->ifindex, ifname,
                                    mac);
  }
  else {
    cp_unit_nl_handle_teamslave_link_msg(s, spec->nlmsg_type, spec->ifindex,
                                         ifname, mac);
    if( spec->nlmsg_type == RTM_NEWLINK ) {
      /* If we're adding or updating the interface, we need to provide it with
       * an artificial hwport. */
      struct cp_mibs* mib;
      int mib_i;
      MIB_UPDATE_LOOP(mib, s, mib_i)
        cicp_rowid_t llap_id = cp_llap_find_row(mib, spec->ifindex);
        cicp_hwport_mask_t hwports = 1 << ifindex_to_hwport(spec->ifindex);
        ci_assert(CICP_ROWID_IS_VALID(llap_id));
        cp_llap_set_hwports(s, mib, llap_id, hwports, hwports,
                            mib->llap[llap_id].encap.type, mib_i == 0);
      MIB_UPDATE_LOOP_END(mib, s)
    }
  }

  ci_assert(validate_bond_table(s));

  free(spec);
}


static void
despatch_teambond_call(struct cp_session* s, struct test_state* state)
{
  ci_assert(! ci_dllist_is_empty(&state->teambond_queue));
  ci_dllink* link = ci_dllist_pop(&state->teambond_queue);
  struct teambond_call_spec* spec = CI_CONTAINER(struct teambond_call_spec,
                                                 link, link);
  switch( spec->call ) {
  case CP_TEAM_SET_MODE:
    diag_verbose("Set mode: master=%d mode=%d", spec->master, spec->mode);
    cp_team_set_mode(s, spec->master, spec->mode, 0 /* hash policy */);
    break;
  case CP_TEAM_REMOVE_MASTER:
    diag_verbose("Remove master: master=%d", spec->master);
    cp_team_remove_master(s, spec->master);
    break;
  case CP_TEAM_SLAVE_ADD:
  {
    diag_verbose("Add slave: master=%d slave=%d", spec->master, spec->slave);
    cicp_rowid_t port_id = cp_team_port_add(s, spec->master, spec->slave);
    if( CICP_ROWID_IS_VALID(port_id) )
      cp_team_slave_update_flags(s, port_id, CICP_BOND_ROW_FLAG_UP,
                                 spec->up ? CICP_BOND_ROW_FLAG_UP : 0);
    break;
  }
  case CP_TEAM_SLAVE_DEL:
    diag_verbose("Delete slave: master=%d slave=%d", spec->master, spec->slave);
    cp_team_slave_del(s, spec->master, spec->slave);
    break;
  case CP_TEAM_ACTIVEBACKUP_SET_ACTIVE:
    cp_team_activebackup_set_active(s, spec->master, spec->slave);
    break;
  case CP_TEAM_ENABLE_PORT:
  {
    diag_verbose("Enable port: master=%d slave=%d", spec->master, spec->slave);
    cicp_rowid_t port_id = cp_team_port_add(s, spec->master, spec->slave);
    if( CICP_ROWID_IS_VALID(port_id) )
      cp_team_slave_update_flags(s, port_id, CICP_BOND_ROW_FLAG_ENABLED,
                                 CICP_BOND_ROW_FLAG_ENABLED);
    break;
  }
  case CP_TEAM_DISABLE_PORT:
  {
    diag_verbose("Disable port: master=%d slave=%d", spec->master, spec->slave);
    cicp_rowid_t port_id = cp_team_port_add(s, spec->master, spec->slave);
    if( CICP_ROWID_IS_VALID(port_id) )
      cp_team_slave_update_flags(s, port_id, CICP_BOND_ROW_FLAG_ENABLED,
                                 0);
    break;
  }
    break;
  case CP_TEAM_UPDATE_HWPORTS:
    {
      diag_verbose("Update hwports: master=%d", spec->master);
      cicp_rowid_t bond_rowid = cp_bond_find_master(s, spec->master);
      /* Reordering between LLAP and teaming events means that there might not
       * be an entry for the requested master in the bonding table.  This is
       * OK; just do nothing in that case. */
      if( CICP_ROWID_IS_VALID(bond_rowid) ) {
        struct cp_mibs* mib;
        int mib_i;

        MIB_UPDATE_LOOP(mib, s, mib_i)
          cp_team_update_hwports(s, mib, bond_rowid, false /* log_changes */);
        MIB_UPDATE_LOOP_END(mib, s)
      }
    }
    break;
  default:
    ci_assert(0);
  }

  ci_assert(validate_bond_table(s));

  free(spec);
}


/* Despatch all pending netlink and teambond messages to the control plane. */
static void
flush_message_queues(struct cp_session* s, struct test_state* state)
{
  /* Do netlink messages first, so that the control plane can make sense of the
   * teambond calls. */
  while( ! ci_dllist_is_empty(&state->netlink_queue) )
    despatch_netlink_message(s, state);
  while( ! ci_dllist_is_empty(&state->teambond_queue) )
    despatch_teambond_call(s, state);
  state->total_queue_length = 0;
}


/* Probe all of the test's state to the control plane.  This should ensure that
 * the control plane's bonding table matches that of the test. */
static void sync_test_to_cplane(struct cp_session* s, struct test_state* state)
{
  ci_assert_equal(state->total_queue_length, 0);

  cicp_bond_row_t* row;
  for( row = &state->expected_table[0];
       row - state->expected_table < s->bond_max;
       ++row ) {
    if( row->type == CICP_BOND_ROW_TYPE_MASTER ) {
      enqueue_master_messages(state, row);
    }
    else if( row->type == CICP_BOND_ROW_TYPE_SLAVE ) {
      ci_assert(CICP_ROWID_IS_VALID(row->slave.master));
      cicp_bond_row_t* bond = &state->expected_table[row->slave.master];
      ci_assert_equal(bond->type, CICP_BOND_ROW_TYPE_MASTER);
      enqueue_slave_messages(state, bond->ifid, row,
                             row->slave.flags & CICP_BOND_ROW_FLAG_UP);
      enqueue_teambond_call(state,
                            row->slave.flags & CICP_BOND_ROW_FLAG_ENABLED ?
                            CP_TEAM_ENABLE_PORT : CP_TEAM_DISABLE_PORT,
                            bond->ifid, row->ifid, 0 /* mode */,
                            false /* up */);
      if( bond->master.mode == CICP_BOND_MODE_ACTIVE_BACKUP &&
          row->slave.flags & CICP_BOND_ROW_FLAG_ACTIVE )
        enqueue_teambond_call(state, CP_TEAM_ACTIVEBACKUP_SET_ACTIVE,
                              bond->ifid, row->ifid, 0 /* mode */,
                              false /* up */);
    }
  }

  flush_message_queues(s, state);
  ci_assert_equal(state->total_queue_length, 0);
}


int main(void)
{
  cp_unit_init();
  struct cp_session s;
  struct test_state state;
  int rc;
  int i;

  unsigned seed = time(NULL);
  diag("Using seed %u", seed);
  srand(seed);

  cp_unit_init_session(&s);

  memset(&state, 0, sizeof(state));
  state.expected_table = calloc(sizeof(cicp_bond_row_t), s.bond_max);
  ci_assert(state.expected_table);
  ci_dllist_init(&state.netlink_queue);
  ci_dllist_init(&state.teambond_queue);
  /* Maintain a pool of ifindices that is a bit bigger than the size of the
   * LLAP table (so that the in-use pool can vary) but small enough that they
   * get recycled quickly. */
  const int MAX_IFINDEX = s.mib[0].dim->llap_max * 4;
  ci_fifo2_ctor(&state.free_ifindices, MAX_IFINDEX, &rc);
  ci_assert_equal(rc, 0);
  for( i = 1; i <= MAX_IFINDEX; ++i )
    ci_fifo2_put(&state.free_ifindices, i);

  /* Too much output slows down the JUnit formatter, so keep to one test point.
   */
  plan(1);

  const int ITERATIONS = 1000000;
  const int MAX_BACKLOG = 10;
  const int MAX_BACKLOGGED_ITERATIONS = 1000;
  bool tests_pass = false;
  int backlogged_iterations = 0;

  for( i = 0; i < ITERATIONS; ++i ) {
    /* Run a random event.  Some events are not always possible, so don't count
     * them. */
    while( handle_event(&s, &state, rand() % EVENT_COUNT) == -EINVAL )
      ;

    /* The event-handler might have enqueued some LLAP and teaming netlink
     * messages.  Despatch some of them. */
    int messages_to_despatch = CI_MAX(1 + rand() % 2,
                                      state.total_queue_length - MAX_BACKLOG);
    messages_to_despatch = CI_MIN(messages_to_despatch,
                                  state.total_queue_length);
    int j;
    for( j = 0; j < messages_to_despatch; ++j ) {
      if( ci_dllist_is_empty(&state.teambond_queue) ||
          (! ci_dllist_is_empty(&state.netlink_queue) && rand() % 2) )
        despatch_netlink_message(&s, &state);
      else
        despatch_teambond_call(&s, &state);
      --state.total_queue_length;

      if( ! validate_bond_table(&s) )
        goto done;
    }

    /* If we've had a backlog for a long time, flush it so that we have a
     * chance to verify the correctness of the bonding state. */
    if( backlogged_iterations >= MAX_BACKLOGGED_ITERATIONS )
      flush_message_queues(&s, &state);

    /* Check that the bonding table is as expected. */
    if( state.total_queue_length == 0 ) {
      backlogged_iterations = 0;

      /* We are up-to-date with our message-processing, meaning that all of the
       * state in [state.expected_table] has been probed to the control plane.
       * However, reordering between LLAP and teaming messages means that the
       * control plane might have had to throw some of that information away.
       * In the real world, this situation would be repaired by the periodic
       * dump, and we will simulate such a dump in a moment.  In the meantime,
       * though, we rely on some implementation details to allow us to make a
       * few checks. */

      /* Implementation detail: The control plane will always know about all
       * of the masters. */
      cicp_bond_row_t* row;
      for( row = &state.expected_table[0];
           row - state.expected_table < s.bond_max;
           ++row )
        if( row->type == CICP_BOND_ROW_TYPE_MASTER )
          if( ! CICP_ROWID_IS_VALID(cp_bond_find_master(&s, row->ifid)) ) {
            diag("No master for ifindex %d", row->ifid);
            goto done;
          }

      /* Implementation detail: All slaves known to the control plane will be
       * known to us. */
      for( row = &s.bond[0]; row - s.bond < s.bond_max; ++row )
        if( row->type == CICP_BOND_ROW_TYPE_SLAVE )
          if( ! test_has_slave(&s, &state, row->ifid) ) {
            diag("Unknown slave with ifindex %d", row->ifid);
            goto done;
          }

      /* To simulate the effect of a netlink dump, sync all of the test's state
       * to the control plane, without any reordering.  Then, check that the
       * control plane's state matches the test's. */
      sync_test_to_cplane(&s, &state);
      if( ! verify_cplane_state(&s, &state) ) {
        cp_unit_dump_cplane_tables(&s);
        __cp_team_print(&s, state.expected_table);
        goto done;
      }
    }
    else {
      ++backlogged_iterations;
    }
  }

  tests_pass = true;

 done:
  ok(tests_pass, "Survived stress test");

  done_testing();

  ci_fifo2_dtor(&state.free_ifindices);

  return 0;
}
