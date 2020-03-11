#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "cplane_unit.h"
#include <cplane/server.h>

#include "../../tap/tap.h"



#define A inet_addr


static int cp_fwd_rows_matching(struct cp_session* s, unsigned flags)
{
  struct cp_fwd_state* fwd_state = cp_fwd_state_get(s, 0);
  struct cp_fwd_table* fwd_table = &fwd_state->fwd_table;
  cicp_mac_rowid_t id;
  int occupied = 0;

  for( id = 0; id <= fwd_table->mask; id++ ) {
    if( cp_get_fwd_by_id(fwd_table, id)->flags & flags )
      occupied++;
  }

  return occupied;
}

int main(void)
{
  cp_unit_init();
  struct cp_session s;
  int i;
  int n_fwd_rows;
  int n_fwd_entries;

  srand(0);

  cp_unit_init_session(&s);

  /* Total size of the table in rows. */
  n_fwd_rows = cp_get_active_mib(&s)->dim->fwd_mask + 1;

  /* Total number of rows we will attempt to store. This is larger
   * than the table, to test our behaviour when it overflows. */
  n_fwd_entries = n_fwd_rows * 4;

  const char mac1[] = {0x00, 0x0f, 0x53, 0x00, 0x00, 0x00};
  cp_unit_nl_handle_link_msg(&s, RTM_NEWLINK, 1, "ethO0", mac1);

  /* Tell the control plane about more route-resolutions than it has
   * space to store. */

  for( i = 0; i < n_fwd_entries; i++ ) {
    uint32_t dst_addr = rand32();
    cp_unit_insert_resolution(&s, dst_addr, 0, A("1.2.3.4"), 0, 1);
  }

  /* The table should be full. */
  cmp_ok(cp_fwd_rows_matching(&s, CICP_FWD_FLAG_OCCUPIED), "==", n_fwd_rows,
         "All forward table rows are occupied");
  cmp_ok(cp_fwd_rows_matching(&s, CICP_FWD_FLAG_STALE), "==", 0,
         "No forward table rows are stale");

  /* Allow just over half of the timeout to elapse. */
  cp_time_elapse((s.frc_fwd_cache_ttl / 2) + 1000);
  cp_timer_expire(&s.timer_fwd, CP_TIMER_FWD);

  /* The table should still be full, but all the entries should be stale. */
  cmp_ok(cp_fwd_rows_matching(&s, CICP_FWD_FLAG_OCCUPIED), "==", n_fwd_rows,
         "All forward table rows are occupied");
  cmp_ok(cp_fwd_rows_matching(&s, CICP_FWD_FLAG_STALE), "==", n_fwd_rows,
         "All forward table rows are stale");

  /* Allow the rest of the timeout to elapse. */
  cp_time_elapse((s.frc_fwd_cache_ttl / 2) + 1000);
  cp_timer_expire(&s.timer_fwd, CP_TIMER_FWD);

  /* The table should be empty. */
  cmp_ok(cp_fwd_rows_matching(&s, CICP_FWD_FLAG_OCCUPIED), "==", 0,
         "All forward table rows have expired");
  cmp_ok(cp_fwd_rows_matching(&s, CICP_FWD_FLAG_STALE), "==", 0,
         "No forward table rows are stale");

  done_testing();

  return 0;
}
