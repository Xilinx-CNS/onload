/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */

#include "cplane_unit.h"
#include "../../../tools/onload_mibdump/dump_tables.h"

#include <cplane/cplane.h>

static ci_uint64 current_time = 0;

ci_uint64 cp_frc64_get(void)
{
  return current_time;
}

void cp_time_elapse(ci_uint64 ticks)
{
  current_time += ticks;
}

void cp_unit_init_session(struct cp_session* s)
{
  memset(s, 0, sizeof(*s));

  /* XXX: These are duplicated from tools/cplane/server.c.  I don't think it's
   * worth defining constants for these right now. */
  struct cp_tables_dim dim = {
    .hwport_max = 8,
    .llap_max = 32,
    .ipif_max = 64,
    .fwd_ln2 = 8,
    .svc_arrays_max = 64,
    .svc_ep_max = 1024,
  };
  s->bond_max = 64;
  s->mac_max_ln2 = 10;
  s->mac_mask = (1ull << s->mac_max_ln2) - 1;
  dim.fwd_mask = (1ull << dim.fwd_ln2) - 1;

  void* mib_mem;
  CP_TEST(posix_memalign(&mib_mem, CI_PAGE_SIZE, cp_calc_mib_size(&dim)) == 0);
  memset(mib_mem, 0, cp_calc_mib_size(&dim));
  memcpy(mib_mem, &dim, sizeof(dim));
  CP_TEST(cp_session_init_memory(s, &dim, mib_mem) == 0);

  s->sock_net_name.nl_pid = CP_UNIT_NL_PID;

  /* operation of license pipe is needed in
   * tests that call cp_license_checked() */
  CP_TRY(pipe2(s->pipe, O_NONBLOCK));

  /* Initial sizes for route_dst and rule_src are enlarged at need. */
  cp_ippl_init(&s->route_dst, sizeof(struct cp_ip_with_prefix), NULL, 4);
  cp_ippl_init(&s->rule_src, sizeof(struct cp_ip_with_prefix), NULL, 1);

  /* Rather than go to the effort of finding the CPU's frequency, use a value
   * of 1 KHz.  Times will therefore not be reported in milliseconds as
   * claimed, but in kilo-FRCs. */
  s->khz = 1;
  s->frc_fwd_cache_ttl = 300 * s->khz * 1000ULL;
  s->user_hz = 1;
  s->flags = CP_SESSION_NETLINK_DUMPED | CP_SESSION_HWPORT_DUMPED;
  s->llap_type_os_mask = LLAP_TYPE_OS_MASK_DEFAULT;

  ci_dllist_init(&s->fwd_req_ul);
}


/* Tears down a mocked-up session.  Most tests only ever create one session and
 * don't bother tearing it down, which is fine. */
void cp_unit_destroy_session(struct cp_session* s)
{
  free(s->main_cp_handle);
}


void
cp_unit_init_cp_handle(struct oo_cplane_handle* cp, struct cp_session* s)
{
  /* We can use the mibs from [main_cp] in the handle directly. */
  void* mib_base = s->mib[0].dim;
  cp->mib[0].dim = cp->mib[1].dim = mib_base;
  cp_init_mibs(mib_base, cp->mib);
  struct cp_fwd_state* fwd_state = cp_fwd_state_get(s, 0);
  void* fwd_base = fwd_state->fwd_table.rows;
  void* fwd_rw_base = fwd_state->fwd_table.rw_rows;
  cp->mib[0].fwd_table.mask = cp->mib[1].fwd_table.mask =
      cp->mib->dim->fwd_mask;
  cp_init_mibs_fwd_blob(fwd_base, cp->mib);
  cp->mib[0].fwd_table.rw_rows = cp->mib[1].fwd_table.rw_rows = fwd_rw_base;
}


void
cp_unit_set_main_cp_handle(struct cp_session* s_local,
                           struct cp_session* s_main)
{
  struct oo_cplane_handle* main_cp_handle = malloc(
    sizeof(*s_local->main_cp_handle)
  );
  CP_TEST(main_cp_handle);
  cp_unit_init_cp_handle(main_cp_handle, s_main);

  s_local->main_cp_handle = main_cp_handle;
}


/* Not called anywhere normally, but useful for debugging failing tests. */
void cp_unit_dump_cplane_tables(struct cp_session* s)
{
  struct cp_mibs* mib = cp_get_active_mib(s);

  cp_dump_hwport_table(mib);
  cp_dump_llap_table(mib);
  cp_dump_ipif_table(mib);
  cp_fwd_print(s);
  cp_session_print_state(s, 0);
}
