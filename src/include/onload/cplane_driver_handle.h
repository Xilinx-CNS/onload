/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#ifndef __ONLOAD_CPLANE_DRIVER_HANDLE_H__
#define __ONLOAD_CPLANE_DRIVER_HANDLE_H__

#include <ci/tools.h>
#include <onload/cplane_prot_types.h>

struct cp_fwd_req;

/* Important distinction between kernel and UL oo_cplane_handles: in the
 * kernel, there's precisely one handle per cplane instance, but at UL there
 * may be aribtrarily many handles per instance. */
struct oo_cplane_handle {
  unsigned cplane_id;

  struct cp_mibs mib[2];

  struct cp_fwd_table fwd_tables[CP_MAX_INSTANCES];

  /* MIB memory allocation parameters. */
  void* mem;
  unsigned long bytes;

  struct net* cp_netns;

  /* Communicate with the cp_server: */
  struct pid* server_pid;
  struct file* server_file;

  spinlock_t msg_lock;
  wait_queue_head_t msg_wq;
  struct list_head msg;

  /* Unlike all other members of this structure, this link is protected by
   * the global cp_lock, not by cp_handle_lock below. */
  ci_dllink link;


  /* Requests to add new routes into the cache.
   * Protected by cp_handle_lock. */
  struct list_head fwd_req;
  int fwd_req_id;

  /* See cplane_prot.c and cplane_prot.h: */
  struct cicppl_instance cppl;

  /* Reference count for the kernel state.  Stacks and ci_private_t structures
   * take out such references, and when necessary, functions take out
   * short-lived references for the duration of the call.  Memory mappings
   * don't need their own references, as the underlying file has one. */
  atomic_t refcount;

  /* cp_handle_lock protects all members of this structure except "link".
   * Lock-ordering note: cp_handle_lock should be taken after cp_lock when both
   * are needed. */
  spinlock_t cp_handle_lock;
  wait_queue_head_t cp_waitq;

  /* Workitem to schedule descruction from potentially atomic context. */
  struct delayed_work destroy_work;
  int/*bool*/ killed;

  int/*bool*/ usable;
  int/*bool*/ server_initialized;

  struct {
    int fwd_req_complete; /* protected by the lock */
    atomic_t fwd_req_nonblock;
    atomic_t oof_req_nonblock;
    atomic_t arp_confirm_try;
    atomic_t arp_confirm_do;
  } stats;
};
#endif /*__ONLOAD_CPLANE_DRIVER_HANDLE_H__ */
