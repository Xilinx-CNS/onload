/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#include <ci/efhw/efhw_types.h>
#include <ci/efhw/efct.h>
#include <ci/efhw/eventq.h>
#include <ci/efhw/debug_linux.h>

#include <linux/errno.h>


static bool seq_lt(uint32_t a, uint32_t b)
{
  return (int32_t)(a - b) < 0;
}

static uint32_t make_pkt_seq(unsigned sbseq, unsigned pktix)
{
  return (sbseq << 16) | pktix;
}

static int do_wakeup(struct efhw_nic *nic, struct efhw_efct_rxq *app,
                     int budget)
{
  return nic->ev_handlers->wakeup_fn(nic, app->wakeup_instance, budget);
}

int efct_request_wakeup(struct efhw_nic *nic,
                        struct efhw_nic_efct_rxq_wakeup_bits *bits,
                        struct efhw_efct_rxq *app,
                        unsigned sbseq, unsigned pktix, bool allow_recursion)
{
  uint32_t pkt_seqno = make_pkt_seq(sbseq, pktix);
  uint32_t now = CI_READ_ONCE(bits->now);

  app->last_req_seqno = pkt_seqno;
  app->last_req_now = now;

  EFHW_ASSERT(pkt_seqno != EFCT_INVALID_PKT_SEQNO);
  /* Interrupt wakeups are traditionally defined simply by equality, but we
   * need to use proper ordering because apps can run significantly ahead of
   * the net driver due to interrupt coalescing, and it'd be contrary to the
   * goal of being interrupt-driven to spin entering and exiting the kernel
   * for an entire coalesce period */
  if( seq_lt(pkt_seqno, now) ) {
    if( allow_recursion )
      do_wakeup(nic, app, 0);
    return -EAGAIN;
  }

  if( ci_xchg32(&app->wake_at_seqno, pkt_seqno) == EFCT_INVALID_PKT_SEQNO )
    ci_atomic32_inc(&bits->awaiters);

  
  ci_mb();
  now = CI_READ_ONCE(bits->now);
  if( ! seq_lt(pkt_seqno, now) ) {
    return 0;
  }

  if( ci_cas32_succeed(&app->wake_at_seqno, pkt_seqno, EFCT_INVALID_PKT_SEQNO) ) {
    ci_atomic32_dec(&bits->awaiters);
    if( allow_recursion )
      do_wakeup(nic, app, 0);
    return -EAGAIN;
  }

  return -EAGAIN;
}

int efct_handle_wakeup(struct efhw_nic *nic,
                       struct efhw_nic_efct_rxq_wakeup_bits *bits,
                       unsigned sbseq, unsigned pktix, int budget)
{
  struct efhw_efct_rxq *app;
  uint32_t now = make_pkt_seq(sbseq, pktix);
  int spent = 0;

  CI_WRITE_ONCE(bits->now, now);
  ci_mb();
  if( CI_READ_ONCE(bits->awaiters) == 0 )
    return 0;

  for( app = bits->live_apps; app; app = app->next ) {
    uint32_t wake_at = CI_READ_ONCE(app->wake_at_seqno);
    if( wake_at != EFCT_INVALID_PKT_SEQNO && seq_lt(wake_at, now) ) {
      if( ci_cas32_succeed(&app->wake_at_seqno, wake_at, EFCT_INVALID_PKT_SEQNO) ) {
        int rc;
        ci_atomic32_dec(&bits->awaiters);
        rc = do_wakeup(nic, app, budget - spent);
        if( rc >= 0 )
          spent += rc;
      }
    }
  }
  return spent;
}
