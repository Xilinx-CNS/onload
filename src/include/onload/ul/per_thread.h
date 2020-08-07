/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2011-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Per-thread state
**   \date  2011/04/20
**    \cop  (c) Solarflare Communications, Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ONLOAD_UL_PER_THREAD_H__
#define __ONLOAD_UL_PER_THREAD_H__

#include <onload/signals.h>
#include <onload/ul/stackname.h>


#ifdef __i386__
# define OO_VFORK_SCRATCH_SIZE  2   /* rtaddr, ebx */
#endif
#ifdef __x86_64__
# define OO_VFORK_SCRATCH_SIZE  1   /* rtaddr */
#endif
#ifdef __powerpc__
# ifdef __powerpc64__
#  define OO_VFORK_SCRATCH_SIZE  2   /* rtaddr, r31 */
# else
#  define OO_VFORK_SCRATCH_SIZE  3   /* rtaddr, r31, r3 */
# endif
#endif
#ifdef __aarch64__
# define OO_VFORK_SCRATCH_SIZE  1   /* rtaddr */
#endif


struct oo_per_thread {
  ci_netif_config_opts*      thread_local_netif_opts;
  int                        initialised;
  struct oo_sig_thread_state sig;
  struct oo_stackname_state  stackname;
  ci_uint64                  poll_nonblock_fast_frc;
  ci_uint64                  select_nonblock_fast_frc;
  struct oo_timesync         timesync;
  unsigned                   spinstate; 
  int                        in_vfork_child;
  void*                      vfork_scratch[OO_VFORK_SCRATCH_SIZE];
};


/* Initialise the per-thread module. */
extern int oo_per_thread_init(void);


extern __thread struct oo_per_thread* oo_per_thread_p CI_HV;
extern __thread struct oo_per_thread oo_per_thread CI_HV;

/* Initialise this thread's per-thread state. */
extern void oo_per_thread_init_thread(void);

/* Get pointer to per-thread state.  The per-thread state may not be
 * initialised, so only use for members that don't require explicit
 * initialisation (and when performance really matters).
 */
ci_inline struct oo_per_thread* __oo_per_thread_get(void)
{
  return &oo_per_thread;
}

ci_inline struct oo_per_thread* oo_per_thread_get(void)
{
  if(CI_UNLIKELY( !oo_per_thread.initialised ))
    oo_per_thread_init_thread();
  return &oo_per_thread;
}

#endif  /* __ONLOAD_UL_PER_THREAD_H__ */
