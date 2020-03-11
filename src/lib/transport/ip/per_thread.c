/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Per-thread state
**   \date  2011/04/20
**    \cop  (c) Solarflare Communications, Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <ci/internal/ip.h>
#include <onload/ul/per_thread.h>



#ifdef __powerpc__
__thread struct oo_per_thread oo_per_thread __attribute__((tls_model("local-dynamic")));
#else
__thread struct oo_per_thread oo_per_thread;
#endif

citp_init_thread_callback init_thread_callback;


int oo_per_thread_init(void)
{
  return 0;
}


void oo_per_thread_init_thread(void)
{
  if( init_thread_callback ) {
    init_thread_callback(&oo_per_thread);
    oo_per_thread.initialised = 1;
    oo_per_thread.in_vfork_child = 0;
  }
}

