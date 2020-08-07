/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  mjs
**  \brief  Decls needed for async signal management.
**   \date  2005/03/06
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal  */
#ifndef __CI_INTERNAL_IP_SIGNAL_H__
#define __CI_INTERNAL_IP_SIGNAL_H__

#include <onload/signals.h>
#include <onload/ul/per_thread.h>


typedef struct oo_sig_thread_state citp_signal_info;


extern void citp_signal_run_pending(citp_signal_info* info) CI_HF;

ci_inline citp_signal_info *citp_signal_get_specific_inited(void)
{
  struct oo_per_thread* pt = __oo_per_thread_get();
  return &pt->sig;
}


#endif  /* __CI_INTERNAL_IP_SIGNAL_H__ */
/*! \cidoxg_end */
